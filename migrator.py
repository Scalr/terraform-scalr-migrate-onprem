import binascii
import argparse
import fnmatch
import hashlib
import json
import sys
import traceback
import urllib.error
import urllib.request
from urllib.parse import urlencode
from typing import Dict, List, Optional, Any
import os
import re
from datetime import datetime
from dataclasses import dataclass
import time
from packaging import version

# Check Python version
if sys.version_info < (3, 8):
    sys.exit("Python 3.8 or higher is required")

# Constants
MAX_TERRAFORM_VERSION = "1.5.7"
DEFAULT_MANAGEMENT_ENV_NAME = "scalr-admin"
RATE_LIMIT_DELAY = 5  # seconds
MAX_RETRIES = 3

class RateLimitError(Exception):
    pass

class MissingDataError(Exception):
    pass

class MissingMappingError(Exception):
    pass

def handle_rate_limit(response: urllib.response.addinfourl) -> None:
    """Handle rate limit responses and wait if necessary."""
    if response.status == 429:  # Too Many Requests
        retry_after = int(response.headers.get('Retry-After', RATE_LIMIT_DELAY))
        ConsoleOutput.warning(f"Rate limit hit. Waiting {retry_after} seconds...")
        time.sleep(retry_after)
        raise RateLimitError("Rate limit hit")

def make_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Any = None,
    retries: int = MAX_RETRIES
) -> urllib.response.addinfourl:
    """Make HTTP request with rate limit handling and retries."""
    if headers is None:
        headers = {}
    
    for attempt in range(retries):
        try:
            request = urllib.request.Request(url, method=method, headers=headers, data=data)
            with urllib.request.urlopen(request) as response:
                handle_rate_limit(response)
                return response
        except RateLimitError:
            if attempt == retries - 1:
                raise
            time.sleep(RATE_LIMIT_DELAY)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                handle_rate_limit(e)
                if attempt == retries - 1:
                    raise
                time.sleep(RATE_LIMIT_DELAY)
            else:
                raise
        except Exception:
            if attempt == retries - 1:
                raise
            time.sleep(RATE_LIMIT_DELAY)

@dataclass
class MigratorArgs:
    # Destination SaaS Scalr
    scalr_hostname: str
    scalr_token: str
    scalr_environment: str
    
    # Source on-prem Scalr
    source_scalr_hostname: str
    source_scalr_token: str
    source_scalr_environment: str
    
    # Migration options
    vcs_name: Optional[str]
    pc_name: Optional[str]
    workspaces: str
    skip_workspace_creation: bool
    skip_backend_secrets: bool
    management_workspace_name: str
    agent_pool_name: Optional[str] = None
    account_id: Optional[str] = None
    lock: bool = True
    management_env_name: str = DEFAULT_MANAGEMENT_ENV_NAME
    disable_deletion_protection: bool = False
    debug_enabled: bool = os.getenv("SCALR_DEBUG_ENABLED", False)
    skip_variables: Optional[str] = None

    @classmethod
    def from_argparse(cls, args: argparse.Namespace) -> 'MigratorArgs':
        if not args.scalr_environment:
            args.scalr_environment = args.source_scalr_environment

        return cls(
            scalr_hostname=args.scalr_hostname,
            scalr_token=args.scalr_token,
            scalr_environment=args.scalr_environment,
            source_scalr_hostname=args.source_scalr_hostname,
            source_scalr_token=args.source_scalr_token,
            source_scalr_environment=args.source_scalr_environment,
            vcs_name=getattr(args, 'vcs_name', None),
            pc_name=getattr(args, 'pc_name', None),
            agent_pool_name=getattr(args, 'agent_pool_name', None),
            workspaces=getattr(args, 'workspaces', None) or "*",
            skip_workspace_creation=getattr(args, 'skip_workspace_creation', False),
            skip_backend_secrets=getattr(args, 'skip_backend_secrets', False),
            lock=not getattr(args, 'skip_scalr_lock', False),
            management_env_name=getattr(args, 'management_env_name', DEFAULT_MANAGEMENT_ENV_NAME),
            management_workspace_name=f"{args.scalr_environment}",
            disable_deletion_protection=getattr(args, 'disable_deletion_protection', False),
            skip_variables=getattr(args, 'skip_variables', None)
        )

class HClAttribute:
    def __init__(self, value, encode_required: bool = False) -> None:
        self.hcl_value = value
        self.encode_required = encode_required

    def get_hcl_value(self) -> Any:
        if not self.encode_required:
            return self.hcl_value

        try:
            json.loads(self.hcl_value)
            return json.dumps(self.hcl_value)
        except (ValueError, TypeError):
            return self.hcl_value

class HCLObject:
    def __init__(self, attributes: dict) -> None:
        self.attributes = attributes


class AbstractTerraformResource:
    def __init__(self, resource_type: str, name: str, attributes: Dict, hcl_resource_type: str) -> None:
        self.resource_type = resource_type
        self.name = name.lower().replace('-', '_')
        self.attributes = attributes
        self.id = None
        self.hcl_resource_type: str = hcl_resource_type

    def _render_attribute(self, attrs: list, key, value, ident: Optional[int] = None):
        if not ident:
            ident = 2

        if key == "vcs_repo" and self.resource_type == "scalr_workspace":
            # Special handling for vcs_repo block in scalr_workspace
            attrs.append((" "*ident) + "vcs_repo {")
            for repo_key, repo_value in value.items():
                if repo_value is not None:  # Skip None values
                    if isinstance(repo_value, str):
                        # Special handling for trigger_patterns
                        if repo_key == "trigger_patterns" and '\n' in repo_value:
                            attrs.append((" " * (ident + 2)) + f'{repo_key} = <<EOT')
                            attrs.extend(f'{line}' for line in repo_value.split('\n'))
                            attrs.append('    EOT')
                        else:
                            attrs.append((" " * (ident + 2)) + f'{repo_key} = "{repo_value}"')
                    elif isinstance(repo_value, bool):
                        attrs.append((" " * (ident + 2)) + f'{repo_key} = {str(repo_value).lower()}')
                    elif isinstance(repo_value, list):
                        attrs.append((" " * (ident + 2)) + f'{repo_key} = {json.dumps(repo_value)}')
            attrs.append("  }")
        elif isinstance(value, str):
            # Check if the value contains newlines and use EOT format if it does
            if '\n' in value:
                # Split the value into lines and indent each line
                lines = value.split('\n')
                attrs.append((" " * ident) + f'{key} = <<EOT')
                attrs.extend((" " * ident) + f'{line}' for line in lines)
                attrs.append((" " * ident) + f'EOT')
            else:
                attrs.append((" " * ident) + f'{key} = "{value}"')
        elif isinstance(value, bool):
            attrs.append((" " * ident) + f'{key} = {str(value).lower()}')
        elif isinstance(value, dict):
            attrs.append((" " * ident) + f'{key} = {json.dumps(value)}')
        elif isinstance(value, list):
            attrs.append((" " * ident) + f'{key} = [')
            for v in value:
                if isinstance(v, str):
                    attrs.append(f'"{v}",')
                elif isinstance(v, AbstractTerraformResource):
                    attrs.append((" " * (ident + 2)) + f'{v.get_address()},')
            attrs.append((" " * ident) + ']')

        elif isinstance(value, HClAttribute):
            attrs.append((" " * ident) + f'{key} = {value.get_hcl_value()}')
        elif isinstance(value, AbstractTerraformResource):
            attrs.append((" " * ident) + f'{key} = {value.get_address()}')
        elif isinstance(value, HCLObject):
            attrs.append((" " * ident) + f'{key} ' + '{')
            for hcl_key, hcl_value in value.attributes.items():
                self._render_attribute(attrs, hcl_key, hcl_value, ident + 2)
            attrs.append((" " * ident) + '}')
        elif value is None:
            pass
        else:
            attrs.append((" " * ident) + f'{key} = {value}')

    def to_hcl(self) -> str:
        attrs = []
        for key, value in self.attributes.items():
            self._render_attribute(attrs, key, value)
        
        return f'{self.hcl_resource_type} "{self.resource_type}" "{self.name}" {{\n{chr(10).join(attrs)}\n}}'

    def get_address(self):
        hcl_resource_type = f"{self.hcl_resource_type}." if self.hcl_resource_type == "data" else ''
        return f"{hcl_resource_type}{self.resource_type}.{self.name}.id"

    def add_attribute(self, name: str, value):
        self.attributes[name] = value

class TerraformResource(AbstractTerraformResource):
    def __init__(self, resource_type: str, name: str, attributes: Dict) -> None:
        super().__init__(resource_type, name, attributes, "resource")

class TerraformDataSource(AbstractTerraformResource):
    def __init__(self, resource_type: str, name: str, attributes: Dict) -> None:
        super().__init__(resource_type, name, attributes, "data")


def extract_resources(attrs_block: str) -> Dict:
    attrs = {}

    # Parse attributes from the block
    for line in attrs_block.split('\n'):
        line = line.strip()
        if '=' in line:
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip()
            # Handle string values
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            # Handle boolean values
            elif value.lower() in ('true', 'false'):
                value = value.lower() == 'true'
            # Handle vcs_repo block
            elif key.strip() == 'vcs_repo':
                vcs_attrs = {}
                vcs_block = re.search(r'vcs_repo\s*{([^}]+)}', attrs_block, re.DOTALL)
                if vcs_block:
                    for vcs_line in vcs_block.group(1).split('\n'):
                        vcs_line = vcs_line.strip()
                        if '=' in vcs_line:
                            vcs_key, vcs_value = vcs_line.split('=', 1)
                            vcs_key = vcs_key.strip()
                            vcs_value = vcs_value.strip()
                            if vcs_value.startswith('"') and vcs_value.endswith('"'):
                                vcs_value = vcs_value[1:-1]
                            elif vcs_value.lower() in ('true', 'false'):
                                vcs_value = vcs_value.lower() == 'true'
                            vcs_attrs[vcs_key] = vcs_value
                attrs[key] = vcs_attrs
                continue
            attrs[key] = value
    return attrs

class ResourceManager:
    def __init__(self, output_dir: str) -> None:
        self.resources: List[TerraformResource] = []
        self.data_sources: List[TerraformDataSource] = []
        self.output_dir = output_dir
        self._load_existing_data_sources()
        self._load_existing_resources()

    def _load_existing_resources(self):
        """Load existing resources from main.tf if it exists."""
        main_tf_path = os.path.join(self.output_dir, "main.tf")
        if not os.path.exists(main_tf_path):
            return

        regexp = r'resource\s+"([^"]+)"\s+"([^"]+)"\s*{([^}]+)}'

        with open(main_tf_path, "r") as f:
            for match in re.finditer(regexp, f.read(), re.DOTALL):
                resource_type, name, attrs_block = match.groups()
                self.resources.append(
                    TerraformResource(resource_type, name, extract_resources(attrs_block))
                )

    def _load_existing_data_sources(self):
        """Load existing resources from main.tf if it exists."""
        main_tf_path = os.path.join(self.output_dir, "main.tf")
        if not os.path.exists(main_tf_path):
            return

        regexp = r'data\s+"([^"]+)"\s+"([^"]+)"\s*{([^}]+)}'

        with open(main_tf_path, "r") as f:
            for match in re.finditer(regexp, f.read(), re.DOTALL):
                resource_type, name, attrs_block = match.groups()
                self.data_sources.append(
                    TerraformDataSource(resource_type, name, extract_resources(attrs_block))
                )

    def add_resource(self, resource: TerraformResource):
        """Add a resource if it doesn't already exist."""
        # Check if resource already exists
        if self.has_resource(resource.resource_type, resource.name):
            return

        self.resources.append(resource)

    def add_data_source(self, data_source: TerraformDataSource):
        """Add a resource if it doesn't already exist."""
        # Check if resource already exists
        if self.has_data_source(data_source.resource_type, data_source.name):
            return
        self.data_sources.append(data_source)

    def has_resource(self, resource_type: str, name: str) -> bool:
        converted = name.lower().replace('-', '_')

        for existing in self.resources:
            if existing.resource_type == resource_type and existing.name == converted:
                return True

        return  False

    def get_resource(self, resource_type: str, name: str) -> Optional[AbstractTerraformResource]:
        converted = name.lower().replace('-', '_')
        for existing in self.data_sources + self.resources:
            if existing.resource_type == resource_type and existing.name == converted:
                return existing
        return None

    def has_data_source(self, resource_type: str, name: str) -> bool:
        converted = name.lower().replace('-', '_')

        for existing in self.data_sources:
            if existing.resource_type == resource_type and existing.name == converted:
                return True

        return  False

    def write_resources(self, output_dir: str):
        os.makedirs(output_dir, exist_ok=True)
        
        # Write main.tf
        main_tf_path = os.path.join(output_dir, "main.tf")
        file_exists = os.path.exists(main_tf_path)
        
        with open(main_tf_path, "a" if file_exists else "w") as f:
            if not file_exists:
                f.write("# Generated by Scalr Migrator\n")
                f.write(f"# Generated at: {datetime.now().isoformat()}\n\n")
                # Add required provider block only for new file
                f.write('''terraform {
  required_providers {
    scalr = {
      source = "scalr/scalr"
    }
  }
}

''')
            
            # Only write new resources
            existing_resources = set()
            if file_exists:
                with open(main_tf_path, "r") as existing:
                    content = existing.read()
                    for resource in (self.resources + self.data_sources):
                        pattern = f'{resource.hcl_resource_type} "{resource.resource_type}" "{resource.name}"'
                        if pattern in content:
                            existing_resources.add((resource.resource_type, resource.name))
            
            # Write resource blocks
            for resource in (self.data_sources + self.resources):
                if (resource.resource_type, resource.name) not in existing_resources:
                    rs: str = resource.to_hcl()
                    f.write(rs.replace("'", '"') + "\n\n")

        # Write imports.tf
        imports_path = os.path.join(output_dir, "imports.tf")
        with open(imports_path, "w") as f:
            f.write("# Generated by Scalr Migrator\n")
            f.write(f"# Generated at: {datetime.now().isoformat()}\n\n")
            f.write("# This file contains import blocks for resources.\n")
            f.write("# You can safely remove this file after successful import.\n\n")
            
            for resource in self.resources:
                if resource.id and (resource.resource_type, resource.name) not in existing_resources:
                    f.write(f'import {{\n')
                    f.write(f'  to = {resource.resource_type}.{resource.name}\n')
                    f.write(f'  id = "{resource.id}"\n')
                    f.write(f'}}\n\n')

class APIClient:
    def __init__(self, hostname: str, token: str, api_version: str = "v2"):
        self.hostname = hostname
        self.token = token
        self.api_version = api_version
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/vnd.api+json",
        }

    def _encode_filters(self, filters: Optional[Dict] = None) -> str:
        encoded = ''
        if filters:
            encoded = f"?{urlencode(filters)}"
        return encoded

    def get_by_short_url(self, short_url: str) -> Dict:
        return self.make_request(f"https://{self.hostname}/{short_url}")

    def make_request(self, url: str, method: str = "GET", data: Dict = None, headers: dict = None) -> Dict:
        if data:
            data = json.dumps(data).encode('utf-8')

        merged_headers = {**self.headers, **headers} if headers else self.headers
        req = urllib.request.Request(url, data=data, method=method, headers=merged_headers)
        
        with urllib.request.urlopen(req) as response:
            if response.code != 204:
                return json.loads(response.read().decode('utf-8'))
            return {}

    def get(self, route: str, filters: Optional[Dict] = None) -> Dict:
        url = f"https://{self.hostname}{self.api_version}{route}{self._encode_filters(filters)}"
        return self.make_request(url)

    def post(self, route: str, data: Dict, headers: Dict = None) -> Dict:
        url = f"https://{self.hostname}{self.api_version}{route}"
        return self.make_request(url, method="POST", data=data, headers=headers)

    def patch(self, route: str, data: Dict) -> Dict:
        url = f"https://{self.hostname}{self.api_version}{route}"
        return self.make_request(url, method="PATCH", data=data)

class OnPremScalrClient(APIClient):
    def __init__(self, hostname: str, token: str):
        super().__init__(hostname, token, "/api/iacp/v3/")

    def get_environments(self, name: str = None) -> Optional[Dict]:
        """Get environment by name from on-prem Scalr."""
        try:
            response = self.get("environments", filters={"filter[name]": name} if name else None)
            environments = response.get("data", [])

            return environments
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
            return None

    def get_workspaces(self, environment_id: str, page: int = 1) -> Dict:
        """Get workspaces from on-prem Scalr environment."""
        filters = {
            "page[size]": 100,
            "page[number]": page,
            "filter[environment]": environment_id,
        }
        return self.get("workspaces", filters)

    def get_workspace_vars(self, workspace_id: str) -> List[Dict]:
        """Get workspace variables from on-prem Scalr."""
        page = 1

        all_variables = []
        while page:
            filters = {"filter[workspace]": workspace_id, "page[number]": page, "page[size]": 1}
            variables = self.get("vars", filters)
            page = variables["meta"]["pagination"]["next-page"]
            all_variables += variables["data"]

        return all_variables

    def get_workspace_runs(self, workspace_id: str, page_size: int = 1) -> Dict:
        """Get workspace runs from on-prem Scalr."""
        filters = {"page[size]": page_size, 'filter[workspace]': workspace_id}
        return self.get("runs", filters)

    def get_run_plan(self, plan_id: str) -> Dict:
        """Get run plan from on-prem Scalr."""
        try:
            return self.get(f"plans/{plan_id}/json-output")
        except Exception:
            ConsoleOutput.info("Skipping: plan file is unavailable")
            return {}

    def lock_workspace(self, workspace_id: str, reason: str) -> Dict:
        """Lock workspace in on-prem Scalr."""
        return self.post(f"workspaces/{workspace_id}/actions/lock", {"reason": reason}, {"Content-Type": "application/json"})

    def get_current_state_version(self, workspace_id: str) -> Optional[Dict]:
        """Get current state version from on-prem Scalr workspace."""
        try:
            return self.get(f"workspaces/{workspace_id}/current-state-version")
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
            return None

    def get_state_version_download_url(self, state_version_id: str) -> Optional[str]:
        """Get state version download URL from on-prem Scalr."""
        try:
            response = self.get(f"state-versions/{state_version_id}")
            return response.get("data", {}).get("attributes", {}).get("hosted-state-download-url")
        except Exception:
            return None



class ScalrClient(APIClient):
    def __init__(self, hostname: str, token: str):
        super().__init__(hostname, token, "/api/iacp/v3/")

    def update_consumers(self, workspace_id, consumers: list[str]):
        relationships = []

        for consumer in consumers:
            relationships.append({
                "type": "workspaces",
                "id": consumer
            })

        self.patch(f"workspaces/{workspace_id}/relationships/remote-state-consumers", {"data": relationships})

    def update_workspace(self, workspace_id, payload: Dict):
        return self.patch(f"workspaces/{workspace_id}", payload)

    def get_environment(self, name: str) -> Optional[Dict]:
        try:
            response = self.get("environments", filters={"filter[name]": name})
            environments = response.get("data", [])

            return environments[0] if environments else None
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise

    def get_workspace(self, environment_id, name: str) -> Optional[Dict]:
        try:
            response = self.get("workspaces", {"filter[name]": name, "filter[environment]": environment_id})
            workspaces = response.get("data", [])

            return workspaces[0] if workspaces else None
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise

    def create_environment(self, name: str, account_id: str) -> Dict:
        data = {
            "data": {
                "type": "environments",
                "attributes": {
                    "name": name,
                },
                "relationships": {
                    "account": {
                        "data": {
                            "id": account_id,
                            "type": "accounts"
                        }
                    }
                }
            }
        }
        return self.post("environments", data)

    def create_workspace(
        self,
        env_id: str,
        attributes: Dict,
        vcs_id: Optional[str] = None,
        agent_pool_id: Optional[str] = None
    ) -> Dict:
        data = {
            "data": {
                "type": "workspaces",
                "attributes": attributes,
                "relationships": {
                    "environment": {
                        "data": {
                            "type": "environments",
                            "id": env_id
                        }
                    },
                    "vcs-provider": {"data": {"type": "vcs-providers", "id": vcs_id}} if vcs_id else None,
                    "agent-pool": {"data": {"type": "agent-pools", "id": agent_pool_id}} if agent_pool_id else None,
                }
            }
        }

        return self.post("workspaces", data)

    def link_provider_config(self, workspace_id: str, pc_id: str) -> Dict:
        data = {
            "data": {
                "type": "provider-configuration-links",
                "relationships": {
                    "provider-configuration": {
                        "data": {"id": pc_id, "type": "provider-configurations"}
                    }
                }
            }
        }

        return self.post(f"workspaces/{workspace_id}/provider-configuration-links", data)

    def create_state_version(self, workspace_id: str, attributes: Dict) -> Dict:
        data = {
            "data": {
                "type": "state-versions",
                "attributes": attributes,
                "relationships": {
                    "workspace": {
                        "data": {
                            "type": "workspaces",
                            "id": workspace_id
                        }
                    }
                }
            }
        }
        return self.post("state-versions", data)

    def create_variable(
            self,
            key: str,
            value: str,
            category: str,
            sensitive: bool,
            is_hcl: bool = False,
            description: Optional[str] = None,
            relationships: Optional[Dict] = None,
    ) -> Optional[Dict]:
        data = {
            "data": {
                "type": "vars",
                "attributes": {
                    "key": key,
                    "value": value,
                    "category": category,
                    "sensitive": sensitive,
                    "description": description,
                    "hcl": is_hcl,
                },
                "relationships": relationships or {}
            }
        }
        response = self.post("vars", data)

        return response

def _enforce_max_version(tf_version: str, workspace_name) -> str:
    if tf_version == "auto":
        return tf_version

    if  tf_version == "latest" or version.parse(tf_version) > version.parse(MAX_TERRAFORM_VERSION):
        ConsoleOutput.warning(f"Warning: {workspace_name} uses Terraform {tf_version}. "
              f"Downgrading to {MAX_TERRAFORM_VERSION}")
        tf_version = MAX_TERRAFORM_VERSION
    return tf_version

class ConsoleOutput:
    TITLE = '\033[95m'
    HEADER = '\033[96m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    @classmethod
    def info(cls, message: str) -> None:
        print(f"{cls.CYAN}[INFO]{cls.ENDC} {message}")

    @classmethod
    def success(cls, message: str) -> None:
        print(f"{cls.GREEN}[SUCCESS]{cls.ENDC} {message}")

    @classmethod
    def warning(cls, message: str) -> None:
        print(f"{cls.WARNING}[WARNING]{cls.ENDC} {message}")

    @classmethod
    def error(cls, message: str) -> None:
        print(f"{cls.FAIL}[ERROR]{cls.ENDC} {message}")

    @classmethod
    def debug(cls, message: str) -> None:
        print(f"{cls.BLUE}[DEBUG]{cls.ENDC} {message}")

    @classmethod
    def title(cls, message: str) -> None:
        print(f"\n{cls.TITLE}{cls.BOLD}{message}{cls.ENDC}")
        print(f"{cls.TITLE}{'=' * len(message)}{cls.ENDC}\n")

    @classmethod
    def section(cls, message: str) -> None:
        print(f"\n{cls.HEADER}{cls.BOLD}{message}{cls.ENDC}")
        print(f"{cls.HEADER}{'-' * len(message)}{cls.ENDC}\n")

def validate_trigger_pattern(pattern: str) -> bool:
    """
    Validate a trigger pattern format.
    Returns True if the pattern is valid, False otherwise.
    """
    # Skip validation for comments
    if pattern.startswith('#'):
        return True
        
    # Basic validation rules:
    # 1. Pattern should not be empty after stripping
    # 2. Pattern should not contain invalid characters
    # 3. Pattern should follow gitignore-like syntax
    
    pattern = pattern.strip()
    if not pattern:
        return False
        
    # Check for invalid characters (if any)
    # Note: Scalr uses gitignore-like syntax, so most characters are valid
    invalid_chars = ['\n', '\r']  # Newlines are not allowed in patterns
    if any(char in pattern for char in invalid_chars):
        return False
        
    return True

def handle_trigger_patterns(patterns: List[str]) -> Optional[str]:
    """
    Process and validate trigger patterns.
    Returns a multiline string of valid patterns or None if no valid patterns exist.
    """
    try:
        if not patterns:
            return None
        
        validated_patterns = []
        for pattern in patterns:
            if validate_trigger_pattern(pattern):
                validated_patterns.append(pattern)
            else:
                ConsoleOutput.warning(f"Invalid trigger pattern: {pattern}")
        
        return "\n".join(validated_patterns)
    except Exception as e:
        ConsoleOutput.error(f"Error processing trigger patterns: {str(e)}")
        return None


class MigrationService:

    def __init__(self, args: MigratorArgs):
        self.args: MigratorArgs = args
        self.resource_manager: ResourceManager = ResourceManager(f"generated-terraform/{self.args.scalr_environment}")
        self.source_scalr: OnPremScalrClient = OnPremScalrClient(args.source_scalr_hostname, args.source_scalr_token)
        self.dest_scalr: ScalrClient = ScalrClient(args.scalr_hostname, args.scalr_token)
        self.environment_resource_id: Optional[AbstractTerraformResource] = None
        self.project_id: Optional[str] = None
        self.vcs_id: Optional[str] = None
        self.vcs_data: Optional[TerraformDataSource] = None
        self.provider_config: Optional[Dict] = None
        self.pc_data: Optional[TerraformDataSource] = None
        self.workspaces_map = {}
        self.agent_pool_id: Optional[str] = None
        self.agent_pool_data: Optional[TerraformDataSource] = None

        self.load_account_id()

    def create_workspace_map(self, source_workspace_id, workspace: AbstractTerraformResource) -> None:
        self.workspaces_map[source_workspace_id] = workspace

    def get_mapped_scalr_workspace_id(self, source_workspace_id) -> AbstractTerraformResource:
        if not self.workspaces_map.get(source_workspace_id):
            raise MissingMappingError(f"The destination Scalr workspace for the source workspace {source_workspace_id} does not exist or was not created within the current runtime.")
        return self.workspaces_map[source_workspace_id]

    def load_account_id(self):
        accounts = self.dest_scalr.get("accounts")["data"]
        if not accounts:
            ConsoleOutput.error("No account is associated with the given destination Scalr token.")
            sys.exit(1)
        elif len(accounts) > 1:
            ConsoleOutput.error("The destination Scalr token is associated with more than 1 account.")
            sys.exit(1)
        self.args.account_id = accounts[0]["id"]

    def get_vcs_data(self) -> Optional[TerraformDataSource]:
        if self.args.vcs_name and not self.resource_manager.has_data_source('scalr_vcs_provider', self.args.vcs_name):
            self.vcs_data = TerraformDataSource(
                "scalr_vcs_provider",
                self.args.vcs_name,
                {"name": self.args.vcs_name}
            )

            self.resource_manager.add_data_source(self.vcs_data)

        return self.vcs_data

    def get_pc_data(self) -> Optional[TerraformDataSource]:
        if self.args.pc_name and not self.pc_data:
            self.pc_data = TerraformDataSource(
                "scalr_provider_configuration",
                self.args.pc_name,
                {"name": self.args.pc_name}
            )

            self.resource_manager.add_data_source(self.pc_data)

        return self.pc_data


    def get_environment_resource_id(self, env_name) -> Optional[AbstractTerraformResource]:
        if not self.environment_resource_id:
            env_resource = self.resource_manager.get_resource("scalr_environment", env_name)
            self.environment_resource_id = env_resource
        return self.environment_resource_id

    def create_environment(self, name: str, skip_terraform: bool = False) -> Dict:
        """Get existing environment or create a new one."""
        # First try to find existing environment
        environment = self.dest_scalr.get_environment(name)

        if environment:
            if not skip_terraform:
                existing_resource = self.resource_manager.get_resource('scalr_environment', name)
                if not existing_resource:
                    environment_data_source = TerraformDataSource("scalr_environment", name, {"name": name})
                    self.resource_manager.add_data_source(environment_data_source)
            return environment

        response = self.dest_scalr.create_environment(name, self.args.account_id)["data"]

        if not skip_terraform:
            # Create Terraform resource
            env_resource = TerraformResource("scalr_environment", name,{"name": name})
            env_resource.id = response["id"]
            self.resource_manager.add_resource(env_resource)
        ConsoleOutput.success(f"Created destination environment: {name}")

        return response

    def get_agent_pool_data(self) -> Optional[TerraformDataSource]:
        """Get agent pool data source if agent pool name is provided."""
        if self.args.agent_pool_name and not self.agent_pool_data and self.get_agent_pool_id():
            self.agent_pool_data = TerraformDataSource(
                "scalr_agent_pool",
                self.args.agent_pool_name,
                {"name": self.args.agent_pool_name}
            )
            self.resource_manager.add_data_source(self.agent_pool_data)
        return self.agent_pool_data

    def get_agent_pool_id(self) -> str:
        """Get agent pool ID from the destination Scalr."""
        if self.args.agent_pool_name and not self.agent_pool_id:
            agent_pools = self.dest_scalr.get('agent-pools', {"filter[name]": self.args.agent_pool_name})['data']
            if not len(agent_pools):
                raise MissingDataError(f"Agent pool with name '{self.args.agent_pool_name}' not found.")
            agent_pool_id = agent_pools[0]["id"]
            self.agent_pool_id = agent_pool_id
            agents = self.dest_scalr.get('agents', {"filter[agent-pool]": agent_pool_id})['data']

            if not len(agents):
                raise MissingDataError(f"Agent pool with name '{self.args.agent_pool_name}' does not have active agents.")

        return self.agent_pool_id

    def create_management_workspace(self, env: dict) -> None:
        env_id = env["id"]
        environment_name = env["attributes"]["name"]
        workspace = self.dest_scalr.get_workspace(env_id, environment_name)

        if workspace:
            return

        attributes = {
            "name": environment_name,
            "terraform-version": MAX_TERRAFORM_VERSION,
            "auto-apply": False,
            "operations": True,
        }

        self.dest_scalr.create_workspace(env_id, attributes)


    def create_workspace(
        self,
        env: dict,
        source_workspace: Dict,
        is_management_workspace: Optional[bool] = False
    ) -> AbstractTerraformResource:
        """Get existing workspace or create a new one."""
        env_id = env["id"]
        attributes = source_workspace["attributes"]
        # First try to find existing workspace
        workspace = self.dest_scalr.get_workspace(env_id, attributes['name'])

        if workspace and not is_management_workspace:
            workspace_data = TerraformDataSource("scalr_workspace", env_id, {"name": attributes['name']})
            workspace_data.id = workspace["id"]
            if source_workspace.get("id"):
                self.create_workspace_map(source_workspace['id'], workspace_data)
            return workspace_data

        ConsoleOutput.info(f"Creating workspace '{attributes['name']}'...")

        terraform_version = _enforce_max_version(attributes.get("terraform-version", "1.6.0"), attributes["name"])
        execution_mode = "remote" if attributes.get("operations") else "local"
        global_remote_state = attributes.get("remote-state-sharing", False)

        workspace_attrs = {
            "name": attributes["name"],
            "auto-apply": attributes["auto-apply"],
            "operations": attributes["operations"],
            "terraform-version": terraform_version,
            "working-directory": attributes.get("working-directory"),
            "deletion-protection-enabled": attributes.get("deletion-protection-enabled", False),
            "remote-state-sharing": global_remote_state,
        }

        vcs_id = None
        branch = None
        trigger_patterns = None
        configuration = self.get_provider_configuration()
        pc_id = configuration["id"] if not is_management_workspace and configuration else None
        vcs_repo = attributes.get("vcs-repo")

        if vcs_repo:
            vcs_id = self.get_vcs_provider_id()
            branch = vcs_repo["branch"] if vcs_repo.get("branch") in vcs_repo else None

            workspace_attrs["vcs-repo"] = {
                "identifier": vcs_repo["identifier"],
                "dry-runs-enabled": vcs_repo.get("dry-runs-enabled", True),
                "trigger-prefixes": vcs_repo.get("trigger-prefixes", []),
                "trigger-patterns": vcs_repo.get("trigger-patterns"),
                "branch": branch,
                "ingress-submodules": vcs_repo["ingress-submodules"],
            }

        relationships = source_workspace.get('relationships', {})
        agent_pool_id = self.get_agent_pool_id() if relationships.get("agent-pool") else None
        response = self.dest_scalr.create_workspace(env_id, workspace_attrs, vcs_id, agent_pool_id)

        ConsoleOutput.success(f"Created workspace '{attributes['name']}'")

        if is_management_workspace:
            return response['data']

        if pc_id:
            self.dest_scalr.link_provider_config(response["data"]["id"], pc_id)
            ConsoleOutput.info(f"Linked provider configuration: {self.args.pc_name}")

        # Create Terraform resource
        resource_attributes = {
            "name": attributes["name"],
            "auto_apply": attributes["auto-apply"],
            "execution_mode": execution_mode,
            "terraform_version": terraform_version,
            "working_directory": attributes.get("working-directory"),
            "environment_id": self.get_environment_resource_id(env["attributes"]["name"]),
            "deletion_protection_enabled": not self.args.disable_deletion_protection
        }

        if global_remote_state:
            resource_attributes["remote_state_consumers"] = HClAttribute(["*"])

        if vcs_repo:
            resource_attributes["vcs_repo"] = {
                "identifier": vcs_repo["identifier"],
                "dry_runs_enabled": vcs_repo["dry-runs-enabled"],
                "branch": branch,
                "ingress_submodules": vcs_repo["ingress-submodules"],
            }
            resource_attributes["vcs_provider_id"] = self.get_vcs_data()

            if vcs_repo.get("trigger-prefixes"):
                resource_attributes["vcs_repo"]["trigger_prefixes"] = vcs_repo["trigger-prefixes"]

            if trigger_patterns:
                resource_attributes["vcs_repo"]["trigger_patterns"] = trigger_patterns

        if pc_id:
            resource_attributes["provider_configuration"] = HCLObject({"id": self.get_pc_data()})

        if agent_pool_id:
            resource_attributes["agent_pool_id"] = self.get_agent_pool_data()

        workspace_resource = TerraformResource(
            "scalr_workspace",
            attributes["name"],
            resource_attributes
        )

        workspace_resource.id = response["data"]["id"]
        if source_workspace.get('id'):
            self.create_workspace_map(source_workspace['id'], workspace_resource)

        if not is_management_workspace:
            self.resource_manager.add_resource(workspace_resource)
        
        return workspace_resource

    def get_current_state(self, workspace_id: str) -> Optional[Dict]:
        try:
            return self.dest_scalr.get(f"workspaces/{workspace_id}/current-state-version")
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise

    def create_state(self, source_workspace: Dict, workspace_id: str) -> None:
        current_dest_state = self.get_current_state(workspace_id)
        
        # Get current state from source on-prem Scalr
        source_state_version = self.source_scalr.get_current_state_version(source_workspace["id"])
        
        if not source_state_version:
            ConsoleOutput.warning("Source state file is missing")
            return

        # Get state download URL from source
        state_download_url = source_state_version["data"]["links"]["download"]
        
        if not state_download_url:
            ConsoleOutput.warning("Source state file URL is unavailable")
            return

        # Download state from source
        raw_state = self.source_scalr.make_request(state_download_url)
        
        # Check if state is already up-to-date
        serial = current_dest_state["data"]["attributes"]["serial"] if current_dest_state else None
        if serial == raw_state["serial"]:
            ConsoleOutput.info(f"State with serial '{serial}' is up-to-date")
            return

        raw_state["terraform_version"] = _enforce_max_version(raw_state["terraform_version"],'State file')

        state_content = json.dumps(raw_state).encode('utf-8')
        encoded_state = binascii.b2a_base64(state_content)

        state_attrs = {
            "serial": raw_state["serial"],
            "md5": hashlib.md5(state_content).hexdigest(),
            "lineage": raw_state["lineage"],
            "state": encoded_state.decode("utf-8")
        }

        self.dest_scalr.create_state_version(workspace_id, state_attrs)

    def create_backend_config(self) -> None:
        """Create backend configuration for the management workspace."""
        backend_config = f'''terraform {{
  backend "remote" {{
    hostname = "{self.args.scalr_hostname}"
    organization = "{self.args.management_env_name}"
    workspaces {{
      name = "{self.args.management_workspace_name}"
    }}
  }}
}}
'''
        output_dir = self.resource_manager.output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        with open(os.path.join(output_dir, "backend.tf"), "w") as f:
            f.write("# Generated by Scalr Migrator\n")
            f.write(f"# Generated at: {datetime.now().isoformat()}\n\n")
            f.write(backend_config)

    def migrate_workspace(self, source_workspace: Dict, env: Dict) -> bool:
        workspace_name = source_workspace["attributes"]["name"]
        ConsoleOutput.section(f"Migrating workspace '{workspace_name}' into '{env['attributes']['name']}'...")

        workspace = self.create_workspace(env, source_workspace)

        ConsoleOutput.info(f"Migrating state...")
        self.create_state(source_workspace, workspace.id)

        # Skip variable migration if requested
        if self.args.skip_variables == "*":
            ConsoleOutput.info("Skipping all variable migration as requested")
            return True

        ConsoleOutput.info("Migrating variables...")
        relationships = {
            "workspace": {
                "data": {
                    "type": "workspaces",
                    "id": workspace.id
                }
            }
        }

        skipped_sensitive_vars = {}
        skip_patterns = self.args.skip_variables.split(',') if self.args.skip_variables else []

        for api_var in self.source_scalr.get_workspace_vars(source_workspace["id"]):
            attributes = api_var["attributes"]
            var_key: str = attributes["key"]

            # Skip variable if it matches any of the skip patterns
            if any(fnmatch.fnmatch(var_key, pattern.strip()) for pattern in skip_patterns):
                ConsoleOutput.info(f"Skipping variable '{var_key}' as requested")
                continue

            if attributes["category"] == "env":
                attributes["category"] = "shell"

            if attributes["sensitive"]:
                msg = f"Skipping creation of sensitive {attributes['category']} variable '{attributes['key']}'"
                if attributes["category"] == "terraform" or var_key.startswith('TF_VAR_'):
                    msg += ", will try to create it from the plan file"
                    skipped_sensitive_vars.update({attributes["key"]: attributes})
                ConsoleOutput.info(msg)
                continue

            try:
                response = self.dest_scalr.create_variable(
                    attributes["key"],
                    attributes["value"],
                    attributes["category"],
                    False,
                    attributes["hcl"],
                    attributes["description"],
                    relationships,
                )
            except urllib.error.HTTPError as e:
                if e.code == 422:
                    ConsoleOutput.info(f"Variable '{attributes['key']}' already exists")
                    continue
                raise e

            # Create Terraform resource for non-sensitive variables
            var_resource = TerraformResource(
                "scalr_variable",
                attributes['key'],
                {
                    "key": attributes["key"],
                    "description": attributes["description"],
                    "value": HClAttribute(attributes["value"], True) if attributes["hcl"] else attributes["value"],
                    "category": attributes["category"],
                    "workspace_id": workspace,
                    "hcl": attributes["hcl"],
                    "sensitive": False,
                },
            )
            var_resource.id = response["data"]["id"]
            self.resource_manager.add_resource(var_resource)

        # Get sensitive variables from plan
        run = self.source_scalr.get_workspace_runs(source_workspace["id"])["data"]
        if run:
            ConsoleOutput.info("Trying to migrate sensitive variables...")
            plan = self.source_scalr.get_run_plan(run[0]["relationships"]["plan"]["data"]["id"])
            if "variables" in plan:
                ConsoleOutput.info("Plan file is available, reading its variables...")
                variables = plan["variables"]
                root_module = plan["configuration"]["root_module"]
                configuration_variables = root_module.get("variables", {})

                for var in configuration_variables:
                    if "sensitive" in configuration_variables[var]:
                        ConsoleOutput.info(f"Creating sensitive variable '{var}' from the plan file")
                        try:
                            response = self.dest_scalr.create_variable(
                                var,
                                variables[var]["value"],
                                "terraform",
                                True,
                                skipped_sensitive_vars[var].get("hcl", False),
                                skipped_sensitive_vars[var]["description"],
                                relationships
                            )
                        except Exception as e:
                            ConsoleOutput.warning(f"Failed to create sensitive variable '{var}': {e}")
                            continue

                        var_resource = TerraformResource(
                            "scalr_variable",
                            var,
                            {
                                "key":var,
                                "description": skipped_sensitive_vars[var]["description"],
                                "value": HClAttribute(variables[var]["value"], True) if skipped_sensitive_vars[var]["hcl"] else variables[var]["value"],
                                "category": 'terraform',
                                "workspace_id": workspace,
                                "hcl": skipped_sensitive_vars[var]["hcl"],
                                "sensitive": True,
                            },
                        )

                        var_resource.id = response["data"]["id"]
                        self.resource_manager.add_resource(var_resource)

        if self.args.lock:
            if source_workspace["attributes"]["locked"]:
                ConsoleOutput.info("Source workspace is already locked")
                return True

            env_name = env["attributes"]["name"]
            self.source_scalr.lock_workspace(
                source_workspace["id"],
                f"Workspace is migrated to the SaaS Scalr environment '{env_name}' with name '{workspace_name}'."
            )
            ConsoleOutput.success(f"Source workspace '{workspace_name}' is locked")

        return True


    def should_migrate_workspace(self, workspace_name: str) -> bool:
        for pattern in self.args.workspaces.split(','):
            if fnmatch.fnmatch(workspace_name, pattern):
                return True
        return False

    def init_backend_secrets(self):
        if self.args.skip_backend_secrets:
            return

        account_relationships = {
            "account": {
                "data": {
                    "type": "accounts",
                    "id": self.args.account_id
                }
            }
        }

        vars_to_create = {
            "SCALR_HOSTNAME": self.args.scalr_hostname,
            "SCALR_TOKEN": self.args.scalr_token,
            "SOURCE_SCALR_HOSTNAME": self.args.source_scalr_hostname,
            "SOURCE_SCALR_TOKEN": self.args.source_scalr_token,
        }

        for key in vars_to_create:
            vars_filters = {
                "filter[account]": self.args.account_id,
                "filter[key]": key,
                "filter[environment]": None
            }
            if self.dest_scalr.get("vars", vars_filters)["data"]:
                continue
            try:
                self.dest_scalr.create_variable(
                    key,
                    vars_to_create[key],
                    "shell",
                    True,
                    False,
                    "Created by migrator",
                    account_relationships
                )
            except urllib.error.HTTPError as e:
                if e.code == 422:
                    ConsoleOutput.info(f"Variable '{key}' already exists")
                    continue

        ConsoleOutput.success("Initialized backend secrets")

    def check_and_update_credentials(self) -> None:
        """Check and update Terraform credentials for Scalr hostname."""
        credentials_file = os.path.expanduser("~/.terraform.d/credentials.tfrc.json")
        os.makedirs(os.path.dirname(credentials_file), exist_ok=True)

        # Read existing credentials or create new structure
        if os.path.exists(credentials_file):
            try:
                with open(credentials_file, 'r') as f:
                    credentials = json.load(f)
            except json.JSONDecodeError:
                credentials = {"credentials": {}}
        else:
            credentials = {"credentials": {}}

        # Check if credentials for Scalr hostname exist
        if self.args.scalr_hostname not in credentials["credentials"]:
            ConsoleOutput.info(f"Adding Scalr credentials to {credentials_file}...")
            credentials["credentials"][self.args.scalr_hostname] = {
                "token": self.args.scalr_token
            }
            with open(credentials_file, 'w') as f:
                f.write(json.dumps(credentials, indent=2))
            ConsoleOutput.success("Credentials added successfully.")
        else:
            ConsoleOutput.info(f"Credentials for {self.args.scalr_hostname} already exist in {credentials_file}")

    def get_vcs_provider_id(self) -> str:
        if self.args.vcs_name and not self.vcs_id:
            vcs_provider = self.dest_scalr.get("vcs-providers", {"query": self.args.vcs_name})["data"][0]
            if not vcs_provider:
                raise MissingDataError(f"VCS provider with name '{self.args.vcs_name}' not found.")
            self.vcs_id = vcs_provider["id"]

        return self.vcs_id

    def get_provider_configuration(self) -> Dict:
        if self.args.pc_name and not self.provider_config:
            pc_provider = self.dest_scalr.get("provider-configurations", {"filter[name]": self.args.pc_name})["data"][0]
            if not pc_provider:
                raise MissingDataError(f"Provider configuration with name '{self.args.pc_name}' not found.")
            self.provider_config = pc_provider

        return self.provider_config

    def update_provider_configuration(self, env_id: str) -> None:
        provider_configuration = self.get_provider_configuration()
        if not provider_configuration:
            return

        if provider_configuration["attributes"]["is-shared"]:
            return

        allowed_environments = provider_configuration["relationships"].get('environments')
        data = allowed_environments.get('data', [])

        for allowed_environment in data:
            if allowed_environment['id'] == env_id:
                return

        data.append({
            "id": env_id,
            'type': 'environments',
        })

        attributes = {
            'data': {
                'type': 'provider-configurations',
                'id': provider_configuration["id"],
                'relationships': {
                    'environments': {
                        'data': data
                    }
                }
            }
        }

        self.dest_scalr.patch(f"provider-configurations/{provider_configuration['id']}", attributes)

    def migrate(self, source_environment: dict) -> dict:
        environment_name = source_environment['attributes']['name']
        ConsoleOutput.title(f"Migrating from on-prem Scalr environment '{environment_name}' to SaaS")

        # Create or get the main environment
        ConsoleOutput.info(f"Creating destination Scalr environment '{environment_name}'...")
        env = self.create_environment(environment_name)
        self.update_provider_configuration(env['id'])

        # Create backend configuration for the management workspace
        ConsoleOutput.info("Creating remote backend configuration...")
        self.create_backend_config()
        ConsoleOutput.success("Backend remote configuration created, starting workspaces migration...")

        # Migrate workspaces
        next_page = 1
        skipped_workspaces = []
        successful_workspaces = []
        workspace_state_consumers = {}

        while True:
            source_workspaces = self.source_scalr.get_workspaces(source_environment["id"], next_page)
            next_page = source_workspaces["meta"]["pagination"]["next-page"]

            for source_workspace in source_workspaces["data"]:
                workspace_name = source_workspace["attributes"]["name"]
                state_consumers = source_workspace["relationships"].get('remote-state-consumers')
                if not source_workspace["attributes"].get("global-remote-state", False) and state_consumers:
                    workspace_state_consumers.update({source_workspace['id']: {
                        "url": state_consumers['links']['related'],
                        "workspace_name": workspace_name,
                    }})
                if not self.should_migrate_workspace(workspace_name):
                    skipped_workspaces.append(workspace_name)
                    continue

                try:
                    result = self.migrate_workspace(source_workspace, env)

                    if not result:
                        skipped_workspaces.append(workspace_name)
                        continue

                    successful_workspaces.append(workspace_name)
                    ConsoleOutput.success(f"Successfully migrated workspace: {workspace_name}")
                except Exception as e:
                    ConsoleOutput.error(f"Error migrating workspace {workspace_name}: {str(e)}")
                    if self.args.debug_enabled:
                        ConsoleOutput.debug(f"Traceback: {traceback.format_exc()}")
                    skipped_workspaces.append(workspace_name)
                    continue

            if not next_page:
                break

        if len(workspace_state_consumers):
            ConsoleOutput.section("Post-migrating state consumers")
        for source_id, consumers_data in workspace_state_consumers.items():
            try:
                dest_workspace_id = self.get_mapped_scalr_workspace_id(source_id).id
                consumer_ids = []
                consumer_resources: List[AbstractTerraformResource] = []
                source_consumers = self.source_scalr.get_by_short_url(consumers_data['url'])['data']
                for state_consumer in source_consumers:
                    consumer = self.get_mapped_scalr_workspace_id(state_consumer['id'])
                    consumer_ids.append(consumer.id)
                    consumer_resources.append(consumer)

                if consumer_ids:
                    self.dest_scalr.update_consumers(dest_workspace_id, consumer_ids)

                    self.resource_manager.get_resource(
                        'scalr_workspace',
                        consumers_data['workspace_name']
                    ).add_attribute('remote_state_consumers', consumer_resources)
                    ConsoleOutput.info(f"Updated state consumers for workspace '{consumers_data['workspace_name']}'...")
            except MissingMappingError as e:
                ConsoleOutput.warning(f"Unable to post-migrate state consumers. {e}")
                continue
            except RuntimeError as e:
                ConsoleOutput.warning(e.args[0])
                continue
            except urllib.error.HTTPError as e:
                ConsoleOutput.error(f"Unable to update remote state consumers: {e}")
                continue

        # Write generated Terraform resources
        output_dir = self.resource_manager.output_dir
        self.resource_manager.write_resources(output_dir)

        ConsoleOutput.success(f"Successfully migrated {len(successful_workspaces)} workspaces.")

        return {
            "successful-workspaces": len(successful_workspaces),
            "skipped-workspaces": len(skipped_workspaces),
        }

def validate_vcs_name(args: argparse.Namespace) -> None:
    if not args.skip_workspace_creation and not args.vcs_name:
        ConsoleOutput.error("Error: If --skip-workspace-creation flag is not set, a valid vcs_name must be passed.")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Migrate workspaces from on-prem Scalr to SaaS Scalr')
    
    # Destination SaaS Scalr arguments
    parser.add_argument('--scalr-hostname', type=str, required=True, help='Destination SaaS Scalr hostname')
    parser.add_argument('--scalr-token', type=str, required=True, help='Destination SaaS Scalr token')
    parser.add_argument('--scalr-environment', type=str, help='Destination Scalr environment name. Defaults to source environment name.')
    
    # Source on-prem Scalr arguments
    parser.add_argument('--source-scalr-hostname', type=str, required=True, help='Source on-prem Scalr hostname')
    parser.add_argument('--source-scalr-token', type=str, required=True, help='Source on-prem Scalr token')
    parser.add_argument('--source-scalr-environment', type=str, help='Source on-prem Scalr environment name')
    
    # Migration options
    parser.add_argument('-v', '--vcs-name', type=str, help='VCS provider name in destination Scalr')
    parser.add_argument('--pc-name', type=str, help='Provider configuration name in destination Scalr')
    parser.add_argument('--agent-pool-name', type=str, help='Agent pool name in destination Scalr')
    parser.add_argument('-w', '--workspaces', type=str, help='Workspace name pattern (supports glob patterns, default: "*")')
    parser.add_argument('--skip-workspace-creation', action='store_true', help='Skip creating new workspaces in destination Scalr')
    parser.add_argument('--skip-backend-secrets', action='store_true', help='Skip creating shell variables in destination Scalr')
    parser.add_argument('--skip-scalr-lock', action='store_true', help='Skip locking source on-prem Scalr workspaces after migration')
    parser.add_argument('--management-env-name', type=str, default=DEFAULT_MANAGEMENT_ENV_NAME, help=f'Name of the management environment. Default: {DEFAULT_MANAGEMENT_ENV_NAME}')
    parser.add_argument('--disable-deletion-protection', action='store_true', help='Disable deletion protection in workspace resources')
    parser.add_argument('--skip-variables', type=str, help='Comma-separated list of variable keys to skip, or "*" to skip all variables')

    args = parser.parse_args()
    
    # Validate vcs_name if needed
    validate_vcs_name(args)

    # Convert argparse namespace to MigratorArgs and run migration
    migrator_args = MigratorArgs.from_argparse(args)
    migration_service = MigrationService(migrator_args)
    # Get source environment
    source_environments = migration_service.source_scalr.get_environments(migrator_args.source_scalr_environment)
    if not source_environments:
        ConsoleOutput.error(f"Source environment '{migrator_args.source_scalr_environment}' not found in on-prem Scalr")
        sys.exit(1)

    ConsoleOutput.title("Preparing migration")
    migration_service.init_backend_secrets()
    migrated_environments = 0
    migrated_workspaces = 0
    skipped_workspaces = 0

    # Create management environment and workspace
    ConsoleOutput.info(f"Creating post-management Scalr environment '{migrator_args.management_env_name}'...")
    management_env = migration_service.create_environment(migrator_args.management_env_name, skip_terraform=True)

    for source_env in source_environments:
        environment_name = source_env['attributes']['name']
        args.scalr_environment = environment_name
        migrator = MigrationService(migrator_args)
        result = migrator.migrate(source_env)

        ConsoleOutput.info(f"Creating post-management Scalr workspace '{environment_name}'...")
        migrator.create_management_workspace(management_env)

        migrated_workspaces += result["successful-workspaces"]
        skipped_workspaces += result["skipped-workspaces"]
        migrated_environments += 1 if result["successful-workspaces"] else 0
        ConsoleOutput.success(f"Successfully migrated environment '{environment_name}'.")

    ConsoleOutput.title("Migration summary")
    ConsoleOutput.info(f"Migrated environments: {migrated_environments}")
    ConsoleOutput.info(f"Migrated workspaces: {migrated_workspaces}")
    ConsoleOutput.info(f"Skipped workspaces: {skipped_workspaces}")

    # Check and update Terraform credentials
    migration_service.check_and_update_credentials()
    ConsoleOutput.info("Credentials have been automatically configured in ~/.terraform.d/credentials.tfrc.json")

if __name__ == "__main__":
    main()
