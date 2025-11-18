# On-Prem Scalr to SaaS Scalr Migration Overview

This script will migrate the following objects from on-prem Scalr to SaaS Scalr in bulk:
- Workspaces with all attributes
  - VCS settings and trigger patterns
  - Terraform version
  - Execution mode (remote/local)
  - Working directory
  - Auto-apply settings
  - Remote state sharing
  - Variable values (including sensitive variables when available)
  - Workspace dependencies
- State file migration
  - Preserves state history
- Variable migration (including sensitive variables from plan files)
- VCS provider configuration
- Provider configuration linking
- Remote state consumers
- Trigger patterns handling
- Workspace locking in source on-prem Scalr after migration to avoid conflicting runs

At the end of the migration, the Scalr Terraform provider code will be generated, allowing you to continue managing destination SaaS Scalr objects with code. A management environment and workspace will be created for managing Scalr environments and workspaces.

# Usage

## Prerequisites

- Python 3.8 or higher
- On-prem Scalr credentials (source)
- SaaS Scalr credentials (destination)
- [VCS provider configured in destination SaaS Scalr](https://docs.scalr.io/docs/vcs-providers) (if migrating workspaces with VCS)
- [Provider configuration in destination SaaS Scalr](https://docs.scalr.io/docs/provider-configurations) (if linking workspaces to provider configurations)

## Installation

1. Clone this repository:
```bash
git clone https://github.com/Scalr/terraform-scalr-migrate-onprem.git
cd terraform-scalr-migrate-onprem
```

2. Make the scripts executable:
```bash
chmod +x migrate.sh
```

## Authentication

Authentication can be performed through the command line by setting the credentials as environment variables or in the Terraform credentials file.

### Command line arguments:
Note: The Scalr tokens can be set as environment variables (see below)
```bash
./migrate.sh --source-scalr-hostname "onprem.scalr.local" --source-scalr-token "your-source-token" --source-scalr-environment "source-env" --scalr-hostname "account.scalr.io" --scalr-token "your-dest-token"
```

### Environment variables:
```bash
export SCALR_HOSTNAME="account.scalr.io" # Replace `account` with the actual account name
export SCALR_TOKEN="your-destination-token"
export SOURCE_SCALR_HOSTNAME="onprem.scalr.local" # Your on-prem Scalr hostname
export SOURCE_SCALR_TOKEN="your-source-token"
```

### Terraform credentials file (`~/.terraform.d/credentials.tfrc.json`):

When the Scalr hostnames are known, the migrator can read tokens from the locally cached credentials file (usually written by the `terraform login` command).

```json
{
  "credentials": {
    "account.scalr.io": {
      "token": "your-destination-scalr-token"
    },
    "onprem.scalr.local": {
      "token": "your-source-scalr-token"
    }
  }
}
```

To use this auth method, run these commands first:

Cache destination SaaS Scalr token (replace `account` with the actual account name):
```shell
terraform login account.scalr.io
```

Cache source on-prem Scalr token:
```shell
terraform login onprem.scalr.local
```

## Execution

```bash
./migrate.sh --source-scalr-hostname "onprem.scalr.local" --source-scalr-token "your-source-token" --source-scalr-environment "source-env" --scalr-hostname "account.scalr.io" --scalr-token "your-dest-token"
```

### Required Arguments

- `--scalr-hostname`: Destination SaaS Scalr hostname (e.g., `myorg.scalr.io`)
- `--scalr-token`: Destination SaaS Scalr API token
- `--source-scalr-hostname`: Source on-prem Scalr hostname (e.g., `onprem.scalr.local`)
- `--source-scalr-token`: Source on-prem Scalr API token
- `--source-scalr-environment`: Source on-prem Scalr environment name (required)

### Optional Arguments

- `-v|--vcs-name`: VCS provider name in destination SaaS Scalr (required if not using `--skip-workspace-creation` for VCS driven-workspaces)
- `--pc-name`: Provider configuration name in destination SaaS Scalr to link to workspaces
- `--agent-pool-name`: Agent pool name in destination SaaS Scalr to link to workspaces
- `-w|--workspaces`: Workspace name pattern (supports glob patterns, default: "*")
- `--scalr-environment`: Destination Scalr environment name (defaults to source environment name)
- `--skip-workspace-creation`: Skip workspace creation in destination Scalr (use if workspaces already exist)
- `--skip-backend-secrets`: Skip creation of shell variables for backend configuration
- `--skip-scalr-lock`: Skip locking source on-prem Scalr workspaces after migration
- `--management-env-name`: Name of the management environment (default: "scalr-admin")
- `--disable-deletion-protection`: Disable deletion protection in workspace resources
- `--skip-variables`: Comma-separated list of variable patterns to skip, or "*" to skip all variables

## Generated Files

The tool generates the following files in the `generated-terraform/$SCALR_ENVIRONMENT` directory so you can manage your workspaces with the Scalr Terraform provider:

- `main.tf`: Contains all Terraform resources
- `backend.tf`: Remote backend configuration
- `import_commands.sh`: Script to import resources and push state

### Post-Migration

After successful migration, you can navigate to the generated Terraform directory and run:

```bash
cd generated-terraform/<environment-name>
terraform init
terraform plan
terraform apply
```

This will import all previously created resources into the management workspace state file, allowing you to manage your Scalr infrastructure as code.

## Limitations

- Supports up to Terraform 1.5.7. If a higher version is used, the script will downgrade it to 1.5.7.
- State migration requires at least one state file in the source on-prem Scalr workspace.
- Sensitive terraform variables migration requires at least one plan file in the source on-prem Scalr workspace.
- Sensitive environment variables are not migrated

## Troubleshooting

1. If you encounter authentication errors:
   - Verify your tokens are correct
   - Check the credentials file format
   - Ensure you have the necessary permissions

2. If state migration fails:
   - Check if the source on-prem Scalr workspace has a valid state file
   - Ensure you have sufficient permissions in both on-prem and SaaS Scalr platforms

3. If workspace creation fails:
   - Verify the VCS provider is correctly configured in destination SaaS Scalr
   - Check if the workspace name is available in the destination environment
   - Ensure you have sufficient permissions in both platforms

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
