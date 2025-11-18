#!/bin/bash

# Cross-platform migration script for Windows and Linux/macOS
# Supports Git Bash, WSL, Cygwin, MSYS2 on Windows and native bash on Unix-like systems
# Automatically detects Python 3.x installation and handles platform-specific paths

set -e

# Detect operating system
detect_os() {
    case "$(uname -s)" in
        CYGWIN*|MINGW32*|MINGW64*|MSYS*) OS="windows" ;;
        *) OS="unix" ;;
    esac
}

# Find Python executable
find_python() {
    local python_cmd=""
    
    # Try different Python commands in order of preference
    for cmd in python3.12 python3.11 python3.10 python3.9 python3.8 python3 python; do
        if command_exists "$cmd"; then
            # Check if it's Python 3.x
            local version
            version=$("$cmd" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
            local major_version
            major_version=$(echo "$version" | cut -d. -f1)
            if [ "$major_version" = "3" ]; then
                python_cmd="$cmd"
                break
            fi
        fi
    done
    
    if [ -z "$python_cmd" ]; then
        echo "Python 3.8 or higher is required but not found. Please install Python 3.8+ first."
        exit 1
    fi
    
    echo "$python_cmd"
}

# Get user home directory cross-platform
get_home_dir() {
    if [ "$OS" = "windows" ]; then
        echo "${USERPROFILE:-$HOME}"
    else
        echo "$HOME"
    fi
}

# Activate virtual environment cross-platform
activate_venv() {
    if [ "$OS" = "windows" ]; then
        source venv/Scripts/activate
    else
        source venv/bin/activate
    fi
}

# Check if command exists cross-platform
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Initialize OS detection and Python command
detect_os
PYTHON_CMD=$(find_python)
USER_HOME=$(get_home_dir)

# Function to read credentials from file
read_tfrc_credentials() {
    local credentials_file="$USER_HOME/.terraform.d/credentials.tfrc.json"
    if [ -f "$credentials_file" ]; then
        # Check if jq is available
        if ! command_exists "jq"; then
            echo "Warning: jq is not available. Cannot read credentials from $credentials_file"
            echo "Please install jq or provide tokens manually via command line arguments."
            return
        fi
        
        # Read Scalr token
        local scalr_token
        scalr_token=$(jq -r ".credentials.\"$SCALR_HOSTNAME\".token" "$credentials_file" 2>/dev/null)
        if [ "$scalr_token" != "null" ]; then
            export SCALR_TOKEN="$scalr_token"
        fi

        # Read source Scalr token
        local source_scalr_token
        source_scalr_token=$(jq -r ".credentials.\"$SOURCE_SCALR_HOSTNAME\".token" "$credentials_file" 2>/dev/null)
        if [ "$source_scalr_token" != "null" ]; then
            export SOURCE_SCALR_TOKEN="$source_scalr_token"
        fi
    fi
}

# Function to validate required parameters
validate_required_params() {
    local missing_params=()
    
    if [ -z "$SCALR_HOSTNAME" ]; then
        missing_params+=("SCALR_HOSTNAME")
    fi
    
    if [ -z "$SCALR_TOKEN" ]; then
        missing_params+=("SCALR_TOKEN")
    fi
    
    if [ -z "$SOURCE_SCALR_HOSTNAME" ]; then
        missing_params+=("SOURCE_SCALR_HOSTNAME")
    fi
    
    if [ -z "$SOURCE_SCALR_TOKEN" ]; then
        missing_params+=("SOURCE_SCALR_TOKEN")
    fi
    
    if [ -z "$SCALR_VCS_NAME" ] && [ "$SKIP_WORKSPACE_CREATION" != "true" ]; then
        missing_params+=("SCALR_VCS_NAME")
    fi
    
    if [ ${#missing_params[@]} -ne 0 ]; then
        echo "Missing required parameters: ${missing_params[*]}"
        exit 1
    fi
}

# Function to display help
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo "Migrate workspaces from on-prem Scalr to SaaS Scalr"
    echo ""
    echo "Required options:"
    echo "  --scalr-hostname HOSTNAME         Destination SaaS Scalr hostname"
    echo "  --scalr-token TOKEN               Destination SaaS Scalr token"
    echo "  --source-scalr-hostname HOSTNAME Source on-prem Scalr hostname"
    echo "  --source-scalr-token TOKEN       Source on-prem Scalr token"
    echo "  --source-scalr-environment ENV   Source on-prem Scalr environment name"
    echo ""
    echo "Optional options:"
    echo "  --scalr-environment ENV           Destination Scalr environment name (default: source environment name)"
    echo "  --vcs-name NAME                   VCS provider name in destination Scalr"
    echo "  --pc-name NAME                    Provider configuration name in destination Scalr"
    echo "  --agent-pool-name NAME            Agent pool name in destination Scalr"
    echo "  --workspaces PATTERN              Workspaces to migrate (default: all)"
    echo "  --skip-workspace-creation         Skip creating new workspaces in destination Scalr"
    echo "  --skip-backend-secrets            Skip creating shell variables in destination Scalr"
    echo "  --skip-scalr-lock                 Skip locking source on-prem Scalr workspaces after migration"
    echo "  --management-env-name NAME        Name of the management environment (default: scalr-admin)"
    echo "  --disable-deletion-protection     Disable deletion protection in workspace resources"
    echo "  --skip-variables PATTERNS         Comma-separated list of variable keys to skip, or '*' to skip all variables"
    echo "  --help                            Show this help message"
    echo ""
    echo "Example:"
    echo "  $0 --source-scalr-hostname onprem.scalr.local --source-scalr-token src-token --source-scalr-environment src-env --scalr-hostname account.scalr.io --scalr-token dest-token --vcs-name vcs"
}

# Parse command line arguments
ARGS=()
while [[ $# -gt 0 ]]; do
    case $1 in
        # Handle equal-sign format first
        -v=*|-w=*|--*=*)
            # Extract parameter name and value
            param="${1#-}"   # Remove first -
            param="${param#-}"  # Remove second - if it exists
            param="${param%=*}"  # Remove =value part
            value="${1#*=}"
            # Convert parameter name to environment variable name
            env_var=$(echo "$param" | tr '[:lower:]' '[:upper:]' | tr '-' '_')
            # Handle special cases
            case $1 in
                -v=*|--vcs-name=*) env_var="SCALR_VCS_NAME" ;;
                -w=*|--workspaces=*) env_var="WORKSPACES" ;;
            esac
            export "$env_var"="$value"
            shift
            ;;
        # Handle space-separated format
        --scalr-hostname|--scalr-token|--scalr-environment|--source-scalr-hostname|--source-scalr-token|--source-scalr-environment|--vcs-name|--pc-name|--workspaces|--management-env-name|--skip-variables|--agent-pool-name)
            param="${1#--}"  # Remove leading --
            env_var=$(echo "$param" | tr '[:lower:]' '[:upper:]' | tr '-' '_')
            case $1 in
                -v|--vcs-name) env_var="SCALR_VCS_NAME" ;;
                -w|--workspaces) env_var="WORKSPACES" ;;
            esac
            export "$env_var"="$2"
            echo "DEBUG: Setting $env_var=$2"
            shift 2
            ;;
        # Handle short options with space
        -v|-w)
            case $1 in
                -v) env_var="SCALR_VCS_NAME" ;;
                -w) env_var="WORKSPACES" ;;
            esac
            export "$env_var"="$2"
            echo "DEBUG: Setting $env_var=$2"
            shift 2
            ;;
        # Handle boolean flags
        --skip-workspace-creation|--skip-backend-secrets|--skip-scalr-lock|--disable-deletion-protection)
            param="${1#--}"  # Remove leading --
            env_var=$(echo "$param" | tr '[:lower:]' '[:upper:]' | tr '-' '_')
            export "$env_var"=true
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

# Set default values if not provided
if [ -z "$SCALR_ENVIRONMENT" ]; then
    export SCALR_ENVIRONMENT="$SOURCE_SCALR_ENVIRONMENT"
fi

# Read credentials from file if not provided
read_tfrc_credentials

# Validate required parameters
validate_required_params

# Set default values if not provided
MANAGEMENT_ENV_NAME=${MANAGEMENT_ENV_NAME:-"scalr-admin"}

install_dependencies=false
# Create and activate virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    "$PYTHON_CMD" -m venv venv
    install_dependencies=true
fi

echo "Activating virtual environment..."
activate_venv

# Install dependencies only on first execution
if [ "$install_dependencies" = true ]; then
    echo "Installing dependencies..."
    pip install -r requirements.txt
fi

# Build the command
CMD="\"$PYTHON_CMD\" migrator.py"
CMD="$CMD --scalr-hostname \"$SCALR_HOSTNAME\""
CMD="$CMD --scalr-token \"$SCALR_TOKEN\""
CMD="$CMD --scalr-environment \"$SCALR_ENVIRONMENT\""
CMD="$CMD --source-scalr-hostname \"$SOURCE_SCALR_HOSTNAME\""
CMD="$CMD --source-scalr-token \"$SOURCE_SCALR_TOKEN\""
CMD="$CMD --source-scalr-environment \"$SOURCE_SCALR_ENVIRONMENT\""
[ -n "$SCALR_VCS_NAME" ] && CMD="$CMD --vcs-name \"$SCALR_VCS_NAME\""
[ -n "$SCALR_PC_NAME" ] && CMD="$CMD --pc-name \"$SCALR_PC_NAME\""
[ -n "$WORKSPACES" ] && CMD="$CMD -w \"$WORKSPACES\""
[ "$SKIP_WORKSPACE_CREATION" = true ] && CMD="$CMD --skip-workspace-creation"
[ "$SKIP_BACKEND_SECRETS" = true ] && CMD="$CMD --skip-backend-secrets"
[ "$SKIP_SCALR_LOCK" = true ] && CMD="$CMD --skip-scalr-lock"
[ -n "$MANAGEMENT_ENV_NAME" ] && CMD="$CMD --management-env-name \"$MANAGEMENT_ENV_NAME\""
[ "$DISABLE_DELETION_PROTECTION" = true ] && CMD="$CMD --disable-deletion-protection"
[ -n "$SKIP_VARIABLES" ] && CMD="$CMD --skip-variables \"$SKIP_VARIABLES\""
[ -n "$SCALR_AGENT_POOL_NAME" ] && CMD="$CMD --agent-pool-name \"$SCALR_AGENT_POOL_NAME\""

# Run the migrator
echo "Running migrator..."
eval "$CMD"

# Deactivate virtual environment
deactivate

# Check if migration was successful
if [ $? -eq 0 ]; then
    echo "Migration completed successfully! The code is generated to $PWD/generated-terraform "
else
    echo "Migration failed. Please check the errors above."
    exit 1
fi 