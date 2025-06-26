# Scripts Directory

This directory contains various utility scripts for building, releasing, and maintaining the CommandChronicles CLI project.

## Scripts Overview

### 🔄 sync-public-mirror.sh
**Purpose**: Creates and maintains a clean public mirror of the project for GitHub release

**Usage**:
```bash
# Basic usage - sync to default location
./scripts/sync-public-mirror.sh

# Sync to specific directory
./scripts/sync-public-mirror.sh ~/my-public-repo

# Preview changes without copying
./scripts/sync-public-mirror.sh --dry-run --verbose

# Force overwrite and initialize git
./scripts/sync-public-mirror.sh --init-git --force ~/clean-repo
```

**Key Features**:
- Excludes development files (implementation plans, debug logs, etc.)
- Includes only essential files for public release
- Supports dry-run mode for previewing changes
- Can initialize git repository with initial commit
- Comprehensive logging and error handling

**See**: [PUBLIC_MIRROR_GUIDE.md](../PUBLIC_MIRROR_GUIDE.md) for detailed usage instructions.

### 🔨 build-release.sh
**Purpose**: Builds release binaries for multiple platforms

**Usage**:
```bash
./scripts/build-release.sh
```

**Features**:
- Cross-platform compilation
- Version embedding
- Release artifact generation

### 📦 install.sh
**Purpose**: User installation script for CommandChronicles CLI

**Usage**:
```bash
# Download and run directly
curl -sSL https://raw.githubusercontent.com/yourusername/commandchronicles-cli/main/scripts/install.sh | bash

# Or download and inspect first
wget https://raw.githubusercontent.com/yourusername/commandchronicles-cli/main/scripts/install.sh
chmod +x install.sh
./install.sh
```

**Features**:
- Automatic platform detection
- Binary installation to system PATH
- Shell hook installation
- Permission handling

## Development Scripts

### 📝 Task and Planning Files
- `prd.txt` - Product Requirements Document
- `example_prd.txt` - Example PRD template
- `task-complexity-report.json` - Task complexity analysis

These files are used for project planning and development workflow management.

## Script Permissions

Make scripts executable before running:

```bash
chmod +x scripts/*.sh
```

## Requirements

### For sync-public-mirror.sh
- `rsync` (for file synchronization)
- `bash` 4.0+ (for advanced features)
- `git` (if using --init-git option)

### For build-release.sh
- `go` 1.23+ (Go compiler)
- Cross-compilation support

### For install.sh
- `curl` or `wget` (for downloading)
- System package manager (apt, yum, brew, etc.)

## Contributing

When adding new scripts:

1. **Make them executable**: `chmod +x scripts/new-script.sh`
2. **Add usage documentation** to this README
3. **Include help text** in the script (`--help` option)
4. **Follow naming conventions**: Use kebab-case with `.sh` extension
5. **Add error handling**: Use `set -euo pipefail` for safety
6. **Include logging**: Use consistent log formatting

## Script Template

Use this template for new scripts:

```bash
#!/bin/bash
set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# Usage function
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Description of what this script does.

OPTIONS:
    -h, --help      Show this help message

EXAMPLES:
    $0              # Basic usage example
EOF
}

# Main function
main() {
    # Script logic here
    log_info "Starting script execution..."
    # ... your code ...
    log_success "Script completed successfully!"
}

# Parse arguments and run
case "${1:-}" in
    -h|--help) usage; exit 0 ;;
    *) main "$@" ;;
esac
```

## Troubleshooting

### Common Issues

**Permission denied**:
```bash
chmod +x scripts/<script-name>.sh
```

**Command not found**:
```bash
# Run from project root
./scripts/<script-name>.sh

# Or add to PATH temporarily
export PATH="$PATH:./scripts"
<script-name>.sh
```

**Script fails with "No such file or directory"**:
- Ensure you're running from the project root directory
- Check that all dependencies are installed
- Verify file paths are correct

### Getting Help

For script-specific help, use the `--help` option:
```bash
./scripts/<script-name>.sh --help
```

For general issues, check:
1. Script permissions (`ls -la scripts/`)
2. Shell compatibility (`echo $SHELL`)
3. Required dependencies are installed
4. You're in the correct directory (project root)

## Security Notes

- 🔒 Scripts may require elevated permissions for system-wide installation
- 🔍 Always review scripts before running, especially when downloaded from the internet
- ⚠️ Some scripts modify system files - use caution in production environments
- 🛡️ The sync-public-mirror.sh script is designed to exclude sensitive development files