#!/bin/bash

# CommandChronicles CLI - Public Mirror Sync Script
# This script creates a clean mirror of the project for public GitHub release,
# excluding development files and keeping only essential components.

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DEFAULT_TARGET_DIR="$HOME/commandchronicles-cli-public"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script options
DRY_RUN=false
INIT_GIT=false
FORCE=false
VERBOSE=false
TARGET_DIR=""

# Usage information
usage() {
    cat << EOF
Usage: $0 [OPTIONS] [TARGET_DIRECTORY]

Creates a clean public mirror of CommandChronicles CLI by copying only essential files
and excluding development-specific content.

OPTIONS:
    -d, --dry-run           Show what would be copied without actually copying
    -g, --init-git          Initialize git repository in target directory
    -f, --force             Force overwrite of existing target directory
    -v, --verbose           Enable verbose output
    -h, --help              Show this help message

ARGUMENTS:
    TARGET_DIRECTORY        Destination directory for the public mirror
                           (default: $DEFAULT_TARGET_DIR)

EXAMPLES:
    $0                                          # Copy to default location
    $0 ~/my-public-repo                         # Copy to specific directory
    $0 --dry-run --verbose                      # Preview what will be copied
    $0 --init-git --force ~/clean-repo          # Force overwrite and init git

WHAT GETS INCLUDED:
    ✓ Source code (main.go, internal/, pkg/)
    ✓ Build configuration (go.mod, go.sum, Makefile)
    ✓ Essential documentation (README.md)
    ✓ User-facing scripts (install.sh, build-release.sh)
    ✓ Configuration templates (.env.example, .gitignore)
    ✓ CI/CD workflows (.github/)
    ✓ Tests (test/)
    ✓ User documentation (selected docs/)

WHAT GETS EXCLUDED:
    ✗ Implementation plans (*PLAN*.md, *SUMMARY*.md, *ANALYSIS*.md)
    ✗ Development configuration (.taskmasterconfig)
    ✗ Debug logs (debug.log, *.log)
    ✗ Build artifacts (ccr, commandchronicles-cli binaries, build/)
    ✗ Development docs (SERVER_DOCS/, SYNC-IMPLEMENTATION-PLAN/)
    ✗ Empty or dev-specific directories (test-scripts/)
    ✗ Development decision documents (TUI-BEHAVIOR-DECISION.md, etc.)

EOF
}

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_verbose() {
    if [[ "$VERBOSE" == true ]]; then
        echo -e "${BLUE}[VERBOSE]${NC} $1"
    fi
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -g|--init-git)
                INIT_GIT=true
                shift
                ;;
            -f|--force)
                FORCE=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -*)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                if [[ -z "$TARGET_DIR" ]]; then
                    TARGET_DIR="$1"
                else
                    log_error "Multiple target directories specified"
                    exit 1
                fi
                shift
                ;;
        esac
    done

    # Set default target directory if not specified
    if [[ -z "$TARGET_DIR" ]]; then
        TARGET_DIR="$DEFAULT_TARGET_DIR"
    fi

    # Convert to absolute path
    TARGET_DIR="$(realpath "$TARGET_DIR" 2>/dev/null || echo "$TARGET_DIR")"
}

# Validate prerequisites
validate_prerequisites() {
    log_info "Validating prerequisites..."

    # Check if we're in the correct project directory
    if [[ ! -f "$PROJECT_ROOT/main.go" ]] || [[ ! -f "$PROJECT_ROOT/go.mod" ]]; then
        log_error "This doesn't appear to be the CommandChronicles CLI project root"
        log_error "Expected to find main.go and go.mod in: $PROJECT_ROOT"
        exit 1
    fi

    # Check if rsync is available
    if ! command -v rsync &> /dev/null; then
        log_error "rsync is required but not installed"
        exit 1
    fi

    # Check target directory
    if [[ -d "$TARGET_DIR" ]] && [[ "$FORCE" != true ]]; then
        log_error "Target directory already exists: $TARGET_DIR"
        log_error "Use --force to overwrite or choose a different directory"
        exit 1
    fi

    log_success "Prerequisites validated"
}

# Create rsync exclude patterns file
create_exclude_patterns() {
    local exclude_file=$(mktemp)

    cat > "$exclude_file" << 'EOF'
# Development documentation and plans
*PLAN*.md
*SUMMARY*.md
*ANALYSIS*.md
*IMPLEMENTATION*.md
TUI-BEHAVIOR-DECISION.md
UPDATE_SYSTEM_README.md
PASSWORD_CHANGE_IMPLEMENTATION_ANALYSIS.md
FORCE_UPDATE_IMPLEMENTATION_SUMMARY.md
CROSS_DEVICE_PASSWORD_CHANGE_IMPLEMENTATION_PLAN.md
PRODUCTION_FEATURES_IMPLEMENTATION_PLAN.md
REFRESH_TOKEN_IMPLEMENTATION_PLAN.md
SERVER-IMPLEMENTATION-SPEC.md
SERVER-SPEC-COMPLETE.md
SYNC_CLIENT_IMPLEMENTATION.md

# Development configuration
.taskmasterconfig

# Logs and temporary files
debug.log
*.log
*.tmp
*.cache
*.pid

# Build artifacts and binaries
ccr
commandchronicles-cli
build/

# Development directories
SERVER_DOCS/
SYNC-IMPLEMENTATION-PLAN/
test-scripts/

# Development-specific docs (keep only user-facing docs)
docs/PERFECT_SYNC_IMPLEMENTATION.md

# Git directory (we'll handle this separately if needed)
.git/

# IDE and editor files
.vscode/
.idea/
*.swp
*.swo
*~

# OS specific files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Personal development files
tasks.json
tasks/
dev-debug.log
EOF

    echo "$exclude_file"
}

# Perform the sync operation
perform_sync() {
    local exclude_file=$(create_exclude_patterns)
    local rsync_options="-av"

    if [[ "$DRY_RUN" == true ]]; then
        rsync_options+="n"
        log_info "DRY RUN MODE - No files will be actually copied"
    fi

    if [[ "$VERBOSE" == true ]]; then
        rsync_options+=" --progress"
    else
        rsync_options+=" --quiet"
    fi

    log_info "Syncing files from $PROJECT_ROOT to $TARGET_DIR"

    # Create target directory if it doesn't exist
    if [[ "$DRY_RUN" != true ]]; then
        mkdir -p "$TARGET_DIR"
    fi

    # Perform the sync with exclude patterns
    if rsync $rsync_options \
        --exclude-from="$exclude_file" \
        --delete-excluded \
        "$PROJECT_ROOT/" \
        "$TARGET_DIR/"; then

        if [[ "$DRY_RUN" != true ]]; then
            log_success "Files synced successfully"
        else
            log_success "Dry run completed - see above for what would be copied"
        fi
    else
        log_error "Sync operation failed"
        rm -f "$exclude_file"
        exit 1
    fi

    # Clean up temporary exclude file
    rm -f "$exclude_file"
}

# Initialize git repository if requested
init_git_repo() {
    if [[ "$INIT_GIT" == true ]] && [[ "$DRY_RUN" != true ]]; then
        log_info "Initializing git repository in target directory..."

        cd "$TARGET_DIR"

        if [[ -d ".git" ]]; then
            log_warning "Git repository already exists in target directory"
        else
            git init
            git add .
            git commit -m "Initial commit: Clean public mirror of CommandChronicles CLI

This repository contains only the essential files for public release,
excluding development documentation, implementation plans, and build artifacts.

Generated by sync-public-mirror.sh script."

            log_success "Git repository initialized with initial commit"
        fi

        cd - > /dev/null
    fi
}

# Display summary of what was copied
display_summary() {
    if [[ "$DRY_RUN" == true ]]; then
        return
    fi

    log_info "Sync Summary:"
    echo "  Source: $PROJECT_ROOT"
    echo "  Target: $TARGET_DIR"

    # Count files and directories
    local file_count=$(find "$TARGET_DIR" -type f | wc -l)
    local dir_count=$(find "$TARGET_DIR" -type d | wc -l)

    echo "  Files copied: $file_count"
    echo "  Directories: $dir_count"

    # Show disk usage
    local size=$(du -sh "$TARGET_DIR" 2>/dev/null | cut -f1 || echo "unknown")
    echo "  Total size: $size"

    echo ""
    log_success "Public mirror created successfully!"
    echo ""
    echo "Next steps:"
    echo "  1. Review the contents of: $TARGET_DIR"
    echo "  2. Create a new GitHub repository"
    echo "  3. Push the mirrored content:"
    echo "     cd '$TARGET_DIR'"
    echo "     git remote add origin <your-public-repo-url>"
    echo "     git push -u origin main"
    echo ""
    echo "To update the mirror in the future, run this script again."
}

# Main execution
main() {
    echo "CommandChronicles CLI - Public Mirror Sync Script"
    echo "================================================"
    echo ""

    parse_args "$@"
    validate_prerequisites
    perform_sync
    init_git_repo
    display_summary
}

# Execute main function with all arguments
main "$@"
