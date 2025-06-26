#!/usr/bin/env bash

# CommandChronicles CLI Installation Script
# This script installs the latest version of CommandChronicles CLI
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/commandchronicles/cli/main/scripts/install.sh | sh
#
# Or with custom options:
#   curl -fsSL https://raw.githubusercontent.com/commandchronicles/cli/main/scripts/install.sh | sh -s -- --version v1.0.0 --install-dir /usr/local/bin

set -e

# Default configuration
GITHUB_REPO="commandchronicles/cli"
INSTALL_DIR=""
VERSION=""
BINARY_NAME="ccr"
FORCE_INSTALL=false
VERIFY_CHECKSUM=true

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✅${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠️${NC} $1"
}

log_error() {
    echo -e "${RED}❌${NC} $1" >&2
}

log_step() {
    echo -e "${BOLD}$1${NC}"
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --version)
                VERSION="$2"
                shift 2
                ;;
            --install-dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            --force)
                FORCE_INSTALL=true
                shift
                ;;
            --no-verify)
                VERIFY_CHECKSUM=false
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

show_help() {
    cat << EOF
CommandChronicles CLI Installation Script

USAGE:
    install.sh [OPTIONS]

OPTIONS:
    --version <version>     Install specific version (e.g., v1.0.0)
    --install-dir <dir>     Custom installation directory
    --force                 Force installation even if already installed
    --no-verify            Skip checksum verification
    --help                  Show this help message

EXAMPLES:
    # Install latest version
    curl -fsSL https://raw.githubusercontent.com/commandchronicles/cli/main/scripts/install.sh | sh

    # Install specific version
    curl -fsSL https://raw.githubusercontent.com/commandchronicles/cli/main/scripts/install.sh | sh -s -- --version v1.0.0

    # Install to custom directory
    curl -fsSL https://raw.githubusercontent.com/commandchronicles/cli/main/scripts/install.sh | sh -s -- --install-dir ~/.local/bin

Note: This installer supports Unix systems only (Linux and macOS). Windows is not supported.

EOF
}

# Detect operating system (Unix systems only)
detect_os() {
    case "$(uname -s)" in
        Linux*)     echo "linux";;
        Darwin*)    echo "darwin";;
        *)          log_error "Unsupported operating system: $(uname -s) - Unix systems only"; exit 1;;
    esac
}

# Detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   echo "amd64";;
        arm64|aarch64)  echo "arm64";;
        armv7l)         echo "arm";;
        i386|i686)      echo "386";;
        *)              log_error "Unsupported architecture: $(uname -m)"; exit 1;;
    esac
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
check_prerequisites() {
    log_step "🔍 Checking prerequisites..."

    if ! command_exists curl && ! command_exists wget; then
        log_error "curl or wget is required but not installed"
        log_info "Please install curl or wget and try again"
        exit 1
    fi

    if ! command_exists tar && ! command_exists unzip; then
        log_warning "tar or unzip not found - may be needed for some downloads"
    fi

    if ! command_exists sha256sum && ! command_exists shasum; then
        log_warning "sha256sum or shasum not found - checksum verification will be skipped"
        VERIFY_CHECKSUM=false
    fi

    log_success "Prerequisites check completed"
}

# Determine installation directory
determine_install_dir() {
    if [[ -n "$INSTALL_DIR" ]]; then
        return
    fi

    # Try common installation directories in order of preference
    local dirs=(
        "/usr/local/bin"
        "$HOME/.local/bin"
        "$HOME/bin"
    )

    for dir in "${dirs[@]}"; do
        if [[ -w "$dir" ]] || [[ ! -e "$dir" && -w "$(dirname "$dir")" ]]; then
            INSTALL_DIR="$dir"
            return
        fi
    done

    # If no writable directory found, use ~/.local/bin and create it
    INSTALL_DIR="$HOME/.local/bin"
    log_warning "No writable installation directory found, will use: $INSTALL_DIR"
}

# Get the latest release version from GitHub
get_latest_version() {
    log_step "🔍 Fetching latest version information..."

    local api_url="https://api.github.com/repos/$GITHUB_REPO/releases/latest"
    local latest_version

    if command_exists curl; then
        latest_version=$(curl -fsSL "$api_url" | grep '"tag_name":' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    elif command_exists wget; then
        latest_version=$(wget -qO- "$api_url" | grep '"tag_name":' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    else
        log_error "Unable to fetch latest version - no HTTP client available"
        exit 1
    fi

    if [[ -z "$latest_version" ]]; then
        log_error "Failed to fetch latest version from GitHub"
        exit 1
    fi

    echo "$latest_version"
}

# Download file with progress
download_file() {
    local url="$1"
    local output="$2"

    log_info "Downloading from: $url"

    if command_exists curl; then
        curl -fL --progress-bar "$url" -o "$output"
    elif command_exists wget; then
        wget --progress=bar:force:noscroll "$url" -O "$output"
    else
        log_error "No HTTP client available for download"
        exit 1
    fi
}

# Verify checksum
verify_checksum() {
    local file="$1"
    local expected_checksum="$2"

    if [[ "$VERIFY_CHECKSUM" == false ]]; then
        log_warning "Checksum verification skipped"
        return 0
    fi

    log_step "🔐 Verifying checksum..."

    local actual_checksum
    if command_exists sha256sum; then
        actual_checksum=$(sha256sum "$file" | cut -d' ' -f1)
    elif command_exists shasum; then
        actual_checksum=$(shasum -a 256 "$file" | cut -d' ' -f1)
    else
        log_warning "No checksum tool available, skipping verification"
        return 0
    fi

    if [[ "$actual_checksum" == "$expected_checksum" ]]; then
        log_success "Checksum verification passed"
        return 0
    else
        log_error "Checksum verification failed!"
        log_error "Expected: $expected_checksum"
        log_error "Actual:   $actual_checksum"
        return 1
    fi
}

# Check if CLI is already installed
check_existing_installation() {
    if [[ "$FORCE_INSTALL" == true ]]; then
        return 0
    fi

    if command_exists "$BINARY_NAME"; then
        local installed_version
        installed_version=$($BINARY_NAME version 2>/dev/null | grep -o 'Version: [^[:space:]]*' | cut -d' ' -f2 || echo "unknown")

        log_info "CommandChronicles CLI is already installed (version: $installed_version)"

        if [[ -n "$VERSION" && "$installed_version" == "${VERSION#v}" ]]; then
            log_success "Requested version $VERSION is already installed"
            exit 0
        elif [[ -z "$VERSION" ]]; then
            log_info "Use --force to reinstall or --version to install a specific version"
            exit 0
        fi
    fi
}

# Main installation function
install_cli() {
    log_step "🚀 Installing CommandChronicles CLI..."

    # Detect system information
    local os arch
    os=$(detect_os)
    arch=$(detect_arch)

    log_info "Detected platform: $os/$arch"

    # Determine version to install
    if [[ -z "$VERSION" ]]; then
        VERSION=$(get_latest_version)
    fi

    log_info "Installing version: $VERSION"

    # Construct download URLs (Unix systems only)
    local binary_name="ccr-$os-$arch"

    local base_url="https://github.com/$GITHUB_REPO/releases/download/$VERSION"
    local binary_url="$base_url/$binary_name"
    local checksum_url="$base_url/$binary_name.sha256"

    # Create temporary directory
    local temp_dir
    temp_dir=$(mktemp -d)
    trap "rm -rf '$temp_dir'" EXIT

    local temp_binary="$temp_dir/$binary_name"
    local temp_checksum="$temp_dir/$binary_name.sha256"

    # Download binary
    log_step "📦 Downloading binary..."
    download_file "$binary_url" "$temp_binary"

    # Download and verify checksum
    if [[ "$VERIFY_CHECKSUM" == true ]]; then
        log_step "📦 Downloading checksum..."
        if ! download_file "$checksum_url" "$temp_checksum"; then
            log_warning "Failed to download checksum file, skipping verification"
            VERIFY_CHECKSUM=false
        else
            local expected_checksum
            expected_checksum=$(cut -d' ' -f1 "$temp_checksum")
            verify_checksum "$temp_binary" "$expected_checksum"
        fi
    fi

    # Create installation directory if it doesn't exist
    if [[ ! -d "$INSTALL_DIR" ]]; then
        log_info "Creating installation directory: $INSTALL_DIR"
        mkdir -p "$INSTALL_DIR"
    fi

    # Install binary
    log_step "📋 Installing binary..."
    local install_path="$INSTALL_DIR/$BINARY_NAME"

    # Remove existing binary if it exists
    if [[ -f "$install_path" ]]; then
        rm "$install_path"
    fi

    cp "$temp_binary" "$install_path"
    chmod +x "$install_path"

    log_success "CommandChronicles CLI installed successfully!"
    log_info "Installation location: $install_path"

    # Check if installation directory is in PATH
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        log_warning "Installation directory is not in your PATH"
        log_info "Add the following line to your shell profile (.bashrc, .zshrc, etc.):"
        log_info "export PATH=\"\$PATH:$INSTALL_DIR\""
        log_info ""
        log_info "Or run the CLI directly: $install_path"
    fi

    # Test installation
    log_step "🧪 Testing installation..."
    if "$install_path" version >/dev/null 2>&1; then
        log_success "Installation test passed!"

        # Show version information
        echo ""
        "$install_path" version

        echo ""
        log_success "🎉 CommandChronicles CLI is ready to use!"
        log_info "Run 'ccr --help' to get started"
        log_info "Run 'ccr init' to initialize your command history"
    else
        log_error "Installation test failed"
        log_error "The binary was installed but doesn't seem to work correctly"
        exit 1
    fi
}

# Main execution
main() {
    echo "CommandChronicles CLI Installer"
    echo "==============================="
    echo ""

    parse_args "$@"
    check_prerequisites
    determine_install_dir
    check_existing_installation
    install_cli
}

# Run main function with all arguments
main "$@"
