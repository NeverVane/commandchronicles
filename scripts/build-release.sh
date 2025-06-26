#!/usr/bin/env bash

# CommandChronicles CLI Local Release Builder
# This script builds binaries for all supported platforms locally
# Useful for testing the release process before pushing to GitHub

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/dist"
BINARY_NAME="ccr"

# Default values
VERSION=""
COMMIT=""
DATE=""
AUTHOR="Leonardo Zanobi"
WEBSITE="https://commandchronicles.dev"
CLEAN_BUILD=false
VERIFY_BUILDS=true

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

# Show help
show_help() {
    cat << EOF
CommandChronicles CLI Local Release Builder

USAGE:
    build-release.sh [OPTIONS]

OPTIONS:
    --version <version>     Set version (default: auto-detect from git or use 0.1.0-dev)
    --commit <commit>       Set commit hash (default: current git commit)
    --date <date>           Set build date (default: current date)
    --clean                 Clean build directory before building
    --no-verify             Skip build verification
    --help                  Show this help message

EXAMPLES:
    # Build with auto-detected version
    ./scripts/build-release.sh

    # Build specific version
    ./scripts/build-release.sh --version v1.0.0

    # Clean build with custom version
    ./scripts/build-release.sh --clean --version v1.0.0-rc1

PLATFORMS:
    - Linux AMD64
    - Linux ARM64
    - macOS Intel (AMD64)
    - macOS Apple Silicon (ARM64)

OUTPUT:
    Binaries will be created in: $BUILD_DIR/
    Checksums will be created in: $BUILD_DIR/checksums.txt

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --version)
                VERSION="$2"
                shift 2
                ;;
            --commit)
                COMMIT="$2"
                shift 2
                ;;
            --date)
                DATE="$2"
                shift 2
                ;;
            --clean)
                CLEAN_BUILD=true
                shift
                ;;
            --no-verify)
                VERIFY_BUILDS=false
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

# Auto-detect build metadata
detect_metadata() {
    if [[ -z "$VERSION" ]]; then
        if git describe --tags --exact-match HEAD 2>/dev/null; then
            VERSION=$(git describe --tags --exact-match HEAD)
        elif git describe --tags 2>/dev/null; then
            VERSION=$(git describe --tags)
        else
            VERSION="0.1.0-dev"
        fi
        log_info "Auto-detected version: $VERSION"
    fi

    if [[ -z "$COMMIT" ]]; then
        if git rev-parse --short HEAD 2>/dev/null; then
            COMMIT=$(git rev-parse --short HEAD)
        else
            COMMIT="unknown"
        fi
        log_info "Auto-detected commit: $COMMIT"
    fi

    if [[ -z "$DATE" ]]; then
        DATE=$(date -u +'%Y-%m-%d')
        log_info "Using build date: $DATE"
    fi

    # Clean version (remove 'v' prefix if present)
    VERSION_CLEAN="${VERSION#v}"
}

# Check prerequisites
check_prerequisites() {
    log_step "🔍 Checking prerequisites..."

    if ! command -v go >/dev/null 2>&1; then
        log_error "Go is required but not installed"
        exit 1
    fi

    if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
        log_warning "sha256sum or shasum not found - checksums will not be generated"
    fi

    # Check if we're in the right directory
    if [[ ! -f "$PROJECT_DIR/main.go" ]]; then
        log_error "main.go not found. Please run this script from the project root or scripts directory"
        exit 1
    fi

    if [[ ! -f "$PROJECT_DIR/go.mod" ]]; then
        log_error "go.mod not found. Please run this script from a Go project directory"
        exit 1
    fi

    log_success "Prerequisites check completed"
}

# Setup build environment
setup_build_env() {
    log_step "🏗️  Setting up build environment..."

    if [[ "$CLEAN_BUILD" == true && -d "$BUILD_DIR" ]]; then
        log_info "Cleaning build directory: $BUILD_DIR"
        rm -rf "$BUILD_DIR"
    fi

    mkdir -p "$BUILD_DIR"

    # Change to project directory
    cd "$PROJECT_DIR"

    log_success "Build environment ready"
}

# Build for a specific platform
build_platform() {
    local goos="$1"
    local goarch="$2"
    local platform_name="$3"
    local ext="$4"

    local binary_name="${BINARY_NAME}-${platform_name}${ext}"
    local output_path="$BUILD_DIR/$binary_name"

    log_info "Building for $platform_name ($goos/$goarch)..."

    # Set build environment
    export GOOS="$goos"
    export GOARCH="$goarch"
    export CGO_ENABLED=1

    # Platform-specific CGO setup
    case "$goos" in
        linux)
            if [[ "$goarch" == "arm64" ]]; then
                # For cross-compilation, you might need to install cross-compilation tools
                # export CC=aarch64-linux-gnu-gcc
                log_warning "ARM64 cross-compilation may require additional tools"
            fi
            ;;

        darwin)
            if [[ "$(uname)" != "Darwin" ]]; then
                log_warning "Cross-compiling for macOS from non-macOS system"
            fi
            ;;
    esac

    # Build the binary
    go build \
        -ldflags="-X main.version=$VERSION_CLEAN \
                  -X main.commit=$COMMIT \
                  -X main.date=$DATE \
                  -X main.author='$AUTHOR' \
                  -X main.website=$WEBSITE \
                  -w -s" \
        -o "$output_path" \
        . || {
        log_error "Failed to build for $platform_name"
        return 1
    }

    # Verify binary was created
    if [[ ! -f "$output_path" ]]; then
        log_error "Binary not created: $output_path"
        return 1
    fi

    # Get file size
    local size
    if command -v stat >/dev/null 2>&1; then
        if [[ "$(uname)" == "Darwin" ]]; then
            size=$(stat -f%z "$output_path")
        else
            size=$(stat -c%s "$output_path")
        fi
        size_mb=$(echo "scale=1; $size / 1024 / 1024" | bc -l 2>/dev/null || echo "?.?")
    else
        size_mb="?.?"
    fi

    log_success "Built $binary_name (${size_mb}MB)"

    # Generate checksum
    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$BUILD_DIR" && sha256sum "$binary_name" >> "${binary_name}.sha256")
    elif command -v shasum >/dev/null 2>&1; then
        (cd "$BUILD_DIR" && shasum -a 256 "$binary_name" >> "${binary_name}.sha256")
    fi

    return 0
}

# Build all platforms
build_all_platforms() {
    log_step "🚀 Building for all platforms..."

    local platforms=(
        "linux amd64 linux-amd64 ''"
        "linux arm64 linux-arm64 ''"
        "darwin amd64 darwin-amd64 ''"
        "darwin arm64 darwin-arm64 ''"
    )

    local success_count=0
    local total_count=${#platforms[@]}

    for platform_info in "${platforms[@]}"; do
        # Parse platform info
        eval "platform_array=($platform_info)"
        local goos="${platform_array[0]}"
        local goarch="${platform_array[1]}"
        local platform_name="${platform_array[2]}"
        local ext="${platform_array[3]}"

        if build_platform "$goos" "$goarch" "$platform_name" "$ext"; then
            ((success_count++))
        fi
    done

    log_info "Successfully built $success_count/$total_count platforms"

    if [[ $success_count -eq 0 ]]; then
        log_error "No platforms built successfully"
        exit 1
    fi
}

# Generate combined checksums file
generate_checksums() {
    log_step "🔐 Generating checksums..."

    local checksums_file="$BUILD_DIR/checksums.txt"

    # Remove existing checksums file
    rm -f "$checksums_file"

    # Combine all individual checksum files
    for checksum_file in "$BUILD_DIR"/*.sha256; do
        if [[ -f "$checksum_file" ]]; then
            cat "$checksum_file" >> "$checksums_file"
        fi
    done

    if [[ -f "$checksums_file" ]]; then
        log_success "Generated combined checksums file"
        log_info "Checksums:"
        cat "$checksums_file" | sed 's/^/  /'
    else
        log_warning "No checksums generated"
    fi
}

# Verify builds
verify_builds() {
    if [[ "$VERIFY_BUILDS" != true ]]; then
        return
    fi

    log_step "🧪 Verifying builds..."

    local current_os
    case "$(uname)" in
        Linux*) current_os="linux";;
        Darwin*) current_os="darwin";;
        *)
            log_warning "Cannot verify builds on $(uname) - Unix systems only"
            return
            ;;
    esac

    local current_arch
    case "$(uname -m)" in
        x86_64|amd64) current_arch="amd64";;
        arm64|aarch64) current_arch="arm64";;
        *)
            log_warning "Cannot verify builds on $(uname -m)"
            return
            ;;
    esac

    local test_binary="$BUILD_DIR/${BINARY_NAME}-${current_os}-${current_arch}"

    if [[ -f "$test_binary" ]]; then
        log_info "Testing $test_binary..."
        if "$test_binary" version >/dev/null 2>&1; then
            log_success "Build verification passed"
        else
            log_warning "Build verification failed - binary may not work correctly"
        fi
    else
        log_warning "No binary available for verification on this platform"
    fi
}

# Show build summary
show_summary() {
    log_step "📋 Build Summary"

    echo "Build Information:"
    echo "  Version: $VERSION"
    echo "  Commit:  $COMMIT"
    echo "  Date:    $DATE"
    echo "  Author:  $AUTHOR"
    echo ""

    echo "Generated Files:"
    if [[ -d "$BUILD_DIR" ]]; then
        find "$BUILD_DIR" -type f -name "${BINARY_NAME}-*" | sort | while read -r file; do
            local basename=$(basename "$file")
            local size
            if command -v stat >/dev/null 2>&1; then
                if [[ "$(uname)" == "Darwin" ]]; then
                    size=$(stat -f%z "$file")
                else
                    size=$(stat -c%s "$file")
                fi
                size_mb=$(echo "scale=1; $size / 1024 / 1024" | bc -l 2>/dev/null || echo "unknown")
                echo "  $basename (${size_mb}MB)"
            else
                echo "  $basename"
            fi
        done
    fi

    echo ""
    echo "Build directory: $BUILD_DIR"
    echo ""
    log_success "Build completed successfully!"

    echo ""
    echo "Next steps:"
    echo "  1. Test the binaries: $BUILD_DIR/${BINARY_NAME}-<platform>"
    echo "  2. Verify checksums: sha256sum -c $BUILD_DIR/checksums.txt"
    echo "  3. Create GitHub release with these binaries"
}

# Main execution
main() {
    echo "CommandChronicles CLI Local Release Builder"
    echo "=========================================="
    echo ""

    parse_args "$@"
    detect_metadata
    check_prerequisites
    setup_build_env
    build_all_platforms
    generate_checksums
    verify_builds
    show_summary
}

# Run main function with all arguments
main "$@"
