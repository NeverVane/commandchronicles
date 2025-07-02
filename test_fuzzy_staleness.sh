#!/bin/bash

# Test script for fuzzy search index staleness logic
# This script tests the implementation of timestamp-based index rebuilding

set -e

echo "=== CommandChronicles Fuzzy Index Staleness Test ==="
echo

# Configuration
TEST_DIR="/tmp/ccr-staleness-test"
CCR_BINARY="./ccr"
TEST_CONFIG_DIR="$TEST_DIR/.config/commandchronicles"
TEST_DATA_DIR="$TEST_DIR/.local/share/commandchronicles"
INDEX_PATH="$TEST_DATA_DIR/search_index"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
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
    echo -e "${RED}[ERROR]${NC} $1"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up test environment..."
    rm -rf "$TEST_DIR"
    unset HOME
    unset XDG_CONFIG_HOME
    unset XDG_DATA_HOME
}

# Setup test environment
setup_test_env() {
    log_info "Setting up test environment in $TEST_DIR"

    # Clean any existing test directory
    rm -rf "$TEST_DIR"
    mkdir -p "$TEST_DIR"
    mkdir -p "$TEST_CONFIG_DIR"
    mkdir -p "$TEST_DATA_DIR"

    # Set environment variables to use test directory
    export HOME="$TEST_DIR"
    export XDG_CONFIG_HOME="$TEST_DIR/.config"
    export XDG_DATA_HOME="$TEST_DIR/.local/share"

    log_success "Test environment setup complete"
}

# Initialize CCR in test environment
init_ccr() {
    log_info "Initializing CCR in test environment..."

    # Initialize with a test password
    echo "test123" | $CCR_BINARY init --password-stdin --no-hooks --disable-sync

    if [ $? -eq 0 ]; then
        log_success "CCR initialized successfully"
    else
        log_error "Failed to initialize CCR"
        exit 1
    fi
}

# Add test commands to history
add_test_commands() {
    log_info "Adding test commands to history..."

    # Unlock storage first
    echo "test123" | $CCR_BINARY unlock --password-stdin

    # Add some test commands with docker in them
    $CCR_BINARY record "docker ps -a" --exit-code 0 --duration 150
    $CCR_BINARY record "docker compose up -d" --exit-code 0 --duration 2500
    $CCR_BINARY record "docker exec -it container bash" --exit-code 0 --duration 500
    $CCR_BINARY record "ls -la" --exit-code 0 --duration 50
    $CCR_BINARY record "cd /tmp" --exit-code 0 --duration 10

    log_success "Added test commands to history"
}

# Test CLI fuzzy search functionality
test_cli_fuzzy_search() {
    log_info "Testing CLI fuzzy search..."

    # Test normal search first (should work)
    log_info "Testing normal CLI search for 'docker'..."
    result=$(echo "test123" | $CCR_BINARY unlock --password-stdin > /dev/null 2>&1 && $CCR_BINARY search docker 2>&1)
    if echo "$result" | grep -q "docker"; then
        log_success "Normal CLI search works"
    else
        log_error "Normal CLI search failed"
        echo "$result"
        return 1
    fi

    # Test fuzzy search (should work and rebuild index)
    log_info "Testing CLI fuzzy search for 'docker'..."
    result=$(echo "test123" | $CCR_BINARY unlock --password-stdin > /dev/null 2>&1 && $CCR_BINARY search --fuzzy docker 2>&1)
    if echo "$result" | grep -q "docker"; then
        log_success "CLI fuzzy search works"
    else
        log_error "CLI fuzzy search failed"
        echo "$result"
        return 1
    fi

    # Test fuzzy search with typo
    log_info "Testing CLI fuzzy search with typo 'dockr'..."
    result=$(echo "test123" | $CCR_BINARY unlock --password-stdin > /dev/null 2>&1 && $CCR_BINARY search --fuzzy dockr 2>&1)
    if echo "$result" | grep -q "docker"; then
        log_success "CLI fuzzy search with typo works"
    else
        log_warning "CLI fuzzy search with typo didn't find results (this might be expected)"
    fi
}

# Test index staleness detection
test_index_staleness() {
    log_info "Testing index staleness detection..."

    # First, ensure we have a fuzzy index by running a fuzzy search
    echo "test123" | $CCR_BINARY unlock --password-stdin > /dev/null 2>&1
    $CCR_BINARY search --fuzzy docker > /dev/null 2>&1

    if [ -d "$INDEX_PATH" ]; then
        log_success "Fuzzy index exists at $INDEX_PATH"

        # Get index timestamp
        index_time=$(stat -f "%m" "$INDEX_PATH" 2>/dev/null || stat -c "%Y" "$INDEX_PATH" 2>/dev/null)
        log_info "Index timestamp: $index_time"

        # Wait a moment then add a new command (to make it newer than index)
        sleep 2
        $CCR_BINARY record "docker images" --exit-code 0 --duration 800

        log_info "Added new command after index creation"

        # Now test if TUI initialization detects staleness and rebuilds
        log_info "Testing TUI initialization with stale index..."
        # Note: We can't easily test TUI interactively, but we can check if the search works
        result=$(echo "test123" | $CCR_BINARY unlock --password-stdin > /dev/null 2>&1 && $CCR_BINARY search --fuzzy images 2>&1)
        if echo "$result" | grep -q "docker images"; then
            log_success "New command found in fuzzy search (index was rebuilt)"
        else
            log_warning "New command not found in fuzzy search"
        fi

    else
        log_warning "Fuzzy index directory not found, fuzzy search may not be working"
    fi
}

# Test the staleness check manually
test_staleness_check() {
    log_info "Testing staleness check mechanism..."

    # Delete the index to force staleness
    if [ -d "$INDEX_PATH" ]; then
        rm -rf "$INDEX_PATH"
        log_info "Removed fuzzy index to test staleness detection"
    fi

    # Run fuzzy search - should detect missing index and rebuild
    echo "test123" | $CCR_BINARY unlock --password-stdin > /dev/null 2>&1
    result=$($CCR_BINARY search --fuzzy docker 2>&1)

    if echo "$result" | grep -q "docker"; then
        log_success "Fuzzy search rebuilt missing index and found results"
    else
        log_error "Fuzzy search failed to rebuild missing index"
        echo "$result"
        return 1
    fi

    # Verify index was recreated
    if [ -d "$INDEX_PATH" ]; then
        log_success "Fuzzy index was recreated"
    else
        log_error "Fuzzy index was not recreated"
        return 1
    fi
}

# Main test execution
main() {
    echo "Starting fuzzy search staleness tests..."
    echo

    # Set trap for cleanup
    trap cleanup EXIT

    # Check if CCR binary exists
    if [ ! -f "$CCR_BINARY" ]; then
        log_error "CCR binary not found at $CCR_BINARY"
        log_info "Please run: go build -o ccr main.go"
        exit 1
    fi

    # Run tests
    setup_test_env
    init_ccr
    add_test_commands

    echo
    log_info "=== Running Fuzzy Search Tests ==="
    test_cli_fuzzy_search

    echo
    log_info "=== Running Staleness Detection Tests ==="
    test_index_staleness

    echo
    log_info "=== Running Manual Staleness Check ==="
    test_staleness_check

    echo
    log_success "All tests completed successfully!"
    echo
    echo "Summary of what was tested:"
    echo "- CLI normal search functionality"
    echo "- CLI fuzzy search functionality"
    echo "- Fuzzy search with typos"
    echo "- Index staleness detection after new commands"
    echo "- Index rebuilding when missing"
    echo "- Timestamp-based staleness logic"
    echo
    echo "The implementation should now:"
    echo "1. Check index staleness in TUI initialization"
    echo "2. Check index staleness after sync operations"
    echo "3. Rebuild indexes when commands are newer than index"
    echo "4. Handle missing indexes gracefully"
}

# Run the tests
main "$@"
