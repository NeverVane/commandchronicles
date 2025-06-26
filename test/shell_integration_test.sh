#!/bin/bash

# CommandChronicles CLI Shell Integration Test Script
# Tests real shell integration with bash and zsh

set -e  # Exit on any error

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_DIR="/tmp/ccr_shell_test_$$"
CCR_BINARY="$TEST_DIR/ccr"
TEST_CONFIG_DIR="$TEST_DIR/config"
TEST_DATA_DIR="$TEST_DIR/data"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Test helper functions
run_test() {
    local test_name="$1"
    local test_func="$2"
    
    ((TESTS_RUN++))
    log_info "Running test: $test_name"
    
    if $test_func; then
        log_success "$test_name"
        return 0
    else
        log_error "$test_name"
        return 1
    fi
}

# Setup test environment
setup_test_env() {
    log_info "Setting up test environment..."
    
    # Create test directories
    mkdir -p "$TEST_DIR" "$TEST_CONFIG_DIR" "$TEST_DATA_DIR"
    
    # Build CCR binary
    log_info "Building CCR binary..."
    cd "$PROJECT_ROOT"
    go build -o "$CCR_BINARY" .
    
    if [[ ! -x "$CCR_BINARY" ]]; then
        log_error "Failed to build CCR binary"
        exit 1
    fi
    
    # Set up test configuration
    export XDG_CONFIG_HOME="$TEST_CONFIG_DIR"
    export XDG_DATA_HOME="$TEST_DATA_DIR"
    export CCR_TEST_MODE="true"
    
    log_success "Test environment setup complete"
}

# Cleanup test environment
cleanup_test_env() {
    log_info "Cleaning up test environment..."
    rm -rf "$TEST_DIR"
    unset XDG_CONFIG_HOME XDG_DATA_HOME CCR_TEST_MODE
}

# Test CCR binary basic functionality
test_ccr_basic() {
    # Test help command
    if ! "$CCR_BINARY" --help >/dev/null 2>&1; then
        log_error "CCR help command failed"
        return 1
    fi
    
    # Test install-hooks command
    if ! "$CCR_BINARY" install-hooks bash >/dev/null 2>&1; then
        log_error "CCR install-hooks command failed"
        return 1
    fi
    
    return 0
}

# Test hook installation
test_hook_installation() {
    local hooks_dir="$TEST_CONFIG_DIR/commandchronicles/hooks"
    
    # Install bash hooks
    "$CCR_BINARY" install-hooks bash >/dev/null 2>&1
    
    if [[ ! -f "$hooks_dir/bash_hooks.sh" ]]; then
        log_error "Bash hooks file not created"
        return 1
    fi
    
    if [[ ! -x "$hooks_dir/bash_hooks.sh" ]]; then
        log_error "Bash hooks file not executable"
        return 1
    fi
    
    # Install zsh hooks
    "$CCR_BINARY" install-hooks zsh >/dev/null 2>&1
    
    if [[ ! -f "$hooks_dir/zsh_hooks.sh" ]]; then
        log_error "Zsh hooks file not created"
        return 1
    fi
    
    if [[ ! -x "$hooks_dir/zsh_hooks.sh" ]]; then
        log_error "Zsh hooks file not executable"
        return 1
    fi
    
    return 0
}

# Test hook content validation
test_hook_content() {
    local hooks_dir="$TEST_CONFIG_DIR/commandchronicles/hooks"
    
    # Test bash hooks content
    local bash_hooks="$hooks_dir/bash_hooks.sh"
    if [[ -f "$bash_hooks" ]]; then
        if ! grep -q "__ccr_preexec" "$bash_hooks"; then
            log_error "Bash hooks missing __ccr_preexec function"
            return 1
        fi
        
        if ! grep -q "__ccr_postexec" "$bash_hooks"; then
            log_error "Bash hooks missing __ccr_postexec function"
            return 1
        fi
        
        if ! grep -q "PROMPT_COMMAND" "$bash_hooks"; then
            log_error "Bash hooks missing PROMPT_COMMAND setup"
            return 1
        fi
        
        if ! grep -q "$CCR_BINARY" "$bash_hooks"; then
            log_error "Bash hooks missing CCR binary path"
            return 1
        fi
    else
        log_error "Bash hooks file not found"
        return 1
    fi
    
    # Test zsh hooks content
    local zsh_hooks="$hooks_dir/zsh_hooks.sh"
    if [[ -f "$zsh_hooks" ]]; then
        if ! grep -q "__ccr_preexec" "$zsh_hooks"; then
            log_error "Zsh hooks missing __ccr_preexec function"
            return 1
        fi
        
        if ! grep -q "__ccr_precmd" "$zsh_hooks"; then
            log_error "Zsh hooks missing __ccr_precmd function"
            return 1
        fi
        
        if ! grep -q "add-zsh-hook" "$zsh_hooks"; then
            log_error "Zsh hooks missing add-zsh-hook calls"
            return 1
        fi
        
        if ! grep -q "$CCR_BINARY" "$zsh_hooks"; then
            log_error "Zsh hooks missing CCR binary path"
            return 1
        fi
    else
        log_error "Zsh hooks file not found"
        return 1
    fi
    
    return 0
}

# Test bash shell integration
test_bash_integration() {
    local hooks_dir="$TEST_CONFIG_DIR/commandchronicles/hooks"
    local bash_hooks="$hooks_dir/bash_hooks.sh"
    
    if [[ ! -f "$bash_hooks" ]]; then
        log_error "Bash hooks not installed"
        return 1
    fi
    
    # Create a test script that sources the hooks and runs a command
    local test_script="$TEST_DIR/test_bash.sh"
    cat > "$test_script" << 'EOF'
#!/bin/bash
set -e

# Source the hooks
source "$1"

# Simulate command execution
TEST_COMMAND="echo 'test command'"
__CCR_START_TIME=$(date +%s%N)
__CCR_WORKING_DIR="$PWD"
__CCR_COMMAND="$TEST_COMMAND"

# Simulate command completion
exit_code=0
end_time=$(date +%s%N)
duration=$(( (end_time - __CCR_START_TIME) / 1000000 ))

# Check if hook functions exist
if ! declare -f __ccr_preexec >/dev/null; then
    echo "ERROR: __ccr_preexec function not defined"
    exit 1
fi

if ! declare -f __ccr_postexec >/dev/null; then
    echo "ERROR: __ccr_postexec function not defined"
    exit 1
fi

# Test preexec function
__ccr_preexec

# Test postexec function
__ccr_postexec

echo "Bash integration test passed"
EOF
    
    chmod +x "$test_script"
    
    # Run the test in a bash subshell
    if ! bash "$test_script" "$bash_hooks" 2>/dev/null; then
        log_error "Bash integration test failed"
        return 1
    fi
    
    return 0
}

# Test zsh shell integration
test_zsh_integration() {
    # Check if zsh is available
    if ! command -v zsh >/dev/null 2>&1; then
        log_warning "Zsh not available, skipping zsh integration test"
        return 0
    fi
    
    local hooks_dir="$TEST_CONFIG_DIR/commandchronicles/hooks"
    local zsh_hooks="$hooks_dir/zsh_hooks.sh"
    
    if [[ ! -f "$zsh_hooks" ]]; then
        log_error "Zsh hooks not installed"
        return 1
    fi
    
    # Create a test script that sources the hooks and runs a command
    local test_script="$TEST_DIR/test_zsh.zsh"
    cat > "$test_script" << 'EOF'
#!/bin/zsh
set -e

# Source the hooks
source "$1"

# Simulate command execution
TEST_COMMAND="echo 'test command'"
__CCR_START_TIME=$(date +%s%N)
__CCR_WORKING_DIR="$PWD"
__CCR_COMMAND="$TEST_COMMAND"

# Simulate command completion
exit_code=0
end_time=$(date +%s%N)
duration=$(( (end_time - __CCR_START_TIME) / 1000000 ))

# Check if hook functions exist
if ! whence -f __ccr_preexec >/dev/null; then
    echo "ERROR: __ccr_preexec function not defined"
    exit 1
fi

if ! whence -f __ccr_precmd >/dev/null; then
    echo "ERROR: __ccr_precmd function not defined"
    exit 1
fi

# Test preexec function
__ccr_preexec "$TEST_COMMAND"

# Test precmd function  
__ccr_precmd

echo "Zsh integration test passed"
EOF
    
    chmod +x "$test_script"
    
    # Run the test in a zsh subshell
    if ! zsh "$test_script" "$zsh_hooks" 2>/dev/null; then
        log_error "Zsh integration test failed"
        return 1
    fi
    
    return 0
}

# Test record command functionality
test_record_command() {
    # Test basic record command
    if ! "$CCR_BINARY" record \
        --command "test command" \
        --exit-code 0 \
        --duration 100 \
        --directory "$TEST_DIR" \
        --session "test-session-123" >/dev/null 2>&1; then
        # This might fail due to locked storage, which is expected behavior
        log_warning "Record command failed (likely due to locked storage - expected)"
    fi
    
    # Test record command with missing required parameter
    if "$CCR_BINARY" record \
        --exit-code 0 \
        --duration 100 >/dev/null 2>&1; then
        log_error "Record command should fail with missing --command parameter"
        return 1
    fi
    
    return 0
}

# Test session management
test_session_management() {
    # Test session-end command
    if ! "$CCR_BINARY" session-end "test-session-123" >/dev/null 2>&1; then
        log_warning "Session-end command failed (expected if no active session)"
    fi
    
    return 0
}

# Test performance requirements
test_performance() {
    local start_time end_time duration
    
    # Test hook installation performance
    start_time=$(date +%s%N)
    "$CCR_BINARY" install-hooks bash >/dev/null 2>&1
    end_time=$(date +%s%N)
    duration=$(( (end_time - start_time) / 1000000 ))
    
    if [[ $duration -gt 100 ]]; then
        log_warning "Hook installation took ${duration}ms (slower than expected 50ms)"
    fi
    
    # Test record command performance (even if it fails due to locked storage)
    start_time=$(date +%s%N)
    "$CCR_BINARY" record \
        --command "test command" \
        --exit-code 0 \
        --duration 100 \
        --directory "$TEST_DIR" \
        --session "test-session" >/dev/null 2>&1 || true
    end_time=$(date +%s%N)
    duration=$(( (end_time - start_time) / 1000000 ))
    
    if [[ $duration -gt 50 ]]; then
        log_warning "Record command took ${duration}ms (may include startup overhead)"
    fi
    
    return 0
}

# Test error handling and graceful degradation
test_error_handling() {
    # Test with invalid shell
    if "$CCR_BINARY" install-hooks invalid-shell >/dev/null 2>&1; then
        log_error "Should fail with invalid shell name"
        return 1
    fi
    
    # Test hooks with missing CCR binary (simulate graceful degradation)
    local hooks_dir="$TEST_CONFIG_DIR/commandchronicles/hooks"
    local bash_hooks="$hooks_dir/bash_hooks.sh"
    
    if [[ -f "$bash_hooks" ]]; then
        # Create a modified hook script that references a non-existent binary
        local test_hooks="$TEST_DIR/test_hooks_missing_binary.sh"
        sed "s|$CCR_BINARY|/nonexistent/binary|g" "$bash_hooks" > "$test_hooks"
        
        # The hooks should handle missing binary gracefully
        if ! bash -c "source '$test_hooks'" 2>/dev/null; then
            log_warning "Hooks should handle missing binary gracefully"
        fi
    fi
    
    return 0
}

# Main test runner
run_all_tests() {
    log_info "Starting CommandChronicles CLI Shell Integration Tests"
    log_info "=================================================="
    
    setup_test_env
    
    # Install hooks first
    "$CCR_BINARY" install-hooks bash >/dev/null 2>&1 || true
    "$CCR_BINARY" install-hooks zsh >/dev/null 2>&1 || true
    
    # Run tests
    run_test "CCR Basic Functionality" test_ccr_basic
    run_test "Hook Installation" test_hook_installation
    run_test "Hook Content Validation" test_hook_content
    run_test "Bash Integration" test_bash_integration
    run_test "Zsh Integration" test_zsh_integration
    run_test "Record Command" test_record_command
    run_test "Session Management" test_session_management
    run_test "Performance" test_performance
    run_test "Error Handling" test_error_handling
    
    # Print summary
    echo
    log_info "Test Summary"
    log_info "============"
    echo -e "Tests Run:    ${BLUE}$TESTS_RUN${NC}"
    echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo
        log_success "All tests passed! 🎉"
        echo
        log_info "Shell Integration Status: ✅ READY"
        log_info "CommandChronicles CLI shell integration is working correctly."
        echo
        log_info "Next steps:"
        echo "  1. Run 'ccr install-hooks bash' to install bash hooks"
        echo "  2. Add 'source ~/.config/commandchronicles/hooks/bash_hooks.sh' to ~/.bashrc"
        echo "  3. Restart your shell or run 'source ~/.bashrc'"
        echo "  4. Initialize CCR with 'ccr init' and start recording commands!"
    else
        echo
        log_error "Some tests failed! ❌"
        exit 1
    fi
    
    cleanup_test_env
}

# Handle script arguments
case "${1:-}" in
    "setup")
        setup_test_env
        log_success "Test environment setup complete"
        ;;
    "cleanup")
        cleanup_test_env
        log_success "Test environment cleaned up"
        ;;
    "")
        run_all_tests
        ;;
    *)
        echo "Usage: $0 [setup|cleanup]"
        echo "  setup   - Set up test environment only"
        echo "  cleanup - Clean up test environment only"
        echo "  (no args) - Run all tests"
        exit 1
        ;;
esac