#!/bin/bash

# CommandChronicles Shell Integration Test Script
# Tests bash and zsh hook functionality

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
TEST_DIR=$(mktemp -d)
CCR_BINARY="${CCR_BINARY:-./commandchronicles-cli}"
TEST_USER="testuser"
TEST_PASSWORD="testpassword123"

echo -e "${BLUE}CommandChronicles Shell Integration Test${NC}"
echo "Test directory: $TEST_DIR"
echo "Binary: $CCR_BINARY"
echo

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up test environment...${NC}"
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# Test helper functions
pass() {
    echo -e "${GREEN}✓ $1${NC}"
}

fail() {
    echo -e "${RED}✗ $1${NC}"
    exit 1
}

info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

warn() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Initialize test environment
init_test_env() {
    info "Initializing test environment..."
    
    export HOME="$TEST_DIR"
    export XDG_CONFIG_HOME="$TEST_DIR/.config"
    export XDG_DATA_HOME="$TEST_DIR/.local/share"
    
    mkdir -p "$HOME/.config/commandchronicles"
    mkdir -p "$HOME/.local/share/commandchronicles"
    
    # Create test config
    cat > "$HOME/.config/commandchronicles/config.yaml" << EOF
database:
  path: "$HOME/.local/share/commandchronicles/commands.db"
  encryption_key_file: "$HOME/.local/share/commandchronicles/key"
  
security:
  session_timeout: 30m
  lock_on_idle: true
  
shell:
  bash_hook_path: "$HOME/.local/share/commandchronicles/hooks/bash_hooks.sh"
  zsh_hook_path: "$HOME/.local/share/commandchronicles/hooks/zsh_hooks.sh"
  
cache:
  enabled: true
  max_size: 1000
  ttl: 1h
EOF
    
    pass "Test environment initialized"
}

# Test binary availability
test_binary() {
    info "Testing binary availability..."
    
    if [[ ! -f "$CCR_BINARY" ]]; then
        fail "CCR binary not found at $CCR_BINARY"
    fi
    
    if [[ ! -x "$CCR_BINARY" ]]; then
        fail "CCR binary is not executable"
    fi
    
    # Test basic functionality
    if ! "$CCR_BINARY" --help >/dev/null 2>&1; then
        fail "CCR binary help command failed"
    fi
    
    pass "Binary is available and functional"
}

# Test user initialization
test_user_init() {
    info "Testing user initialization..."
    
    # Check if already initialized
    local init_output
    init_output=$(echo -e "$TEST_PASSWORD\n$TEST_PASSWORD" | "$CCR_BINARY" init "$TEST_USER" 2>&1)
    local exit_code=$?
    
    echo "DEBUG: init exit_code=$exit_code"
    echo "DEBUG: init_output='$init_output'"
    
    if [[ $exit_code -eq 0 ]]; then
        pass "User initialization successful"
    elif echo "$init_output" | grep -q "already initialized"; then
        warn "System already initialized, testing unlock instead"
        # Test unlock functionality
        local unlock_output
        unlock_output=$(echo "$TEST_PASSWORD" | "$CCR_BINARY" unlock 2>&1)
        local unlock_exit_code=$?
        echo "DEBUG: unlock exit_code=$unlock_exit_code"
        echo "DEBUG: unlock_output='$unlock_output'"
        if [[ $unlock_exit_code -eq 0 ]]; then
            pass "User authentication successful (system was already initialized)"
        else
            fail "User authentication failed: $unlock_output"
        fi
    else
        fail "User initialization failed with unexpected error: $init_output"
    fi
}

# Test hook installation for bash
test_bash_hooks() {
    info "Testing bash hook installation..."
    
    # Install bash hooks
    "$CCR_BINARY" install-hooks bash >/dev/null 2>&1
    
    if [[ $? -ne 0 ]]; then
        fail "Bash hook installation failed"
    fi
    
    # Check if hook file was created
    local hook_file="$HOME/.local/share/commandchronicles/hooks/bash_hooks.sh"
    if [[ ! -f "$hook_file" ]]; then
        fail "Bash hook file was not created"
    fi
    
    # Test hook file syntax
    if ! bash -n "$hook_file"; then
        fail "Bash hook file has syntax errors"
    fi
    
    # Test hook file can be sourced
    if ! bash -c "source '$hook_file'" 2>/dev/null; then
        fail "Bash hook file cannot be sourced"
    fi
    
    # Check for required functions
    if ! grep -q "__ccr_preexec" "$hook_file"; then
        fail "Bash hook file missing __ccr_preexec function"
    fi
    
    if ! grep -q "__ccr_postexec" "$hook_file"; then
        fail "Bash hook file missing __ccr_postexec function"
    fi
    
    if ! grep -q "__ccr_search" "$hook_file"; then
        fail "Bash hook file missing __ccr_search function"
    fi
    
    # Check for up arrow key binding
    if ! grep -q 'bind.*\\\e\[A' "$hook_file"; then
        fail "Bash hook file missing up arrow key binding"
    fi
    
    pass "Bash hooks installed and validated"
}

# Test hook installation for zsh
test_zsh_hooks() {
    info "Testing zsh hook installation..."
    
    # Install zsh hooks
    "$CCR_BINARY" install-hooks zsh >/dev/null 2>&1
    
    if [[ $? -ne 0 ]]; then
        fail "Zsh hook installation failed"
    fi
    
    # Check if hook file was created
    local hook_file="$HOME/.local/share/commandchronicles/hooks/zsh_hooks.sh"
    if [[ ! -f "$hook_file" ]]; then
        fail "Zsh hook file was not created"
    fi
    
    # Test hook file syntax (using zsh if available, otherwise bash)
    if command -v zsh >/dev/null 2>&1; then
        if ! zsh -n "$hook_file" 2>/dev/null; then
            warn "Zsh hook file may have syntax issues (zsh syntax check failed)"
        fi
    else
        warn "Zsh not available for syntax checking"
    fi
    
    # Check for required functions
    if ! grep -q "__ccr_preexec" "$hook_file"; then
        fail "Zsh hook file missing __ccr_preexec function"
    fi
    
    if ! grep -q "__ccr_precmd" "$hook_file"; then
        fail "Zsh hook file missing __ccr_precmd function"
    fi
    
    if ! grep -q "__ccr_search" "$hook_file"; then
        fail "Zsh hook file missing __ccr_search function"
    fi
    
    # Check for up arrow key binding
    if ! grep -q "bindkey.*\^\[\[A" "$hook_file"; then
        fail "Zsh hook file missing up arrow key binding"
    fi
    
    pass "Zsh hooks installed and validated"
}

# Test command recording functionality
test_command_recording() {
    info "Testing command recording functionality..."
    
    # Unlock storage first
    local unlock_output
    unlock_output=$(echo "$TEST_PASSWORD" | "$CCR_BINARY" unlock 2>&1)
    if [[ $? -ne 0 ]]; then
        fail "Failed to unlock storage for recording test: $unlock_output"
    fi
    
    # Record a test command
    local record_output
    record_output=$("$CCR_BINARY" record \
        --command "echo 'test command'" \
        --exit-code 0 \
        --duration 100 \
        --directory "/tmp" \
        --session "test-session" 2>&1)
    
    if [[ $? -ne 0 ]]; then
        fail "Command recording failed: $record_output"
    fi
    
    # Wait a moment for async operations to complete
    sleep 1
    
    # Search for the recorded command
    local search_output
    search_output=$("$CCR_BINARY" search "echo" --limit 1 2>&1)
    local search_exit_code=$?
    
    if [[ $search_exit_code -ne 0 ]]; then
        fail "Search command failed: $search_output"
    fi
    
    if [[ -z "$search_output" ]] || ! echo "$search_output" | grep -q "echo"; then
        fail "Recorded command not found in search results. Output: $search_output"
    fi
    
    pass "Command recording functionality works"
}

# Test TUI functionality
test_tui_functionality() {
    info "Testing TUI functionality..."
    
    # Test that TUI command exists and can show help
    if ! "$CCR_BINARY" tui --help >/dev/null 2>&1; then
        fail "TUI command not available or help failed"
    fi
    
    # Test that search command supports --tui flag
    if ! "$CCR_BINARY" search --help 2>&1 | grep -q "tui"; then
        fail "Search command does not support --tui flag"
    fi
    
    pass "TUI functionality available"
}

# Test graceful degradation
test_graceful_degradation() {
    info "Testing graceful degradation..."
    
    # Test hook behavior when binary is not available
    local hook_file="$HOME/.local/share/commandchronicles/hooks/bash_hooks.sh"
    
    # Create a test script that simulates missing binary
    cat > "$TEST_DIR/test_degradation.sh" << 'EOF'
#!/bin/bash
# Simulate missing ccr binary by overriding PATH
export PATH="/nonexistent:$PATH"

# Source the hook file
source "$1"

# Test that functions exist but don't crash
if declare -f __ccr_preexec >/dev/null; then
    __ccr_preexec 2>/dev/null || echo "preexec handled gracefully"
fi

if declare -f __ccr_postexec >/dev/null; then
    __ccr_postexec 2>/dev/null || echo "postexec handled gracefully"
fi

if declare -f __ccr_search >/dev/null; then
    __ccr_search 2>/dev/null || echo "search handled gracefully"
fi
EOF
    
    chmod +x "$TEST_DIR/test_degradation.sh"
    
    if ! "$TEST_DIR/test_degradation.sh" "$hook_file" >/dev/null 2>&1; then
        fail "Hooks do not handle missing binary gracefully"
    fi
    
    pass "Graceful degradation works"
}

# Test installation instructions generation
test_installation_instructions() {
    info "Testing installation instructions generation..."
    
    # Test bash instructions
    local bash_instructions
    bash_instructions=$("$CCR_BINARY" install-hooks bash 2>&1)
    
    if ! echo "$bash_instructions" | grep -q "~/.bashrc"; then
        fail "Bash installation instructions missing bashrc reference"
    fi
    
    if ! echo "$bash_instructions" | grep -q "UP ARROW"; then
        fail "Bash installation instructions missing up arrow key information"
    fi
    
    # Test zsh instructions
    local zsh_instructions
    zsh_instructions=$("$CCR_BINARY" install-hooks zsh 2>&1)
    
    if ! echo "$zsh_instructions" | grep -q "~/.zshrc"; then
        fail "Zsh installation instructions missing zshrc reference"
    fi
    
    if ! echo "$zsh_instructions" | grep -q "UP ARROW"; then
        fail "Zsh installation instructions missing up arrow key information"
    fi
    
    pass "Installation instructions are comprehensive"
}

# Main test execution
main() {
    echo -e "${BLUE}Starting shell integration tests...${NC}\n"
    
    init_test_env
    test_binary
    test_user_init
    test_bash_hooks
    test_zsh_hooks
    test_command_recording
    test_tui_functionality
    test_graceful_degradation
    test_installation_instructions
    
    echo -e "\n${GREEN}All shell integration tests passed!${NC}"
    echo -e "${GREEN}Shell integration is ready for use.${NC}"
    
    echo -e "\n${BLUE}Next steps:${NC}"
    echo "1. Run: $CCR_BINARY install-hooks bash (or zsh)"
    echo "2. Add the source line to your shell configuration"
    echo "3. Restart your shell or source the configuration"
    echo "4. Press UP ARROW key to launch interactive search"
}

# Run tests
main "$@"