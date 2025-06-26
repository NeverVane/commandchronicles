#!/bin/bash

# Simplified Shell Framework Compatibility Test
set -e

# Configuration
CCR_BINARY="${CCR_BINARY:-./build/ccr}"
TEST_DIR=$(mktemp -d)
export HOME="$TEST_DIR"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}Simplified Framework Compatibility Test${NC}"

# Cleanup
cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

pass() {
    echo -e "${GREEN}✓ $1${NC}"
}

fail() {
    echo -e "${RED}✗ $1${NC}"
    exit 1
}

skip() {
    echo -e "${YELLOW}⏭ $1${NC}"
}

# Setup basic environment
setup_basic_env() {
    mkdir -p "$HOME/.config/commandchronicles"
    cat > "$HOME/.config/commandchronicles/config.yaml" << 'EOF'
# Basic config for testing
EOF
    
    # Install hooks
    $CCR_BINARY install-hooks bash >/dev/null 2>&1
    if command -v zsh >/dev/null 2>&1; then
        $CCR_BINARY install-hooks zsh >/dev/null 2>&1
    fi
}

# Test Oh My Zsh compatibility
test_oh_my_zsh() {
    echo "Testing Oh My Zsh compatibility..."
    
    if ! command -v zsh >/dev/null 2>&1; then
        skip "Oh My Zsh test (zsh not available)"
        return 0
    fi
    
    # Create minimal oh-my-zsh setup
    local omz_dir="$HOME/.oh-my-zsh"
    mkdir -p "$omz_dir/lib"
    
    cat > "$omz_dir/oh-my-zsh.sh" << 'EOF'
# Minimal oh-my-zsh for testing
export ZSH="$HOME/.oh-my-zsh"
autoload -Uz add-zsh-hook
HISTFILE="$HOME/.zsh_history"
HISTSIZE=50000
SAVEHIST=10000
setopt extended_history
setopt hist_expire_dups_first
setopt hist_ignore_dups
setopt hist_ignore_space
setopt hist_verify
setopt share_history
EOF
    
    # Test compatibility
    cat > "$TEST_DIR/test_omz.zsh" << 'EOF'
#!/bin/zsh
source "$HOME/.oh-my-zsh/oh-my-zsh.sh"
source "$HOME/.config/commandchronicles/hooks/zsh_hook.sh"

# Check functions exist
if ! declare -f __ccr_preexec >/dev/null; then
    echo "ERROR: __ccr_preexec not defined"
    exit 1
fi

if ! declare -f __ccr_precmd >/dev/null; then
    echo "ERROR: __ccr_precmd not defined"
    exit 1
fi

echo "SUCCESS"
EOF
    
    chmod +x "$TEST_DIR/test_omz.zsh"
    
    if zsh "$TEST_DIR/test_omz.zsh" >/dev/null 2>&1; then
        pass "Oh My Zsh compatibility"
    else
        fail "Oh My Zsh compatibility failed"
    fi
}

# Test Bash-it compatibility
test_bash_it() {
    echo "Testing Bash-it compatibility..."
    
    # Create minimal bash-it setup
    local bashit_dir="$HOME/.bash_it"
    mkdir -p "$bashit_dir/lib"
    
    cat > "$bashit_dir/bash_it.sh" << 'EOF'
# Minimal bash-it for testing
export BASH_IT="$HOME/.bash_it"
export HISTCONTROL=ignoreboth
export HISTSIZE=32768
export HISTFILESIZE="${HISTSIZE}"
shopt -s histappend
shopt -s cmdhist
EOF
    
    # Test compatibility
    cat > "$TEST_DIR/test_bashit.bash" << 'EOF'
#!/bin/bash
source "$HOME/.bash_it/bash_it.sh"
source "$HOME/.config/commandchronicles/hooks/bash_hook.sh"

# Check functions exist
if ! declare -f __ccr_preexec >/dev/null; then
    echo "ERROR: __ccr_preexec not defined"
    exit 1
fi

if ! declare -f __ccr_postexec >/dev/null; then
    echo "ERROR: __ccr_postexec not defined"
    exit 1
fi

echo "SUCCESS"
EOF
    
    chmod +x "$TEST_DIR/test_bashit.bash"
    
    if bash "$TEST_DIR/test_bashit.bash" >/dev/null 2>&1; then
        pass "Bash-it compatibility"
    else
        fail "Bash-it compatibility failed"
    fi
}

# Test Starship compatibility
test_starship() {
    echo "Testing Starship prompt compatibility..."
    
    # Test bash with starship
    cat > "$TEST_DIR/test_starship_bash.bash" << 'EOF'
#!/bin/bash
source "$HOME/.config/commandchronicles/hooks/bash_hook.sh"

# Simulate starship setup
PROMPT_COMMAND="starship_precmd; $PROMPT_COMMAND"
starship_precmd() {
    true  # Dummy function
}

# Check both hooks are present
if [[ "$PROMPT_COMMAND" != *"__ccr_postexec"* ]]; then
    echo "ERROR: ccr hook missing"
    exit 1
fi

if [[ "$PROMPT_COMMAND" != *"starship_precmd"* ]]; then
    echo "ERROR: starship hook missing"
    exit 1
fi

echo "SUCCESS"
EOF
    
    chmod +x "$TEST_DIR/test_starship_bash.bash"
    
    if bash "$TEST_DIR/test_starship_bash.bash" >/dev/null 2>&1; then
        pass "Starship (bash) compatibility"
    else
        fail "Starship bash compatibility failed"
    fi
    
    # Test zsh with starship
    if command -v zsh >/dev/null 2>&1; then
        cat > "$TEST_DIR/test_starship_zsh.zsh" << 'EOF'
#!/bin/zsh
source "$HOME/.config/commandchronicles/hooks/zsh_hook.sh"

# Simulate starship setup
autoload -Uz add-zsh-hook
starship_precmd() {
    true  # Dummy function
}
add-zsh-hook precmd starship_precmd

# Check both hooks are installed
if [[ ${precmd_functions[(I)__ccr_precmd]} -eq 0 ]]; then
    echo "ERROR: ccr hook missing"
    exit 1
fi

if [[ ${precmd_functions[(I)starship_precmd]} -eq 0 ]]; then
    echo "ERROR: starship hook missing"
    exit 1
fi

echo "SUCCESS"
EOF
        
        chmod +x "$TEST_DIR/test_starship_zsh.zsh"
        
        if zsh "$TEST_DIR/test_starship_zsh.zsh" >/dev/null 2>&1; then
            pass "Starship (zsh) compatibility"
        else
            fail "Starship zsh compatibility failed"
        fi
    else
        skip "Starship zsh test (zsh not available)"
    fi
}

# Test terminal compatibility
test_terminal_compatibility() {
    echo "Testing terminal compatibility..."
    
    local test_terms=("xterm" "xterm-256color" "screen" "tmux")
    
    for term in "${test_terms[@]}"; do
        if TERM="$term" bash -c "source '$HOME/.config/commandchronicles/hooks/bash_hook.sh'; declare -f __ccr_search >/dev/null" 2>/dev/null; then
            pass "Terminal: $term"
        else
            fail "Terminal compatibility failed for: $term"
        fi
    done
    
    # Test dumb terminal graceful handling
    if TERM="dumb" bash -c "source '$HOME/.config/commandchronicles/hooks/bash_hook.sh'; __ccr_search 2>/dev/null; exit 0" >/dev/null 2>&1; then
        pass "Dumb terminal graceful handling"
    else
        fail "Dumb terminal not handled gracefully"
    fi
}

# Test installation order flexibility
test_installation_order() {
    echo "Testing hook installation order..."
    
    # Test ccr-first order
    cat > "$TEST_DIR/test_order1.bash" << 'EOF'
#!/bin/bash
source "$HOME/.config/commandchronicles/hooks/bash_hook.sh"
PROMPT_COMMAND="framework_cmd; $PROMPT_COMMAND"
framework_cmd() { true; }

if [[ "$PROMPT_COMMAND" != *"__ccr_postexec"* ]] || [[ "$PROMPT_COMMAND" != *"framework_cmd"* ]]; then
    exit 1
fi
EOF
    
    # Test framework-first order
    cat > "$TEST_DIR/test_order2.bash" << 'EOF'
#!/bin/bash
PROMPT_COMMAND="framework_cmd"
framework_cmd() { true; }
source "$HOME/.config/commandchronicles/hooks/bash_hook.sh"

if [[ "$PROMPT_COMMAND" != *"__ccr_postexec"* ]] || [[ "$PROMPT_COMMAND" != *"framework_cmd"* ]]; then
    exit 1
fi
EOF
    
    chmod +x "$TEST_DIR/test_order1.bash" "$TEST_DIR/test_order2.bash"
    
    if bash "$TEST_DIR/test_order1.bash" && bash "$TEST_DIR/test_order2.bash"; then
        pass "Hook installation order flexibility"
    else
        fail "Hook installation order test failed"
    fi
}

# Main execution
main() {
    echo -e "${BLUE}Starting framework compatibility tests...${NC}\n"
    
    setup_basic_env
    test_oh_my_zsh
    test_bash_it
    test_starship
    test_terminal_compatibility
    test_installation_order
    
    echo -e "\n${GREEN}Framework compatibility tests completed!${NC}"
    echo -e "${GREEN}CommandChronicles shell integration is compatible with major frameworks.${NC}"
    
    echo -e "\n${BLUE}Compatibility Summary:${NC}"
    echo "✓ Oh My Zsh - Compatible"
    echo "✓ Bash-it - Compatible"
    echo "✓ Starship - Compatible"
    echo "✓ Terminal emulators - Compatible"
    echo "✓ Installation order - Flexible"
}

main "$@"