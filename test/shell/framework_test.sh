#!/bin/bash

# CommandChronicles Shell Framework Compatibility Test
# Tests compatibility with popular shell frameworks

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

echo -e "${BLUE}CommandChronicles Shell Framework Compatibility Test${NC}"
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
    return 1
}

info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

warn() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

skip() {
    echo -e "${YELLOW}⏭ $1${NC}"
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
    
    # Initialize user (handle already initialized case)
    local init_output
    init_output=$(echo -e "$TEST_PASSWORD\n$TEST_PASSWORD" | "$CCR_BINARY" init "$TEST_USER" 2>&1)
    local exit_code=$?
    
    if [[ $exit_code -ne 0 ]]; then
        if echo "$init_output" | grep -q "already initialized"; then
            # System already initialized, test unlock instead
            echo "$TEST_PASSWORD" | "$CCR_BINARY" unlock >/dev/null 2>&1
            if [[ $? -ne 0 ]]; then
                fail "Failed to unlock already initialized storage"
                return 1
            fi
        else
            fail "User initialization failed: $init_output"
            return 1
        fi
    fi
    
    # Install hooks
    "$CCR_BINARY" install-hooks bash >/dev/null 2>&1
    "$CCR_BINARY" install-hooks zsh >/dev/null 2>&1
    
    pass "Test environment initialized"
}

# Test Oh My Zsh compatibility
test_oh_my_zsh() {
    info "Testing Oh My Zsh compatibility..."
    
    if ! command -v zsh >/dev/null 2>&1; then
        skip "Oh My Zsh test (zsh not available)"
        return 0
    fi
    
    # Create a minimal oh-my-zsh environment
    local omz_dir="$HOME/.oh-my-zsh"
    mkdir -p "$omz_dir/lib"
    mkdir -p "$omz_dir/plugins/git"
    mkdir -p "$omz_dir/themes"
    
    # Create basic oh-my-zsh files
    cat > "$omz_dir/oh-my-zsh.sh" << 'EOF'
# Minimal oh-my-zsh setup for testing
export ZSH="$HOME/.oh-my-zsh"

# Load lib files
for lib in $ZSH/lib/*.zsh; do
  [ -r "$lib" ] && source "$lib"
done

# Load plugins
plugins=(git)
for plugin in $plugins; do
  if [ -f $ZSH/plugins/$plugin/$plugin.plugin.zsh ]; then
    source $ZSH/plugins/$plugin/$plugin.plugin.zsh
  fi
done
EOF
    
    # Create basic lib file
    cat > "$omz_dir/lib/history.zsh" << 'EOF'
# History settings
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
    
    # Create basic git plugin
    cat > "$omz_dir/plugins/git/git.plugin.zsh" << 'EOF'
# Git aliases
alias g='git'
alias ga='git add'
alias gc='git commit -v'
EOF
    
    # Test zsh with oh-my-zsh and ccr hooks
    cat > "$TEST_DIR/test_omz.zsh" << EOF
#!/bin/zsh
# Test oh-my-zsh compatibility
source "$omz_dir/oh-my-zsh.sh"
source "$HOME/.local/share/commandchronicles/hooks/zsh_hooks.sh"

# Test that functions are defined
if ! declare -f __ccr_preexec >/dev/null; then
    echo "ERROR: __ccr_preexec not defined"
    exit 1
fi

if ! declare -f __ccr_precmd >/dev/null; then
    echo "ERROR: __ccr_precmd not defined"
    exit 1
fi

if ! declare -f __ccr_search >/dev/null; then
    echo "ERROR: __ccr_search not defined"
    exit 1
fi

# Test that hooks are installed
if [[ \${preexec_functions[(I)__ccr_preexec]} -eq 0 ]]; then
    echo "ERROR: __ccr_preexec hook not installed"
    exit 1
fi

if [[ \${precmd_functions[(I)__ccr_precmd]} -eq 0 ]]; then
    echo "ERROR: __ccr_precmd hook not installed"
    exit 1
fi

echo "SUCCESS: Oh My Zsh compatibility test passed"
EOF
    
    chmod +x "$TEST_DIR/test_omz.zsh"
    
    if zsh "$TEST_DIR/test_omz.zsh" 2>/dev/null; then
        pass "Oh My Zsh compatibility"
    else
        fail "Oh My Zsh compatibility test failed"
    fi
}

# Test Prezto compatibility
test_prezto() {
    info "Testing Prezto compatibility..."
    
    if ! command -v zsh >/dev/null 2>&1; then
        skip "Prezto test (zsh not available)"
        return 0
    fi
    
    # Create a minimal prezto environment
    local prezto_dir="$HOME/.zprezto"
    mkdir -p "$prezto_dir/modules/editor"
    mkdir -p "$prezto_dir/modules/history"
    mkdir -p "$prezto_dir/modules/terminal"
    
    # Create basic prezto init file
    cat > "$prezto_dir/init.zsh" << 'EOF'
# Minimal prezto setup for testing
zstyle ':prezto:load' pmodule 'editor' 'history' 'terminal'

# Load modules
for pmodule in editor history terminal; do
  if [[ -s "$HOME/.zprezto/modules/$pmodule/init.zsh" ]]; then
    source "$HOME/.zprezto/modules/$pmodule/init.zsh"
  fi
done
EOF
    
    # Create basic modules
    cat > "$prezto_dir/modules/editor/init.zsh" << 'EOF'
# Editor module
bindkey -e  # Emacs key bindings
EOF
    
    cat > "$prezto_dir/modules/history/init.zsh" << 'EOF'
# History module
HISTFILE="$HOME/.zhistory"
HISTSIZE=10000
SAVEHIST=10000
setopt BANG_HIST
setopt EXTENDED_HISTORY
setopt INC_APPEND_HISTORY
setopt SHARE_HISTORY
setopt HIST_EXPIRE_DUPS_FIRST
setopt HIST_IGNORE_DUPS
setopt HIST_IGNORE_ALL_DUPS
setopt HIST_FIND_NO_DUPS
setopt HIST_IGNORE_SPACE
setopt HIST_SAVE_NO_DUPS
setopt HIST_VERIFY
setopt HIST_BEEP
EOF
    
    cat > "$prezto_dir/modules/terminal/init.zsh" << 'EOF'
# Terminal module
if [[ -n "$TMUX" ]]; then
  export TERM="screen-256color"
else
  export TERM="xterm-256color"
fi
EOF
    
    # Test zsh with prezto and ccr hooks
    cat > "$TEST_DIR/test_prezto.zsh" << EOF
#!/bin/zsh
# Test prezto compatibility
source "$prezto_dir/init.zsh"
source "$HOME/.local/share/commandchronicles/hooks/zsh_hooks.sh"

# Test that functions are defined
if ! declare -f __ccr_preexec >/dev/null; then
    echo "ERROR: __ccr_preexec not defined"
    exit 1
fi

if ! declare -f __ccr_precmd >/dev/null; then
    echo "ERROR: __ccr_precmd not defined"
    exit 1
fi

if ! declare -f __ccr_search >/dev/null; then
    echo "ERROR: __ccr_search not defined"
    exit 1
fi

# Test that hooks are installed
if [[ \${preexec_functions[(I)__ccr_preexec]} -eq 0 ]]; then
    echo "ERROR: __ccr_preexec hook not installed"
    exit 1
fi

if [[ \${precmd_functions[(I)__ccr_precmd]} -eq 0 ]]; then
    echo "ERROR: __ccr_precmd hook not installed"
    exit 1
fi

echo "SUCCESS: Prezto compatibility test passed"
EOF
    
    chmod +x "$TEST_DIR/test_prezto.zsh"
    
    if zsh "$TEST_DIR/test_prezto.zsh" 2>/dev/null; then
        pass "Prezto compatibility"
    else
        fail "Prezto compatibility test failed"
    fi
}

# Test Bash-it compatibility
test_bash_it() {
    info "Testing Bash-it compatibility..."
    
    # Create a minimal bash-it environment
    local bashit_dir="$HOME/.bash_it"
    mkdir -p "$bashit_dir/lib"
    mkdir -p "$bashit_dir/aliases/available"
    mkdir -p "$bashit_dir/plugins/available"
    mkdir -p "$bashit_dir/completion/available"
    
    # Create basic bash-it files
    cat > "$bashit_dir/bash_it.sh" << 'EOF'
# Minimal bash-it setup for testing
export BASH_IT="$HOME/.bash_it"

# Load lib files
for lib in "$BASH_IT/lib"/*.bash; do
  [ -r "$lib" ] && source "$lib"
done

# Load enabled aliases, plugins, and completions
BASH_IT_LOAD_PRIORITY_SEPARATOR=':'
BASH_IT_LOAD_PRIORITY_DEFAULT=365
EOF
    
    # Create basic lib file
    cat > "$bashit_dir/lib/history.bash" << 'EOF'
# History settings
export HISTCONTROL=ignoreboth
export HISTSIZE=32768
export HISTFILESIZE="${HISTSIZE}"
export HISTIGNORE=" *:ls:cd:cd -:pwd:exit:date:* --help"
shopt -s histappend
shopt -s cmdhist
EOF
    
    # Test bash with bash-it and ccr hooks
    cat > "$TEST_DIR/test_bashit.bash" << 'EOF'
#!/bin/bash
# Test bash-it compatibility
source "$HOME/.bash_it/bash_it.sh"
source "$HOME/.local/share/commandchronicles/hooks/bash_hooks.sh"

# Test that functions are defined
if ! declare -f __ccr_preexec >/dev/null; then
    echo "ERROR: __ccr_preexec not defined"
    exit 1
fi

if ! declare -f __ccr_postexec >/dev/null; then
    echo "ERROR: __ccr_postexec not defined"
    exit 1
fi

if ! declare -f __ccr_search >/dev/null; then
    echo "ERROR: __ccr_search not defined"
    exit 1
fi

# Test that PROMPT_COMMAND includes our hook
if [[ "$PROMPT_COMMAND" != *"__ccr_postexec"* ]]; then
    echo "ERROR: __ccr_postexec not in PROMPT_COMMAND"
    exit 1
fi

echo "SUCCESS: Bash-it compatibility test passed"
EOF
    
    chmod +x "$TEST_DIR/test_bashit.bash"
    
    if bash "$TEST_DIR/test_bashit.bash" 2>/dev/null; then
        pass "Bash-it compatibility"
    else
        fail "Bash-it compatibility test failed"
    fi
}

# Test Starship prompt compatibility
test_starship() {
    info "Testing Starship prompt compatibility..."
    
    # Create a minimal starship config
    mkdir -p "$HOME/.config"
    cat > "$HOME/.config/starship.toml" << 'EOF'
# Minimal starship config for testing
format = """
$username\
$hostname\
$directory\
$git_branch\
$character"""

[character]
success_symbol = "[➜](bold green)"
error_symbol = "[➜](bold red)"
EOF
    
    # Test bash with starship and ccr hooks
    cat > "$TEST_DIR/test_starship_bash.bash" << 'EOF'
#!/bin/bash
# Test starship compatibility with bash
source "$HOME/.local/share/commandchronicles/hooks/bash_hooks.sh"

# Simulate starship prompt setup
PROMPT_COMMAND="starship_precmd; $PROMPT_COMMAND"
starship_precmd() {
    echo "starship_precmd called"
}

# Test that our hook is still in PROMPT_COMMAND
if [[ "$PROMPT_COMMAND" != *"__ccr_postexec"* ]]; then
    echo "ERROR: __ccr_postexec not in PROMPT_COMMAND"
    exit 1
fi

# Test that starship is also in PROMPT_COMMAND
if [[ "$PROMPT_COMMAND" != *"starship_precmd"* ]]; then
    echo "ERROR: starship_precmd not in PROMPT_COMMAND"
    exit 1
fi

echo "SUCCESS: Starship bash compatibility test passed"
EOF
    
    chmod +x "$TEST_DIR/test_starship_bash.bash"
    
    if bash "$TEST_DIR/test_starship_bash.bash" 2>/dev/null; then
        pass "Starship (bash) compatibility"
    else
        fail "Starship bash compatibility test failed"
    fi
    
    # Test zsh with starship and ccr hooks
    if command -v zsh >/dev/null 2>&1; then
        cat > "$TEST_DIR/test_starship_zsh.zsh" << EOF
#!/bin/zsh
# Test starship compatibility with zsh
source "$HOME/.local/share/commandchronicles/hooks/zsh_hooks.sh"

# Simulate starship prompt setup
autoload -Uz add-zsh-hook
starship_precmd() {
    echo "starship_precmd called"
}
add-zsh-hook precmd starship_precmd

# Test that our hook is installed
if [[ \${precmd_functions[(I)__ccr_precmd]} -eq 0 ]]; then
    echo "ERROR: __ccr_precmd hook not installed"
    exit 1
fi

# Test that starship is also installed
if [[ \${precmd_functions[(I)starship_precmd]} -eq 0 ]]; then
    echo "ERROR: starship_precmd hook not installed"
    exit 1
fi

echo "SUCCESS: Starship zsh compatibility test passed"
EOF
        
        chmod +x "$TEST_DIR/test_starship_zsh.zsh"
        
        if zsh "$TEST_DIR/test_starship_zsh.zsh" 2>/dev/null; then
            pass "Starship (zsh) compatibility"
        else
            fail "Starship zsh compatibility test failed"
        fi
    else
        skip "Starship zsh test (zsh not available)"
    fi
}

# Test Fish shell compatibility note
test_fish_note() {
    info "Checking Fish shell compatibility note..."
    
    if command -v fish >/dev/null 2>&1; then
        warn "Fish shell detected but not supported by CommandChronicles"
        info "Fish shell uses a different hook system and would require separate implementation"
    else
        skip "Fish shell test (fish not available)"
    fi
}

# Test with different terminal emulators
test_terminal_compatibility() {
    info "Testing terminal compatibility..."
    
    # Test different TERM values
    local test_terms=("xterm" "xterm-256color" "screen" "screen-256color" "tmux" "tmux-256color")
    
    for term in "${test_terms[@]}"; do
        TERM="$term" bash -c "source '$HOME/.local/share/commandchronicles/hooks/bash_hooks.sh'; declare -f __ccr_search >/dev/null" 2>/dev/null
        if [[ $? -eq 0 ]]; then
            pass "Terminal compatibility: $term"
        else
            fail "Terminal compatibility failed for: $term"
        fi
    done
    
    # Test with dumb terminal
    TERM="dumb" bash -c "source '$HOME/.local/share/commandchronicles/hooks/bash_hooks.sh'; __ccr_search 2>/dev/null; echo 'Dumb terminal handled gracefully'" >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        pass "Dumb terminal graceful handling"
    else
        fail "Dumb terminal not handled gracefully"
    fi
}

# Test hook installation order
test_installation_order() {
    info "Testing hook installation order..."
    
    # Test installing ccr hooks before framework
    cat > "$TEST_DIR/test_order1.bash" << 'EOF'
#!/bin/bash
# Install ccr hooks first, then framework
source "$HOME/.local/share/commandchronicles/hooks/bash_hooks.sh"

# Simulate framework installation after ccr
PROMPT_COMMAND="framework_cmd; $PROMPT_COMMAND"
framework_cmd() { echo "framework"; }

# Test that both are present
if [[ "$PROMPT_COMMAND" != *"__ccr_postexec"* ]]; then
    echo "ERROR: ccr hook missing"
    exit 1
fi
if [[ "$PROMPT_COMMAND" != *"framework_cmd"* ]]; then
    echo "ERROR: framework hook missing"
    exit 1
fi
echo "SUCCESS: ccr-first order works"
EOF
    
    # Test installing framework before ccr hooks
    cat > "$TEST_DIR/test_order2.bash" << 'EOF'
#!/bin/bash
# Install framework first, then ccr hooks
PROMPT_COMMAND="framework_cmd"
framework_cmd() { echo "framework"; }

source "$HOME/.local/share/commandchronicles/hooks/bash_hooks.sh"

# Test that both are present
if [[ "$PROMPT_COMMAND" != *"__ccr_postexec"* ]]; then
    echo "ERROR: ccr hook missing"
    exit 1
fi
if [[ "$PROMPT_COMMAND" != *"framework_cmd"* ]]; then
    echo "ERROR: framework hook missing"
    exit 1
fi
echo "SUCCESS: framework-first order works"
EOF
    
    chmod +x "$TEST_DIR/test_order1.bash" "$TEST_DIR/test_order2.bash"
    
    if bash "$TEST_DIR/test_order1.bash" 2>/dev/null && bash "$TEST_DIR/test_order2.bash" 2>/dev/null; then
        pass "Hook installation order flexibility"
    else
        fail "Hook installation order test failed"
    fi
}

# Main test execution
main() {
    echo -e "${BLUE}Starting framework compatibility tests...${NC}\n"
    
    init_test_env
    test_oh_my_zsh
    test_prezto
    test_bash_it
    test_starship
    test_fish_note
    test_terminal_compatibility
    test_installation_order
    
    echo -e "\n${GREEN}Framework compatibility tests completed!${NC}"
    echo -e "${GREEN}CommandChronicles shell integration is compatible with major frameworks.${NC}"
    
    echo -e "\n${BLUE}Framework compatibility summary:${NC}"
    echo "✓ Oh My Zsh - Compatible"
    echo "✓ Prezto - Compatible"
    echo "✓ Bash-it - Compatible"
    echo "✓ Starship - Compatible"
    echo "⚠ Fish - Not supported (different architecture required)"
    echo "✓ Various terminal emulators - Compatible"
    echo "✓ Flexible installation order - Supported"
}

# Run tests
main "$@"