package shell

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
	"time"

	"github.com/NeverVane/commandchronicles-cli/internal/config"
	"github.com/NeverVane/commandchronicles-cli/internal/logger"
)

// HookManager manages shell integration hooks
type HookManager struct {
	config        *config.Config
	logger        *logger.Logger
	sessionMgr    *SessionManager
	contextMgr    *ContextCapture
	hooksDir      string
	binaryPath    string
}

// NewHookManager creates a new hook manager
func NewHookManager(cfg *config.Config) (*HookManager, error) {
	hooksDir := filepath.Dir(cfg.Shell.BashHookPath)
	if err := os.MkdirAll(hooksDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create hooks directory: %w", err)
	}

	// Get the path to the ccr binary
	binaryPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	sessionMgr, err := NewSessionManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create session manager: %w", err)
	}

	return &HookManager{
		config:     cfg,
		logger:     logger.GetLogger().WithComponent("hooks"),
		sessionMgr: sessionMgr,
		contextMgr: NewContextCapture(),
		hooksDir:   hooksDir,
		binaryPath: binaryPath,
	}, nil
}

// InstallHooks generates and installs shell hooks for the specified shell
func (hm *HookManager) InstallHooks(shell string) error {
	switch shell {
	case "bash":
		return hm.installBashHooks()
	case "zsh":
		return hm.installZshHooks()
	default:
		return fmt.Errorf("unsupported shell: %s", shell)
	}
}

// installBashHooks creates and installs bash hooks
func (hm *HookManager) installBashHooks() error {
	hookContent, err := hm.generateBashHooks()
	if err != nil {
		return fmt.Errorf("failed to generate bash hooks: %w", err)
	}

	hookFile := filepath.Join(hm.hooksDir, "bash_hook.sh")
	if err := os.WriteFile(hookFile, []byte(hookContent), 0755); err != nil {
		return fmt.Errorf("failed to write bash hooks file: %w", err)
	}

	hm.logger.WithField("hook_file", hookFile).Info().Msg("Bash hooks installed")
	return nil
}

// installZshHooks creates and installs zsh hooks
func (hm *HookManager) installZshHooks() error {
	hookContent, err := hm.generateZshHooks()
	if err != nil {
		return fmt.Errorf("failed to generate zsh hooks: %w", err)
	}

	hookFile := filepath.Join(hm.hooksDir, "zsh_hook.sh")
	if err := os.WriteFile(hookFile, []byte(hookContent), 0755); err != nil {
		return fmt.Errorf("failed to write zsh hooks file: %w", err)
	}

	hm.logger.WithField("hook_file", hookFile).Info().Msg("Zsh hooks installed")
	return nil
}

// generateBashHooks generates bash hook script content
func (hm *HookManager) generateBashHooks() (string, error) {
	sessionID, err := hm.sessionMgr.GetCurrentSessionID()
	if err != nil {
		return "", fmt.Errorf("failed to get session ID: %w", err)
	}

	tmpl := template.Must(template.New("bash_hooks").Parse(bashHookTemplate))
	
	var buf strings.Builder
	data := struct {
		BinaryPath string
		SessionID  string
	}{
		BinaryPath: hm.binaryPath,
		SessionID:  sessionID,
	}

	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute bash hook template: %w", err)
	}

	return buf.String(), nil
}

// generateZshHooks generates zsh hook script content
func (hm *HookManager) generateZshHooks() (string, error) {
	sessionID, err := hm.sessionMgr.GetCurrentSessionID()
	if err != nil {
		return "", fmt.Errorf("failed to get session ID: %w", err)
	}

	tmpl := template.Must(template.New("zsh_hooks").Parse(zshHookTemplate))
	
	var buf strings.Builder
	data := struct {
		BinaryPath string
		SessionID  string
	}{
		BinaryPath: hm.binaryPath,
		SessionID:  sessionID,
	}

	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute zsh hook template: %w", err)
	}

	return buf.String(), nil
}

// GetHookPath returns the path to the hook file for the specified shell
func (hm *HookManager) GetHookPath(shell string) string {
	switch shell {
	case "bash":
		return filepath.Join(hm.hooksDir, "bash_hook.sh")
	case "zsh":
		return filepath.Join(hm.hooksDir, "zsh_hook.sh")
	default:
		return ""
	}
}

// GenerateInstallInstructions generates installation instructions for the user
func (hm *HookManager) GenerateInstallInstructions(shell string) string {
	hookPath := hm.GetHookPath(shell)
	
	switch shell {
	case "bash":
		return fmt.Sprintf(`To enable CommandChronicles in bash, add the following line to your ~/.bashrc:

source "%s"

Then restart your shell or run:
source ~/.bashrc

Features enabled:
• Automatic command recording with metadata (execution time, exit codes, etc.)
• Press CTRL+R to launch interactive TUI search
• Graceful fallback to standard history if TUI unavailable`, hookPath)
	case "zsh":
		return fmt.Sprintf(`To enable CommandChronicles in zsh, add the following line to your ~/.zshrc:

source "%s"

Then restart your shell or run:
source ~/.zshrc

Features enabled:
• Automatic command recording with metadata (execution time, exit codes, etc.)
• Press CTRL+R to launch interactive TUI search
• Graceful fallback to standard history if TUI unavailable`, hookPath)
	default:
		return "Shell not supported"
	}
}

// Constants for shell config markers
const (
	CCRMarkerStart = "# CommandChronicles Integration - START"
	CCRMarkerEnd   = "# CommandChronicles Integration - END"
)

// GetShellConfigPath detects the appropriate shell configuration file
func (hm *HookManager) GetShellConfigPath(shell string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	var candidates []string
	switch shell {
	case "bash":
		candidates = []string{
			filepath.Join(homeDir, ".bashrc"),
		}
		// On macOS, bash typically uses .bash_profile
		if runtime.GOOS == "darwin" {
			candidates = append([]string{filepath.Join(homeDir, ".bash_profile")}, candidates...)
		}
		// Fallback to .profile if neither exists
		candidates = append(candidates, filepath.Join(homeDir, ".profile"))
	case "zsh":
		candidates = []string{
			filepath.Join(homeDir, ".zshrc"),
			filepath.Join(homeDir, ".zprofile"),
		}
	default:
		return "", fmt.Errorf("unsupported shell: %s", shell)
	}

	// Find existing config file or return the first candidate for creation
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	// Return the primary config file for creation
	return candidates[0], nil
}

// BackupShellConfig creates a timestamped backup of the shell config file
func (hm *HookManager) BackupShellConfig(configPath string) (string, error) {
	// Check if source file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// No backup needed for non-existent file
		return "", nil
	}

	// Generate backup filename with timestamp
	timestamp := time.Now().Format("20060102-150405")
	backupPath := fmt.Sprintf("%s.ccr-backup-%s", configPath, timestamp)

	// Use configured backup directory if specified
	if hm.config.Shell.BackupDir != "" {
		if err := os.MkdirAll(hm.config.Shell.BackupDir, 0700); err != nil {
			return "", fmt.Errorf("failed to create backup directory: %w", err)
		}
		filename := filepath.Base(configPath)
		backupPath = filepath.Join(hm.config.Shell.BackupDir, fmt.Sprintf("%s.ccr-backup-%s", filename, timestamp))
	}

	// Copy file content
	content, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to read config file for backup: %w", err)
	}

	if err := os.WriteFile(backupPath, content, 0644); err != nil {
		return "", fmt.Errorf("failed to create backup file: %w", err)
	}

	hm.logger.WithField("backup_path", backupPath).Info().Msg("Created shell config backup")
	return backupPath, nil
}

// IsAlreadyInstalled checks if CommandChronicles is already integrated in the shell config
func (hm *HookManager) IsAlreadyInstalled(configPath string) (bool, error) {
	content, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to read config file: %w", err)
	}

	return strings.Contains(string(content), CCRMarkerStart), nil
}

// removeExistingIntegration removes any existing CommandChronicles integration from config content
func (hm *HookManager) removeExistingIntegration(content string) string {
	lines := strings.Split(content, "\n")
	var result []string
	inCCRBlock := false

	for _, line := range lines {
		if strings.Contains(line, CCRMarkerStart) {
			inCCRBlock = true
			continue
		}
		if strings.Contains(line, CCRMarkerEnd) {
			inCCRBlock = false
			continue
		}
		if !inCCRBlock {
			result = append(result, line)
		}
	}

	return strings.Join(result, "\n")
}

// AddSourceLine safely adds a source line to the shell config file
func (hm *HookManager) AddSourceLine(configPath, hookPath string) error {
	// Read existing content or start with empty
	var content string
	if existingContent, err := os.ReadFile(configPath); err == nil {
		content = string(existingContent)
	}

	// Remove any existing CommandChronicles integration
	cleanContent := hm.removeExistingIntegration(content)

	// Ensure clean content ends with newline
	if cleanContent != "" && !strings.HasSuffix(cleanContent, "\n") {
		cleanContent += "\n"
	}

	// Build integration block
	integrationBlock := fmt.Sprintf(`
%s
# Auto-generated by CommandChronicles CLI
if [ -f "%s" ]; then
    source "%s"
fi
%s
`, CCRMarkerStart, hookPath, hookPath, CCRMarkerEnd)

	// For zsh, add widget registration fix at the end to ensure it loads after Oh My Zsh etc
	widgetFix := ""
	if strings.Contains(configPath, ".zshrc") || strings.Contains(configPath, ".zprofile") {
		widgetFix = `
# Ensure CommandChronicles ctrl+r binding is active
if type __ccr_search >/dev/null 2>&1; then
    zle -N __ccr_search
    bindkey '^R' __ccr_search
fi
`
	}

	// Combine content
	newContent := cleanContent + integrationBlock + widgetFix

	// Write to file with appropriate permissions
	if err := os.WriteFile(configPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write to config file: %w", err)
	}

	hm.logger.WithFields(map[string]interface{}{
		"config_path": configPath,
		"hook_path":   hookPath,
	}).Info().Msg("Added source line to shell config")

	return nil
}

// RemoveSourceLine removes CommandChronicles integration from shell config file
func (hm *HookManager) RemoveSourceLine(configPath string) error {
	content, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		// Nothing to remove
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Remove integration
	cleanContent := hm.removeExistingIntegration(string(content))

	// Write back the cleaned content
	if err := os.WriteFile(configPath, []byte(cleanContent), 0644); err != nil {
		return fmt.Errorf("failed to write cleaned config file: %w", err)
	}

	hm.logger.WithField("config_path", configPath).Info().Msg("Removed CommandChronicles integration from shell config")
	return nil
}

// InstallHooksAutomatically performs complete automatic hook installation
func (hm *HookManager) InstallHooksAutomatically(shell string, force bool) error {
	// Get shell config path
	configPath, err := hm.GetShellConfigPath(shell)
	if err != nil {
		return fmt.Errorf("failed to detect shell config: %w", err)
	}

	// Check if already installed (unless force is specified)
	if !force {
		installed, err := hm.IsAlreadyInstalled(configPath)
		if err != nil {
			return fmt.Errorf("failed to check installation status: %w", err)
		}
		if installed {
			return fmt.Errorf("CommandChronicles is already installed in %s (use --force to reinstall)", configPath)
		}
	}

	// Create backup before modification
	backupPath, err := hm.BackupShellConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	if backupPath != "" {
		hm.logger.WithField("backup_path", backupPath).Info().Msg("Created backup before installation")
	}

	// Install hook files
	if err := hm.InstallHooks(shell); err != nil {
		return fmt.Errorf("failed to install hook files: %w", err)
	}

	// Add source line to shell config
	hookPath := hm.GetHookPath(shell)
	if err := hm.AddSourceLine(configPath, hookPath); err != nil {
		return fmt.Errorf("failed to add source line: %w", err)
	}

	hm.logger.WithFields(map[string]interface{}{
		"shell":       shell,
		"config_path": configPath,
		"hook_path":   hookPath,
	}).Info().Msg("Successfully installed CommandChronicles hooks automatically")

	return nil
}

// UninstallHooks removes CommandChronicles integration from shell
func (hm *HookManager) UninstallHooks(shell string) error {
	// Get shell config path
	configPath, err := hm.GetShellConfigPath(shell)
	if err != nil {
		return fmt.Errorf("failed to detect shell config: %w", err)
	}

	// Check if installed
	installed, err := hm.IsAlreadyInstalled(configPath)
	if err != nil {
		return fmt.Errorf("failed to check installation status: %w", err)
	}
	if !installed {
		return fmt.Errorf("CommandChronicles is not installed in %s", configPath)
	}

	// Create backup before modification
	backupPath, err := hm.BackupShellConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	if backupPath != "" {
		hm.logger.WithField("backup_path", backupPath).Info().Msg("Created backup before uninstallation")
	}

	// Remove source line from shell config
	if err := hm.RemoveSourceLine(configPath); err != nil {
		return fmt.Errorf("failed to remove source line: %w", err)
	}

	// Optionally remove hook files
	hookPath := hm.GetHookPath(shell)
	if err := os.Remove(hookPath); err != nil && !os.IsNotExist(err) {
		hm.logger.WithError(err).WithField("hook_path", hookPath).Warn().Msg("Failed to remove hook file")
	}

	hm.logger.WithFields(map[string]interface{}{
		"shell":       shell,
		"config_path": configPath,
	}).Info().Msg("Successfully uninstalled CommandChronicles hooks")

	return nil
}

// bash hook template
const bashHookTemplate = `#!/bin/bash
# CommandChronicles bash integration hooks
# Auto-generated file - do not edit manually

# Check if ccr binary is available
if ! command -v "{{.BinaryPath}}" >/dev/null 2>&1; then
    return 0  # Graceful degradation
fi

# Session ID for this shell session
export CCR_SESSION_ID="{{.SessionID}}"

# Suppress job control messages for background recording
set +m 2>/dev/null

# Pre-execution hook - capture start time and working directory
__ccr_preexec() {
    # Only capture if the command is not empty and not a ccr command
    if [[ -n "$BASH_COMMAND" && "$BASH_COMMAND" != ccr* && "$BASH_COMMAND" != *__ccr_* ]]; then
        # Get timestamp with nanoseconds (fallback to milliseconds on macOS)
        __CCR_START_TIME=$(date +%s%N 2>/dev/null)
        if [[ "$__CCR_START_TIME" == *"N" ]]; then
            __CCR_START_TIME=$(($(date +%s) * 1000000000))
        fi
        __CCR_WORKING_DIR="$PWD"
        __CCR_COMMAND="$BASH_COMMAND"
    fi
}

# Post-execution hook - capture exit code and duration, then record
__ccr_postexec() {
    local exit_code=$?
    
    # Skip if no command was captured or it's a ccr command
    if [[ -z "$__CCR_COMMAND" || "$__CCR_COMMAND" == ccr* || "$__CCR_COMMAND" == *__ccr_* ]]; then
        unset __CCR_COMMAND __CCR_START_TIME __CCR_WORKING_DIR
        return
    fi
    
    # Calculate duration
    # Get timestamp with nanoseconds (fallback to milliseconds on macOS)
    local end_time=$(date +%s%N 2>/dev/null)
    if [[ "$end_time" == *"N" ]]; then
        end_time=$(($(date +%s) * 1000000000))
    fi
    local duration=0
    if [[ -n "$__CCR_START_TIME" && "$__CCR_START_TIME" =~ ^[0-9]+$ && "$end_time" =~ ^[0-9]+$ ]]; then
        duration=$(( (end_time - __CCR_START_TIME) / 1000000 ))
    fi
    
    # Record the command asynchronously to avoid blocking the shell
    (
        "{{.BinaryPath}}" record \
            --command "$__CCR_COMMAND" \
            --exit-code "$exit_code" \
            --duration "$duration" \
            --directory "$__CCR_WORKING_DIR" \
            --session "$CCR_SESSION_ID" \
            >/dev/null 2>&1 &
    )
    
    # Clean up variables
    unset __CCR_COMMAND __CCR_START_TIME __CCR_WORKING_DIR
}

# Install hooks into bash
trap '__ccr_preexec' DEBUG

# Add to PROMPT_COMMAND, preserving existing value
if [[ -z "$PROMPT_COMMAND" ]]; then
    PROMPT_COMMAND="__ccr_postexec"
else
    # Only add if not already present
    if [[ "$PROMPT_COMMAND" != *"__ccr_postexec"* ]]; then
        PROMPT_COMMAND="__ccr_postexec; $PROMPT_COMMAND"
    fi
fi



# TUI search function for ctrl+r key binding
__ccr_search() {
    # Clear current line and launch TUI
    printf '\r\033[K'
    "{{.BinaryPath}}" search --tui
    local exit_code=$?
    
    # Check if command was selected
    local cmd_file="/tmp/ccr_selected_command"
    if [[ -f "$cmd_file" && $exit_code -eq 0 ]]; then
        local selected_cmd=$(head -n1 "$cmd_file" 2>/dev/null)
        local exec_flag=$(tail -n1 "$cmd_file" 2>/dev/null)
        rm -f "$cmd_file" 2>/dev/null
        
        if [[ -n "$selected_cmd" ]]; then
            # Insert command into readline buffer
            READLINE_LINE="$selected_cmd"
            READLINE_POINT=${#READLINE_LINE}
            
            # If exec flag is set, execute immediately
            if [[ "$exec_flag" == "exec" ]]; then
                printf '%s\n' "$selected_cmd"
                eval "$selected_cmd"
            fi
        fi
    fi
    
    # Redraw the prompt
    kill -WINCH $$ 2>/dev/null
}

# Bind ctrl+r to TUI search (only if in interactive mode)
if [[ $- == *i* && -n "$BASH_VERSION" ]]; then
    # Use bind -x to execute function on ctrl+r
    bind -x '"\C-r": __ccr_search' 2>/dev/null
fi

# Clean up on shell exit
__ccr_cleanup() {
    if command -v "{{.BinaryPath}}" >/dev/null 2>&1; then
        "{{.BinaryPath}}" session-end "$CCR_SESSION_ID" >/dev/null 2>&1 &
    fi
}
trap '__ccr_cleanup' EXIT
`

// zsh hook template  
const zshHookTemplate = `#!/bin/zsh
# CommandChronicles zsh integration hooks
# Auto-generated file - do not edit manually

# Check if ccr binary is available
if ! command -v "{{.BinaryPath}}" >/dev/null 2>&1; then
    return 0  # Graceful degradation
fi

# Session ID for this shell session
export CCR_SESSION_ID="{{.SessionID}}"

# Suppress job control messages for background recording
setopt NO_MONITOR 2>/dev/null
setopt NO_NOTIFY 2>/dev/null

# Pre-execution hook - capture start time and working directory
__ccr_preexec() {
    local cmd="$1"
    
    # Skip if empty command or ccr command
    if [[ -z "$cmd" || "$cmd" == ccr* || "$cmd" == *__ccr_* ]]; then
        return
    fi
    
    # Get timestamp with nanoseconds (fallback to milliseconds on macOS)
    __CCR_START_TIME=$(date +%s%N 2>/dev/null)
    if [[ "$__CCR_START_TIME" == *"N" ]]; then
        __CCR_START_TIME=$(($(date +%s) * 1000000000))
    fi
    __CCR_WORKING_DIR="$PWD"
    __CCR_COMMAND="$cmd"
}

# Post-execution hook - capture exit code and duration, then record
__ccr_precmd() {
    local exit_code=$?
    
    # Skip if no command was captured
    if [[ -z "$__CCR_COMMAND" ]]; then
        return
    fi
    
    # Calculate duration
    # Get timestamp with nanoseconds (fallback to milliseconds on macOS)
    local end_time=$(date +%s%N 2>/dev/null)
    if [[ "$end_time" == *"N" ]]; then
        end_time=$(($(date +%s) * 1000000000))
    fi
    local duration=0
    if [[ -n "$__CCR_START_TIME" && "$__CCR_START_TIME" =~ ^[0-9]+$ && "$end_time" =~ ^[0-9]+$ ]]; then
        duration=$(( (end_time - __CCR_START_TIME) / 1000000 ))
    fi
    
    # Record the command asynchronously to avoid blocking the shell
    {
        "{{.BinaryPath}}" record \
            --command "$__CCR_COMMAND" \
            --exit-code "$exit_code" \
            --duration "$duration" \
            --directory "$__CCR_WORKING_DIR" \
            --session "$CCR_SESSION_ID" \
            >/dev/null 2>&1
    } &!
    
    # Clean up variables
    unset __CCR_COMMAND __CCR_START_TIME __CCR_WORKING_DIR
}

# Install hooks into zsh
autoload -Uz add-zsh-hook

# Add hooks, avoiding duplicates
if [[ ${preexec_functions[(I)__ccr_preexec]} -eq 0 ]]; then
    add-zsh-hook preexec __ccr_preexec
fi

if [[ ${precmd_functions[(I)__ccr_precmd]} -eq 0 ]]; then
    add-zsh-hook precmd __ccr_precmd
fi

# Clean up on shell exit
__ccr_cleanup() {
    if command -v "{{.BinaryPath}}" >/dev/null 2>&1; then
        "{{.BinaryPath}}" session-end "$CCR_SESSION_ID" >/dev/null 2>&1 &
    fi
}

# TUI search function for ctrl+r key binding
__ccr_search() {
    # Save current buffer
    local saved_buffer="$BUFFER"
    local saved_cursor="$CURSOR"
    
    # Clear current buffer and launch TUI
    BUFFER=""
    zle -R
    "{{.BinaryPath}}" search --tui </dev/tty
    local exit_code=$?
    
    # Check if command was selected
    local cmd_file="/tmp/ccr_selected_command"
    if [[ -f "$cmd_file" && $exit_code -eq 0 ]]; then
        local selected_cmd=$(head -n1 "$cmd_file" 2>/dev/null)
        local exec_flag=$(tail -n1 "$cmd_file" 2>/dev/null)
        rm -f "$cmd_file" 2>/dev/null
        
        if [[ -n "$selected_cmd" ]]; then
            # Insert command into ZLE buffer
            BUFFER="$selected_cmd"
            CURSOR=${#BUFFER}
            
            # If exec flag is set, execute immediately
            if [[ "$exec_flag" == "exec" ]]; then
                zle accept-line
            fi
        fi
    else
        # Restore buffer if cancelled
        BUFFER="$saved_buffer"
        CURSOR="$saved_cursor"
    fi
    
    zle reset-prompt
}

# Function to set up ctrl+r binding
__ccr_setup_binding() {
    if [[ -n "$ZLE_VERSION" ]]; then
        zle -N __ccr_search 2>/dev/null
        bindkey '^R' __ccr_search 2>/dev/null
    fi
}

# Bind ctrl+r to TUI search (only if in interactive mode)
if [[ -o interactive ]]; then
    # Try to bind immediately
    __ccr_setup_binding
    
    # Also set up delayed binding for Oh My Zsh compatibility
    if [[ -z "$ZLE_VERSION" ]]; then
        # ZLE not ready yet, try again in precmd
        __ccr_delayed_bind() {
            __ccr_setup_binding
            # Remove this hook after binding
            if [[ -n "$ZLE_VERSION" ]]; then
                add-zsh-hook -d precmd __ccr_delayed_bind
            fi
        }
        add-zsh-hook precmd __ccr_delayed_bind 2>/dev/null
    fi
fi

# Install exit hook
if [[ ${zshexit_functions[(I)__ccr_cleanup]} -eq 0 ]]; then
    add-zsh-hook zshexit __ccr_cleanup
fi
`