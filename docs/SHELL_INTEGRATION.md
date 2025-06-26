# CommandChronicles Shell Integration

CommandChronicles provides seamless integration with bash and zsh shells to automatically record your command history with rich metadata and enable instant access to your command history through an interactive TUI.

## Features

### ✨ Key Features

- **Automatic Command Recording**: Every command you run is automatically recorded with execution time, exit codes, working directory, and session information
- **Interactive TUI Search**: Press the **UP ARROW** key to launch an interactive search interface for your command history
- **Rich Metadata**: Commands are recorded with timestamps, execution duration, exit codes, working directory, hostname, and session context
- **Secure Storage**: All command history is encrypted and stored securely
- **Framework Compatibility**: Works seamlessly with popular shell frameworks like Oh My Zsh, Prezto, Bash-it, and Starship
- **Graceful Degradation**: Falls back to standard shell history if CommandChronicles is unavailable

## Installation

### 1. Install Shell Hooks

First, install the shell integration hooks for your shell:

```bash
# For bash users
ccr install-hooks bash

# For zsh users  
ccr install-hooks zsh

# Auto-detect current shell
ccr install-hooks
```

### 2. Enable Integration

Add the provided source line to your shell configuration file:

**For Bash** - Add to `~/.bashrc`:
```bash
source "/path/to/commandchronicles/hooks/bash_hook.sh"
```

**For Zsh** - Add to `~/.zshrc`:
```bash
source "/path/to/commandchronicles/hooks/zsh_hook.sh"
```

### 3. Restart Your Shell

Either restart your terminal or reload your configuration:

```bash
# For bash
source ~/.bashrc

# For zsh
source ~/.zshrc
```

## Usage

### Interactive Search (UP ARROW Key)

Once installed, simply press the **UP ARROW** key in your terminal to launch the interactive TUI search interface. This replaces the standard history navigation and provides:

- **Real-time fuzzy search** as you type
- **Rich command metadata** display (execution time, exit codes, etc.)
- **Advanced filtering** by directory, session, time range, and more
- **Syntax highlighting** for better readability
- **Keyboard navigation** with vim-like controls

### Manual Search

You can also access the TUI manually:

```bash
# Launch TUI search
ccr search --tui

# Launch TUI with initial query
ccr search --tui "git commit"

# Use command-line search
ccr search "docker run" --limit 10
```

### Command Recording

Commands are automatically recorded when you run them. Each recorded command includes:

- **Command text** - The exact command that was executed
- **Exit code** - Success (0) or failure status
- **Execution time** - How long the command took to run
- **Working directory** - Where the command was executed
- **Timestamp** - When the command was run
- **Session ID** - Groups commands by shell session
- **Hostname** - Which machine the command was run on

## Framework Compatibility

CommandChronicles shell integration is designed to work seamlessly with popular shell frameworks:

### Oh My Zsh
```bash
# In your ~/.zshrc
# ... oh-my-zsh configuration ...
source "$HOME/.oh-my-zsh/oh-my-zsh.sh"

# Add CommandChronicles integration
source "/path/to/commandchronicles/hooks/zsh_hook.sh"
```

### Prezto
```bash
# In your ~/.zshrc  
# ... prezto configuration ...
source "$HOME/.zprezto/init.zsh"

# Add CommandChronicles integration
source "/path/to/commandchronicles/hooks/zsh_hook.sh"
```

### Bash-it
```bash
# In your ~/.bashrc
# ... bash-it configuration ...
source "$HOME/.bash_it/bash_it.sh"

# Add CommandChronicles integration  
source "/path/to/commandchronicles/hooks/bash_hook.sh"
```

### Starship Prompt
CommandChronicles works with Starship in both bash and zsh. The hooks are designed to coexist with Starship's prompt functions without interference.

## Configuration

### Hook Paths

You can customize where shell hooks are installed by editing your configuration file:

```yaml
# ~/.config/commandchronicles/config.yaml
shell:
  bash_hook_path: "/custom/path/bash_hook.sh"
  zsh_hook_path: "/custom/path/zsh_hook.sh"
  capture_timeout_ms: 10
  graceful_degradation: true
```

### Session Management

Each shell session gets a unique session ID. You can:

```bash
# View current session info
echo $CCR_SESSION_ID

# End current session manually
ccr session-end $CCR_SESSION_ID
```

## Troubleshooting

### UP ARROW Key Not Working

1. **Check if hooks are loaded**:
   ```bash
   # For bash
   declare -f __ccr_search
   
   # For zsh  
   which __ccr_search
   ```

2. **Verify key binding**:
   ```bash
   # For bash
   bind -p | grep __ccr_search
   
   # For zsh
   bindkey | grep __ccr_search
   ```

3. **Test TUI manually**:
   ```bash
   ccr search --tui
   ```

### Commands Not Being Recorded

1. **Check if ccr binary is in PATH**:
   ```bash
   which ccr
   ```

2. **Verify storage is unlocked**:
   ```bash
   ccr unlock
   ```

3. **Check session ID**:
   ```bash
   echo $CCR_SESSION_ID
   ```

### Framework Conflicts

If you experience conflicts with your shell framework:

1. **Load CommandChronicles after your framework** - This ensures proper hook ordering
2. **Check for duplicate key bindings** - Some frameworks may override the UP ARROW key
3. **Use manual TUI access** - `ccr search --tui` always works regardless of key bindings

### Terminal Compatibility

CommandChronicles supports most terminal emulators. If you experience issues:

1. **Check TERM environment variable**:
   ```bash
   echo $TERM
   ```

2. **Test alternate screen support**:
   ```bash
   tput smcup && echo "Alternate screen works" && tput rmcup
   ```

3. **Dumb terminal fallback** - In limited terminals, the system gracefully falls back to standard history

## Advanced Usage

### Filtering and Search

The TUI supports advanced filtering:

- **Time-based**: Search commands from specific time periods
- **Directory-based**: Find commands run in specific directories  
- **Exit code**: Filter by successful/failed commands
- **Session-based**: View commands from specific shell sessions
- **Fuzzy search**: Smart matching even with typos

### Keyboard Shortcuts

In the TUI interface:

- **↑/↓ or j/k**: Navigate results
- **Enter**: Execute selected command
- **Ctrl+C**: Copy command to clipboard
- **Esc**: Exit TUI
- **?**: Show help
- **/**: Toggle fuzzy search
- **f**: Toggle filters

### Export and Import

```bash
# Export command history
ccr export --format json > history.json

# Import from another system
ccr import history.json
```

## Security Notes

- All command history is encrypted at rest
- Session keys are managed securely
- Commands containing sensitive information (passwords, tokens) should use `HISTIGNORE` patterns
- Regular password rotation is recommended for long-term usage

## Performance

- **Async recording**: Command recording happens in the background and doesn't slow down your shell
- **Efficient search**: Cached search results for fast TUI performance
- **Minimal overhead**: Shell hooks are optimized for minimal performance impact

For more information, see the main CommandChronicles documentation or run `ccr --help`.