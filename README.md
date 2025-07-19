# CommandChronicles CLI (ccr)

```
===================================================================
                CommandChronicles CLI (ccr) v0.4.0
===================================================================

  🚀 A modern shell history management tool that supercharges
     your command line experience with intelligent search
                and secure local storage

===================================================================
```

<p align="center">
  <a href="https://github.com/NeverVane/commandchronicles/releases">
    <img src="https://img.shields.io/badge/version-0.4.1-blue.svg" alt="Version">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  </a>
  <a href="https://golang.org">
    <img src="https://img.shields.io/badge/go-%3E%3D1.23-00ADD8.svg" alt="Go Version">
  </a>
</p>

**CommandChronicles CLI** transforms your shell history into a powerful knowledge base, capturing rich context for every command and providing lightning-fast search capabilities through an intuitive TUI interface.

## ✨ Key Features

- 🔐 **Military-grade encryption** (XChaCha20-Poly1305) for your command history
- 🔍 **Blazing-fast fuzzy search** with real-time interactive TUI (Ctrl+R)
- 📝 **Rich note system** for annotating commands with context and explanations
- 🏷️ **Comprehensive tag system** for categorizing and organizing commands with visual indicators
- 🔗 **Sync rules system** for fine-grained control over command synchronization across devices
- 📊 **Rich command metadata** (exit codes, duration, working directory, git info)
- 🐚 **Seamless shell integration** for bash and zsh with automatic setup
- 🔑 **Secure key derivation** (Argon2id) and session management
- ⚡ **Smart caching system** for instant search results
- 📈 **Beautiful command statistics** and usage analytics

## 🖼️ CommandChronicles TUI vs Traditional History

![History Comparison](docs/images/screenshots/historyComparison.png)

*Transform your command line experience: From basic history to intelligent, searchable command management*

## 🚀 Quick Start

### Installation

```bash
# One line install
curl -sSL https://get.commandchronicles.dev | bash
```

#or

```bash
# Clone the repository
git clone https://github.com/NeverVane/commandchronicles.git
cd commandchronicles

# Build the binary
go build -o ccr

# Move to your PATH
sudo mv ccr /usr/local/bin/
```

### Initial Setup

```bash
# Initialize CommandChronicles
ccr init

# Automatically install shell hooks (recommended)
ccr install-hooks --auto

# Or manually install for specific shell
ccr install-hooks zsh
ccr install-hooks bash

# Enable auto-sync daemon (recommended)
ccr daemon-control install-service
ccr daemon-control start
```

After installation, restart your shell or run:
```bash
source ~/.zshrc  # for zsh
source ~/.bashrc # for bash
```

## 📖 Usage

### Interactive Search (TUI)

Press `Ctrl+R` in your shell to launch the interactive TUI search interface.

**TUI Key Bindings:**
- `↑/↓` - Navigate through commands
- `Enter` - Copy command to shell prompt
- `Ctrl+J` - Execute command immediately
- `Tab` - View detailed command information
- `Ctrl+F` - Toggle fuzzy search
- `Ctrl+F+N` - Toggle combined notes+commands search
- `Ctrl+N` - Edit note for selected command
- `Ctrl+S` - Show only successful commands
- `Ctrl+X` - Show only failed commands
- `Ctrl+T` - View statistics
- `Ctrl+K` - Clear search
- `?` - Show help
- `Esc/Ctrl+C` - Exit

**Important TUI Behavior:**
- **Shell Integration Required**: Command injection (Enter/Ctrl+J) only works when TUI is launched via `Ctrl+R` after installing shell hooks
- **Direct TUI Calls**: Running `ccr tui` directly will show the interface but cannot inject commands into your shell
- **Recommended Usage**: Always use `Ctrl+R` for interactive command search and selection
- **Installation**: Run `ccr install-hooks` to enable full TUI functionality
- **Note Editing**: Use `Ctrl+N` to edit notes directly in the TUI interface
- **Combined Search**: Use `Ctrl+F+N` to search both commands and notes simultaneously

### Command Line Search

```bash
# Search for commands containing "git"
ccr search git

# Search with fuzzy matching
ccr search --fuzzy "gt sttus"

# Filter by exit code
ccr search --exit-code 0 "docker"

# Filter by directory
ccr search --directory /project "npm"

# Filter by time
ccr search --since 1h "build"
ccr search --since 2d --until 1d "test"
```

### Note System

CommandChronicles includes a comprehensive note system for annotating your commands with context, explanations, and reminders.

![Note System](docs/images/features/noteSystem.png)

*Add rich, multi-line notes to your commands with the integrated note editor*

```bash
# Add a note to a command (use command ID from search results)
ccr note add 123 "This command deploys to production"

# Edit an existing note
ccr note edit 123 "Updated: This command deploys to staging environment"

# View a note
ccr note show 123

# List all commands with notes
ccr note list

# Search within notes
ccr note search "deployment"

# Delete a note
ccr note delete 123
```

**Note Features:**
- **Multi-line support**: Notes can span multiple lines with proper formatting
- **Character limit**: 1000 characters maximum per note
- **Encrypted storage**: Notes are encrypted alongside command data
- **Visual indicators**: Commands with notes show a colored dot (●) in the TUI
- **Integrated search**: Use `Ctrl+F+N` in TUI for combined command+note searching
- **Rich editing**: Full-featured note editor with word wrapping in TUI

**TUI Note Editing:**
- Press `Ctrl+N` on any command to open the note editor
- **Multi-line editing**: Press `Enter` for new lines, `Ctrl+S` to save, `Esc` to cancel
- **Real-time validation**: Character count display with 1000 character limit
- **Word wrapping**: Automatic text wrapping for long content
- **Visual feedback**: Commands with notes show a colored indicator (●) in the list
- **Responsive design**: Editor adapts to terminal size automatically

### Tag System

CommandChronicles includes a comprehensive tag system for categorizing and organizing your commands with visual indicators and powerful search capabilities.

![Tag System](docs/images/features/tagSystem.png)

*Organize and categorize your commands with color-coded tags for better workflow management*

```bash
# Add a tag to a command (use command ID from search results)
ccr tag add 123 "docker"

# Remove a tag from a command
ccr tag remove 123 "docker"

# List all tags for a command
ccr tag list 123

# Show all commands with tags
ccr tag show

# Search commands by tag
ccr tag search "docker"
```

**Tag Features:**
- **Tag limits**: Up to 5 tags per command, 50 characters maximum per tag
- **Color customization**: Per-tag color configuration for better visual organization
- **Auto-tagging engine**: Intelligent automatic tagging based on command patterns
- **Default tag rules**: Pre-configured tags for common categories (docker, git, file-ops, network, system, etc.)
- **Encrypted storage**: Tags are encrypted alongside command data
- **Visual indicators**: Tagged commands display colored tag badges in the TUI
- **Integrated search**: Tag-based filtering and search capabilities

**TUI Tag Integration:**
- Tags appear as colored badges in the command list
- View tags in command details view (Tab key)
- Tags are preserved during search and filtering operations
- Color-coded organization for quick visual categorization

### Sync Rules System

CommandChronicles includes a powerful sync rules system that gives you fine-grained control over which commands synchronize to which devices. Create rules to selectively include or exclude commands from specific devices based on flexible conditions.

```bash
# List your devices
ccr devices show

# Create basic rules
ccr rules allow work-laptop                    # Allow all commands to work laptop
ccr rules deny personal-phone                  # Deny all commands to phone

# Create conditional rules
ccr rules deny personal-phone --tag sensitive  # Deny sensitive commands to phone
ccr rules allow home-server --dir /projects    # Only sync /projects commands to server
ccr rules allow dev-machine --pattern "git*"   # Only sync git commands to dev machine

# Manage rules
ccr rules list                    # View all rules
ccr rules delete <rule-id>        # Delete a rule (supports 8-char IDs)
ccr rules simulate "git push"     # Test how rules would apply to a command
ccr rules conflicts               # Detect rule conflicts
```

**Sync Rules Features:**
- **Privacy Control**: Exclude personal/sensitive commands from work devices
- **Device-Specific Workflows**: Only sync relevant commands to each device
- **Conditional Filtering**: Apply rules based on tags, directories, command patterns, or time
- **Retroactive Application**: Rules automatically apply to all existing commands, not just new ones
- **Allow/Deny Logic**: Flexible rule combinations for precise control
- **Device Aliases**: Use friendly names instead of device IDs

**Rule Conditions:**
- **Tags**: `--tag docker` (commands with specific tags)
- **Directories**: `--dir /work` (commands from specific paths)
- **Patterns**: `--pattern "ssh*"` (commands matching patterns)
- **Time**: `--time "09:00-17:00"` (commands during specific hours)

**How It Works:**
Rules use **allow/deny logic** with **target devices**. When rules change, **all existing commands are automatically re-evaluated** and routing is updated across your devices. No rules means all commands sync everywhere (default behavior).

**Example Use Cases:**
- **Work/Personal Separation**: `ccr rules deny personal-laptop --tag work`
- **Server Deployments**: `ccr rules allow production-server --tag deploy`
- **Development Focus**: `ccr rules allow dev-machine --dir /code`
- **Time-Based Rules**: `ccr rules deny mobile --time "09:00-17:00"`

## 📋 Quick Reference

### Tag Commands
```bash
ccr tag add <id> <tag>       # Add tag to command
ccr tag remove <id> <tag>    # Remove tag from command
ccr tag list <id>            # List tags for command
ccr tag show                 # Show all tagged commands
ccr tag search <tag>         # Search by tag
```

### Note Commands
```bash
ccr note add <id> <note>     # Add note to command
ccr note edit <id> <note>    # Edit existing note
ccr note delete <id>         # Remove note
ccr note show <id>           # Display note
ccr note list                # List all noted commands
ccr note search <query>      # Search within notes
```

### TUI Shortcuts
```
Ctrl+R         Launch interactive TUI
Ctrl+F         Toggle fuzzy search
Ctrl+F+N       Toggle combined notes+commands search
Ctrl+N         Edit note for selected command
Tab            View command details (including notes)
Enter          Copy command to shell
Ctrl+J         Execute command immediately
Ctrl+S         Filter successful commands only
Ctrl+X         Filter failed commands only
?              Show help
Esc/Ctrl+C     Exit
```

### Statistics

```bash
# View command usage statistics
ccr stats

# Export statistics as JSON
ccr stats --format json > stats.json
```

### Import/Export

```bash
# Import existing shell history
ccr import ~/.bash_history --format bash
ccr import ~/.zsh_history --format zsh

# Export command history
ccr export --format json > commands.json
ccr export --format bash > commands.bash
```

### Session Management

```bash
# Lock your command history (requires password)
ccr lock

# Unlock for searching
ccr unlock

# Change password
ccr change-password
```

## 🔧 Configuration

CommandChronicles stores its configuration in `~/.config/commandchronicles/config.toml`.

### Example Configuration

```toml
[cache]
hot_cache_size = 2000      # Number of recent commands to keep in memory
search_batch_size = 5000   # Commands to load per search batch
max_memory_mb = 100        # Maximum memory usage

[security]
session_timeout = 7776000  # Session timeout in seconds (90 days)
argon2_time = 3           # Argon2 time parameter
argon2_memory = 65536     # Argon2 memory parameter (KB)

[shell]
auto_install = false      # Auto-install shell integration
graceful_degradation = true # Fallback if ccr is unavailable

[notes]
max_length = 1000         # Maximum characters per note
enable_search = true      # Enable note content searching
show_indicators = true    # Show note indicators in TUI

[tui]
animations = true         # Enable TUI animations
color_scheme = "auto"     # Color scheme: auto, dark, light
results_per_page = 20     # Results per page in TUI
```

## 🛡️ Security

CommandChronicles takes your privacy seriously:

- All command history is encrypted using XChaCha20-Poly1305
- Passwords are processed using Argon2id key derivation
- Session keys are stored securely with configurable timeouts
- All data is stored locally - no cloud services or telemetry ( optional )
- Secure memory handling prevents sensitive data from being swapped to disk

## 🎯 Use Cases

CommandChronicles with notes, tags, and sync rules is perfect for:

- **DevOps workflows**: Document deployment commands with environment details and tag by environment
- **Complex commands**: Add context to long docker, kubectl, or database commands with explanatory notes
- **Learning**: Annotate commands you're learning with explanations and categorize with learning tags
- **Team collaboration**: Share documented and tagged command snippets with colleagues
- **Troubleshooting**: Note solutions and context for debugging commands, tag by issue type
- **Project documentation**: Keep command documentation alongside your history with project-specific tags
- **Command organization**: Categorize commands by technology stack (docker, git, network, system)
- **Quick filtering**: Find all Docker commands, Git operations, or system administration tasks instantly
- **Workflow optimization**: Create searchable command libraries organized by function and context
- **Environment management**: Tag commands by deployment environment (dev, staging, prod)
- **Technology discovery**: Browse related commands through consistent tagging conventions
- **Multi-device privacy**: Use sync rules to keep personal commands off work devices and vice versa
- **Role-based access**: Allow only deployment commands to production servers with targeted rules
- **Development workflows**: Sync coding commands to dev machines while filtering system admin tasks
- **Time-sensitive filtering**: Use time-based rules to prevent work commands from syncing during personal hours
- **Project isolation**: Route project-specific commands only to relevant development environments
- **Security compliance**: Ensure sensitive operations never sync to unauthorized or mobile devices

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Leonardo Zanobi**

- Website: [https://commandchronicles.dev](https://commandchronicles.dev)
- GitHub: [@NeverVane](https://github.com/NeverVane)

## 🙏 Acknowledgments

- [Bubble Tea](https://github.com/charmbracelet/bubbletea) for the amazing TUI framework
- [Bleve](https://github.com/blevesearch/bleve) for powerful full-text search
- [Cobra](https://github.com/spf13/cobra) for CLI structure
- The Go community for excellent cryptography libraries

---

<p align="center">
  Made with ❤️ by Leonardo Zanobi
</p>
