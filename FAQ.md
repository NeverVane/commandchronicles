# CommandChronicles CLI - Frequently Asked Questions

## How it Works

### How does CommandChronicles capture my commands?

CommandChronicles uses shell integration hooks that automatically capture commands as you execute them. Here's how it works:

1. **Shell Hooks Installation**: When you run `ccr install-hooks`, the CLI generates shell-specific hook scripts for bash or zsh
2. **Automatic Capture**: The hooks intercept your commands before and after execution, capturing:
   - The actual command text
   - Exit code (success/failure)
   - Execution duration
   - Working directory
   - Git repository information (if applicable)
   - Timestamp and session information
3. **Background Recording**: Commands are encrypted and stored locally in real-time using the `ccr record` command
4. **Session Management**: Each shell session gets a unique ID to organize your command history

The capture process is completely transparent - you don't need to do anything once the hooks are installed.

## Keybindings

### What are the main keybindings?

CommandChronicles provides an interactive TUI (Text User Interface) accessible via `Ctrl+R`. Here are the key bindings:

**Navigation:**
- `↑/↓` - Navigate through command history
- `Enter` - Copy selected command to shell prompt
- `Ctrl+J` - Execute selected command immediately
- `Esc/Ctrl+C` - Exit TUI

**Search & Filtering:**
- `Ctrl+F` - Toggle fuzzy search mode
- `Ctrl+S` - Show only successful commands (exit code 0)
- `Ctrl+X` - Show only failed commands (non-zero exit code)
- `Ctrl+K` - Clear current search query

**Information:**
- `Tab` - View detailed command information (duration, directory, git info)
- `Ctrl+T` - View command statistics
- `?` - Show help and all available keybindings

**Important Note**: Command injection (Enter/Ctrl+J) only works when the TUI is launched via `Ctrl+R` after installing shell hooks. Running `ccr tui` directly will show the interface but cannot inject commands into your shell.

## Security & Privacy

### Is my command history secure?

Yes, CommandChronicles implements military-grade security:

- **Local-Only Storage**: All data is stored locally on your machine - no cloud services or telemetry
- **Full Encryption**: Every command is encrypted using XChaCha20-Poly1305 before storage
- **Secure Authentication**: Password-based access with Argon2id key derivation
- **Session Management**: Configurable session timeouts with automatic cleanup
- **Memory Protection**: Sensitive data is cleared from memory after use

### What encryption does CommandChronicles use?

CommandChronicles uses state-of-the-art cryptography:

- **Encryption Algorithm**: XChaCha20-Poly1305 (authenticated encryption)
- **Key Derivation**: Argon2id with configurable parameters (default: 3 iterations, 64MB memory)
- **Session Keys**: 256-bit session keys with configurable timeout (default: 90 days)
- **Data Integrity**: All encrypted data includes authentication tags to detect tampering

### Can I exclude sensitive commands?

Currently, CommandChronicles captures all commands executed in shells with installed hooks. However, you can:

- **Lock Your History**: Use `ccr lock` to require password authentication for searches
- **Delete Specific Commands**: Use `ccr delete` to remove sensitive commands from history
- **Disable Temporarily**: Uninstall hooks temporarily with `ccr uninstall-hooks`
- **Session Control**: End sessions cleanly to compartmentalize sensitive work

Future versions may include command filtering and exclusion patterns.

## Cross-Device Sync

### How does cross-device sync work?

CommandChronicles offers optional cross-device synchronization with perfect integrity:

1. **Registration**: Register for sync with `ccr sync register`
2. **Perfect Sync**: Uses integrity verification to ensure all devices have identical command history
3. **Background Daemon**: A lightweight daemon runs in the background to automatically sync your commands
4. **Conflict Resolution**: Automatically resolves conflicts when the same command exists on multiple devices
5. **Device Management**: Each device gets a unique ID for tracking and conflict resolution
6. **Server-Side Encryption**: Commands remain encrypted on the sync server using your password-derived keys

**Daemon Management:**
- `ccr daemon-control start` - Start background sync daemon
- `ccr daemon-control stop` - Stop background sync daemon  
- `ccr daemon-control status` - Check daemon status
- `ccr daemon-control restart` - Restart daemon with new settings
- `ccr daemon-control install-service` - Install system service for automatic startup
- `ccr daemon-control remove-service` - Remove system service

### Can I use CommandChronicles offline?

Absolutely! CommandChronicles is designed to work offline-first:

- **Local Storage**: All core functionality works without internet connection
- **Search & TUI**: Full search capabilities available offline
- **Command Recording**: Continues capturing commands offline
- **Sync Queue**: Changes are queued and synchronized when connection is restored
- **Independent Operation**: Each device maintains a complete local copy of your history

### How much data does sync use?

Sync usage is minimal and efficient:

- **Command Data**: Typically 100-500 bytes per command (depending on length and metadata)
- **Incremental Sync**: Only new/changed commands are synchronized
- **Compression**: Data is compressed during transmission
- **Estimated Usage**: For heavy users (1000 commands/day), expect ~150KB/day of sync data
- **Perfect Sync**: Integrity checks use hash comparisons, not full data transfers

## Data Storage

### Where is my data stored?

CommandChronicles stores data in standard system locations:

- **Configuration**: `~/.config/commandchronicles/config.toml`
- **Database**: `~/.local/share/commandchronicles/commands.db` (encrypted SQLite)
- **Session Keys**: `~/.local/share/commandchronicles/session.key`
- **Shell Hooks**: `~/.local/share/commandchronicles/hooks/`
- **Search Index**: `~/.local/share/commandchronicles/search_index/` (for fuzzy search)

All files are created with secure permissions (mode 0700/0600) to prevent unauthorized access.

### How much storage space does it use?

Storage usage depends on your command history volume:

- **Database Overhead**: ~50KB for empty database with schema
- **Per Command**: ~200-800 bytes (depending on command length and metadata)
- **Search Index**: ~2-5x the database size (for fuzzy search capabilities)
- **Example**: 10,000 commands ≈ 5-8MB total storage

The system automatically manages storage efficiently with configurable cache sizes and cleanup options.

### Can I backup or export my data?

Yes, CommandChronicles provides comprehensive export options:

**Export Formats:**
- `ccr export --format json` - Complete data with metadata
- `ccr export --format bash` - Plain bash history format
- `ccr export --format csv` - Spreadsheet-compatible format

**Backup Strategy:**
- Copy the entire `~/.local/share/commandchronicles/` directory
- Use `ccr export` regularly to create readable backups
- Database files can be backed up while the system is running

**Import Options:**
- `ccr import ~/.bash_history --format bash`
- `ccr import ~/.zsh_history --format zsh`
- Import from JSON exports to restore complete data

**Note**: Exported data includes timestamps, directories, exit codes, and git information, making it more comprehensive than standard shell history files.

---

## Getting Help

If you need additional help:

- Run `ccr --help` for command-line help
- Use `?` in the TUI for interactive help
- Check the [documentation](DOCS.md) for technical details
- Visit [commandchronicles.dev](https://commandchronicles.dev) for more resources

---

*CommandChronicles CLI - Transforming your shell history into a powerful knowledge base*