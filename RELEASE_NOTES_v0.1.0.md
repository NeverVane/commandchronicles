# CommandChronicles CLI v0.1.0 - Initial Release 🚀

**Release Date:** December 2024

We're excited to announce the first release of CommandChronicles CLI - a modern shell history management tool that transforms your command line experience with intelligent search, military-grade encryption, and seamless cross-device synchronization.

## 🎉 What's New

This is the **initial release** of CommandChronicles CLI, introducing a comprehensive set of features for advanced shell history management.

## ✨ Key Features

### 🔐 **Military-Grade Security**
- **XChaCha20-Poly1305 encryption** for all command data
- **Argon2id key derivation** with configurable parameters
- **Local-first storage** - your data never leaves your machine unless you enable sync
- **Session management** with configurable timeouts (default: 90 days)

### 🔍 **Intelligent Search**
- **Interactive TUI** accessible via `Ctrl+R` with beautiful interface
- **Fuzzy search** powered by Bleve search engine
- **Smart caching** with hot cache for instant access to recent commands
- **Advanced filtering** by exit code, directory, time range, and more
- **Rich metadata** capture including git info, duration, and context

### 🐚 **Seamless Shell Integration**
- **Automatic installation** for bash and zsh shells
- **Zero-configuration** command capture after setup
- **Rich context capture** including working directory, git branch, exit codes
- **Session tracking** with unique identifiers

### 🌐 **Cross-Device Synchronization** *(Optional)*
- **Perfect Sync** system with integrity verification
- **End-to-end encryption** - server cannot decrypt your data
- **Conflict resolution** with deterministic algorithms  
- **Background daemon** for automatic synchronization
- **Device management** with unique device identification

### 📊 **Analytics & Insights**
- **Command statistics** with usage patterns
- **Performance metrics** and search analytics
- **Export capabilities** to JSON, bash, CSV formats
- **Import support** from existing bash/zsh history

## 🛠 **Installation**

### Quick Install
```bash
# Clone and build
git clone https://github.com/NeverVane/commandchronicles-cli.git
cd commandchronicles-cli
go build -o ccr
sudo mv ccr /usr/local/bin/

# Initialize and setup
ccr init
ccr install-hooks --auto
```

### First-Time Setup
```bash
# Initialize CommandChronicles
ccr init

# Install shell hooks (auto-detects your shell)
ccr install-hooks --auto

# Start using with Ctrl+R in your shell!
```

## 📋 **Core Commands**

| Command | Description |
|---------|-------------|
| `ccr init` | Initialize CommandChronicles |
| `ccr install-hooks` | Install shell integration |
| `ccr search <query>` | Search command history |
| `ccr stats` | View usage statistics |
| `ccr lock/unlock` | Secure your history |
| `ccr import/export` | Data management |
| `ccr sync register` | Enable cross-device sync |
| `ccr daemon-control start` | Start background sync |

## 🎯 **TUI Keybindings**

Access the interactive interface with `Ctrl+R`:

- `↑/↓` - Navigate commands
- `Enter` - Copy to shell prompt  
- `Ctrl+J` - Execute immediately
- `Ctrl+F` - Toggle fuzzy search
- `Ctrl+S/X` - Filter by success/failure
- `Tab` - View detailed info
- `?` - Show help

## 🔧 **Configuration**

CommandChronicles is highly configurable via `~/.config/commandchronicles/config.toml`:

```toml
[cache]
hot_cache_size = 1000      # Commands kept in RAM
max_memory_mb = 100        # Memory limit

[security]
session_timeout = 7776000  # 90 days
argon2_memory = 65536     # 64MB for key derivation

[daemon]
sync_interval = "5m"       # Auto-sync frequency
```

## 🗂 **Data Storage**

- **Database**: `~/.local/share/commandchronicles/commands.db`
- **Configuration**: `~/.config/commandchronicles/config.toml`
- **Session Keys**: `~/.local/share/commandchronicles/session.key`
- **Shell Hooks**: `~/.local/share/commandchronicles/hooks/`

## 🚨 **Important Notes**

- **Shell Restart Required**: After installing hooks, restart your shell or source your RC file
- **TUI Limitations**: Command injection only works when launched via `Ctrl+R` (not `ccr tui` directly)
- **Sync Registration**: Cross-device sync requires account registration at commandchronicles.dev
- **Go Version**: Requires Go 1.23 or later for building from source

## 🐛 **Known Issues**

- Fuzzy search index rebuilds on first search (one-time setup)
- Fish shell support planned for future release
- Some advanced git information may not capture in all repository states

## 🔒 **Security & Privacy**

- **Zero telemetry** - no data collection or tracking
- **Local encryption** using industry-standard algorithms
- **Open source** - fully auditable codebase
- **Optional sync** - works completely offline by default

## 📈 **Performance**

- **Fast startup**: < 100ms TUI launch time
- **Memory efficient**: ~10-50MB RAM usage
- **Storage efficient**: ~200-800 bytes per command
- **Search speed**: Sub-millisecond search on 10k+ commands

## 🔄 **What's Next?**

- Fish shell support
- Enhanced conflict resolution
- Plugin system for extensibility  
- Advanced analytics dashboard
- Mobile companion app

## 🙏 **Acknowledgments**

Built with amazing open-source libraries:
- [Bubble Tea](https://github.com/charmbracelet/bubbletea) - TUI framework
- [Bleve](https://github.com/blevesearch/bleve) - Search engine
- [Cobra](https://github.com/spf13/cobra) - CLI framework
- Go's excellent cryptography libraries

## 📞 **Support**

- 📖 **Documentation**: See [DOCS.md](DOCS.md) for technical details
- ❓ **FAQ**: Check [FAQ.md](FAQ.md) for common questions
- 🐛 **Issues**: Report bugs on [GitHub Issues](https://github.com/NeverVane/commandchronicles-cli/issues)
- 🌐 **Website**: [commandchronicles.dev](https://commandchronicles.dev)

---

**Download**: [Latest Release](https://github.com/NeverVane/commandchronicles-cli/releases/latest)  
**License**: MIT  
**Author**: Leonardo Zanobi ([@NeverVane](https://github.com/NeverVane))

*Transform your shell history into a powerful knowledge base! 🎯*