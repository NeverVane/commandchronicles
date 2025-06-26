# CommandChronicles CLI (ccr)

```
===================================================================
                CommandChronicles CLI (ccr) v0.1.0
===================================================================

  🚀 A modern shell history management tool that supercharges
     your command line experience with intelligent search
                and secure local storage

===================================================================
```

<p align="center">
  <a href="https://github.com/NeverVane/commandchronicles/releases">
    <img src="https://img.shields.io/badge/version-0.1.0-blue.svg" alt="Version">
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
- 📊 **Rich command metadata** (exit codes, duration, working directory, git info)
- 🐚 **Seamless shell integration** for bash and zsh with automatic setup
- 🔑 **Secure key derivation** (Argon2id) and session management
- ⚡ **Smart caching system** for instant search results
- 📈 **Beautiful command statistics** and usage analytics

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
