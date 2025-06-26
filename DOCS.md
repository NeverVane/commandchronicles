# CommandChronicles CLI - Technical Documentation

## Table of Contents

1. [Core Logic & Architecture](#core-logic--architecture)
2. [Security Implementation](#security-implementation)
3. [Usage Guide](#usage-guide)
4. [Configuration](#configuration)
5. [Troubleshooting](#troubleshooting)

---

## Core Logic & Architecture

### Command Capture

CommandChronicles implements a comprehensive command capture system through shell integration hooks:

#### Hook System Architecture
- **Shell Integration**: Generates shell-specific hooks for bash and zsh
- **Session Management**: Each shell session receives a unique UUID for tracking
- **Context Capture**: Collects rich metadata including:
  - Command text and arguments
  - Exit codes and execution duration
  - Working directory and hostname
  - Git repository information (root, branch, commit)
  - Environment variables and shell type

#### Implementation Details
```go
type CommandRecord struct {
    ID          int64             `json:"id"`
    Command     string            `json:"command"`
    ExitCode    int               `json:"exit_code"`
    Duration    int64             `json:"duration_ms"`
    WorkingDir  string            `json:"working_dir"`
    Timestamp   int64             `json:"timestamp_ms"`
    SessionID   string            `json:"session_id"`
    Hostname    string            `json:"hostname"`
    GitRoot     string            `json:"git_root,omitempty"`
    GitBranch   string            `json:"git_branch,omitempty"`
    GitCommit   string            `json:"git_commit,omitempty"`
    User        string            `json:"user"`
    Shell       string            `json:"shell"`
    Environment map[string]string `json:"environment,omitempty"`
}
```

### Data Processing

#### Encryption Pipeline
1. **Command Serialization**: Commands are serialized to JSON
2. **Encryption**: Each record is encrypted using XChaCha20-Poly1305
3. **Database Storage**: Encrypted payloads stored in SQLite with metadata indexes
4. **Memory Management**: Decrypted data is securely cleared from memory

#### Database Schema
```sql
CREATE TABLE history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    encrypted_data BLOB NOT NULL,
    timestamp INTEGER NOT NULL,
    session TEXT NOT NULL,
    hostname TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    device_id TEXT,
    record_hash TEXT,
    last_synced INTEGER,
    sync_status INTEGER DEFAULT 0
);
```

### Sync Logic

#### Perfect Sync System
CommandChronicles implements a "Perfect Sync" system ensuring data integrity across devices:

1. **Integrity Verification**: Hash-based integrity checking
2. **Conflict Resolution**: Deterministic conflict resolution using timestamps and device IDs
3. **Incremental Sync**: Only synchronizes changed/new records
4. **Device Management**: Unique device identification and tracking

#### Sync Architecture Components
- **RemoteAuthenticator**: Handles server authentication using password-derived keys
- **SyncClient**: Manages API communication with the sync server
- **ConflictResolver**: Implements conflict resolution algorithms
- **TokenManager**: Manages authentication tokens and refresh cycles
- **HashGenerator**: Creates deterministic hashes for integrity verification
- **Daemon**: Background service for automatic synchronization

#### Sync Process Flow
```
1. Generate local integrity state (hash checksum of all records)
2. Send integrity request to server with device ID and local state
3. Server responds with missing records and conflict information
4. Download missing records and resolve conflicts
5. Update local database and sync status
6. Confirm successful sync with server
```

### Search Engine

#### Hybrid Search Architecture
CommandChronicles implements a two-tier search system:

1. **Hot Cache**: Configurable number of recent commands kept in RAM
2. **Batch Loading**: Additional commands loaded from database as needed
3. **Fuzzy Search**: Bleve-powered full-text search with scoring

#### Cache Implementation
```go
type Cache struct {
    hotCache        []*CacheEntry
    hotCacheSize    int
    searchBatchSize int
    maxMemoryMB     int
    storage         *SecureStorage
    mu              sync.RWMutex
}

type CacheEntry struct {
    Record      *CommandRecord
    AccessTime  time.Time
    AccessCount int64
    InsertTime  time.Time
    Size        int64
}
```

#### Fuzzy Search Engine
- **Backend**: Bleve search engine with custom mapping
- **Features**: Configurable fuzziness, boost factors for recent/frequent commands
- **Indexing**: Commands are indexed with metadata for enhanced search
- **Scoring**: Relevance scoring with configurable boost parameters

### Background Daemon

CommandChronicles includes a lightweight background daemon for automatic synchronization:

#### Daemon Architecture
```go
type Daemon struct {
    config      *config.Config
    syncService *sync.SyncService
    logger      *logger.Logger
    pidManager  *PIDManager
    authManager *auth.AuthManager
    storage     *securestorage.SecureStorage
    ctx         context.Context
    cancel      context.CancelFunc
}
```

#### Functionality
- **Automatic Sync**: Periodically synchronizes command history in the background
- **Configurable Intervals**: Sync frequency configurable (default: 5 minutes)
- **Retry Logic**: Exponential backoff for failed sync attempts
- **Signal Handling**: Graceful shutdown on SIGINT/SIGTERM, config reload on SIGHUP  
- **PID Management**: Prevents multiple daemon instances
- **Resource Efficient**: Minimal CPU and memory usage when idle

#### Lifecycle Management
- **Start**: `ccr daemon-control start` - Starts daemon process
- **Stop**: `ccr daemon-control stop` - Gracefully stops daemon
- **Restart**: `ccr daemon-control restart` - Restarts with new configuration
- **Status**: `ccr daemon-control status` - Shows daemon status and statistics

---

## Security Implementation

### XChaCha20-Poly1305 Encryption

CommandChronicles uses XChaCha20-Poly1305 for authenticated encryption:

#### Key Features
- **Algorithm**: XChaCha20 stream cipher with Poly1305 MAC
- **Key Size**: 256-bit encryption keys
- **Nonce**: 192-bit extended nonce (XChaCha20 variant)
- **Authentication**: Built-in message authentication preventing tampering

#### Implementation
```go
func (e *Encryptor) Encrypt(data []byte, key []byte) ([]byte, error) {
    cipher, err := chacha20poly1305.NewX(key)
    if err != nil {
        return nil, err
    }
    
    nonce := make([]byte, cipher.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return nil, err
    }
    
    ciphertext := cipher.Seal(nonce, nonce, data, nil)
    return ciphertext, nil
}
```

### Argon2id Key Derivation

Password-based key derivation using Argon2id:

#### Parameters
- **Variant**: Argon2id (hybrid of Argon2i and Argon2d)
- **Time Cost**: 3 iterations (configurable)
- **Memory Cost**: 64MB (configurable)
- **Parallelism**: 1 thread (configurable)
- **Output Length**: 64 bytes (split for local and remote keys)

#### Key Derivation Process
```go
func (kd *KeyDerivator) DeriveKeys(password string, salt []byte) (*KeyDerivationResult, error) {
    key := argon2.IDKey(
        []byte(password),
        salt,
        kd.timeCost,
        kd.memoryCost,
        kd.threads,
        64, // 64 bytes output
    )
    
    return &KeyDerivationResult{
        LocalKey:      key,
        EncryptionKey: key[:32],  // First 32 bytes for local encryption
        RemoteAuthKey: key[32:],  // Last 32 bytes for server authentication
        Salt:          salt,
    }, nil
}
```

### Privacy Model

#### Data Protection Principles
1. **Local-First**: All data stored locally by default
2. **Zero-Knowledge**: Server cannot decrypt user data
3. **Minimal Metadata**: Only necessary metadata stored unencrypted
4. **Session Security**: Configurable session timeouts with automatic cleanup
5. **Memory Protection**: Sensitive data cleared from memory after use

#### Threat Model
- **Protection Against**: Disk theft, memory dumps, network interception
- **Assumptions**: Trusted local environment, secure password practices
- **Limitations**: Cannot protect against compromised local system

---

## Usage Guide

### Basic Commands

#### Installation and Setup
```bash
# Initialize CommandChronicles
ccr init

# Install shell hooks (auto-detects shell)
ccr install-hooks --auto

# Install for specific shell
ccr install-hooks bash
ccr install-hooks zsh

# Verify installation
ccr status
```

#### Authentication
```bash
# Lock command history (requires password)
ccr lock

# Unlock for searching
ccr unlock

# Change password
ccr change-password

# Check session status
ccr status
```

#### Search Operations
```bash
# Interactive TUI search (use Ctrl+R in shell)
# Direct command line search
ccr search "git commit"

# Fuzzy search
ccr search --fuzzy "gt sttus"

# Filter by exit code
ccr search --exit-code 0 "docker"

# Filter by directory
ccr search --directory /project "npm"

# Time-based filtering
ccr search --since 1h "build"
ccr search --since 2d --until 1d "test"
```

#### Data Management
```bash
# Import existing history
ccr import ~/.bash_history --format bash
ccr import ~/.zsh_history --format zsh

# Export command history
ccr export --format json > commands.json
ccr export --format bash > commands.bash

# View statistics
ccr stats
ccr stats --format json

# Delete specific commands
ccr delete --query "sensitive-command"

# Complete data wipe
ccr wipe --confirm
```

#### Sync Operations
```bash
# Register for sync
ccr sync register

# Enable sync
ccr sync enable

# Check sync status
ccr sync status

# Manual sync
ccr sync now

# Verify integrity
ccr sync integrity

# Disable sync
ccr sync disable

# Cancel subscription
ccr cancel-subscription
```

#### Daemon Operations
```bash
# Start background sync daemon
ccr daemon-control start

# Stop sync daemon
ccr daemon-control stop

# Restart daemon (useful after config changes)
ccr daemon-control restart

# Check daemon status
ccr daemon-control status

# Install system service for automatic startup
ccr daemon-control install-service

# Remove system service
ccr daemon-control remove-service
```

---

## Configuration

### Config File Structure

Configuration is stored in `~/.config/commandchronicles/config.toml`:

```toml
[database]
path = "~/.local/share/commandchronicles/commands.db"
max_open_conns = 10
max_idle_conns = 5
wal_mode = true
pragma_settings = [
    "PRAGMA journal_mode=WAL",
    "PRAGMA synchronous=NORMAL",
    "PRAGMA cache_size=10000",
    "PRAGMA temp_store=memory"
]

[cache]
hot_cache_size = 1000
search_batch_size = 5000
max_memory_mb = 100
refresh_interval_seconds = 300
eviction_policy = "lru"
maintenance_interval_minutes = 60

[security]
session_key_path = "~/.local/share/commandchronicles/session.key"
session_timeout = 7776000  # 90 days
argon2_time = 3
argon2_memory = 65536      # 64MB
argon2_threads = 1
memory_lock_enabled = true
secure_deletion = true

[tui]
launch_timeout_ms = 2000
syntax_highlighting = true
color_scheme = "auto"      # auto, dark, light
animations = true
results_per_page = 20
fuzzy_search_default = false

[shell]
enabled = true
supported_shells = ["bash", "zsh"]
bash_hook_path = "~/.local/share/commandchronicles/hooks/bash_hook.sh"
zsh_hook_path = "~/.local/share/commandchronicles/hooks/zsh_hook.sh"
auto_install = false
graceful_degradation = true
capture_environment = false

[import_export]
default_format = "auto"
deduplicate = true
batch_size = 1000
supported_formats = ["bash", "zsh", "json", "csv"]

[sync]
enabled = false
server_url = "https://api.commandchronicles.dev"
email = ""
sync_interval_seconds = 3600
auto_sync = true
conflict_resolution = "timestamp"
device_name = ""
compression_enabled = true

[daemon]
sync_interval = "5m"           # Sync every 5 minutes
retry_interval = "30s"         # Wait 30 seconds before retry
max_retries = 3                # Maximum retry attempts
log_level = "info"             # Daemon log level
enable_metrics = false         # Enable performance metrics
health_check_interval = "30s"  # Health check frequency
max_concurrent_syncs = 3       # Maximum concurrent sync operations
pid_file = "~/.local/share/commandchronicles/daemon.pid"
log_file = "~/.local/share/commandchronicles/daemon.log"
daemonize = false              # Run as background process
auto_start = false             # Auto-start daemon when needed
system_service = false         # Register as system service
```

### Environment Variables

CommandChronicles respects the following environment variables:

- `CCR_CONFIG_DIR`: Override config directory location
- `CCR_DATA_DIR`: Override data directory location
- `CCR_LOG_LEVEL`: Set logging level (debug, info, warn, error)
- `CCR_SESSION_TIMEOUT`: Override session timeout
- `CCR_DISABLE_HOOKS`: Disable hook functionality
- `CCR_SERVER_URL`: Override sync server URL

---

## Troubleshooting

### Common Issues

#### Installation Problems
**Issue**: Hooks not working after installation
```bash
# Verify hook files exist
ls -la ~/.local/share/commandchronicles/hooks/

# Check shell configuration
echo $SHELL
ccr install-hooks --auto --verbose

# Manually source hooks (temporary fix)
source ~/.local/share/commandchronicles/hooks/bash_hook.sh
```

**Issue**: Permission denied errors
```bash
# Fix permissions
chmod 700 ~/.local/share/commandchronicles/
chmod 600 ~/.local/share/commandchronicles/commands.db
```

#### Authentication Issues
**Issue**: Session expired or authentication failed
```bash
# Check session status
ccr status

# Re-authenticate
ccr unlock

# Reset session if corrupted
rm ~/.local/share/commandchronicles/session.key
ccr unlock
```

#### Search Performance
**Issue**: Slow search results
```bash
# Check cache configuration
ccr stats

# Increase cache size in config
[cache]
hot_cache_size = 2000
max_memory_mb = 200

# Rebuild search index
rm -rf ~/.local/share/commandchronicles/search_index/
ccr search "test"  # Rebuilds index
```

#### Sync Problems
**Issue**: Sync failures or conflicts
```bash
# Check sync status
ccr sync status

# Verify integrity
ccr sync integrity

# Force full sync
ccr sync now --force

# Reset sync state (last resort)
ccr sync disable
ccr sync enable
```

#### Daemon Issues
**Issue**: Daemon not starting or stopping unexpectedly
```bash
# Check daemon status
ccr daemon-control status

# Check for stale PID files
rm ~/.local/share/commandchronicles/daemon.pid

# Restart daemon
ccr daemon-control restart

# Check daemon log file directly
tail -f ~/.local/share/commandchronicles/daemon.log
```

**Issue**: Frequent sync failures in daemon mode
```bash
# Check daemon status
ccr daemon-control status

# Increase retry settings in config
[daemon]
retry_interval = "1m"
max_retries = 5

# Check authentication
ccr sync status

# Check daemon logs
tail -f ~/.local/share/commandchronicles/daemon.log
```

### Debug Mode

Enable comprehensive debugging:

```bash
# Enable debug logging
export CCR_LOG_LEVEL=debug

# Run with verbose output
ccr --verbose search "test"

# Generate debug report
ccr debug --output debug-report.json

# Check system status
ccr debug --system-info
```

#### Debug Command Output
The `ccr debug` command provides:
- System information (OS, shell, version)
- Configuration validation
- Database integrity checks
- Cache statistics
- Search index status
- Hook installation verification
- Daemon status information
- Recent error logs

### Performance Tuning

#### Database Optimization
```toml
[database]
pragma_settings = [
    "PRAGMA journal_mode=WAL",
    "PRAGMA synchronous=NORMAL",
    "PRAGMA cache_size=20000",     # Increase cache
    "PRAGMA temp_store=memory",
    "PRAGMA mmap_size=268435456"   # 256MB memory mapping
]
```

#### Cache Tuning
```toml
[cache]
hot_cache_size = 2000              # More commands in RAM
search_batch_size = 10000          # Larger batch loads
max_memory_mb = 200                # More memory usage
refresh_interval_seconds = 600     # Less frequent refreshes
```

#### Search Optimization
```toml
[tui]
results_per_page = 50              # More results per page
fuzzy_search_default = false       # Disable fuzzy by default
```

### Error Codes

CommandChronicles uses standard exit codes:
- `0`: Success
- `1`: General error
- `2`: Authentication failure
- `3`: Database error
- `4`: Network/sync error
- `5`: Configuration error
- `6`: Permission error

---

## API Reference

For developers extending CommandChronicles, the main packages provide:

- `internal/auth`: Authentication and session management
- `internal/storage`: Database operations and schema
- `internal/search`: Search engine and caching
- `internal/sync`: Cross-device synchronization
- `pkg/crypto`: Cryptographic primitives
- `pkg/security`: Security utilities

Refer to the source code for detailed API documentation and examples.

---

*CommandChronicles CLI - Advanced shell history management with security and sync*