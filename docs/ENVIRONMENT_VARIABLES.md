# Environment Variables

CommandChronicles CLI supports several environment variables for configuration and customization.

## Data Directory Override

### `CCR_DATA_DIR`

**Purpose**: Override the default data directory location for CommandChronicles storage.

**Default**: `~/.local/share/commandchronicles`

**Usage**:
```bash
export CCR_DATA_DIR="/custom/path/to/data"
ccr init
```

**Common Use Cases**:

1. **Docker Containers**:
   ```bash
   docker run -e CCR_DATA_DIR=/app/data -v /host/data:/app/data myimage
   ```

2. **Kubernetes Deployments**:
   ```yaml
   env:
     - name: CCR_DATA_DIR
       value: /persistent-volume/ccr-data
   ```

3. **CI/CD Pipelines**:
   ```bash
   CCR_DATA_DIR=/tmp/test-$BUILD_ID ./ccr test
   ```

4. **Testing Environments**:
   ```bash
   CCR_DATA_DIR=/tmp/ccr-test-$(date +%s) ./ccr init testuser
   ```

5. **Network Storage**:
   ```bash
   export CCR_DATA_DIR="/mnt/shared/ccr-data"
   ```

**Security Requirements**:
- Must be an absolute path
- Directory will be created with 0700 permissions
- Path is validated for security (no path traversal attacks)

**Files Affected**:
When `CCR_DATA_DIR` is set, the following files are relocated:
- `history.db` - SQLite database
- `session` - Session key file
- `user.json` - User configuration
- `hooks/` - Shell integration hooks
- `search_index/` - Fuzzy search index

## Session Management

### `CCR_SESSION_ID`

**Purpose**: Unique identifier for shell sessions used by CommandChronicles hooks.

**Auto-generated**: Yes, by shell hooks

**Usage**: Typically set automatically by shell integration hooks.

**Manual Usage**:
```bash
export CCR_SESSION_ID="custom-session-$(date +%s)"
ccr record "echo test" 0 100
```

## Logging and Debug

### `CCR_VERBOSE`

**Purpose**: Enable verbose logging output.

**Values**: Any non-empty value enables verbose mode

**Usage**:
```bash
export CCR_VERBOSE=1
ccr sync now
```

### `CCR_DEBUG`

**Purpose**: Enable debug logging and show internal operations.

**Values**: Any non-empty value enables debug mode

**Usage**:
```bash
export CCR_DEBUG=1
ccr init
```

**Effect**: Shows data directory overrides and internal state changes.

## Shell Integration

### `SHELL`

**Purpose**: Used to detect the current shell for automatic hook installation.

**Auto-detected**: Yes, by the system

**Usage**: Typically set by your shell automatically.

**Manual Override**:
```bash
export SHELL=/bin/zsh
ccr install-hooks --auto
```

### `TTY`

**Purpose**: Terminal device information captured with command records.

**Auto-detected**: Yes, by the system

**Usage**: Automatically captured during command recording.

## System Integration

### `HOME`

**Purpose**: Used to determine default configuration and data directories.

**Auto-detected**: Yes, by the system

**Default Paths**:
- Config: `$HOME/.config/commandchronicles/`
- Data: `$HOME/.local/share/commandchronicles/`

## Server Configuration (Sync)

### `CCR_SERVER_URL`

**Purpose**: Default sync server URL (future feature).

**Usage**:
```bash
export CCR_SERVER_URL="https://sync.example.com"
ccr sync enable --email user@example.com
```

### `CCR_SYNC_TOKEN`

**Purpose**: Pre-configured sync authentication token (future feature).

**Security**: Should be kept secret, stored securely.

**Usage**:
```bash
export CCR_SYNC_TOKEN="eyJhbGciOiJIUzI1NiIs..."
ccr sync now
```

## Testing and Development

### `CCR_TEST_MODE`

**Purpose**: Enable test mode with reduced security for automated testing.

**Values**: `1` or `true` to enable

**Usage**:
```bash
export CCR_TEST_MODE=1
export CCR_DATA_DIR=/tmp/ccr-test
ccr init testuser
```

**Security Warning**: Only use in testing environments. Reduces encryption and validation.

## Environment Variable Precedence

1. **Command-line flags** (highest priority)
2. **Environment variables**
3. **Configuration file**
4. **Built-in defaults** (lowest priority)

Example:
```bash
# This combination works together
export CCR_DATA_DIR="/custom/data"
export CCR_VERBOSE=1
ccr --config /custom/config.toml search "git"
```

## Best Practices

### Production Environments

1. **Use absolute paths**:
   ```bash
   export CCR_DATA_DIR="/opt/ccr/data"
   ```

2. **Set proper permissions**:
   ```bash
   mkdir -p /opt/ccr/data
   chmod 700 /opt/ccr/data
   export CCR_DATA_DIR="/opt/ccr/data"
   ```

3. **Use persistent storage**:
   ```bash
   # In Docker
   docker run -v ccr-data:/app/data -e CCR_DATA_DIR=/app/data
   ```

### Development and Testing

1. **Isolated environments**:
   ```bash
   export CCR_DATA_DIR="/tmp/ccr-dev-$(whoami)"
   ```

2. **Automated cleanup**:
   ```bash
   TEST_DIR="/tmp/ccr-test-$$"
   export CCR_DATA_DIR="$TEST_DIR"
   trap "rm -rf $TEST_DIR" EXIT
   ```

3. **Debug mode**:
   ```bash
   export CCR_DEBUG=1
   export CCR_VERBOSE=1
   ```

## Security Considerations

1. **Directory Permissions**: All CCR directories are created with 0700 (owner-only access)

2. **Path Validation**: `CCR_DATA_DIR` is validated for security:
   - Must be absolute path
   - No path traversal attempts
   - Cleaned of dangerous components

3. **Sensitive Data**: Never set sensitive tokens in permanent environment files:
   ```bash
   # Bad - stored in shell history
   export CCR_SYNC_TOKEN="secret123"
   
   # Good - temporary session only
   read -s CCR_SYNC_TOKEN
   export CCR_SYNC_TOKEN
   ```

## Troubleshooting

### Permission Errors
```bash
# Check directory permissions
ls -la $(dirname $CCR_DATA_DIR)

# Fix permissions
chmod 700 $CCR_DATA_DIR
```

### Path Issues
```bash
# Verify environment variable
echo "CCR_DATA_DIR: $CCR_DATA_DIR"

# Check if path is absolute
[[ "$CCR_DATA_DIR" = /* ]] && echo "Absolute" || echo "Relative (invalid)"
```

### Debug Information
```bash
# Show all CCR-related environment variables
env | grep CCR_

# Show effective configuration
CCR_DEBUG=1 ccr debug
```