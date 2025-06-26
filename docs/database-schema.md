# CommandChronicles Database Schema Design

## Overview

The CommandChronicles CLI uses SQLite as its underlying database with a security-focused design that encrypts all sensitive command data while maintaining searchable metadata for efficient filtering and indexing.

## Design Principles

1. **Security First**: All command content is encrypted at rest using XChaCha20-Poly1305 AEAD
2. **Searchable Metadata**: Unencrypted metadata fields enable efficient filtering without decryption
3. **Version Management**: Schema versioning supports future migrations and backwards compatibility
4. **Performance Optimized**: Strategic indexing for common query patterns
5. **Data Integrity**: Foreign key relationships and constraints ensure data consistency

## Database Tables

### 1. history

The primary table storing encrypted command records with searchable metadata.

```sql
CREATE TABLE history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    encrypted_data BLOB NOT NULL,
    timestamp INTEGER NOT NULL,
    session TEXT NOT NULL,
    hostname TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
```

**Field Descriptions:**

- `id`: Auto-incrementing primary key
- `encrypted_data`: Encrypted CommandRecord JSON blob (XChaCha20-Poly1305 AEAD)
- `timestamp`: Unix timestamp in milliseconds (unencrypted for filtering)
- `session`: Session UUID (unencrypted for session-based queries)
- `hostname`: Machine hostname (unencrypted for multi-host filtering)
- `created_at`: Record insertion timestamp in milliseconds

**Encrypted Data Structure:**

The `encrypted_data` field contains an encrypted JSON object with the following structure:

```json
{
    "command": "git commit -m 'Initial commit'",
    "exit_code": 0,
    "duration_ms": 1250,
    "working_dir": "/home/user/project",
    "timestamp_ms": 1640995200000,
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "hostname": "dev-machine",
    "git_root": "/home/user/project",
    "git_branch": "main",
    "git_commit": "a1b2c3d4",
    "user": "username",
    "shell": "bash",
    "tty": "/dev/pts/0",
    "environment": {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "PWD": "/home/user/project"
    },
    "version": 1,
    "created_at_ms": 1640995200000
}
```

### 2. session_metadata

Tracks shell session information for context and cleanup.

```sql
CREATE TABLE session_metadata (
    session_id TEXT PRIMARY KEY,
    start_time INTEGER NOT NULL,
    end_time INTEGER,
    hostname TEXT NOT NULL,
    user_name TEXT NOT NULL,
    shell_type TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
```

**Field Descriptions:**

- `session_id`: UUID identifying the shell session
- `start_time`: Session start timestamp in milliseconds
- `end_time`: Session end timestamp (NULL for active sessions)
- `hostname`: Machine hostname
- `user_name`: Username for the session
- `shell_type`: Shell type (bash, zsh, fish, etc.)
- `created_at`: Record creation timestamp

### 3. schema_version

Tracks database schema versions for migration management.

```sql
CREATE TABLE schema_version (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL,
    description TEXT
);
```

**Field Descriptions:**

- `version`: Schema version number
- `applied_at`: Timestamp when version was applied
- `description`: Human-readable description of the migration

## Indexes

Performance-optimized indexes for common query patterns:

```sql
-- Primary filtering indexes
CREATE INDEX idx_history_timestamp ON history(timestamp);
CREATE INDEX idx_history_session ON history(session);
CREATE INDEX idx_history_hostname ON history(hostname);
CREATE INDEX idx_history_created_at ON history(created_at);

-- Composite index for time-range + session queries
CREATE INDEX idx_history_timestamp_session ON history(timestamp, session);

-- Session metadata indexes
CREATE INDEX idx_session_start_time ON session_metadata(start_time);
CREATE INDEX idx_session_hostname ON session_metadata(hostname);
CREATE INDEX idx_session_user ON session_metadata(user_name);
```

## Data Constraints

### Size Limits

```go
MaxCommandLength    = 65536  // Maximum command text length
MaxWorkingDirLength = 4096   // Maximum working directory path
MaxHostnameLength   = 253    // RFC 1035 hostname limit
MaxSessionIDLength  = 36     // UUID length
MaxEnvironmentVars  = 100    // Maximum environment variables
MaxEnvironmentSize  = 8192   // Maximum environment data size
```

### Schema Versioning

```go
CurrentSchemaVersion = 1
MinSupportedVersion  = 1
```

## Security Considerations

### Encryption Strategy

1. **Field-Level Encryption**: Only sensitive command data is encrypted
2. **Searchable Metadata**: Timestamps, sessions, and hostnames remain unencrypted for indexing
3. **AEAD Protection**: XChaCha20-Poly1305 provides both confidentiality and authenticity
4. **No Key Storage**: Encryption keys are never stored in the database

### Data Exposure Minimization

**Encrypted Fields:**
- Command text and arguments
- Working directory paths
- Environment variables
- Git repository information
- User-specific context

**Unencrypted Fields (for searching):**
- Timestamps (for time-based filtering)
- Session IDs (for session grouping)
- Hostnames (for multi-machine filtering)

## Query Patterns

### Common Queries

**Recent Commands:**
```sql
SELECT encrypted_data FROM history 
WHERE timestamp > ? 
ORDER BY timestamp DESC 
LIMIT 50;
```

**Session-Based Search:**
```sql
SELECT encrypted_data FROM history 
WHERE session = ? 
ORDER BY timestamp ASC;
```

**Time Range with Host Filter:**
```sql
SELECT encrypted_data FROM history 
WHERE timestamp BETWEEN ? AND ? 
  AND hostname = ?
ORDER BY timestamp DESC;
```

**Latest Commands per Session:**
```sql
SELECT h.encrypted_data, h.timestamp, h.session
FROM history h
INNER JOIN (
    SELECT session, MAX(timestamp) as max_time
    FROM history
    GROUP BY session
) latest ON h.session = latest.session 
         AND h.timestamp = latest.max_time;
```

## Migration Strategy

### Version Management

The schema supports forward migrations through the `schema_version` table and migration scripts:

```go
type DatabaseSchema struct {
    Version    int
    Tables     []string
    Indexes    []string
    Migrations map[int][]string  // Version -> SQL statements
}
```

### Future Migration Example

```go
// Example migration for version 2
Migrations: map[int][]string{
    2: []string{
        "ALTER TABLE history ADD COLUMN tags TEXT",
        "CREATE INDEX idx_history_tags ON history(tags)",
        "UPDATE schema_version SET description = 'Added tags support' WHERE version = 2",
    },
}
```

## Data Types and Encoding

### Timestamp Format

All timestamps use Unix milliseconds (int64) for precision and consistency:

```go
timestamp := time.Now().UnixMilli()
```

### Session ID Format

Session IDs use UUID4 format for uniqueness:

```go
sessionID := uuid.New().String() // "550e8400-e29b-41d4-a716-446655440000"
```

### Encryption Format

Encrypted data format:
```
[24-byte nonce][ciphertext][16-byte auth tag]
```

## Performance Characteristics

### Expected Data Growth

- **Commands per day**: ~1,000-10,000 per active user
- **Storage per command**: ~1KB average (encrypted)
- **Database growth**: ~1-10MB per day per user
- **Index overhead**: ~20% of data size

### Query Performance Targets

- **Recent commands (LIMIT 50)**: <10ms
- **Session lookup**: <5ms
- **Time range queries**: <50ms
- **Full-text search**: <200ms (with cache)

### Optimization Strategies

1. **Partial Indexes**: For frequently filtered columns
2. **Vacuum Strategy**: Regular VACUUM INCREMENTAL
3. **Cache Layer**: Hot cache for recent commands
4. **Batch Operations**: For bulk inserts/updates

## Maintenance Operations

### Database Maintenance

```sql
-- Analyze query performance
EXPLAIN QUERY PLAN SELECT * FROM history WHERE timestamp > ?;

-- Update statistics
ANALYZE;

-- Incremental vacuum
PRAGMA incremental_vacuum(1000);

-- Integrity check
PRAGMA integrity_check;
```

### Cleanup Operations

```sql
-- Clean up old sessions (older than 30 days)
DELETE FROM session_metadata 
WHERE end_time IS NOT NULL 
  AND end_time < (strftime('%s', 'now', '-30 days') * 1000);

-- Archive old history (implementation dependent)
-- Note: Requires decryption/re-encryption for archival
```

## Backup and Recovery

### Backup Strategy

1. **SQLite Backup API**: Use SQLite's online backup for consistency
2. **Encrypted Backups**: Maintain encryption in backup files
3. **Incremental Backups**: Track changes since last backup
4. **Cross-Platform**: Ensure backups work across different systems

### Recovery Procedures

1. **Schema Validation**: Verify schema version compatibility
2. **Integrity Check**: Run PRAGMA integrity_check
3. **Migration Check**: Ensure migrations are applied correctly
4. **Key Validation**: Verify encryption keys can decrypt data

## Testing Strategy

### Schema Tests

1. **Migration Testing**: Forward and backward compatibility
2. **Integrity Testing**: Foreign key constraints and data consistency
3. **Performance Testing**: Query performance under load
4. **Encryption Testing**: Verify no plaintext leakage

### Data Validation

1. **Constraint Testing**: Verify size limits and data types
2. **Index Testing**: Ensure indexes improve query performance
3. **Concurrency Testing**: Multi-process access patterns
4. **Corruption Testing**: Recovery from database corruption