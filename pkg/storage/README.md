# CommandChronicles CLI - Secure Storage Package

This package provides the high-level secure storage and retrieval API for the CommandChronicles CLI, integrating all security components (encryption, key derivation, permission enforcement) with database operations.

## Overview

The secure storage system is the core component that brings together all the security subsystems to provide encrypted, authenticated, and permission-enforced storage of command history records. It acts as the primary interface between the application and the underlying encrypted database.

## Key Features

- **Unified Security API**: Combines database operations, encryption/decryption, and permission enforcement in a single interface
- **Session-Based Access Control**: Lock/unlock mechanism with session key management
- **Cross-Device Compatibility**: Deterministic encryption allows data access from multiple devices with same credentials
- **Comprehensive Security**: File permissions, encryption, authentication, and audit logging
- **Query Capabilities**: Flexible querying with filtering, pagination, and sorting
- **Statistics and Monitoring**: Built-in operation statistics and security violation tracking
- **Integrity Validation**: Comprehensive integrity checking for data and cryptographic operations

## Architecture

### Core Components

```
SecureStorage
├── Database (SQLite with secure configuration)
├── KeyDerivator (Argon2id key derivation)
├── Encryptor (XChaCha20-Poly1305 AEAD)
├── SessionManager (Session key management)
├── PermissionEnforcer (File system security)
└── Logger (Security audit logging)
```

### Data Flow

1. **Initialization**: Set up database, crypto components, and secure environment
2. **Authentication**: Derive master key from username/password
3. **Session Management**: Create/load encrypted session keys
4. **Storage Operations**: Encrypt data before database storage
5. **Retrieval Operations**: Decrypt data after database retrieval
6. **Security Validation**: Continuous permission and integrity checking

## Usage Examples

### Basic Setup

```go
package main

import (
    "github.com/NeverVane/commandchronicles-cli/internal/config"
    "github.com/NeverVane/commandchronicles-cli/pkg/storage"
)

func main() {
    // Load configuration
    cfg := &config.Config{
        Database: config.DatabaseConfig{
            Path: "/home/user/.local/share/commandchronicles/history.db",
            MaxOpenConns: 10,
            MaxIdleConns: 5,
            WALMode: true,
            SyncMode: "NORMAL",
        },
        Security: config.SecurityConfig{
            SessionKeyPath: "/home/user/.local/share/commandchronicles/session.key",
            SessionTimeout: 7776000, // 3 months
            Argon2Time: 3,
            Argon2Memory: 65536, // 64MB
            Argon2Threads: 4,
        },
    }

    // Create secure storage
    opts := &storage.StorageOptions{
        Config:              cfg,
        EnableSecureDelete:  true,
        ValidatePermissions: true,
        CreateIfMissing:     true,
    }

    secureStorage, err := storage.NewSecureStorage(opts)
    if err != nil {
        log.Fatal(err)
    }
    defer secureStorage.Close()
}
```

### Authentication and Session Management

```go
// Unlock storage with credentials
err := secureStorage.Unlock("username", "password")
if err != nil {
    log.Fatalf("Failed to unlock storage: %v", err)
}

// Check if storage is locked
if secureStorage.IsLocked() {
    log.Println("Storage is locked")
    return
}

// Lock storage when done
err = secureStorage.Lock()
if err != nil {
    log.Printf("Failed to lock storage: %v", err)
}
```

### Storing Command Records

```go
// Create a command record
record := storage.NewCommandRecord(
    "git commit -m 'Add new feature'",
    0,                    // exit code
    1500,                 // duration in ms
    "/home/user/project", // working directory
    "session-123",        // session ID
    "dev-laptop",         // hostname
)

// Add additional context
record.User = "developer"
record.Shell = "zsh"
record.GitRoot = "/home/user/project"
record.GitBranch = "feature-branch"

// Store the record
result, err := secureStorage.Store(record)
if err != nil {
    log.Fatalf("Failed to store record: %v", err)
}

log.Printf("Stored record ID: %d, Size: %d bytes", 
    result.RecordID, result.EncryptedSize)
```

### Querying Command History

```go
// Basic retrieval
opts := &storage.QueryOptions{
    Limit: 50,
    Offset: 0,
}

result, err := secureStorage.Retrieve(opts)
if err != nil {
    log.Fatalf("Failed to retrieve records: %v", err)
}

log.Printf("Retrieved %d records (total: %d)", 
    len(result.Records), result.TotalCount)

// Advanced filtering
opts = &storage.QueryOptions{
    SessionID:  "session-123",
    Hostname:   "dev-laptop",
    Since:      &time.Time{}, // last week
    Until:      &time.Time{}, // now
    OrderBy:    "timestamp",
    Ascending:  false,
    Limit:      100,
}

result, err = secureStorage.Retrieve(opts)
if err != nil {
    log.Fatalf("Failed to retrieve filtered records: %v", err)
}

// Process results
for _, record := range result.Records {
    fmt.Printf("[%s] %s (exit: %d, duration: %dms)\n",
        time.UnixMilli(record.Timestamp).Format("15:04:05"),
        record.Command,
        record.ExitCode,
        record.Duration,
    )
}
```

### Pagination Support

```go
const pageSize = 20
var offset int

for {
    opts := &storage.QueryOptions{
        Limit:  pageSize,
        Offset: offset,
        OrderBy: "timestamp",
        Ascending: false,
    }

    result, err := secureStorage.Retrieve(opts)
    if err != nil {
        log.Fatalf("Failed to retrieve page: %v", err)
    }

    if len(result.Records) == 0 {
        break // No more records
    }

    // Process page of records
    processRecords(result.Records)

    if !result.HasMore {
        break // Last page
    }

    offset += pageSize
}
```

### Deleting Records

```go
// Delete specific records by ID
recordIDs := []int64{1, 2, 3, 4, 5}

err := secureStorage.Delete(recordIDs)
if err != nil {
    log.Fatalf("Failed to delete records: %v", err)
}

log.Printf("Deleted %d records", len(recordIDs))
```

### Statistics and Monitoring

```go
// Get storage statistics
stats := secureStorage.GetStats()

fmt.Printf("Storage Statistics:\n")
fmt.Printf("  Records Stored: %d\n", stats.RecordsStored)
fmt.Printf("  Records Retrieved: %d\n", stats.RecordsRetrieved)
fmt.Printf("  Bytes Encrypted: %d\n", stats.BytesEncrypted)
fmt.Printf("  Bytes Decrypted: %d\n", stats.BytesDecrypted)
fmt.Printf("  Security Violations: %d\n", stats.SecurityViolations)
fmt.Printf("  Last Operation: %v\n", stats.LastOperation)
```

### Integrity Validation

```go
// Perform comprehensive integrity check
err := secureStorage.ValidateIntegrity()
if err != nil {
    log.Fatalf("Integrity validation failed: %v", err)
}

log.Println("Storage integrity validated successfully")
```

## API Reference

### SecureStorage

#### Constructor

- `NewSecureStorage(opts *StorageOptions) (*SecureStorage, error)`

#### Authentication Methods

- `Unlock(username, password string) error`
- `Lock() error`
- `IsLocked() bool`

#### Storage Operations

- `Store(record *CommandRecord) (*StoreResult, error)`
- `Retrieve(opts *QueryOptions) (*RetrieveResult, error)`
- `Delete(recordIDs []int64) error`

#### Management Methods

- `GetStats() StorageStats`
- `ValidateIntegrity() error`
- `Close() error`

### Data Structures

#### StorageOptions
```go
type StorageOptions struct {
    Config              *config.Config
    AutoLockTimeout     time.Duration
    EnableSecureDelete  bool
    ValidatePermissions bool
    CreateIfMissing     bool
}
```

#### QueryOptions
```go
type QueryOptions struct {
    Limit      int
    Offset     int
    SessionID  string
    Hostname   string
    Since      *time.Time
    Until      *time.Time
    Command    string
    ExitCode   *int
    WorkingDir string
    OrderBy    string
    Ascending  bool
}
```

#### StoreResult
```go
type StoreResult struct {
    RecordID      int64
    BytesStored   int64
    EncryptedSize int64
    StoredAt      time.Time
}
```

#### RetrieveResult
```go
type RetrieveResult struct {
    Records       []*CommandRecord
    TotalCount    int64
    HasMore       bool
    DecryptedSize int64
    RetrievedAt   time.Time
}
```

#### StorageStats
```go
type StorageStats struct {
    RecordsStored      int64
    RecordsRetrieved   int64
    BytesEncrypted     int64
    BytesDecrypted     int64
    SecurityViolations int64
    LastOperation      time.Time
}
```

## Error Handling

### Common Errors

- `ErrStorageLocked`: Storage is locked and requires authentication
- `ErrInvalidCredentials`: Invalid username or password provided
- `ErrPermissionViolation`: File permission security violation detected
- `ErrRecordNotFound`: Requested record does not exist
- `ErrInvalidInput`: Invalid input parameters provided
- `ErrSessionExpired`: Session has expired and requires re-authentication
- `ErrStorageCorrupted`: Storage corruption detected

### Error Handling Patterns

```go
// Handle specific error types
_, err := secureStorage.Store(record)
if err != nil {
    switch {
    case errors.Is(err, storage.ErrStorageLocked):
        log.Println("Please unlock storage first")
        return
    case errors.Is(err, storage.ErrPermissionViolation):
        log.Println("Security violation detected")
        return
    case errors.Is(err, storage.ErrSessionExpired):
        log.Println("Session expired, please re-authenticate")
        return
    default:
        log.Printf("Storage error: %v", err)
        return
    }
}
```

## Security Considerations

### File Permissions
- Database files: 0600 (read/write owner only)
- Session key files: 0600 (read/write owner only)
- Data directories: 0700 (read/write/execute owner only)

### Encryption Details
- **Algorithm**: XChaCha20-Poly1305 AEAD
- **Key Size**: 256 bits
- **Nonce**: 192 bits (random per record)
- **Authentication**: Built-in AEAD authentication

### Key Derivation
- **Algorithm**: Argon2id
- **Time Parameter**: 3 iterations
- **Memory**: 64MB
- **Threads**: 4
- **Salt**: Username-based for deterministic derivation

### Session Security
- **Timeout**: Configurable (default: 3 months)
- **Storage**: Encrypted session key files
- **Rotation**: Automatic on timeout or manual lock/unlock

## Cross-Device Usage

The system supports cross-device access through deterministic key derivation:

```go
// Device 1: Store data
device1Storage.Unlock("user", "password")
device1Storage.Store(record)

// Device 2: Access same data (shared database file)
device2Storage.Unlock("user", "password") // Same credentials
result, _ := device2Storage.Retrieve(opts) // Decrypts successfully
```

## Performance Considerations

- **Bulk Operations**: Store/retrieve operations are optimized for individual records
- **Pagination**: Use pagination for large result sets to manage memory
- **Connection Pooling**: Database connection pooling reduces overhead
- **Encryption Overhead**: ~40 bytes per record (nonce + auth tag)
- **Index Usage**: Queries leverage database indexes for performance

## Testing

The package includes comprehensive test coverage:

- **Unit Tests**: Individual component testing
- **Integration Tests**: Full workflow testing
- **Security Tests**: Permission and encryption validation
- **Performance Tests**: Bulk operation benchmarks
- **Cross-Device Tests**: Multi-instance compatibility

Run tests:
```bash
go test ./pkg/storage -v
go test ./pkg/storage -run TestSecureStorage_CompleteWorkflow -v
go test ./pkg/storage -bench=. -benchmem
```

## Dependencies

- `internal/config`: Configuration management
- `internal/storage`: Database schema and operations
- `pkg/crypto`: Encryption and key derivation
- `pkg/security`: File permission enforcement
- `internal/logger`: Security audit logging

## Thread Safety

The SecureStorage type is designed to be thread-safe for concurrent operations:
- Internal mutex protects session state
- Database connection pooling handles concurrent queries
- Separate operations on different records are safe
- Statistics updates are atomic

## Limitations

- **Platform Support**: Full security features require Unix-like systems
- **File System**: Requires file system that supports Unix permissions
- **Memory**: Key material is kept in memory during unlocked sessions
- **Concurrent Access**: Multiple processes cannot safely share the same database
- **Database Size**: Performance may degrade with very large databases (>1M records)