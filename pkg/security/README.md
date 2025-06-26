# CommandChronicles CLI - Security Package

This package provides comprehensive security enforcement for the CommandChronicles CLI, focusing on file system permissions and secure data handling for the encrypted shell history system.

## Overview

The security package implements a robust permission enforcement layer that ensures all sensitive data files and directories maintain appropriate Unix file permissions. This is critical for protecting encrypted command history data, session keys, and configuration files from unauthorized access.

## Key Features

- **Secure File Permissions**: Enforces 0600 permissions on sensitive files (database, session keys, config)
- **Secure Directory Permissions**: Enforces 0700 permissions on data directories
- **Permission Validation**: Comprehensive validation and auditing of existing permissions
- **Permission Repair**: Automatic fixing of insecure permissions
- **Integration with Crypto**: Seamless integration with encryption and key derivation systems
- **Cross-Platform Support**: Unix-focused with Windows compatibility awareness
- **Comprehensive Logging**: Detailed security audit logging

## Core Components

### PermissionEnforcer

The main component responsible for enforcing and validating file system permissions.

#### Key Methods

- `SetSecureFilePermissions(path string) error` - Sets 0600 permissions on files
- `SetSecureDirectoryPermissions(path string) error` - Sets 0700 permissions on directories
- `CreateSecureDirectory(path string) error` - Creates directories with secure permissions
- `ValidateFilePermissions(path string, expected os.FileMode) error` - Validates file permissions
- `ValidateDirectoryPermissions(path string, expected os.FileMode) error` - Validates directory permissions
- `SecureDataEnvironment(configDir, dataDir, dbPath, sessionPath string) error` - Secures entire data environment
- `AuditFilePermissions(path string) error` - Performs security audit on files
- `FixFilePermissions(path string) error` - Repairs insecure permissions

#### Convenience Methods

- `IsFileSecure(path string) bool` - Quick check if file has secure permissions
- `IsDirectorySecure(path string) bool` - Quick check if directory has secure permissions
- `ValidateSecureFile(path string) error` - Validates file has 0600 permissions
- `ValidateSecureDirectory(path string) error` - Validates directory has 0700 permissions

## Permission Constants

```go
const (
    SecureFilePermission = 0600  // Read/write for owner only
    SecureDirPermission  = 0700  // Read/write/execute for owner only
    TempFilePermission   = 0600  // Permissions for temporary files
    MaxFilePermission    = 0644  // Maximum allowed file permissions
    MaxDirPermission     = 0755  // Maximum allowed directory permissions
)
```

## Usage Examples

### Basic File Security

```go
pe := security.NewPermissionEnforcer()

// Secure a single file
err := pe.SetSecureFilePermissions("/path/to/database.db")
if err != nil {
    log.Fatalf("Failed to secure file: %v", err)
}

// Validate file permissions
err = pe.ValidateSecureFile("/path/to/database.db")
if err != nil {
    log.Fatalf("File permissions validation failed: %v", err)
}
```

### Directory Security

```go
pe := security.NewPermissionEnforcer()

// Create and secure a directory
err := pe.CreateSecureDirectory("/home/user/.config/commandchronicles")
if err != nil {
    log.Fatalf("Failed to create secure directory: %v", err)
}

// Secure existing directory tree
err = pe.SecureDirectoryTree("/home/user/.local/share/commandchronicles")
if err != nil {
    log.Fatalf("Failed to secure directory tree: %v", err)
}
```

### Complete Environment Security

```go
pe := security.NewPermissionEnforcer()

configDir := "/home/user/.config/commandchronicles"
dataDir := "/home/user/.local/share/commandchronicles"
dbPath := filepath.Join(dataDir, "history.db")
sessionPath := filepath.Join(dataDir, "session.key")

// Secure entire data environment
err := pe.SecureDataEnvironment(configDir, dataDir, dbPath, sessionPath)
if err != nil {
    log.Fatalf("Failed to secure data environment: %v", err)
}

// Validate environment security
err = pe.ValidateDataDirectories(configDir, dataDir)
if err != nil {
    log.Fatalf("Directory validation failed: %v", err)
}

err = pe.ValidateDataFiles(dbPath, sessionPath)
if err != nil {
    log.Fatalf("File validation failed: %v", err)
}
```

### Security Auditing

```go
pe := security.NewPermissionEnforcer()

// Audit file permissions
err := pe.AuditFilePermissions("/path/to/sensitive/file")
if err != nil {
    log.Printf("Security audit failed: %v", err)
    
    // Attempt to fix permissions
    err = pe.FixFilePermissions("/path/to/sensitive/file")
    if err != nil {
        log.Fatalf("Failed to fix permissions: %v", err)
    }
}

// Get detailed permission information
info, err := pe.GetFilePermissionInfo("/path/to/file")
if err != nil {
    log.Fatalf("Failed to get permission info: %v", err)
}

log.Printf("File: %s, Mode: %o, Secure: %v, Owner: %s", 
    info.Path, info.Mode.Perm(), info.IsSecure, info.Owner)
```

## Integration with Crypto System

The permission enforcement system is designed to work seamlessly with the CommandChronicles crypto system:

```go
// Example: Secure encryption workflow
pe := security.NewPermissionEnforcer()
kd := crypto.NewKeyDerivator()
encryptor := crypto.NewEncryptor()

// Derive encryption key
key, err := kd.DeriveKeyFromCredentials("username", "password")
if err != nil {
    log.Fatalf("Key derivation failed: %v", err)
}
defer key.SecureErase()

// Create encrypted data
record := storage.NewCommandRecord("ls -la", 0, 150, "/home/user", "session123", "hostname")
encryptedData, err := encryptor.EncryptRecord(record, key.Key)
if err != nil {
    log.Fatalf("Encryption failed: %v", err)
}

// Store with secure permissions
dbPath := "/secure/path/database.db"
err = os.WriteFile(dbPath, encryptedData, security.SecureFilePermission)
if err != nil {
    log.Fatalf("Failed to write encrypted data: %v", err)
}

// Validate security
if !pe.IsFileSecure(dbPath) {
    log.Fatal("Database file is not secure!")
}
```

## Error Handling

The package provides structured error handling with the `PermissionError` type:

```go
err := pe.ValidateFilePermissions("/path/to/file", security.SecureFilePermission)
if err != nil {
    if security.IsPermissionError(err) {
        permErr := err.(*security.PermissionError)
        log.Printf("Permission error: %s (expected %o, got %o)", 
            permErr.Path, permErr.Expected, permErr.Actual)
    } else {
        log.Printf("Other error: %v", err)
    }
}
```

## Recommended Permissions

The package provides recommended permissions for different file types:

```go
recommendations := security.GetRecommendedPermissions()
// Returns:
// {
//     "database":   0600,
//     "session":    0600,
//     "config":     0600,
//     "config_dir": 0700,
//     "data_dir":   0700,
//     "temp_file":  0600,
// }
```

## Security Considerations

1. **Owner-Only Access**: All sensitive files are restricted to owner-only access (0600)
2. **Directory Protection**: Data directories use 0700 to prevent enumeration
3. **Path Validation**: All paths are validated to prevent directory traversal attacks
4. **Home Directory Scope**: Directory tree operations are limited to user's home directory
5. **Windows Compatibility**: Limited permission enforcement on Windows with appropriate warnings
6. **Audit Logging**: All permission operations are logged for security audit trails

## Testing

The package includes comprehensive test coverage:

- **Unit Tests**: `permissions_test.go` - Tests all core functionality
- **Integration Tests**: `integration_test.go` - Tests integration with crypto system
- **Cross-Platform Tests**: Appropriate skipping on unsupported platforms

Run tests with:

```bash
go test ./pkg/security -v
```

## Platform Support

- **Unix/Linux**: Full permission enforcement
- **macOS**: Full permission enforcement  
- **Windows**: Limited support with warnings (NTFS permissions differ from Unix)

## Dependencies

- `github.com/NeverVane/commandchronicles-cli/internal/logger` - Structured logging
- `github.com/NeverVane/commandchronicles-cli/pkg/crypto` - Crypto system integration
- `github.com/NeverVane/commandchronicles-cli/internal/storage` - Data structures

## Thread Safety

The PermissionEnforcer is designed to be thread-safe for concurrent operations on different paths. However, concurrent operations on the same path should be avoided.