package security

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/NeverVane/commandchronicles-cli/internal/logger"
)

// File permission constants for secure operation
const (
	// Secure file permissions (read/write for owner only)
	SecureFilePermission = 0600
	
	// Secure directory permissions (read/write/execute for owner only)
	SecureDirPermission = 0700
	
	// Permissions for temporary files
	TempFilePermission = 0600
	
	// Maximum allowed permissions for data files
	MaxFilePermission = 0644
	
	// Maximum allowed permissions for directories
	MaxDirPermission = 0755
)

// PermissionEnforcer handles file and directory permission enforcement
type PermissionEnforcer struct {
	logger *logger.Logger
}

// PermissionError represents a permission-related error
type PermissionError struct {
	Path        string
	Expected    os.FileMode
	Actual      os.FileMode
	Operation   string
	Message     string
}

func (pe *PermissionError) Error() string {
	return fmt.Sprintf("permission error on %s: %s (expected %o, got %o)", 
		pe.Path, pe.Message, pe.Expected, pe.Actual)
}

// FilePermissionInfo contains information about a file's permissions
type FilePermissionInfo struct {
	Path        string
	Mode        os.FileMode
	IsSecure    bool
	Owner       string
	Size        int64
	ModTime     time.Time
}

// NewPermissionEnforcer creates a new permission enforcer
func NewPermissionEnforcer() *PermissionEnforcer {
	return &PermissionEnforcer{
		logger: logger.GetLogger().Security(),
	}
}

// SetSecureFilePermissions sets secure permissions on a file (0600)
func (pe *PermissionEnforcer) SetSecureFilePermissions(path string) error {
	if err := pe.validatePath(path); err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}
	
	pe.logger.WithField("path", path).Debug().Msg("Setting secure file permissions")
	
	if err := os.Chmod(path, SecureFilePermission); err != nil {
		pe.logger.WithError(err).WithField("path", path).Error().Msg("Failed to set secure file permissions")
		return fmt.Errorf("failed to set permissions on %s: %w", path, err)
	}
	
	// Verify permissions were set correctly
	if err := pe.ValidateFilePermissions(path, SecureFilePermission); err != nil {
		pe.logger.WithError(err).WithField("path", path).Warn().Msg("File permissions verification failed after setting")
		return fmt.Errorf("permission verification failed: %w", err)
	}
	
	pe.logger.WithField("path", path).Info().Msg("Secure file permissions set successfully")
	return nil
}

// SetSecureDirectoryPermissions sets secure permissions on a directory (0700)
func (pe *PermissionEnforcer) SetSecureDirectoryPermissions(path string) error {
	if err := pe.validatePath(path); err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}
	
	pe.logger.WithField("path", path).Debug().Msg("Setting secure directory permissions")
	
	if err := os.Chmod(path, SecureDirPermission); err != nil {
		pe.logger.WithError(err).WithField("path", path).Error().Msg("Failed to set secure directory permissions")
		return fmt.Errorf("failed to set permissions on %s: %w", path, err)
	}
	
	// Verify permissions were set correctly
	if err := pe.ValidateDirectoryPermissions(path, SecureDirPermission); err != nil {
		pe.logger.WithError(err).WithField("path", path).Warn().Msg("Directory permissions verification failed after setting")
		return fmt.Errorf("permission verification failed: %w", err)
	}
	
	pe.logger.WithField("path", path).Info().Msg("Secure directory permissions set successfully")
	return nil
}

// CreateSecureDirectory creates a directory with secure permissions
func (pe *PermissionEnforcer) CreateSecureDirectory(path string) error {
	if err := pe.validatePath(path); err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}
	
	pe.logger.WithField("path", path).Debug().Msg("Creating secure directory")
	
	// Create directory with secure permissions
	if err := os.MkdirAll(path, SecureDirPermission); err != nil {
		pe.logger.WithError(err).WithField("path", path).Error().Msg("Failed to create secure directory")
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}
	
	// Ensure all parent directories also have secure permissions
	if err := pe.SecureDirectoryTree(path); err != nil {
		pe.logger.WithError(err).WithField("path", path).Warn().Msg("Failed to secure directory tree")
		// Don't fail the operation for this, just log the warning
	}
	
	pe.logger.WithField("path", path).Info().Msg("Secure directory created successfully")
	return nil
}

// SecureDirectoryTree ensures all directories in the path have secure permissions
func (pe *PermissionEnforcer) SecureDirectoryTree(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}
	
	// Get user's home directory to avoid modifying system directories
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}
	
	// Only secure directories under user's home directory
	if !strings.HasPrefix(absPath, homeDir) {
		pe.logger.WithField("path", absPath).Debug().Msg("Skipping directory outside home directory")
		return nil
	}
	
	dir := absPath
	for dir != homeDir && dir != "/" {
		if err := pe.SetSecureDirectoryPermissions(dir); err != nil {
			pe.logger.WithError(err).WithField("path", dir).Warn().Msg("Failed to secure directory in tree")
		}
		dir = filepath.Dir(dir)
	}
	
	return nil
}

// ValidateFilePermissions validates that a file has the expected permissions
func (pe *PermissionEnforcer) ValidateFilePermissions(path string, expected os.FileMode) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat file %s: %w", path, err)
	}
	
	if info.IsDir() {
		return fmt.Errorf("path %s is a directory, not a file", path)
	}
	
	actual := info.Mode().Perm()
	if actual != expected {
		pe.logger.WithFields(map[string]interface{}{
			"path":     path,
			"expected": fmt.Sprintf("%o", expected),
			"actual":   fmt.Sprintf("%o", actual),
		}).Warn().Msg("File permissions validation failed")
		
		return &PermissionError{
			Path:      path,
			Expected:  expected,
			Actual:    actual,
			Operation: "validate_file",
			Message:   "file permissions are not secure",
		}
	}
	
	return nil
}

// ValidateDirectoryPermissions validates that a directory has the expected permissions
func (pe *PermissionEnforcer) ValidateDirectoryPermissions(path string, expected os.FileMode) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat directory %s: %w", path, err)
	}
	
	if !info.IsDir() {
		return fmt.Errorf("path %s is not a directory", path)
	}
	
	actual := info.Mode().Perm()
	if actual != expected {
		pe.logger.WithFields(map[string]interface{}{
			"path":     path,
			"expected": fmt.Sprintf("%o", expected),
			"actual":   fmt.Sprintf("%o", actual),
		}).Warn().Msg("Directory permissions validation failed")
		
		return &PermissionError{
			Path:      path,
			Expected:  expected,
			Actual:    actual,
			Operation: "validate_directory",
			Message:   "directory permissions are not secure",
		}
	}
	
	return nil
}

// ValidateSecureFile checks if a file has secure permissions and is accessible only by owner
func (pe *PermissionEnforcer) ValidateSecureFile(path string) error {
	return pe.ValidateFilePermissions(path, SecureFilePermission)
}

// ValidateSecureDirectory checks if a directory has secure permissions
func (pe *PermissionEnforcer) ValidateSecureDirectory(path string) error {
	return pe.ValidateDirectoryPermissions(path, SecureDirPermission)
}

// IsFileSecure checks if a file has secure permissions without returning an error
func (pe *PermissionEnforcer) IsFileSecure(path string) bool {
	return pe.ValidateSecureFile(path) == nil
}

// IsDirectorySecure checks if a directory has secure permissions without returning an error
func (pe *PermissionEnforcer) IsDirectorySecure(path string) bool {
	return pe.ValidateSecureDirectory(path) == nil
}

// GetFilePermissionInfo returns detailed permission information about a file
func (pe *PermissionEnforcer) GetFilePermissionInfo(path string) (*FilePermissionInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat %s: %w", path, err)
	}
	
	isSecure := false
	if info.IsDir() {
		isSecure = info.Mode().Perm() == SecureDirPermission
	} else {
		isSecure = info.Mode().Perm() == SecureFilePermission
	}
	
	owner := "unknown"
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		owner = fmt.Sprintf("uid:%d", stat.Uid)
	}
	
	return &FilePermissionInfo{
		Path:     path,
		Mode:     info.Mode(),
		IsSecure: isSecure,
		Owner:    owner,
		Size:     info.Size(),
		ModTime:  info.ModTime(),
	}, nil
}

// AuditFilePermissions performs a security audit on a file or directory
func (pe *PermissionEnforcer) AuditFilePermissions(path string) error {
	info, err := pe.GetFilePermissionInfo(path)
	if err != nil {
		return fmt.Errorf("audit failed: %w", err)
	}
	
	pe.logger.WithFields(map[string]interface{}{
		"path":      info.Path,
		"mode":      fmt.Sprintf("%o", info.Mode.Perm()),
		"is_secure": info.IsSecure,
		"owner":     info.Owner,
		"size":      info.Size,
		"mod_time":  info.ModTime.Format(time.RFC3339),
	}).Info().Msg("File permission audit")
	
	if !info.IsSecure {
		pe.logger.WithField("path", path).Warn().Msg("File does not have secure permissions")
		return fmt.Errorf("file %s does not have secure permissions", path)
	}
	
	return nil
}

// FixFilePermissions attempts to fix insecure file permissions
func (pe *PermissionEnforcer) FixFilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat %s: %w", path, err)
	}
	
	pe.logger.WithField("path", path).Info().Msg("Attempting to fix file permissions")
	
	if info.IsDir() {
		return pe.SetSecureDirectoryPermissions(path)
	} else {
		return pe.SetSecureFilePermissions(path)
	}
}

// ValidateDataDirectories validates permissions on all CommandChronicles data directories
func (pe *PermissionEnforcer) ValidateDataDirectories(configDir, dataDir string) error {
	directories := []string{configDir, dataDir}
	
	pe.logger.WithFields(map[string]interface{}{
		"config_dir": configDir,
		"data_dir":   dataDir,
	}).Info().Msg("Validating data directory permissions")
	
	for _, dir := range directories {
		if err := pe.ValidateSecureDirectory(dir); err != nil {
			pe.logger.WithError(err).WithField("directory", dir).Error().Msg("Data directory validation failed")
			return fmt.Errorf("validation failed for %s: %w", dir, err)
		}
	}
	
	pe.logger.Info().Msg("All data directories have secure permissions")
	return nil
}

// ValidateDataFiles validates permissions on all CommandChronicles data files
func (pe *PermissionEnforcer) ValidateDataFiles(dbPath, sessionPath string) error {
	files := map[string]string{
		"database": dbPath,
		"session":  sessionPath,
	}
	
	pe.logger.WithFields(map[string]interface{}{
		"database_path": dbPath,
		"session_path":  sessionPath,
	}).Info().Msg("Validating data file permissions")
	
	for fileType, path := range files {
		// Skip validation if file doesn't exist
		if _, err := os.Stat(path); os.IsNotExist(err) {
			pe.logger.WithField("path", path).Debug().Msg("File does not exist, skipping validation")
			continue
		}
		
		if err := pe.ValidateSecureFile(path); err != nil {
			pe.logger.WithError(err).WithFields(map[string]interface{}{
				"file_type": fileType,
				"path":      path,
			}).Error().Msg("Data file validation failed")
			return fmt.Errorf("validation failed for %s (%s): %w", fileType, path, err)
		}
	}
	
	pe.logger.Info().Msg("All data files have secure permissions")
	return nil
}

// SecureDataEnvironment ensures all CommandChronicles directories and files have secure permissions
func (pe *PermissionEnforcer) SecureDataEnvironment(configDir, dataDir, dbPath, sessionPath string) error {
	pe.logger.Info().Msg("Securing CommandChronicles data environment")
	
	// Create and secure directories
	directories := []string{configDir, dataDir}
	for _, dir := range directories {
		if err := pe.CreateSecureDirectory(dir); err != nil {
			return fmt.Errorf("failed to secure directory %s: %w", dir, err)
		}
		// Explicitly set secure permissions on the directory (in case it already existed)
		if err := pe.SetSecureDirectoryPermissions(dir); err != nil {
			return fmt.Errorf("failed to secure existing directory %s: %w", dir, err)
		}
	}
	
	// Secure existing files
	files := []string{dbPath, sessionPath}
	for _, file := range files {
		if _, err := os.Stat(file); err == nil {
			if err := pe.SetSecureFilePermissions(file); err != nil {
				pe.logger.WithError(err).WithField("file", file).Warn().Msg("Failed to secure existing file")
			}
		}
	}
	
	pe.logger.Info().Msg("Data environment secured successfully")
	return nil
}

// validatePath performs basic validation on file paths
// ValidatePath validates that a path is safe to use (public method)
func (pe *PermissionEnforcer) ValidatePath(path string) error {
	return pe.validatePath(path)
}

func (pe *PermissionEnforcer) validatePath(path string) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}
	
	if strings.Contains(path, "..") {
		return fmt.Errorf("path contains directory traversal")
	}
	
	// On Windows, different validation might be needed
	if runtime.GOOS == "windows" {
		// Windows file permission model is different, this implementation is Unix-focused
		pe.logger.Warn().Msg("Permission enforcement on Windows is limited")
	}
	
	return nil
}

// GetRecommendedPermissions returns the recommended permissions for different file types
func GetRecommendedPermissions() map[string]os.FileMode {
	return map[string]os.FileMode{
		"database":      SecureFilePermission,
		"session":       SecureFilePermission,
		"config":        SecureFilePermission,
		"config_dir":    SecureDirPermission,
		"data_dir":      SecureDirPermission,
		"temp_file":     TempFilePermission,
	}
}

// IsPermissionError checks if an error is a permission-related error
func IsPermissionError(err error) bool {
	_, ok := err.(*PermissionError)
	return ok
}