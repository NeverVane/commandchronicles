package security

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPermissionEnforcer(t *testing.T) {
	pe := NewPermissionEnforcer()
	assert.NotNil(t, pe)
	assert.NotNil(t, pe.logger)
}

func TestSetSecureFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	pe := NewPermissionEnforcer()

	t.Run("valid file", func(t *testing.T) {
		// Create temporary file
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.txt")
		require.NoError(t, os.WriteFile(testFile, []byte("test"), 0644))

		// Set secure permissions
		err := pe.SetSecureFilePermissions(testFile)
		assert.NoError(t, err)

		// Verify permissions
		info, err := os.Stat(testFile)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(SecureFilePermission), info.Mode().Perm())
	})

	t.Run("non-existent file", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "nonexistent.txt")

		err := pe.SetSecureFilePermissions(testFile)
		assert.Error(t, err)
	})

	t.Run("empty path", func(t *testing.T) {
		err := pe.SetSecureFilePermissions("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "path cannot be empty")
	})

	t.Run("path with directory traversal", func(t *testing.T) {
		err := pe.SetSecureFilePermissions("../../../etc/passwd")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "directory traversal")
	})
}

func TestSetSecureDirectoryPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	pe := NewPermissionEnforcer()

	t.Run("valid directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		testDir := filepath.Join(tmpDir, "testdir")
		require.NoError(t, os.Mkdir(testDir, 0755))

		err := pe.SetSecureDirectoryPermissions(testDir)
		assert.NoError(t, err)

		info, err := os.Stat(testDir)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(SecureDirPermission), info.Mode().Perm())
	})

	t.Run("non-existent directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		testDir := filepath.Join(tmpDir, "nonexistent")

		err := pe.SetSecureDirectoryPermissions(testDir)
		assert.Error(t, err)
	})
}

func TestCreateSecureDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	pe := NewPermissionEnforcer()

	t.Run("create new directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		testDir := filepath.Join(tmpDir, "newdir")

		err := pe.CreateSecureDirectory(testDir)
		assert.NoError(t, err)

		info, err := os.Stat(testDir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
		assert.Equal(t, os.FileMode(SecureDirPermission), info.Mode().Perm())
	})

	t.Run("create nested directories", func(t *testing.T) {
		tmpDir := t.TempDir()
		testDir := filepath.Join(tmpDir, "parent", "child", "grandchild")

		err := pe.CreateSecureDirectory(testDir)
		assert.NoError(t, err)

		info, err := os.Stat(testDir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
		assert.Equal(t, os.FileMode(SecureDirPermission), info.Mode().Perm())
	})
}

func TestValidateFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	pe := NewPermissionEnforcer()

	t.Run("correct permissions", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.txt")
		require.NoError(t, os.WriteFile(testFile, []byte("test"), SecureFilePermission))

		err := pe.ValidateFilePermissions(testFile, SecureFilePermission)
		assert.NoError(t, err)
	})

	t.Run("incorrect permissions", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.txt")
		require.NoError(t, os.WriteFile(testFile, []byte("test"), 0644))

		err := pe.ValidateFilePermissions(testFile, SecureFilePermission)
		assert.Error(t, err)
		assert.IsType(t, &PermissionError{}, err)

		permErr := err.(*PermissionError)
		assert.Equal(t, testFile, permErr.Path)
		assert.Equal(t, os.FileMode(SecureFilePermission), permErr.Expected)
		assert.Equal(t, os.FileMode(0644), permErr.Actual)
	})

	t.Run("directory instead of file", func(t *testing.T) {
		tmpDir := t.TempDir()

		err := pe.ValidateFilePermissions(tmpDir, SecureFilePermission)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "is a directory")
	})
}

func TestValidateDirectoryPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	pe := NewPermissionEnforcer()

	t.Run("correct permissions", func(t *testing.T) {
		tmpDir := t.TempDir()
		testDir := filepath.Join(tmpDir, "testdir")
		require.NoError(t, os.Mkdir(testDir, SecureDirPermission))

		err := pe.ValidateDirectoryPermissions(testDir, SecureDirPermission)
		assert.NoError(t, err)
	})

	t.Run("incorrect permissions", func(t *testing.T) {
		tmpDir := t.TempDir()
		testDir := filepath.Join(tmpDir, "testdir")
		require.NoError(t, os.Mkdir(testDir, 0755))

		err := pe.ValidateDirectoryPermissions(testDir, SecureDirPermission)
		assert.Error(t, err)
		assert.IsType(t, &PermissionError{}, err)
	})

	t.Run("file instead of directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.txt")
		require.NoError(t, os.WriteFile(testFile, []byte("test"), 0644))

		err := pe.ValidateDirectoryPermissions(testFile, SecureDirPermission)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "is not a directory")
	})
}

func TestValidateSecureFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	pe := NewPermissionEnforcer()

	t.Run("secure file", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.txt")
		require.NoError(t, os.WriteFile(testFile, []byte("test"), SecureFilePermission))

		err := pe.ValidateSecureFile(testFile)
		assert.NoError(t, err)
	})

	t.Run("insecure file", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.txt")
		require.NoError(t, os.WriteFile(testFile, []byte("test"), 0644))

		err := pe.ValidateSecureFile(testFile)
		assert.Error(t, err)
	})
}

func TestIsFileSecure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	pe := NewPermissionEnforcer()

	t.Run("secure file", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.txt")
		require.NoError(t, os.WriteFile(testFile, []byte("test"), SecureFilePermission))

		secure := pe.IsFileSecure(testFile)
		assert.True(t, secure)
	})

	t.Run("insecure file", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.txt")
		require.NoError(t, os.WriteFile(testFile, []byte("test"), 0644))

		secure := pe.IsFileSecure(testFile)
		assert.False(t, secure)
	})

	t.Run("non-existent file", func(t *testing.T) {
		secure := pe.IsFileSecure("/nonexistent/file.txt")
		assert.False(t, secure)
	})
}

func TestIsDirectorySecure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	pe := NewPermissionEnforcer()

	t.Run("secure directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		testDir := filepath.Join(tmpDir, "testdir")
		require.NoError(t, os.Mkdir(testDir, SecureDirPermission))

		secure := pe.IsDirectorySecure(testDir)
		assert.True(t, secure)
	})

	t.Run("insecure directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		testDir := filepath.Join(tmpDir, "testdir")
		require.NoError(t, os.Mkdir(testDir, 0755))

		secure := pe.IsDirectorySecure(testDir)
		assert.False(t, secure)
	})
}

func TestGetFilePermissionInfo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	pe := NewPermissionEnforcer()

	t.Run("file info", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.txt")
		content := []byte("test content")
		require.NoError(t, os.WriteFile(testFile, content, SecureFilePermission))

		info, err := pe.GetFilePermissionInfo(testFile)
		require.NoError(t, err)
		assert.Equal(t, testFile, info.Path)
		assert.Equal(t, os.FileMode(SecureFilePermission), info.Mode.Perm())
		assert.True(t, info.IsSecure)
		assert.Equal(t, int64(len(content)), info.Size)
		assert.WithinDuration(t, time.Now(), info.ModTime, time.Second)
	})

	t.Run("directory info", func(t *testing.T) {
		tmpDir := t.TempDir()
		testDir := filepath.Join(tmpDir, "testdir")
		require.NoError(t, os.Mkdir(testDir, SecureDirPermission))

		info, err := pe.GetFilePermissionInfo(testDir)
		require.NoError(t, err)
		assert.Equal(t, testDir, info.Path)
		assert.True(t, info.IsSecure)
	})

	t.Run("non-existent file", func(t *testing.T) {
		info, err := pe.GetFilePermissionInfo("/nonexistent/file.txt")
		assert.Error(t, err)
		assert.Nil(t, info)
	})
}

func TestAuditFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	pe := NewPermissionEnforcer()

	t.Run("secure file passes audit", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.txt")
		require.NoError(t, os.WriteFile(testFile, []byte("test"), SecureFilePermission))

		err := pe.AuditFilePermissions(testFile)
		assert.NoError(t, err)
	})

	t.Run("insecure file fails audit", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.txt")
		require.NoError(t, os.WriteFile(testFile, []byte("test"), 0644))

		err := pe.AuditFilePermissions(testFile)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "does not have secure permissions")
	})
}

func TestFixFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	pe := NewPermissionEnforcer()

	t.Run("fix file permissions", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.txt")
		require.NoError(t, os.WriteFile(testFile, []byte("test"), 0644))

		// Verify initial insecure permissions
		assert.False(t, pe.IsFileSecure(testFile))

		// Fix permissions
		err := pe.FixFilePermissions(testFile)
		assert.NoError(t, err)

		// Verify permissions are now secure
		assert.True(t, pe.IsFileSecure(testFile))
	})

	t.Run("fix directory permissions", func(t *testing.T) {
		tmpDir := t.TempDir()
		testDir := filepath.Join(tmpDir, "testdir")
		require.NoError(t, os.Mkdir(testDir, 0755))

		// Verify initial insecure permissions
		assert.False(t, pe.IsDirectorySecure(testDir))

		// Fix permissions
		err := pe.FixFilePermissions(testDir)
		assert.NoError(t, err)

		// Verify permissions are now secure
		assert.True(t, pe.IsDirectorySecure(testDir))
	})
}

func TestValidateDataDirectories(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	pe := NewPermissionEnforcer()

	t.Run("secure directories", func(t *testing.T) {
		tmpDir := t.TempDir()
		configDir := filepath.Join(tmpDir, "config")
		dataDir := filepath.Join(tmpDir, "data")

		require.NoError(t, os.Mkdir(configDir, SecureDirPermission))
		require.NoError(t, os.Mkdir(dataDir, SecureDirPermission))

		err := pe.ValidateDataDirectories(configDir, dataDir)
		assert.NoError(t, err)
	})

	t.Run("insecure directories", func(t *testing.T) {
		tmpDir := t.TempDir()
		configDir := filepath.Join(tmpDir, "config")
		dataDir := filepath.Join(tmpDir, "data")

		require.NoError(t, os.Mkdir(configDir, 0755))
		require.NoError(t, os.Mkdir(dataDir, SecureDirPermission))

		err := pe.ValidateDataDirectories(configDir, dataDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation failed")
	})
}

func TestValidateDataFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	pe := NewPermissionEnforcer()

	t.Run("secure files", func(t *testing.T) {
		tmpDir := t.TempDir()
		dbPath := filepath.Join(tmpDir, "db.sqlite")
		sessionPath := filepath.Join(tmpDir, "session.key")

		require.NoError(t, os.WriteFile(dbPath, []byte("db"), SecureFilePermission))
		require.NoError(t, os.WriteFile(sessionPath, []byte("session"), SecureFilePermission))

		err := pe.ValidateDataFiles(dbPath, sessionPath)
		assert.NoError(t, err)
	})

	t.Run("insecure files", func(t *testing.T) {
		tmpDir := t.TempDir()
		dbPath := filepath.Join(tmpDir, "db.sqlite")
		sessionPath := filepath.Join(tmpDir, "session.key")

		require.NoError(t, os.WriteFile(dbPath, []byte("db"), 0644))
		require.NoError(t, os.WriteFile(sessionPath, []byte("session"), SecureFilePermission))

		err := pe.ValidateDataFiles(dbPath, sessionPath)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation failed")
	})

	t.Run("non-existent files", func(t *testing.T) {
		tmpDir := t.TempDir()
		dbPath := filepath.Join(tmpDir, "nonexistent.db")
		sessionPath := filepath.Join(tmpDir, "nonexistent.key")

		err := pe.ValidateDataFiles(dbPath, sessionPath)
		assert.NoError(t, err) // Should not error for non-existent files
	})
}

func TestSecureDataEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	pe := NewPermissionEnforcer()

	t.Run("secure environment setup", func(t *testing.T) {
		tmpDir := t.TempDir()
		configDir := filepath.Join(tmpDir, "config")
		dataDir := filepath.Join(tmpDir, "data")
		dbPath := filepath.Join(dataDir, "db.sqlite")
		sessionPath := filepath.Join(dataDir, "session.key")

		// Create existing files with insecure permissions
		require.NoError(t, os.MkdirAll(dataDir, 0755))
		require.NoError(t, os.WriteFile(dbPath, []byte("db"), 0644))
		require.NoError(t, os.WriteFile(sessionPath, []byte("session"), 0644))

		err := pe.SecureDataEnvironment(configDir, dataDir, dbPath, sessionPath)
		assert.NoError(t, err)

		// Verify directories were created/secured
		assert.True(t, pe.IsDirectorySecure(configDir))
		assert.True(t, pe.IsDirectorySecure(dataDir))

		// Verify files were secured
		assert.True(t, pe.IsFileSecure(dbPath))
		assert.True(t, pe.IsFileSecure(sessionPath))
	})
}

func TestPermissionError(t *testing.T) {
	err := &PermissionError{
		Path:      "/test/path",
		Expected:  0600,
		Actual:    0644,
		Operation: "validate",
		Message:   "permissions too permissive",
	}

	expectedMsg := "permission error on /test/path: permissions too permissive (expected 600, got 644)"
	assert.Equal(t, expectedMsg, err.Error())
}

func TestGetRecommendedPermissions(t *testing.T) {
	perms := GetRecommendedPermissions()
	
	expectedPerms := map[string]os.FileMode{
		"database":   SecureFilePermission,
		"session":    SecureFilePermission,
		"config":     SecureFilePermission,
		"config_dir": SecureDirPermission,
		"data_dir":   SecureDirPermission,
		"temp_file":  TempFilePermission,
	}

	assert.Equal(t, expectedPerms, perms)
}

func TestIsPermissionError(t *testing.T) {
	t.Run("permission error", func(t *testing.T) {
		err := &PermissionError{
			Path:     "/test",
			Message:  "test error",
		}
		assert.True(t, IsPermissionError(err))
	})

	t.Run("other error", func(t *testing.T) {
		err := assert.AnError
		assert.False(t, IsPermissionError(err))
	})

	t.Run("nil error", func(t *testing.T) {
		assert.False(t, IsPermissionError(nil))
	})
}

func TestSecureDirectoryTree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	pe := NewPermissionEnforcer()

	t.Run("secure directories under home", func(t *testing.T) {
		// Get home directory
		homeDir, err := os.UserHomeDir()
		require.NoError(t, err)

		// Create test directory structure under home
		testBase := filepath.Join(homeDir, "ccr-test-secure-tree")
		testPath := filepath.Join(testBase, "level1", "level2")
		
		// Clean up after test
		defer os.RemoveAll(testBase)

		require.NoError(t, os.MkdirAll(testPath, 0755))

		err = pe.SecureDirectoryTree(testPath)
		assert.NoError(t, err)

		// Verify directories are secured
		assert.True(t, pe.IsDirectorySecure(testPath))
		assert.True(t, pe.IsDirectorySecure(filepath.Join(testBase, "level1")))
		assert.True(t, pe.IsDirectorySecure(testBase))
	})

	t.Run("skip directories outside home", func(t *testing.T) {
		// Try to secure a system directory (should be skipped)
		err := pe.SecureDirectoryTree("/tmp")
		assert.NoError(t, err) // Should not error, just skip
	})
}

func TestConstants(t *testing.T) {
	// Test that constants have expected values
	assert.Equal(t, 0600, int(SecureFilePermission))
	assert.Equal(t, 0700, int(SecureDirPermission))
	assert.Equal(t, 0600, int(TempFilePermission))
	assert.Equal(t, 0644, int(MaxFilePermission))
	assert.Equal(t, 0755, int(MaxDirPermission))
}