package security

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/NeverVane/commandchronicles-cli/pkg/crypto"
	"github.com/NeverVane/commandchronicles-cli/internal/storage"
)

func TestPermissionCryptoIntegration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	t.Run("secure key derivation with file permissions", func(t *testing.T) {
		tmpDir := t.TempDir()
		keyFile := filepath.Join(tmpDir, "derived.key")
		
		pe := NewPermissionEnforcer()
		kd := crypto.NewKeyDerivator()
		
		// Derive a key
		derivedKey, err := kd.DeriveKeyFromCredentials("testuser", "testpassword123")
		require.NoError(t, err)
		defer derivedKey.SecureErase()
		
		// Write key to file with insecure permissions initially
		require.NoError(t, os.WriteFile(keyFile, derivedKey.Key, 0644))
		
		// Verify file is insecure
		assert.False(t, pe.IsFileSecure(keyFile))
		
		// Secure the file
		err = pe.SetSecureFilePermissions(keyFile)
		require.NoError(t, err)
		
		// Verify file is now secure
		assert.True(t, pe.IsFileSecure(keyFile))
		
		// Verify we can still read the key
		readKey, err := os.ReadFile(keyFile)
		require.NoError(t, err)
		assert.Equal(t, derivedKey.Key, readKey)
	})

	t.Run("secure encryption with database permissions", func(t *testing.T) {
		tmpDir := t.TempDir()
		dbPath := filepath.Join(tmpDir, "test.db")
		
		pe := NewPermissionEnforcer()
		kd := crypto.NewKeyDerivator()
		encryptor := crypto.NewEncryptor()
		
		// Create test command record
		record := storage.NewCommandRecord(
			"ls -la",
			0,
			150,
			"/home/user",
			"session123",
			"testhost",
		)
		
		// Derive encryption key
		derivedKey, err := kd.DeriveKeyFromCredentials("testuser", "testpassword123")
		require.NoError(t, err)
		defer derivedKey.SecureErase()
		
		// Encrypt the record
		encryptedData, err := encryptor.EncryptRecord(record, derivedKey.Key)
		require.NoError(t, err)
		
		// Write encrypted data to database file with secure permissions
		require.NoError(t, os.WriteFile(dbPath, encryptedData, SecureFilePermission))
		
		// Verify database has secure permissions
		assert.True(t, pe.IsFileSecure(dbPath))
		
		// Read and decrypt the data
		readData, err := os.ReadFile(dbPath)
		require.NoError(t, err)
		
		decryptedRecord, err := encryptor.DecryptRecord(readData, derivedKey.Key)
		require.NoError(t, err)
		
		// Verify decrypted data matches original
		assert.Equal(t, record.Command, decryptedRecord.Command)
		assert.Equal(t, record.SessionID, decryptedRecord.SessionID)
		assert.Equal(t, record.Hostname, decryptedRecord.Hostname)
	})

	t.Run("session key management with secure storage", func(t *testing.T) {
		tmpDir := t.TempDir()
		sessionPath := filepath.Join(tmpDir, "session.key")
		
		pe := NewPermissionEnforcer()
		kd := crypto.NewKeyDerivator()
		skm := crypto.NewSessionKeyManager(sessionPath, 0) // Use default timeout
		defer skm.Close()
		
		// Generate master key
		masterKey, err := kd.DeriveKeyFromCredentials("testuser", "testpassword123")
		require.NoError(t, err)
		defer masterKey.SecureErase()
		
		// Store session key
		err = skm.StoreSessionKey("testuser", "testpassword123", masterKey.Key)
		require.NoError(t, err)
		
		// Verify session file has secure permissions
		assert.True(t, pe.IsFileSecure(sessionPath))
		
		// Load session key
		sessionKey, err := skm.LoadSessionKey("testuser", "testpassword123")
		require.NoError(t, err)
		defer sessionKey.SecureErase()
		
		// Verify loaded key matches original
		assert.Equal(t, masterKey.Key, sessionKey.Key)
		assert.Equal(t, "testuser", sessionKey.Username)
	})

	t.Run("complete data environment security", func(t *testing.T) {
		tmpDir := t.TempDir()
		configDir := filepath.Join(tmpDir, "config")
		dataDir := filepath.Join(tmpDir, "data")
		dbPath := filepath.Join(dataDir, "history.db")
		sessionPath := filepath.Join(dataDir, "session")
		
		pe := NewPermissionEnforcer()
		kd := crypto.NewKeyDerivator()
		encryptor := crypto.NewEncryptor()
		skm := crypto.NewSessionKeyManager(sessionPath, 0)
		defer skm.Close()
		
		// Secure the entire data environment
		err := pe.SecureDataEnvironment(configDir, dataDir, dbPath, sessionPath)
		require.NoError(t, err)
		
		// Verify directories are secure
		assert.True(t, pe.IsDirectorySecure(configDir))
		assert.True(t, pe.IsDirectorySecure(dataDir))
		
		// Create and store encrypted data
		record := storage.NewCommandRecord(
			"echo 'secure test'",
			0,
			50,
			"/secure/path",
			"session456",
			"securehost",
		)
		
		// Derive key and encrypt
		derivedKey, err := kd.DeriveKeyFromCredentials("secureuser", "securepass123")
		require.NoError(t, err)
		defer derivedKey.SecureErase()
		
		encryptedData, err := encryptor.EncryptRecord(record, derivedKey.Key)
		require.NoError(t, err)
		
		// Store encrypted database
		require.NoError(t, os.WriteFile(dbPath, encryptedData, SecureFilePermission))
		
		// Store session key
		err = skm.StoreSessionKey("secureuser", "securepass123", derivedKey.Key)
		require.NoError(t, err)
		
		// Validate entire environment
		err = pe.ValidateDataDirectories(configDir, dataDir)
		assert.NoError(t, err)
		
		err = pe.ValidateDataFiles(dbPath, sessionPath)
		assert.NoError(t, err)
		
		// Verify we can still decrypt the data
		readData, err := os.ReadFile(dbPath)
		require.NoError(t, err)
		
		decryptedRecord, err := encryptor.DecryptRecord(readData, derivedKey.Key)
		require.NoError(t, err)
		
		assert.Equal(t, record.Command, decryptedRecord.Command)
		assert.Equal(t, record.SessionID, decryptedRecord.SessionID)
	})

	t.Run("permission audit with crypto operations", func(t *testing.T) {
		tmpDir := t.TempDir()
		secureFile := filepath.Join(tmpDir, "secure.enc")
		insecureFile := filepath.Join(tmpDir, "insecure.enc")
		
		pe := NewPermissionEnforcer()
		encryptor := crypto.NewEncryptor()
		kd := crypto.NewKeyDerivator()
		
		// Generate key for encryption
		key, err := kd.DeriveKeyFromCredentials("audituser", "auditpass123")
		require.NoError(t, err)
		defer key.SecureErase()
		
		// Encrypt some test data
		testData := []byte("sensitive audit data")
		encryptedData, err := encryptor.EncryptBytes(testData, key.Key)
		require.NoError(t, err)
		
		// Store with secure permissions
		require.NoError(t, os.WriteFile(secureFile, encryptedData, SecureFilePermission))
		
		// Store with insecure permissions
		require.NoError(t, os.WriteFile(insecureFile, encryptedData, 0644))
		
		// Audit both files
		err = pe.AuditFilePermissions(secureFile)
		assert.NoError(t, err, "Secure file should pass audit")
		
		err = pe.AuditFilePermissions(insecureFile)
		assert.Error(t, err, "Insecure file should fail audit")
		
		// Fix insecure file
		err = pe.FixFilePermissions(insecureFile)
		require.NoError(t, err)
		
		// Verify fix worked
		err = pe.AuditFilePermissions(insecureFile)
		assert.NoError(t, err, "Fixed file should now pass audit")
		
		// Verify data is still decryptable after permission changes
		readData, err := os.ReadFile(insecureFile)
		require.NoError(t, err)
		
		decryptedData, err := encryptor.DecryptBytes(readData, key.Key)
		require.NoError(t, err)
		assert.Equal(t, testData, decryptedData)
	})

	t.Run("cross-component security validation", func(t *testing.T) {
		tmpDir := t.TempDir()
		dataDir := filepath.Join(tmpDir, "secure_data")
		dbFile := filepath.Join(dataDir, "commands.db")
		sessionFile := filepath.Join(dataDir, "session.key")
		
		pe := NewPermissionEnforcer()
		kd := crypto.NewKeyDerivator()
		encryptor := crypto.NewEncryptor()
		
		// Secure the environment first
		err := pe.SecureDataEnvironment(dataDir, dataDir, dbFile, sessionFile)
		require.NoError(t, err)
		
		// Create multiple encrypted records
		records := []*storage.CommandRecord{
			storage.NewCommandRecord("git status", 0, 45, "/repo", "sess1", "host1"),
			storage.NewCommandRecord("npm install", 0, 5000, "/project", "sess2", "host1"),
			storage.NewCommandRecord("docker ps", 0, 120, "/", "sess3", "host2"),
		}
		
		// Derive key
		masterKey, err := kd.DeriveKeyFromCredentials("multiuser", "multipass123")
		require.NoError(t, err)
		defer masterKey.SecureErase()
		
		// Encrypt all records
		var allEncryptedData []byte
		for _, record := range records {
			encData, err := encryptor.EncryptRecord(record, masterKey.Key)
			require.NoError(t, err)
			allEncryptedData = append(allEncryptedData, encData...)
		}
		
		// Store encrypted database
		require.NoError(t, os.WriteFile(dbFile, allEncryptedData, SecureFilePermission))
		
		// Create session manager and store session
		skm := crypto.NewSessionKeyManager(sessionFile, 0)
		defer skm.Close()
		
		err = skm.StoreSessionKey("multiuser", "multipass123", masterKey.Key)
		require.NoError(t, err)
		
		// Perform comprehensive security validation
		
		// 1. Validate directory permissions
		err = pe.ValidateDataDirectories(dataDir, dataDir)
		assert.NoError(t, err)
		
		// 2. Validate file permissions  
		err = pe.ValidateDataFiles(dbFile, sessionFile)
		assert.NoError(t, err)
		
		// 3. Verify session key can be loaded
		loadedSession, err := skm.LoadSessionKey("multiuser", "multipass123")
		require.NoError(t, err)
		defer loadedSession.SecureErase()
		
		// 4. Verify master key integrity
		assert.Equal(t, masterKey.Key, loadedSession.Key)
		
		// 5. Get detailed permission info for audit
		dbInfo, err := pe.GetFilePermissionInfo(dbFile)
		require.NoError(t, err)
		assert.True(t, dbInfo.IsSecure)
		assert.Equal(t, os.FileMode(SecureFilePermission), dbInfo.Mode.Perm())
		
		sessionInfo, err := pe.GetFilePermissionInfo(sessionFile)
		require.NoError(t, err)
		assert.True(t, sessionInfo.IsSecure)
		assert.Equal(t, os.FileMode(SecureFilePermission), sessionInfo.Mode.Perm())
		
		// 6. Verify data can still be decrypted
		encryptedDb, err := os.ReadFile(dbFile)
		require.NoError(t, err)
		assert.NotEmpty(t, encryptedDb)
		
		// Note: In a real implementation, you'd need to properly parse 
		// the concatenated encrypted records, but this demonstrates
		// that the file is readable and contains encrypted data
	})
}

func TestPermissionSystemRecommendations(t *testing.T) {
	t.Run("recommended permissions match crypto requirements", func(t *testing.T) {
		recommendations := GetRecommendedPermissions()
		
		// Verify recommendations align with crypto security needs
		assert.Equal(t, os.FileMode(SecureFilePermission), recommendations["database"])
		assert.Equal(t, os.FileMode(SecureFilePermission), recommendations["session"])
		assert.Equal(t, os.FileMode(SecureFilePermission), recommendations["config"])
		assert.Equal(t, os.FileMode(SecureDirPermission), recommendations["config_dir"])
		assert.Equal(t, os.FileMode(SecureDirPermission), recommendations["data_dir"])
		assert.Equal(t, os.FileMode(TempFilePermission), recommendations["temp_file"])
		
		// Ensure all permissions are restrictive enough for crypto operations
		for fileType, perm := range recommendations {
			if fileType == "database" || fileType == "session" || fileType == "config" {
				// Files containing sensitive data should be owner-only readable
				assert.Equal(t, os.FileMode(SecureFilePermission), perm, "File type %s should have 0600 permissions", fileType)
			}
			if fileType == "config_dir" || fileType == "data_dir" {
				// Directories should be owner-only accessible
				assert.Equal(t, os.FileMode(SecureDirPermission), perm, "Directory type %s should have 0700 permissions", fileType)
			}
		}
	})
}