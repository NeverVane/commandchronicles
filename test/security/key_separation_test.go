package security

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeverVane/commandchronicles-cli/internal/auth"
	"github.com/NeverVane/commandchronicles-cli/internal/config"
	"github.com/NeverVane/commandchronicles-cli/internal/storage"
	"github.com/NeverVane/commandchronicles-cli/pkg/crypto"
)

// setupTestAuthManager creates a test auth manager with test configuration
func setupTestAuthManager() *auth.AuthManager {
	tempDir := "/tmp/ccr-test"
	cfg := &config.Config{
		DataDir: tempDir,
		Security: config.SecurityConfig{
			Argon2Time:     1, // Reduced for testing speed
			Argon2Memory:   1024,
			Argon2Threads:  1,
			SessionKeyPath: tempDir + "/session.json",
		},
	}
	
	authMgr, err := auth.NewAuthManager(cfg)
	if err != nil {
		panic("Failed to create test auth manager: " + err.Error())
	}
	return authMgr
}

// generateTestSalt creates a test salt
func generateTestSalt() []byte {
	salt := make([]byte, 32)
	rand.Read(salt)
	return salt
}

func TestKeySeparation(t *testing.T) {
	authMgr := setupTestAuthManager()
	password := "testPassword123"
	salt := generateTestSalt()
	
	keys, err := authMgr.DeriveKeys(password, salt)
	require.NoError(t, err)
	
	t.Run("Key Lengths", func(t *testing.T) {
		assert.Len(t, keys.LocalKey, 64, "LocalKey should be 64 bytes")
		assert.Len(t, keys.EncryptionKey, 64, "EncryptionKey should be 64 bytes")
		assert.Len(t, keys.RemoteAuthKey, 32, "RemoteAuthKey should be 32 bytes")
		assert.Len(t, keys.Salt, 32, "Salt should be 32 bytes")
	})
	
	t.Run("Key Identity", func(t *testing.T) {
		// LocalKey and EncryptionKey should be the same (full 64 bytes)
		assert.Equal(t, keys.LocalKey, keys.EncryptionKey,
			"LocalKey and EncryptionKey should be identical")
	})
	
	t.Run("Key Separation", func(t *testing.T) {
		// First 32 bytes of encryption key must NOT equal remote auth key
		assert.NotEqual(t, keys.EncryptionKey[:32], keys.RemoteAuthKey,
			"First 32 bytes of encryption key must not equal remote auth key")
		
		// Remote auth key should be bytes 32-63 of master key
		assert.Equal(t, keys.LocalKey[32:64], keys.RemoteAuthKey,
			"RemoteAuthKey should be bytes 32-63 of LocalKey")
	})
	
	t.Run("Key Content Validation", func(t *testing.T) {
		// Keys should not be all zeros
		zeroKey32 := make([]byte, 32)
		zeroKey64 := make([]byte, 64)
		
		assert.NotEqual(t, zeroKey64, keys.LocalKey, "LocalKey should not be all zeros")
		assert.NotEqual(t, zeroKey64, keys.EncryptionKey, "EncryptionKey should not be all zeros")
		assert.NotEqual(t, zeroKey32, keys.RemoteAuthKey, "RemoteAuthKey should not be all zeros")
		
		// Keys should have sufficient entropy (basic check)
		assert.True(t, hasMinimalEntropy(keys.LocalKey), "LocalKey should have sufficient entropy")
		assert.True(t, hasMinimalEntropy(keys.RemoteAuthKey), "RemoteAuthKey should have sufficient entropy")
	})
}

func TestDeterministicKeyDerivation(t *testing.T) {
	authMgr := setupTestAuthManager()
	password := "consistent123"
	salt := generateTestSalt()
	
	// Derive keys twice with same inputs
	keys1, err := authMgr.DeriveKeys(password, salt)
	require.NoError(t, err)
	
	keys2, err := authMgr.DeriveKeys(password, salt)
	require.NoError(t, err)
	
	t.Run("Identical Keys", func(t *testing.T) {
		assert.Equal(t, keys1.LocalKey, keys2.LocalKey, "LocalKey should be deterministic")
		assert.Equal(t, keys1.EncryptionKey, keys2.EncryptionKey, "EncryptionKey should be deterministic")
		assert.Equal(t, keys1.RemoteAuthKey, keys2.RemoteAuthKey, "RemoteAuthKey should be deterministic")
	})
	
	t.Run("Different Password Different Keys", func(t *testing.T) {
		keys3, err := authMgr.DeriveKeys("differentPassword456", salt)
		require.NoError(t, err)
		
		assert.NotEqual(t, keys1.LocalKey, keys3.LocalKey, "Different passwords should produce different keys")
		assert.NotEqual(t, keys1.EncryptionKey, keys3.EncryptionKey, "Different passwords should produce different encryption keys")
		assert.NotEqual(t, keys1.RemoteAuthKey, keys3.RemoteAuthKey, "Different passwords should produce different remote auth keys")
	})
	
	t.Run("Different Salt Different Keys", func(t *testing.T) {
		differentSalt := generateTestSalt()
		keys4, err := authMgr.DeriveKeys(password, differentSalt)
		require.NoError(t, err)
		
		assert.NotEqual(t, keys1.LocalKey, keys4.LocalKey, "Different salts should produce different keys")
		assert.NotEqual(t, keys1.EncryptionKey, keys4.EncryptionKey, "Different salts should produce different encryption keys")
		assert.NotEqual(t, keys1.RemoteAuthKey, keys4.RemoteAuthKey, "Different salts should produce different remote auth keys")
	})
}

func TestServerCannotDecrypt(t *testing.T) {
	authMgr := setupTestAuthManager()
	password := "securePassword789"
	salt := generateTestSalt()
	
	keys, err := authMgr.DeriveKeys(password, salt)
	require.NoError(t, err)
	
	encryptor := crypto.NewEncryptor()
	
	t.Run("Record Encryption Security", func(t *testing.T) {
		// Create test record
		testRecord := storage.NewCommandRecord(
			"sensitive command with secrets",
			0,
			100,
			"/home/user/secrets",
			"session-123",
			"test-host",
		)
		
		// Encrypt with full encryption key (64 bytes)
		encrypted, err := encryptor.EncryptRecord(testRecord, keys.EncryptionKey)
		require.NoError(t, err)
		
		// Server should NOT be able to decrypt with remote auth key (32 bytes)
		_, err = encryptor.DecryptRecord(encrypted, keys.RemoteAuthKey)
		assert.Error(t, err, "Server should not decrypt record with remote auth key")
		
		// But decryption should work with correct encryption key
		decrypted, err := encryptor.DecryptRecord(encrypted, keys.EncryptionKey)
		require.NoError(t, err)
		assert.Equal(t, testRecord.Command, decrypted.Command, "Decryption with correct key should work")
	})
	
	t.Run("Bytes Encryption Security", func(t *testing.T) {
		testData := []byte("sensitive user data that server should not see")
		
		// Encrypt with full encryption key
		encrypted, err := encryptor.EncryptBytes(testData, keys.EncryptionKey)
		require.NoError(t, err)
		
		// Server should NOT be able to decrypt with remote auth key
		_, err = encryptor.DecryptBytes(encrypted, keys.RemoteAuthKey)
		assert.Error(t, err, "Server should not decrypt bytes with remote auth key")
		
		// But decryption should work with correct encryption key
		decrypted, err := encryptor.DecryptBytes(encrypted, keys.EncryptionKey)
		require.NoError(t, err)
		assert.Equal(t, testData, decrypted, "Decryption with correct key should work")
	})
}

func TestEncryptionKeyHandling(t *testing.T) {
	encryptor := crypto.NewEncryptor()
	
	t.Run("64-byte Key Support", func(t *testing.T) {
		// Create 64-byte key
		key64 := make([]byte, 64)
		rand.Read(key64)
		
		testData := []byte("test data for 64-byte key")
		
		// Should work with 64-byte key
		encrypted, err := encryptor.EncryptBytes(testData, key64)
		require.NoError(t, err)
		
		decrypted, err := encryptor.DecryptBytes(encrypted, key64)
		require.NoError(t, err)
		assert.Equal(t, testData, decrypted)
	})
	
	t.Run("32-byte Key Backward Compatibility", func(t *testing.T) {
		// Create 32-byte key
		key32 := make([]byte, 32)
		rand.Read(key32)
		
		testData := []byte("test data for 32-byte key")
		
		// Should still work with 32-byte key
		encrypted, err := encryptor.EncryptBytes(testData, key32)
		require.NoError(t, err)
		
		decrypted, err := encryptor.DecryptBytes(encrypted, key32)
		require.NoError(t, err)
		assert.Equal(t, testData, decrypted)
	})
	
	t.Run("Invalid Key Lengths Rejected", func(t *testing.T) {
		testData := []byte("test data")
		
		// Test various invalid key lengths
		invalidLengths := []int{0, 16, 31, 33, 48, 63, 65, 128}
		
		for _, length := range invalidLengths {
			invalidKey := make([]byte, length)
			rand.Read(invalidKey)
			
			_, err := encryptor.EncryptBytes(testData, invalidKey)
			assert.Error(t, err, "Should reject key of length %d", length)
		}
	})
}

func TestKeyDerivationEdgeCases(t *testing.T) {
	authMgr := setupTestAuthManager()
	
	t.Run("Empty Password Rejected", func(t *testing.T) {
		salt := generateTestSalt()
		_, err := authMgr.DeriveKeys("", salt)
		assert.Error(t, err, "Empty password should be rejected")
	})
	
	t.Run("Empty Salt Rejected", func(t *testing.T) {
		_, err := authMgr.DeriveKeys("password", []byte{})
		assert.Error(t, err, "Empty salt should be rejected")
	})
	
	t.Run("Nil Salt Rejected", func(t *testing.T) {
		_, err := authMgr.DeriveKeys("password", nil)
		assert.Error(t, err, "Nil salt should be rejected")
	})
}

func TestCryptographicProperties(t *testing.T) {
	authMgr := setupTestAuthManager()
	password := "testCryptoProperties"
	salt := generateTestSalt()
	
	keys, err := authMgr.DeriveKeys(password, salt)
	require.NoError(t, err)
	
	t.Run("Key Independence", func(t *testing.T) {
		// Test that changing one bit in password produces completely different keys
		// This validates avalanche effect
		password2 := "testCryptoPropertieS" // Changed last 's' to 'S'
		keys2, err := authMgr.DeriveKeys(password2, salt)
		require.NoError(t, err)
		
		// Keys should be completely different (high Hamming distance)
		localDiff := hammingDistance(keys.LocalKey, keys2.LocalKey)
		remoteDiff := hammingDistance(keys.RemoteAuthKey, keys2.RemoteAuthKey)
		
		// Expect at least 25% of bits to be different (conservative threshold)
		assert.Greater(t, localDiff, len(keys.LocalKey)*8/4, "LocalKey should have high Hamming distance")
		assert.Greater(t, remoteDiff, len(keys.RemoteAuthKey)*8/4, "RemoteAuthKey should have high Hamming distance")
	})
	
	t.Run("No Obvious Patterns", func(t *testing.T) {
		// Basic check that keys don't have obvious patterns
		assert.False(t, hasRepeatingPattern(keys.LocalKey), "LocalKey should not have repeating patterns")
		assert.False(t, hasRepeatingPattern(keys.EncryptionKey), "EncryptionKey should not have repeating patterns")
		assert.False(t, hasRepeatingPattern(keys.RemoteAuthKey), "RemoteAuthKey should not have repeating patterns")
	})
}

// Helper function to check if a byte slice has minimal entropy
func hasMinimalEntropy(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	
	// Count unique bytes
	seen := make(map[byte]bool)
	for _, b := range data {
		seen[b] = true
	}
	
	// Require at least 16 different byte values for minimal entropy
	return len(seen) >= 16
}

// Helper function to calculate Hamming distance between two byte slices
func hammingDistance(a, b []byte) int {
	if len(a) != len(b) {
		return -1
	}
	
	distance := 0
	for i := 0; i < len(a); i++ {
		// XOR and count set bits
		xor := a[i] ^ b[i]
		for xor != 0 {
			distance++
			xor &= xor - 1 // Clear lowest set bit
		}
	}
	return distance
}

// Helper function to detect simple repeating patterns
func hasRepeatingPattern(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	
	// Check for 2-byte, 4-byte, and 8-byte repeating patterns
	patternSizes := []int{2, 4, 8}
	
	for _, size := range patternSizes {
		if len(data) < size*2 {
			continue
		}
		
		pattern := data[:size]
		isRepeating := true
		
		for i := size; i+size <= len(data); i += size {
			if !bytes.Equal(pattern, data[i:i+size]) {
				isRepeating = false
				break
			}
		}
		
		if isRepeating {
			return true
		}
	}
	
	return false
}

// Benchmark key derivation performance
func BenchmarkKeyDerivation(b *testing.B) {
	authMgr := setupTestAuthManager()
	password := "benchmarkPassword"
	salt := generateTestSalt()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := authMgr.DeriveKeys(password, salt)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark encryption with 64-byte vs 32-byte keys
func BenchmarkEncryption64vs32(b *testing.B) {
	encryptor := crypto.NewEncryptor()
	testData := make([]byte, 1024) // 1KB test data
	rand.Read(testData)
	
	key32 := make([]byte, 32)
	key64 := make([]byte, 64)
	rand.Read(key32)
	rand.Read(key64)
	
	b.Run("32-byte key", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := encryptor.EncryptBytes(testData, key32)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	
	b.Run("64-byte key", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := encryptor.EncryptBytes(testData, key64)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}