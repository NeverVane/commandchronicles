package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/NeverVane/commandchronicles/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestNewEncryptor(t *testing.T) {
	encryptor := NewEncryptor()

	assert.NotNil(t, encryptor)
	assert.NotNil(t, encryptor.logger)
}

func TestEncryptRecord_ValidRecord(t *testing.T) {
	encryptor := NewEncryptor()
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)

	record := storage.NewCommandRecord(
		"echo hello world",
		0,
		150,
		"/home/user",
		"session-123",
		"test-host",
	)

	encrypted, err := encryptor.EncryptRecord(record, key)
	require.NoError(t, err)
	assert.NotNil(t, encrypted)
	assert.Greater(t, len(encrypted), MinEncryptedSize)
}

func TestEncryptRecord_NilRecord(t *testing.T) {
	encryptor := NewEncryptor()
	key := make([]byte, chacha20poly1305.KeySize)

	_, err := encryptor.EncryptRecord(nil, key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "record cannot be nil")
}

func TestEncryptRecord_InvalidKey(t *testing.T) {
	encryptor := NewEncryptor()
	record := storage.NewCommandRecord("test", 0, 100, "/tmp", "session", "host")

	tests := []struct {
		name string
		key  []byte
	}{
		{"empty key", []byte{}},
		{"short key", make([]byte, 16)},
		{"long key", make([]byte, 64)},
		{"all zeros", make([]byte, chacha20poly1305.KeySize)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encryptor.EncryptRecord(record, tt.key)
			assert.Error(t, err)
		})
	}
}

func TestDecryptRecord_ValidData(t *testing.T) {
	encryptor := NewEncryptor()
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)

	originalRecord := storage.NewCommandRecord(
		"git commit -m 'test'",
		0,
		250,
		"/home/user/project",
		"session-456",
		"dev-machine",
	)

	// Encrypt
	encrypted, err := encryptor.EncryptRecord(originalRecord, key)
	require.NoError(t, err)

	// Decrypt
	decrypted, err := encryptor.DecryptRecord(encrypted, key)
	require.NoError(t, err)

	// Verify round-trip
	assert.Equal(t, originalRecord.Command, decrypted.Command)
	assert.Equal(t, originalRecord.ExitCode, decrypted.ExitCode)
	assert.Equal(t, originalRecord.Duration, decrypted.Duration)
	assert.Equal(t, originalRecord.WorkingDir, decrypted.WorkingDir)
	assert.Equal(t, originalRecord.SessionID, decrypted.SessionID)
	assert.Equal(t, originalRecord.Hostname, decrypted.Hostname)
}

func TestDecryptRecord_InvalidData(t *testing.T) {
	encryptor := NewEncryptor()
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)

	tests := []struct {
		name string
		data []byte
	}{
		{"empty data", []byte{}},
		{"too short", make([]byte, MinEncryptedSize-1)},
		{"random garbage", make([]byte, 100)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encryptor.DecryptRecord(tt.data, key)
			assert.Error(t, err)
		})
	}
}

func TestDecryptRecord_WrongKey(t *testing.T) {
	encryptor := NewEncryptor()

	// Encrypt with one key
	key1 := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key1)

	record := storage.NewCommandRecord("test", 0, 100, "/tmp", "session", "host")
	encrypted, err := encryptor.EncryptRecord(record, key1)
	require.NoError(t, err)

	// Try to decrypt with different key
	key2 := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key2)

	_, err = encryptor.DecryptRecord(encrypted, key2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decryption failed")
}

func TestEncryptBytes_ValidData(t *testing.T) {
	encryptor := NewEncryptor()
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)

	data := []byte("Hello, World! This is test data.")

	encrypted, err := encryptor.EncryptBytes(data, key)
	require.NoError(t, err)
	assert.Greater(t, len(encrypted), len(data))
}

func TestDecryptBytes_ValidData(t *testing.T) {
	encryptor := NewEncryptor()
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)

	originalData := []byte("Test data for encryption and decryption")

	// Encrypt
	encrypted, err := encryptor.EncryptBytes(originalData, key)
	require.NoError(t, err)

	// Decrypt
	decrypted, err := encryptor.DecryptBytes(encrypted, key)
	require.NoError(t, err)

	// Verify round-trip
	assert.True(t, bytes.Equal(originalData, decrypted))
}

func TestEncryptBytes_InvalidInputs(t *testing.T) {
	encryptor := NewEncryptor()
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)

	tests := []struct {
		name string
		data []byte
		key  []byte
	}{
		{"empty data", []byte{}, key},
		{"too large data", make([]byte, MaxPlaintextSize+1), key},
		{"invalid key", []byte("test"), make([]byte, 16)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encryptor.EncryptBytes(tt.data, tt.key)
			assert.Error(t, err)
		})
	}
}

func TestValidateEncryptedData(t *testing.T) {
	encryptor := NewEncryptor()
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)

	// Create valid encrypted data
	data := []byte("test data")
	encrypted, err := encryptor.EncryptBytes(data, key)
	require.NoError(t, err)

	// Valid data should pass
	err = encryptor.ValidateEncryptedData(encrypted)
	assert.NoError(t, err)

	// Invalid data should fail
	tests := []struct {
		name string
		data []byte
	}{
		{"too short", make([]byte, MinEncryptedSize-1)},
		{"too large", make([]byte, MaxPlaintextSize+MinEncryptedSize+1)},
		{"all zeros nonce", append(make([]byte, NonceSize), make([]byte, TagSize)...)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := encryptor.ValidateEncryptedData(tt.data)
			assert.Error(t, err)
		})
	}
}

func TestGenerateNonce(t *testing.T) {
	encryptor := NewEncryptor()

	nonce1, err := encryptor.GenerateNonce()
	require.NoError(t, err)
	assert.Equal(t, NonceSize, len(nonce1))

	nonce2, err := encryptor.GenerateNonce()
	require.NoError(t, err)
	assert.Equal(t, NonceSize, len(nonce2))

	// Nonces should be different
	assert.False(t, bytes.Equal(nonce1, nonce2))
}

func TestGetEncryptionOverhead(t *testing.T) {
	encryptor := NewEncryptor()
	overhead := encryptor.GetEncryptionOverhead()

	expected := NonceSize + TagSize
	assert.Equal(t, expected, overhead)
	assert.Equal(t, 40, overhead) // 24 + 16
}

func TestEstimateEncryptedSize(t *testing.T) {
	encryptor := NewEncryptor()

	tests := []struct {
		plaintextSize int
		expectedSize  int
	}{
		{0, MinEncryptedSize},
		{100, 100 + MinEncryptedSize},
		{1000, 1000 + MinEncryptedSize},
	}

	for _, tt := range tests {
		t.Run("plaintext_size_"+string(rune(tt.plaintextSize)), func(t *testing.T) {
			size := encryptor.EstimateEncryptedSize(tt.plaintextSize)
			assert.Equal(t, tt.expectedSize, size)
		})
	}
}

func TestCreateEncryptedData(t *testing.T) {
	encryptor := NewEncryptor()

	data := []byte("test data")
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)

	encrypted := encryptor.CreateEncryptedData(data, nonce)

	assert.NotNil(t, encrypted)
	assert.True(t, bytes.Equal(data, encrypted.Data))
	assert.True(t, bytes.Equal(nonce, encrypted.Nonce))
	assert.Greater(t, encrypted.Timestamp, int64(0))
	assert.Equal(t, 1, encrypted.Version)
}

func TestEncryptedData_SecureErase(t *testing.T) {
	encryptor := NewEncryptor()

	data := []byte("sensitive data")
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)

	encrypted := encryptor.CreateEncryptedData(data, nonce)

	// Verify data exists
	assert.NotNil(t, encrypted.Data)
	assert.NotNil(t, encrypted.Nonce)
	assert.Greater(t, encrypted.Timestamp, int64(0))

	// Secure erase
	encrypted.SecureErase()

	// Verify data is cleared
	assert.Nil(t, encrypted.Data)
	assert.Nil(t, encrypted.Nonce)
	assert.Equal(t, int64(0), encrypted.Timestamp)
	assert.Equal(t, 0, encrypted.Version)
}

func TestEncryptionDeterminism(t *testing.T) {
	encryptor := NewEncryptor()
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)

	data := []byte("determinism test")

	// Encrypt twice
	encrypted1, err := encryptor.EncryptBytes(data, key)
	require.NoError(t, err)

	encrypted2, err := encryptor.EncryptBytes(data, key)
	require.NoError(t, err)

	// Encrypted data should be different (different nonces)
	assert.False(t, bytes.Equal(encrypted1, encrypted2))

	// But both should decrypt to same plaintext
	decrypted1, err := encryptor.DecryptBytes(encrypted1, key)
	require.NoError(t, err)

	decrypted2, err := encryptor.DecryptBytes(encrypted2, key)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(decrypted1, decrypted2))
	assert.True(t, bytes.Equal(data, decrypted1))
}

func TestCrossDeviceCompatibility(t *testing.T) {
	// Simulate two different devices with same key derivation
	kd := NewKeyDerivator()
	username := "testuser"
	password := "testpassword123"

	// Device 1: Derive key and encrypt
	key1, err := kd.DeriveKeyFromCredentials(username, password)
	require.NoError(t, err)

	encryptor1 := NewEncryptor()
	record := storage.NewCommandRecord(
		"cross-device test command",
		0,
		200,
		"/home/user",
		"session-789",
		"device1",
	)

	encrypted, err := encryptor1.EncryptRecord(record, key1.Key)
	require.NoError(t, err)

	// Device 2: Derive same key and decrypt
	key2, err := kd.DeriveKeyFromCredentials(username, password)
	require.NoError(t, err)

	// Keys should be identical
	assert.True(t, bytes.Equal(key1.Key, key2.Key))

	encryptor2 := NewEncryptor()
	decrypted, err := encryptor2.DecryptRecord(encrypted, key2.Key)
	require.NoError(t, err)

	// Should decrypt successfully to original record
	assert.Equal(t, record.Command, decrypted.Command)
	assert.Equal(t, record.SessionID, decrypted.SessionID)
	assert.Equal(t, record.Hostname, decrypted.Hostname)
}

func TestTamperedDataDetection(t *testing.T) {
	encryptor := NewEncryptor()
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)

	data := []byte("important data")
	encrypted, err := encryptor.EncryptBytes(data, key)
	require.NoError(t, err)

	// Tamper with the encrypted data
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[len(tampered)-1] ^= 0x01 // Flip last bit

	// Decryption should fail due to authentication failure
	_, err = encryptor.DecryptBytes(tampered, key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decryption failed")
}

func TestLargeDataEncryption(t *testing.T) {
	encryptor := NewEncryptor()
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)

	// Test with moderately large data (1MB)
	largeData := make([]byte, 1024*1024)
	rand.Read(largeData)

	encrypted, err := encryptor.EncryptBytes(largeData, key)
	require.NoError(t, err)

	decrypted, err := encryptor.DecryptBytes(encrypted, key)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(largeData, decrypted))
}

func TestEncryptionConstants(t *testing.T) {
	assert.Equal(t, 24, NonceSize)
	assert.Equal(t, 16, TagSize)
	assert.Equal(t, 40, MinEncryptedSize)
	assert.Equal(t, 16*1024*1024, MaxPlaintextSize)
}

// Benchmark tests
func BenchmarkEncryptRecord(b *testing.B) {
	encryptor := NewEncryptor()
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)

	record := storage.NewCommandRecord(
		"benchmark command with some length",
		0,
		100,
		"/home/user",
		"session",
		"host",
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encryptor.EncryptRecord(record, key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptRecord(b *testing.B) {
	encryptor := NewEncryptor()
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)

	record := storage.NewCommandRecord(
		"benchmark command for decryption",
		0,
		100,
		"/home/user",
		"session",
		"host",
	)

	encrypted, err := encryptor.EncryptRecord(record, key)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encryptor.DecryptRecord(encrypted, key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptBytes(b *testing.B) {
	encryptor := NewEncryptor()
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)

	data := make([]byte, 1024) // 1KB data
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encryptor.EncryptBytes(data, key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptBytes(b *testing.B) {
	encryptor := NewEncryptor()
	key := make([]byte, chacha20poly1305.KeySize)
	rand.Read(key)

	data := make([]byte, 1024)
	rand.Read(data)

	encrypted, err := encryptor.EncryptBytes(data, key)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encryptor.DecryptBytes(encrypted, key)
		if err != nil {
			b.Fatal(err)
		}
	}
}
