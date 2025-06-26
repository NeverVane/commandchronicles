package crypto

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKeyDerivator(t *testing.T) {
	kd := NewKeyDerivator()
	
	assert.NotNil(t, kd)
	assert.NotNil(t, kd.params)
	assert.NotNil(t, kd.logger)
	
	// Verify default parameters
	assert.Equal(t, uint32(Argon2Time), kd.params.Time)
	assert.Equal(t, uint32(Argon2Memory), kd.params.Memory)
	assert.Equal(t, uint8(Argon2Threads), kd.params.Threads)
	assert.Equal(t, uint32(KeyLength), kd.params.KeyLength)
}

func TestNewKeyDerivatorWithParams(t *testing.T) {
	customParams := &KeyDerivationParams{
		Time:      5,
		Memory:    128 * 1024,
		Threads:   8,
		KeyLength: 32,
	}
	
	kd := NewKeyDerivatorWithParams(customParams)
	
	assert.NotNil(t, kd)
	assert.Equal(t, uint32(5), kd.params.Time)
	assert.Equal(t, uint32(128*1024), kd.params.Memory)
	assert.Equal(t, uint8(8), kd.params.Threads)
	assert.Equal(t, uint32(32), kd.params.KeyLength)
	assert.NotNil(t, kd.params.SaltBytes)
	assert.Equal(t, SaltLength, len(kd.params.SaltBytes))
}

func TestGenerateSalt(t *testing.T) {
	kd := NewKeyDerivator()
	
	salt1, err := kd.GenerateSalt()
	require.NoError(t, err)
	assert.Equal(t, SaltLength, len(salt1))
	
	salt2, err := kd.GenerateSalt()
	require.NoError(t, err)
	assert.Equal(t, SaltLength, len(salt2))
	
	// Salts should be different (extremely unlikely to be same)
	assert.False(t, bytes.Equal(salt1, salt2))
}

func TestDeriveKey(t *testing.T) {
	kd := NewKeyDerivator()
	password := "test_password_123"
	salt := make([]byte, SaltLength)
	copy(salt, "test_salt_for_derivation_12345678")
	
	derivedKey, err := kd.DeriveKey(password, salt)
	require.NoError(t, err)
	require.NotNil(t, derivedKey)
	
	assert.Equal(t, KeyLength, len(derivedKey.Key))
	assert.True(t, bytes.Equal(salt, derivedKey.Salt))
	assert.Equal(t, kd.params.Time, derivedKey.Params.Time)
	assert.Equal(t, kd.params.Memory, derivedKey.Params.Memory)
	assert.Equal(t, kd.params.Threads, derivedKey.Params.Threads)
}

func TestDeriveKey_Deterministic(t *testing.T) {
	kd := NewKeyDerivator()
	password := "deterministic_test"
	salt := make([]byte, SaltLength)
	copy(salt, "same_salt_every_time_12345678901")
	
	// Derive key twice with same inputs
	key1, err := kd.DeriveKey(password, salt)
	require.NoError(t, err)
	
	key2, err := kd.DeriveKey(password, salt)
	require.NoError(t, err)
	
	// Keys should be identical
	assert.True(t, bytes.Equal(key1.Key, key2.Key))
}

func TestDeriveKey_DifferentPasswords(t *testing.T) {
	kd := NewKeyDerivator()
	salt := make([]byte, SaltLength)
	copy(salt, "same_salt_different_passwords_12")
	
	key1, err := kd.DeriveKey("password1", salt)
	require.NoError(t, err)
	
	key2, err := kd.DeriveKey("password2", salt)
	require.NoError(t, err)
	
	// Keys should be different
	assert.False(t, bytes.Equal(key1.Key, key2.Key))
}

func TestDeriveKey_ValidationErrors(t *testing.T) {
	kd := NewKeyDerivator()
	salt := make([]byte, SaltLength)
	
	tests := []struct {
		name     string
		password string
		salt     []byte
		wantErr  bool
	}{
		{
			name:     "password too short",
			password: "short",
			salt:     salt,
			wantErr:  true,
		},
		{
			name:     "password too long",
			password: string(make([]byte, MaxPasswordLength+1)),
			salt:     salt,
			wantErr:  true,
		},
		{
			name:     "empty salt",
			password: "valid_password",
			salt:     []byte{},
			wantErr:  true,
		},
		{
			name:     "salt too short",
			password: "valid_password",
			salt:     make([]byte, 15),
			wantErr:  true,
		},
		{
			name:     "valid inputs",
			password: "valid_password",
			salt:     salt,
			wantErr:  false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := kd.DeriveKey(tt.password, tt.salt)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDeriveKeyFromCredentials(t *testing.T) {
	kd := NewKeyDerivator()
	username := "testuser"
	password := "testpassword123"
	
	// Derive key twice with same credentials
	key1, err := kd.DeriveKeyFromCredentials(username, password)
	require.NoError(t, err)
	
	key2, err := kd.DeriveKeyFromCredentials(username, password)
	require.NoError(t, err)
	
	// Keys should be identical (deterministic)
	assert.True(t, bytes.Equal(key1.Key, key2.Key))
	assert.True(t, bytes.Equal(key1.Salt, key2.Salt))
}

func TestDeriveKeyFromCredentials_DifferentUsers(t *testing.T) {
	kd := NewKeyDerivator()
	password := "same_password"
	
	key1, err := kd.DeriveKeyFromCredentials("user1", password)
	require.NoError(t, err)
	
	key2, err := kd.DeriveKeyFromCredentials("user2", password)
	require.NoError(t, err)
	
	// Keys should be different (different usernames = different salts)
	assert.False(t, bytes.Equal(key1.Key, key2.Key))
	assert.False(t, bytes.Equal(key1.Salt, key2.Salt))
}

func TestDeriveKeyFromCredentials_EmptyUsername(t *testing.T) {
	kd := NewKeyDerivator()
	
	_, err := kd.DeriveKeyFromCredentials("", "password")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "username cannot be empty")
}

func TestDeriveKeyFromCredentials_LongUsername(t *testing.T) {
	kd := NewKeyDerivator()
	longUsername := string(make([]byte, SaltLength*2))
	password := "testpassword123"
	
	key, err := kd.DeriveKeyFromCredentials(longUsername, password)
	require.NoError(t, err)
	assert.Equal(t, SaltLength, len(key.Salt))
}

func TestDeriveKeyWithRandomSalt(t *testing.T) {
	kd := NewKeyDerivator()
	password := "test_password"
	
	key1, err := kd.DeriveKeyWithRandomSalt(password)
	require.NoError(t, err)
	
	key2, err := kd.DeriveKeyWithRandomSalt(password)
	require.NoError(t, err)
	
	// Keys should be different (different random salts)
	assert.False(t, bytes.Equal(key1.Key, key2.Key))
	assert.False(t, bytes.Equal(key1.Salt, key2.Salt))
	
	// But both should be valid
	assert.Equal(t, KeyLength, len(key1.Key))
	assert.Equal(t, KeyLength, len(key2.Key))
	assert.Equal(t, SaltLength, len(key1.Salt))
	assert.Equal(t, SaltLength, len(key2.Salt))
}

func TestVerifyPassword(t *testing.T) {
	kd := NewKeyDerivator()
	password := "correct_password"
	salt := make([]byte, SaltLength)
	copy(salt, "test_salt_for_verification_123")
	
	derivedKey, err := kd.DeriveKey(password, salt)
	require.NoError(t, err)
	
	// Correct password should verify
	match, err := kd.VerifyPassword(password, derivedKey)
	require.NoError(t, err)
	assert.True(t, match)
	
	// Wrong password should not verify
	match, err = kd.VerifyPassword("wrong_password", derivedKey)
	require.NoError(t, err)
	assert.False(t, match)
}

func TestVerifyPassword_NilKey(t *testing.T) {
	kd := NewKeyDerivator()
	
	_, err := kd.VerifyPassword("password", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "derived key cannot be nil")
}

func TestValidateParameters(t *testing.T) {
	tests := []struct {
		name    string
		params  *KeyDerivationParams
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid parameters",
			params: &KeyDerivationParams{
				Time:      3,
				Memory:    64 * 1024,
				Threads:   4,
				KeyLength: 32,
			},
			wantErr: false,
		},
		{
			name: "zero time",
			params: &KeyDerivationParams{
				Time:      0,
				Memory:    64 * 1024,
				Threads:   4,
				KeyLength: 32,
			},
			wantErr: true,
			errMsg:  "time parameter must be at least 1",
		},
		{
			name: "low memory",
			params: &KeyDerivationParams{
				Time:      3,
				Memory:    512,
				Threads:   4,
				KeyLength: 32,
			},
			wantErr: true,
			errMsg:  "memory parameter must be at least 1024 KB",
		},
		{
			name: "zero threads",
			params: &KeyDerivationParams{
				Time:      3,
				Memory:    64 * 1024,
				Threads:   0,
				KeyLength: 32,
			},
			wantErr: true,
			errMsg:  "threads parameter must be at least 1",
		},
		{
			name: "short key length",
			params: &KeyDerivationParams{
				Time:      3,
				Memory:    64 * 1024,
				Threads:   4,
				KeyLength: 8,
			},
			wantErr: true,
			errMsg:  "key length must be at least 16 bytes",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kd := NewKeyDerivatorWithParams(tt.params)
			err := kd.ValidateParameters()
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetParameters(t *testing.T) {
	originalParams := &KeyDerivationParams{
		Time:      5,
		Memory:    128 * 1024,
		Threads:   8,
		KeyLength: 32,
		SaltBytes: make([]byte, SaltLength),
	}
	
	kd := NewKeyDerivatorWithParams(originalParams)
	returnedParams := kd.GetParameters()
	
	// Should be equal but different instances
	assert.Equal(t, originalParams.Time, returnedParams.Time)
	assert.Equal(t, originalParams.Memory, returnedParams.Memory)
	assert.Equal(t, originalParams.Threads, returnedParams.Threads)
	assert.Equal(t, originalParams.KeyLength, returnedParams.KeyLength)
	assert.True(t, bytes.Equal(originalParams.SaltBytes, returnedParams.SaltBytes))
	
	// Should be different instances (not same pointer)
	assert.False(t, &originalParams.SaltBytes[0] == &returnedParams.SaltBytes[0])
}

func TestEstimateDerivationTime(t *testing.T) {
	kd := NewKeyDerivator()
	
	duration, err := kd.EstimateDerivationTime()
	require.NoError(t, err)
	
	// Should take some measurable time (at least 1ms)
	assert.Greater(t, duration, time.Millisecond)
	
	// But shouldn't take too long in tests (less than 5 seconds)
	assert.Less(t, duration, 5*time.Second)
}

func TestSecureErase(t *testing.T) {
	kd := NewKeyDerivator()
	password := "test_password"
	salt := make([]byte, SaltLength)
	
	derivedKey, err := kd.DeriveKey(password, salt)
	require.NoError(t, err)
	
	// Verify key and salt are not nil initially
	assert.NotNil(t, derivedKey.Key)
	assert.NotNil(t, derivedKey.Salt)
	assert.NotNil(t, derivedKey.Params)
	
	// Secure erase
	derivedKey.SecureErase()
	
	// Verify key and salt are nil after erase
	assert.Nil(t, derivedKey.Key)
	assert.Nil(t, derivedKey.Salt)
	assert.Nil(t, derivedKey.Params)
}

func TestGetRecommendedParams(t *testing.T) {
	tests := []struct {
		level          string
		expectedTime   uint32
		expectedMemory uint32
		expectedThreads uint8
	}{
		{"low", 1, 32 * 1024, 2},
		{"medium", Argon2Time, Argon2Memory, Argon2Threads},
		{"high", 5, 128 * 1024, 8},
		{"invalid", Argon2Time, Argon2Memory, Argon2Threads}, // should default to medium
		{"", Argon2Time, Argon2Memory, Argon2Threads},        // should default to medium
	}
	
	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			params := GetRecommendedParams(tt.level)
			
			assert.Equal(t, tt.expectedTime, params.Time)
			assert.Equal(t, tt.expectedMemory, params.Memory)
			assert.Equal(t, tt.expectedThreads, params.Threads)
			assert.Equal(t, uint32(KeyLength), params.KeyLength)
		})
	}
}

func TestConstants(t *testing.T) {
	assert.Equal(t, 3, Argon2Time)
	assert.Equal(t, 64*1024, Argon2Memory)
	assert.Equal(t, 4, Argon2Threads)
	assert.Equal(t, 32, SaltLength)
	assert.Equal(t, 32, KeyLength)
	assert.Equal(t, 8, MinPasswordLength)
	assert.Equal(t, 128, MaxPasswordLength)
}

// Benchmark tests
func BenchmarkDeriveKey(b *testing.B) {
	kd := NewKeyDerivator()
	password := "benchmark_password"
	salt := make([]byte, SaltLength)
	copy(salt, "benchmark_salt_for_testing_123")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := kd.DeriveKey(password, salt)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDeriveKeyFromCredentials(b *testing.B) {
	kd := NewKeyDerivator()
	username := "benchuser"
	password := "benchmark_password"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := kd.DeriveKeyFromCredentials(username, password)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyPassword(b *testing.B) {
	kd := NewKeyDerivator()
	password := "benchmark_password"
	salt := make([]byte, SaltLength)
	
	derivedKey, err := kd.DeriveKey(password, salt)
	if err != nil {
		b.Fatal(err)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := kd.VerifyPassword(password, derivedKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateSalt(b *testing.B) {
	kd := NewKeyDerivator()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := kd.GenerateSalt()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Security property tests
func TestSecurityProperties(t *testing.T) {
	t.Run("timing_consistency", func(t *testing.T) {
		kd := NewKeyDerivator()
		password := "consistent_timing_test"
		salt := make([]byte, SaltLength)
		
		var durations []time.Duration
		for i := 0; i < 5; i++ {
			start := time.Now()
			_, err := kd.DeriveKey(password, salt)
			require.NoError(t, err)
			durations = append(durations, time.Since(start))
		}
		
		// All durations should be roughly similar (within 50% of each other)
		avg := durations[0]
		for _, d := range durations[1:] {
			ratio := float64(d) / float64(avg)
			assert.True(t, ratio > 0.5 && ratio < 2.0, "Timing should be consistent")
		}
	})
	
	t.Run("avalanche_effect", func(t *testing.T) {
		kd := NewKeyDerivator()
		salt := make([]byte, SaltLength)
		
		key1, err := kd.DeriveKey("password1", salt)
		require.NoError(t, err)
		
		key2, err := kd.DeriveKey("password2", salt)
		require.NoError(t, err)
		
		// Small change in input should cause large change in output
		diffBits := 0
		for i := 0; i < len(key1.Key); i++ {
			xor := key1.Key[i] ^ key2.Key[i]
			for xor != 0 {
				diffBits++
				xor &= xor - 1
			}
		}
		
		// Should have changed approximately half the bits
		totalBits := len(key1.Key) * 8
		expectedDiff := totalBits / 2
		tolerance := totalBits / 4
		
		assert.True(t, diffBits > expectedDiff-tolerance && diffBits < expectedDiff+tolerance,
			"Avalanche effect: expected ~%d different bits, got %d", expectedDiff, diffBits)
	})
}