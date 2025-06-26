package security

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/NeverVane/commandchronicles-cli/internal/config"
	"github.com/NeverVane/commandchronicles-cli/internal/storage"
	"github.com/NeverVane/commandchronicles-cli/pkg/crypto"
	"github.com/NeverVane/commandchronicles-cli/pkg/security"
	secureStorage "github.com/NeverVane/commandchronicles-cli/pkg/storage"
)

// BenchmarkCryptographicOperations benchmarks core cryptographic operations
func BenchmarkKeyDerivation(b *testing.B) {
	kd := crypto.NewKeyDerivator()
	
	b.Run("Argon2id_Default", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key, err := kd.DeriveKeyFromCredentials("user", "password123")
			if err != nil {
				b.Fatal(err)
			}
			key.SecureErase()
		}
	})

	b.Run("Argon2id_HighSecurity", func(b *testing.B) {
		highSecParams := crypto.GetRecommendedParams("high")
		kdHigh := crypto.NewKeyDerivatorWithParams(highSecParams)
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key, err := kdHigh.DeriveKeyFromCredentials("user", "password123")
			if err != nil {
				b.Fatal(err)
			}
			key.SecureErase()
		}
	})

	b.Run("Argon2id_LowSecurity", func(b *testing.B) {
		lowSecParams := crypto.GetRecommendedParams("low")
		kdLow := crypto.NewKeyDerivatorWithParams(lowSecParams)
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key, err := kdLow.DeriveKeyFromCredentials("user", "password123")
			if err != nil {
				b.Fatal(err)
			}
			key.SecureErase()
		}
	})
}

func BenchmarkEncryption(b *testing.B) {
	encryptor := crypto.NewEncryptor()
	kd := crypto.NewKeyDerivator()
	
	key, err := kd.DeriveKeyFromCredentials("benchuser", "benchpass123")
	if err != nil {
		b.Fatal(err)
	}
	defer key.SecureErase()

	// Test different data sizes
	dataSizes := []int{
		100,    // Small command
		1000,   // Medium command
		10000,  // Large command
		100000, // Very large command
	}

	for _, size := range dataSizes {
		b.Run(fmt.Sprintf("Encrypt_%dB", size), func(b *testing.B) {
			data := make([]byte, size)
			rand.Read(data)
			
			b.ResetTimer()
			b.SetBytes(int64(size))
			
			for i := 0; i < b.N; i++ {
				_, err := encryptor.EncryptBytes(data, key.Key)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("Decrypt_%dB", size), func(b *testing.B) {
			data := make([]byte, size)
			rand.Read(data)
			
			ciphertext, err := encryptor.EncryptBytes(data, key.Key)
			if err != nil {
				b.Fatal(err)
			}
			
			b.ResetTimer()
			b.SetBytes(int64(size))
			
			for i := 0; i < b.N; i++ {
				_, err := encryptor.DecryptBytes(ciphertext, key.Key)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}

	b.Run("EncryptRecord", func(b *testing.B) {
		record := storage.NewCommandRecord(
			"benchmark encryption test command with some reasonable length",
			0, 150, "/benchmark", "bench-session", "bench-host")
		
		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			_, err := encryptor.EncryptRecord(record, key.Key)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("DecryptRecord", func(b *testing.B) {
		record := storage.NewCommandRecord(
			"benchmark decryption test command with some reasonable length",
			0, 150, "/benchmark", "bench-session", "bench-host")
		
		ciphertext, err := encryptor.EncryptRecord(record, key.Key)
		if err != nil {
			b.Fatal(err)
		}
		
		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			_, err := encryptor.DecryptRecord(ciphertext, key.Key)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkSessionManagement(b *testing.B) {
	tmpDir := b.TempDir()
	sessionPath := filepath.Join(tmpDir, "session.key")
	
	skm := crypto.NewSessionKeyManager(sessionPath, 5*time.Minute)
	defer skm.Close()

	testKey := make([]byte, 32)
	rand.Read(testKey)

	b.Run("StoreSessionKey", func(b *testing.B) {
		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			err := skm.StoreSessionKey(fmt.Sprintf("user%d", i), "password123", testKey)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	// Store a session for loading benchmark
	err := skm.StoreSessionKey("loaduser", "password123", testKey)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("LoadSessionKey", func(b *testing.B) {
		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			sessionKey, err := skm.LoadSessionKey("loaduser", "password123")
			if err != nil {
				b.Fatal(err)
			}
			sessionKey.SecureErase()
		}
	})
}

// BenchmarkPermissionOperations benchmarks permission checking operations
func BenchmarkPermissionOperations(b *testing.B) {
	if runtime.GOOS == "windows" {
		b.Skip("Skipping permission benchmarks on Windows")
	}

	tmpDir := b.TempDir()
	pe := security.NewPermissionEnforcer()

	// Create test files
	testFiles := make([]string, 100)
	for i := 0; i < 100; i++ {
		testFile := filepath.Join(tmpDir, fmt.Sprintf("test%d.db", i))
		err := os.WriteFile(testFile, []byte("test data"), 0600)
		if err != nil {
			b.Fatal(err)
		}
		testFiles[i] = testFile
	}

	b.Run("IsFileSecure", func(b *testing.B) {
		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			file := testFiles[i%len(testFiles)]
			pe.IsFileSecure(file)
		}
	})

	b.Run("AuditFilePermissions", func(b *testing.B) {
		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			file := testFiles[i%len(testFiles)]
			pe.AuditFilePermissions(file)
		}
	})

	b.Run("ValidatePath", func(b *testing.B) {
		paths := []string{
			"data/history.db",
			"config/settings.toml",
			"logs/audit.log",
			"./valid/path.txt",
		}
		
		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			path := paths[i%len(paths)]
			pe.ValidatePath(path)
		}
	})

	b.Run("SetSecureFilePermissions", func(b *testing.B) {
		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			file := testFiles[i%len(testFiles)]
			err := pe.SetSecureFilePermissions(file)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkSecureStorage benchmarks complete secure storage operations
func BenchmarkSecureStorage(b *testing.B) {
	tmpDir := b.TempDir()
	cfg := createBenchmarkConfig(tmpDir)

	ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
		Config:              cfg,
		AutoLockTimeout:     30 * time.Second,
		EnableSecureDelete:  true,
		ValidatePermissions: true,
		CreateIfMissing:     true,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer ss.Close()

	err = ss.Unlock("benchuser", "benchpassword123")
	if err != nil {
		b.Fatal(err)
	}

	b.Run("StoreRecord", func(b *testing.B) {
		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			record := storage.NewCommandRecord(
				fmt.Sprintf("benchmark command %d with sufficient length for realistic testing", i),
				0, int64(i*10), "/benchmark", "bench-session", "bench-host")
			
			_, err := ss.Store(record)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	// Store some records for retrieval benchmark
	for i := 0; i < 1000; i++ {
		record := storage.NewCommandRecord(
			fmt.Sprintf("retrieval test command %d", i),
			0, int64(i*10), "/test", "test-session", "test-host")
		
		_, err := ss.Store(record)
		if err != nil {
			b.Fatal(err)
		}
	}

	b.Run("RetrieveRecords", func(b *testing.B) {
		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			_, err := ss.Retrieve(&secureStorage.QueryOptions{Limit: 10})
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("RetrieveRecordsLarge", func(b *testing.B) {
		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			_, err := ss.Retrieve(&secureStorage.QueryOptions{Limit: 100})
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ValidateIntegrity", func(b *testing.B) {
		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			err := ss.ValidateIntegrity()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("LockUnlock", func(b *testing.B) {
		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			err := ss.Lock()
			if err != nil {
				b.Fatal(err)
			}
			
			err = ss.Unlock("benchuser", "benchpassword123")
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkConcurrentOperations benchmarks concurrent security operations
func BenchmarkConcurrentOperations(b *testing.B) {
	tmpDir := b.TempDir()
	cfg := createBenchmarkConfig(tmpDir)

	ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
		Config:              cfg,
		AutoLockTimeout:     5 * time.Minute,
		EnableSecureDelete:  true,
		ValidatePermissions: true,
		CreateIfMissing:     true,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer ss.Close()

	err = ss.Unlock("concurrentuser", "password123")
	if err != nil {
		b.Fatal(err)
	}

	b.Run("ConcurrentStores", func(b *testing.B) {
		b.ResetTimer()
		
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				record := storage.NewCommandRecord(
					fmt.Sprintf("concurrent store command %d", i),
					0, int64(i*10), "/concurrent", "concurrent-session", "concurrent-host")
				
				_, err := ss.Store(record)
				if err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
	})

	// Store some data for concurrent retrieval
	for i := 0; i < 500; i++ {
		record := storage.NewCommandRecord(
			fmt.Sprintf("concurrent retrieval test %d", i),
			0, int64(i*10), "/test", "test-session", "test-host")
		
		_, err := ss.Store(record)
		if err != nil {
			b.Fatal(err)
		}
	}

	b.Run("ConcurrentRetrieves", func(b *testing.B) {
		b.ResetTimer()
		
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := ss.Retrieve(&secureStorage.QueryOptions{Limit: 10})
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})

	b.Run("MixedConcurrentOps", func(b *testing.B) {
		b.ResetTimer()
		
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				if i%2 == 0 {
					// Store operation
					record := storage.NewCommandRecord(
						fmt.Sprintf("mixed ops store %d", i),
						0, int64(i*10), "/mixed", "mixed-session", "mixed-host")
					
					_, err := ss.Store(record)
					if err != nil {
						b.Fatal(err)
					}
				} else {
					// Retrieve operation
					_, err := ss.Retrieve(&secureStorage.QueryOptions{Limit: 5})
					if err != nil {
						b.Fatal(err)
					}
				}
				i++
			}
		})
	})
}

// BenchmarkCryptographicConcurrency benchmarks concurrent crypto operations
func BenchmarkCryptographicConcurrency(b *testing.B) {
	encryptor := crypto.NewEncryptor()
	kd := crypto.NewKeyDerivator()
	
	key, err := kd.DeriveKeyFromCredentials("concurrentcrypto", "password123")
	if err != nil {
		b.Fatal(err)
	}
	defer key.SecureErase()

	testData := make([]byte, 1000)
	rand.Read(testData)

	b.Run("ConcurrentEncryption", func(b *testing.B) {
		b.ResetTimer()
		
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := encryptor.EncryptBytes(testData, key.Key)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})

	// Pre-encrypt data for decryption benchmark
	ciphertext, err := encryptor.EncryptBytes(testData, key.Key)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("ConcurrentDecryption", func(b *testing.B) {
		b.ResetTimer()
		
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := encryptor.DecryptBytes(ciphertext, key.Key)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})

	b.Run("ConcurrentKeyDerivation", func(b *testing.B) {
		b.ResetTimer()
		
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				key, err := kd.DeriveKeyFromCredentials(
					fmt.Sprintf("user%d", i), "password123")
				if err != nil {
					b.Fatal(err)
				}
				key.SecureErase()
				i++
			}
		})
	})
}

// BenchmarkMemoryUsage benchmarks memory efficiency
func BenchmarkMemoryUsage(b *testing.B) {
	b.Run("MemoryAllocation_Encryption", func(b *testing.B) {
		encryptor := crypto.NewEncryptor()
		kd := crypto.NewKeyDerivator()
		
		key, err := kd.DeriveKeyFromCredentials("memuser", "password123")
		if err != nil {
			b.Fatal(err)
		}
		defer key.SecureErase()

		data := make([]byte, 10000)
		rand.Read(data)

		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			ciphertext, err := encryptor.EncryptBytes(data, key.Key)
			if err != nil {
				b.Fatal(err)
			}
			_ = ciphertext
		}
	})

	b.Run("MemoryAllocation_KeyDerivation", func(b *testing.B) {
		kd := crypto.NewKeyDerivator()
		
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			key, err := kd.DeriveKeyFromCredentials("user", "password123")
			if err != nil {
				b.Fatal(err)
			}
			key.SecureErase()
		}
	})

	b.Run("MemoryAllocation_SecureStorage", func(b *testing.B) {
		tmpDir := b.TempDir()
		cfg := createBenchmarkConfig(tmpDir)

		ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
			Config:          cfg,
			CreateIfMissing: true,
		})
		if err != nil {
			b.Fatal(err)
		}
		defer ss.Close()

		err = ss.Unlock("memuser", "password123")
		if err != nil {
			b.Fatal(err)
		}

		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			record := storage.NewCommandRecord(
				fmt.Sprintf("memory test command %d", i),
				0, int64(i), "/mem", "mem-session", "mem-host")
			
			_, err := ss.Store(record)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkScalability benchmarks operations at scale
func BenchmarkScalability(b *testing.B) {
	scales := []int{100, 1000, 10000}
	
	for _, scale := range scales {
		b.Run(fmt.Sprintf("Scale_%d", scale), func(b *testing.B) {
			tmpDir := b.TempDir()
			cfg := createBenchmarkConfig(tmpDir)

			ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
				Config:          cfg,
				CreateIfMissing: true,
			})
			if err != nil {
				b.Fatal(err)
			}
			defer ss.Close()

			err = ss.Unlock("scaleuser", "password123")
			if err != nil {
				b.Fatal(err)
			}

			// Pre-populate with data
			for i := 0; i < scale; i++ {
				record := storage.NewCommandRecord(
					fmt.Sprintf("scale test command %d", i),
					0, int64(i), "/scale", "scale-session", "scale-host")
				
				_, err := ss.Store(record)
				if err != nil {
					b.Fatal(err)
				}
			}

			b.ResetTimer()
			
			// Benchmark retrieval performance with existing data
			for i := 0; i < b.N; i++ {
				_, err := ss.Retrieve(&secureStorage.QueryOptions{Limit: 50})
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkSecurityRegression benchmarks to detect performance regressions
func BenchmarkSecurityRegression(b *testing.B) {
	// These benchmarks establish baseline performance expectations
	// and help detect regressions in security-critical operations
	
	b.Run("Baseline_KeyDerivation", func(b *testing.B) {
		kd := crypto.NewKeyDerivator()
		
		start := time.Now()
		key, err := kd.DeriveKeyFromCredentials("baseline", "password123")
		baseline := time.Since(start)
		
		if err != nil {
			b.Fatal(err)
		}
		key.SecureErase()
		
		// Key derivation should not be too fast (security) or too slow (usability)
		if baseline < 10*time.Millisecond {
			b.Errorf("Key derivation too fast: %v (min: 10ms)", baseline)
		}
		if baseline > 5*time.Second {
			b.Errorf("Key derivation too slow: %v (max: 5s)", baseline)
		}
		
		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			key, err := kd.DeriveKeyFromCredentials("baseline", "password123")
			if err != nil {
				b.Fatal(err)
			}
			key.SecureErase()
		}
	})

	b.Run("Baseline_Encryption", func(b *testing.B) {
		encryptor := crypto.NewEncryptor()
		kd := crypto.NewKeyDerivator()
		
		key, err := kd.DeriveKeyFromCredentials("baseline", "password123")
		if err != nil {
			b.Fatal(err)
		}
		defer key.SecureErase()

		data := make([]byte, 1000)
		rand.Read(data)
		
		b.ResetTimer()
		b.SetBytes(1000)
		
		for i := 0; i < b.N; i++ {
			_, err := encryptor.EncryptBytes(data, key.Key)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Baseline_StorageOperation", func(b *testing.B) {
		tmpDir := b.TempDir()
		cfg := createBenchmarkConfig(tmpDir)

		ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
			Config:          cfg,
			CreateIfMissing: true,
		})
		if err != nil {
			b.Fatal(err)
		}
		defer ss.Close()

		err = ss.Unlock("baseline", "password123")
		if err != nil {
			b.Fatal(err)
		}

		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			record := storage.NewCommandRecord(
				fmt.Sprintf("baseline command %d", i),
				0, int64(i), "/baseline", "baseline-session", "baseline-host")
			
			_, err := ss.Store(record)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Helper function for creating benchmark configuration
func createBenchmarkConfig(tmpDir string) *config.Config {
	return &config.Config{
		Database: config.DatabaseConfig{
			Path:         filepath.Join(tmpDir, "data", "benchmark.db"),
			MaxOpenConns: 25,
			MaxIdleConns: 10,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
		Security: config.SecurityConfig{
			SessionKeyPath:    filepath.Join(tmpDir, "data", "session"),
			SessionTimeout:    30,
			Argon2Time:        3,
			Argon2Memory:      64 * 1024,
			Argon2Threads:     4,
			AutoLockTimeout:   0,
			SecureMemoryClear: true,
		},
	}
}