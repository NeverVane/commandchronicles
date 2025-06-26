package security

import (
	"crypto/rand"
	"runtime"
	"testing"
	"time"
)

func TestNewSecureBuffer(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{"valid size", 1024, false},
		{"zero size", 0, true},
		{"negative size", -1, true},
		{"max size", MaxSecureMemorySize, false},
		{"oversized", MaxSecureMemorySize + 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf, err := NewSecureBuffer(tt.size)
			if tt.wantErr {
				if err == nil {
					t.Errorf("NewSecureBuffer() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("NewSecureBuffer() unexpected error: %v", err)
				return
			}

			if buf == nil {
				t.Errorf("NewSecureBuffer() returned nil buffer")
				return
			}

			if buf.Capacity() != tt.size {
				t.Errorf("NewSecureBuffer() capacity = %d, want %d", buf.Capacity(), tt.size)
			}

			if !buf.locked {
				t.Errorf("NewSecureBuffer() buffer not locked")
			}

			buf.Destroy()
		})
	}
}

func TestSecureBufferCopy(t *testing.T) {
	buf, err := NewSecureBuffer(1024)
	if err != nil {
		t.Fatalf("Failed to create secure buffer: %v", err)
	}
	defer buf.Destroy()

	testData := []byte("test sensitive data")
	
	if err := buf.Copy(testData); err != nil {
		t.Errorf("Copy() error = %v", err)
	}

	if buf.Size() != len(testData) {
		t.Errorf("Size() = %d, want %d", buf.Size(), len(testData))
	}

	// Test oversized data
	oversized := make([]byte, 2048)
	if err := buf.Copy(oversized); err == nil {
		t.Errorf("Copy() expected error for oversized data")
	}
}

func TestSecureBufferData(t *testing.T) {
	buf, err := NewSecureBuffer(1024)
	if err != nil {
		t.Fatalf("Failed to create secure buffer: %v", err)
	}
	defer buf.Destroy()

	testData := []byte("sensitive information")
	buf.Copy(testData)

	retrieved := buf.Data()
	if len(retrieved) != len(testData) {
		t.Errorf("Data() length = %d, want %d", len(retrieved), len(testData))
	}

	for i := range testData {
		if retrieved[i] != testData[i] {
			t.Errorf("Data() content mismatch at index %d", i)
		}
	}
}

func TestSecureBufferWipe(t *testing.T) {
	buf, err := NewSecureBuffer(1024)
	if err != nil {
		t.Fatalf("Failed to create secure buffer: %v", err)
	}
	defer buf.Destroy()

	testData := []byte("secret data to be wiped")
	buf.Copy(testData)

	if buf.Size() != len(testData) {
		t.Errorf("Size before wipe = %d, want %d", buf.Size(), len(testData))
	}

	buf.Wipe()

	if buf.Size() != 0 {
		t.Errorf("Size after wipe = %d, want 0", buf.Size())
	}

	// Verify data is actually wiped
	data := buf.Data()
	if len(data) != 0 {
		t.Errorf("Data after wipe has length %d, want 0", len(data))
	}
}

func TestSecureBufferReset(t *testing.T) {
	buf, err := NewSecureBuffer(1024)
	if err != nil {
		t.Fatalf("Failed to create secure buffer: %v", err)
	}
	defer buf.Destroy()

	testData := []byte("initial data")
	buf.Copy(testData)

	// Reset with smaller size
	buf.Reset(512)
	if buf.Size() != 512 {
		t.Errorf("Size after reset = %d, want 512", buf.Size())
	}

	// Reset with larger size (should reallocate)
	buf.Reset(2048)
	if buf.Capacity() < 2048 {
		t.Errorf("Capacity after reset = %d, want at least 2048", buf.Capacity())
	}
}

func TestSecureBufferDestroy(t *testing.T) {
	buf, err := NewSecureBuffer(1024)
	if err != nil {
		t.Fatalf("Failed to create secure buffer: %v", err)
	}

	testData := []byte("data to be destroyed")
	buf.Copy(testData)

	buf.Destroy()

	// Verify buffer is finalized
	if !buf.finalized {
		t.Errorf("Buffer not marked as finalized after Destroy()")
	}

	// Verify operations fail after destroy
	if err := buf.Copy([]byte("test")); err == nil {
		t.Errorf("Copy() should fail after Destroy()")
	}

	data := buf.Data()
	if data != nil {
		t.Errorf("Data() should return nil after Destroy()")
	}
}

func TestSecureBufferPooling(t *testing.T) {
	allocator := NewSecureAllocator(5, MaxSecureMemorySize)

	// Create and return buffers to pool
	buffers := make([]*SecureBuffer, 3)
	for i := range buffers {
		buf, err := NewSecureBuffer(1024)
		if err != nil {
			t.Fatalf("Failed to create buffer %d: %v", i, err)
		}
		buffers[i] = buf
	}

	// Return to pool
	for _, buf := range buffers {
		buf.ReturnToPool()
	}

	stats := allocator.GetStats()
	poolSize := stats["pool_size"].(int)
	if poolSize != 3 {
		t.Errorf("Pool size = %d, want 3", poolSize)
	}

	// Create new buffer (should reuse from pool)
	newBuf, err := NewSecureBuffer(1024)
	if err != nil {
		t.Fatalf("Failed to create new buffer: %v", err)
	}
	defer newBuf.Destroy()

	// Pool size should be reduced
	stats = allocator.GetStats()
	poolSize = stats["pool_size"].(int)
	if poolSize != 2 {
		t.Errorf("Pool size after reuse = %d, want 2", poolSize)
	}
}

func TestSecureWipe(t *testing.T) {
	data := []byte("sensitive data to wipe")
	original := make([]byte, len(data))
	copy(original, data)

	SecureWipe(data)

	// Verify all bytes are zero
	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte at index %d not wiped: %d", i, b)
		}
	}

	// Verify original data was different
	allZero := true
	for _, b := range original {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Errorf("Original data was all zeros, test invalid")
	}
}

func TestSecureWipeString(t *testing.T) {
	original := "sensitive string data"
	s := original

	SecureWipeString(&s)

	if s != "" {
		t.Errorf("String not cleared: %q", s)
	}

	// Test with nil pointer
	var nilPtr *string
	SecureWipeString(nilPtr) // Should not panic

	// Test with empty string
	empty := ""
	SecureWipeString(&empty) // Should not panic
}

func TestWithSecureBuffer(t *testing.T) {
	testData := []byte("test data")
	var result []byte

	err := WithSecureBuffer(1024, func(buf *SecureBuffer) error {
		if err := buf.Copy(testData); err != nil {
			return err
		}
		result = buf.Data()
		return nil
	})

	if err != nil {
		t.Errorf("WithSecureBuffer() error = %v", err)
	}

	if len(result) != len(testData) {
		t.Errorf("Result length = %d, want %d", len(result), len(testData))
	}
}

func TestWithSecureBufferPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic was not recovered")
		}
	}()

	WithSecureBuffer(1024, func(buf *SecureBuffer) error {
		panic("test panic")
	})
}

func TestSecureFunction(t *testing.T) {
	cleanupCalled := false
	cleanup := func() {
		cleanupCalled = true
	}

	err := SecureFunction([]func(){cleanup}, func() error {
		return nil
	})

	if err != nil {
		t.Errorf("SecureFunction() error = %v", err)
	}

	if !cleanupCalled {
		t.Errorf("Cleanup function not called")
	}
}

func TestSecureFunctionPanic(t *testing.T) {
	cleanupCalled := false
	cleanup := func() {
		cleanupCalled = true
	}

	err := SecureFunction([]func(){cleanup}, func() error {
		panic("test panic")
	})

	if err == nil {
		t.Errorf("Expected error from panic")
	}

	if !cleanupCalled {
		t.Errorf("Cleanup function not called during panic")
	}
}

func TestSecureAllocatorStats(t *testing.T) {
	allocator := NewSecureAllocator(10, MaxSecureMemorySize)

	buf, err := NewSecureBuffer(1024)
	if err != nil {
		t.Fatalf("Failed to create buffer: %v", err)
	}
	defer buf.Destroy()

	stats := allocator.GetStats()

	totalAllocated := stats["total_allocated"].(int64)
	if totalAllocated <= 0 {
		t.Errorf("Total allocated = %d, want > 0", totalAllocated)
	}

	maxAllocation := stats["max_allocation"].(int64)
	if maxAllocation != MaxSecureMemorySize {
		t.Errorf("Max allocation = %d, want %d", maxAllocation, MaxSecureMemorySize)
	}
}

func TestCleanup(t *testing.T) {
	// Create some buffers
	buf1, _ := NewSecureBuffer(1024)
	buf2, _ := NewSecureBuffer(2048)
	
	buf1.ReturnToPool()
	buf2.ReturnToPool()

	allocator := GetSecureAllocator()
	stats := allocator.GetStats()
	initialPoolSize := stats["pool_size"].(int)

	if initialPoolSize == 0 {
		t.Errorf("Pool should have buffers before cleanup")
	}

	Cleanup()

	stats = allocator.GetStats()
	finalPoolSize := stats["pool_size"].(int)

	if finalPoolSize != 0 {
		t.Errorf("Pool size after cleanup = %d, want 0", finalPoolSize)
	}
}

func TestMemoryLocking(t *testing.T) {
	buf, err := NewSecureBuffer(4096)
	if err != nil {
		t.Fatalf("Failed to create buffer: %v", err)
	}
	defer buf.Destroy()

	if !buf.locked {
		t.Errorf("Buffer should be locked after creation")
	}

	// Test unlock
	if err := buf.unlock(); err != nil {
		t.Errorf("Failed to unlock buffer: %v", err)
	}

	if buf.locked {
		t.Errorf("Buffer should not be locked after unlock")
	}

	// Test relock
	if err := buf.lock(); err != nil {
		t.Errorf("Failed to lock buffer: %v", err)
	}

	if !buf.locked {
		t.Errorf("Buffer should be locked after lock")
	}
}

func TestConcurrentAccess(t *testing.T) {
	buf, err := NewSecureBuffer(1024)
	if err != nil {
		t.Fatalf("Failed to create buffer: %v", err)
	}
	defer buf.Destroy()

	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	// Concurrent copy operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			data := make([]byte, 100)
			rand.Read(data)
			buf.Copy(data)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("Timeout waiting for goroutine %d", i)
		}
	}
}

func TestFinalizerCleanup(t *testing.T) {
	initialStats := GetSecureAllocator().GetStats()
	initialAllocated := initialStats["total_allocated"].(int64)

	// Create buffer and let it go out of scope
	func() {
		buf, err := NewSecureBuffer(1024)
		if err != nil {
			t.Fatalf("Failed to create buffer: %v", err)
		}
		_ = buf // Use the buffer
	}()

	// Force garbage collection to run finalizers
	runtime.GC()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	finalStats := GetSecureAllocator().GetStats()
	finalAllocated := finalStats["total_allocated"].(int64)

	if finalAllocated != initialAllocated {
		t.Errorf("Memory not cleaned up by finalizer: initial=%d, final=%d", 
			initialAllocated, finalAllocated)
	}
}

func BenchmarkSecureBufferCreate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		buf, err := NewSecureBuffer(1024)
		if err != nil {
			b.Fatal(err)
		}
		buf.Destroy()
	}
}

func BenchmarkSecureBufferCopy(b *testing.B) {
	buf, err := NewSecureBuffer(1024)
	if err != nil {
		b.Fatal(err)
	}
	defer buf.Destroy()

	data := make([]byte, 512)
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Copy(data)
	}
}

func BenchmarkSecureWipe(b *testing.B) {
	data := make([]byte, 1024)
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SecureWipe(data)
		// Refill with random data for next iteration
		if i < b.N-1 {
			rand.Read(data)
		}
	}
}