package security

import (
	"crypto/rand"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

const (
	// Maximum size for secure memory allocation (16MB)
	MaxSecureMemorySize = 16 * 1024 * 1024
	
	// Default secure buffer size (4KB)
	DefaultSecureBufferSize = 4096
	
	// Maximum number of buffers in the pool
	MaxPoolBuffers = 100
)

// SecureBuffer represents a memory region that is protected against swapping
// and automatically cleared when no longer needed
type SecureBuffer struct {
	data     []byte
	size     int
	locked   bool
	finalized bool
	mu       sync.Mutex
}

// SecureAllocator manages a pool of secure memory buffers
type SecureAllocator struct {
	pool chan *SecureBuffer
	mu   sync.RWMutex
	totalAllocated int64
	maxAllocation  int64
}

var (
	globalAllocator *SecureAllocator
	allocatorOnce   sync.Once
)

// GetSecureAllocator returns the global secure memory allocator
func GetSecureAllocator() *SecureAllocator {
	allocatorOnce.Do(func() {
		globalAllocator = NewSecureAllocator(MaxPoolBuffers, MaxSecureMemorySize)
	})
	return globalAllocator
}

// NewSecureAllocator creates a new secure memory allocator
func NewSecureAllocator(poolSize int, maxMemory int64) *SecureAllocator {
	return &SecureAllocator{
		pool:          make(chan *SecureBuffer, poolSize),
		maxAllocation: maxMemory,
	}
}

// NewSecureBuffer creates a new secure memory buffer of the specified size
func NewSecureBuffer(size int) (*SecureBuffer, error) {
	if size <= 0 || size > MaxSecureMemorySize {
		return nil, fmt.Errorf("invalid buffer size: %d (max: %d)", size, MaxSecureMemorySize)
	}

	allocator := GetSecureAllocator()
	
	// Try to get a buffer from the pool first
	select {
	case buf := <-allocator.pool:
		if len(buf.data) >= size {
			buf.Reset(size)
			return buf, nil
		}
		// Buffer too small, will create a new one
		buf.Destroy()
	default:
		// No buffer available in pool
	}

	// Create new buffer
	buf := &SecureBuffer{
		data: make([]byte, size),
		size: size,
	}

	if err := buf.lock(); err != nil {
		return nil, fmt.Errorf("failed to lock memory: %w", err)
	}

	// Set finalizer to ensure cleanup on GC
	runtime.SetFinalizer(buf, (*SecureBuffer).Destroy)

	allocator.mu.Lock()
	allocator.totalAllocated += int64(size)
	allocator.mu.Unlock()

	return buf, nil
}

// Data returns a copy of the secure buffer's data
// Use this method sparingly as it creates a copy in regular memory
func (sb *SecureBuffer) Data() []byte {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	
	if sb.finalized {
		return nil
	}
	
	result := make([]byte, sb.size)
	copy(result, sb.data[:sb.size])
	return result
}

// Copy copies data into the secure buffer
func (sb *SecureBuffer) Copy(src []byte) error {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	
	if sb.finalized {
		return fmt.Errorf("buffer has been destroyed")
	}
	
	if len(src) > len(sb.data) {
		return fmt.Errorf("source data too large: %d > %d", len(src), len(sb.data))
	}
	
	copy(sb.data, src)
	sb.size = len(src)
	return nil
}

// Size returns the current size of data in the buffer
func (sb *SecureBuffer) Size() int {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.size
}

// Capacity returns the total capacity of the buffer
func (sb *SecureBuffer) Capacity() int {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return len(sb.data)
}

// Reset resets the buffer for reuse with a new size
func (sb *SecureBuffer) Reset(size int) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	
	if sb.finalized {
		return
	}
	
	// Clear existing data
	sb.wipe()
	
	if size > len(sb.data) {
		// Need to reallocate
		if sb.locked {
			sb.unlock()
		}
		sb.data = make([]byte, size)
		sb.lock()
	}
	
	sb.size = size
}

// Wipe securely clears the buffer contents
func (sb *SecureBuffer) Wipe() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.wipe()
}

// wipe internal implementation without mutex (caller must hold lock)
func (sb *SecureBuffer) wipe() {
	if sb.finalized || len(sb.data) == 0 {
		return
	}
	
	// Multiple-pass secure wipe
	// Pass 1: Fill with zeros
	for i := range sb.data {
		sb.data[i] = 0
	}
	
	// Pass 2: Fill with 0xFF
	for i := range sb.data {
		sb.data[i] = 0xFF
	}
	
	// Pass 3: Fill with random data
	rand.Read(sb.data)
	
	// Pass 4: Final zero pass
	for i := range sb.data {
		sb.data[i] = 0
	}
	
	sb.size = 0
}

// Destroy securely destroys the buffer and releases resources
func (sb *SecureBuffer) Destroy() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	
	if sb.finalized {
		return
	}
	
	// Wipe the data
	sb.wipe()
	
	// Unlock memory
	if sb.locked {
		sb.unlock()
	}
	
	// Update allocator stats
	allocator := GetSecureAllocator()
	allocator.mu.Lock()
	allocator.totalAllocated -= int64(len(sb.data))
	allocator.mu.Unlock()
	
	// Clear the slice
	sb.data = nil
	sb.finalized = true
	
	// Clear finalizer
	runtime.SetFinalizer(sb, nil)
}

// ReturnToPool returns the buffer to the allocator pool for reuse
func (sb *SecureBuffer) ReturnToPool() {
	if sb.finalized {
		return
	}
	
	allocator := GetSecureAllocator()
	
	// Try to return to pool
	select {
	case allocator.pool <- sb:
		// Successfully returned to pool
	default:
		// Pool is full, destroy the buffer
		sb.Destroy()
	}
}

// lock locks the memory to prevent swapping (platform-specific)
func (sb *SecureBuffer) lock() error {
	if len(sb.data) == 0 {
		return nil
	}
	
	err := mlock(unsafe.Pointer(&sb.data[0]), uintptr(len(sb.data)))
	if err != nil {
		return fmt.Errorf("mlock failed: %w", err)
	}
	
	sb.locked = true
	return nil
}

// unlock unlocks the memory (platform-specific)
func (sb *SecureBuffer) unlock() error {
	if !sb.locked || len(sb.data) == 0 {
		return nil
	}
	
	err := munlock(unsafe.Pointer(&sb.data[0]), uintptr(len(sb.data)))
	if err != nil {
		return fmt.Errorf("munlock failed: %w", err)
	}
	
	sb.locked = false
	return nil
}

// mlock locks memory pages to prevent swapping
func mlock(addr unsafe.Pointer, len uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_MLOCK, uintptr(addr), len, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// munlock unlocks memory pages
func munlock(addr unsafe.Pointer, len uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_MUNLOCK, uintptr(addr), len, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// SecureWipe performs a secure wipe of a regular byte slice
func SecureWipe(data []byte) {
	if len(data) == 0 {
		return
	}
	
	// Multiple-pass secure wipe
	// Pass 1: Fill with zeros
	for i := range data {
		data[i] = 0
	}
	
	// Pass 2: Fill with 0xFF
	for i := range data {
		data[i] = 0xFF
	}
	
	// Pass 3: Fill with random data
	rand.Read(data)
	
	// Pass 4: Final zero pass
	for i := range data {
		data[i] = 0
	}
}

// SecureWipeString securely wipes a string by converting to bytes and wiping
func SecureWipeString(s *string) {
	if s == nil || *s == "" {
		return
	}
	
	// Convert string to byte slice for wiping
	data := []byte(*s)
	SecureWipe(data)
	
	// Clear the string
	*s = ""
}

// WithSecureBuffer executes a function with a secure buffer and ensures cleanup
func WithSecureBuffer(size int, fn func(*SecureBuffer) error) error {
	buf, err := NewSecureBuffer(size)
	if err != nil {
		return err
	}
	
	// Ensure cleanup even on panic
	defer func() {
		if r := recover(); r != nil {
			buf.Destroy()
			panic(r) // Re-panic after cleanup
		} else {
			buf.ReturnToPool()
		}
	}()
	
	return fn(buf)
}

// SecureFunction executes a function with panic recovery and memory cleanup
func SecureFunction(cleanupFuncs []func(), fn func() error) (err error) {
	// Ensure cleanup functions are called even on panic
	defer func() {
		if r := recover(); r != nil {
			// Run cleanup functions
			for _, cleanup := range cleanupFuncs {
				if cleanup != nil {
					func() {
						defer func() {
							// Ignore panics in cleanup functions
							recover()
						}()
						cleanup()
					}()
				}
			}
			
			// Convert panic to error
			if e, ok := r.(error); ok {
				err = fmt.Errorf("panic during secure operation: %w", e)
			} else {
				err = fmt.Errorf("panic during secure operation: %v", r)
			}
		}
	}()
	
	// Execute the function
	err = fn()
	
	// Run cleanup functions on normal completion
	for _, cleanup := range cleanupFuncs {
		if cleanup != nil {
			func() {
				defer func() {
					// Ignore panics in cleanup functions
					recover()
				}()
				cleanup()
			}()
		}
	}
	
	return err
}

// GetStats returns statistics about secure memory usage
func (sa *SecureAllocator) GetStats() map[string]interface{} {
	sa.mu.RLock()
	defer sa.mu.RUnlock()
	
	return map[string]interface{}{
		"total_allocated":   sa.totalAllocated,
		"max_allocation":    sa.maxAllocation,
		"pool_size":         len(sa.pool),
		"pool_capacity":     cap(sa.pool),
	}
}

// Cleanup performs global cleanup of secure memory resources
func Cleanup() {
	if globalAllocator == nil {
		return
	}
	
	// Drain and destroy all buffers in the pool
	for {
		select {
		case buf := <-globalAllocator.pool:
			buf.Destroy()
		default:
			return
		}
	}
}

// init performs platform-specific initialization
func init() {
	// Force garbage collection to run finalizers on exit
	runtime.GOMAXPROCS(runtime.GOMAXPROCS(0))
}