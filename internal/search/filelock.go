package search

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/NeverVane/commandchronicles/internal/logger"
)

// FileLock represents a file-based lock for process synchronization
type FileLock struct {
	path      string
	file      *os.File
	logger    *logger.Logger
	locked    bool
	mu        sync.Mutex
	timeout   time.Duration
	exclusive bool
}

// FileLockOptions configures file lock behavior
type FileLockOptions struct {
	Timeout   time.Duration
	Exclusive bool
	CreateDir bool
}

// NewFileLock creates a new file lock instance
func NewFileLock(lockPath string, opts *FileLockOptions) (*FileLock, error) {
	if opts == nil {
		opts = &FileLockOptions{
			Timeout:   30 * time.Second,
			Exclusive: true,
			CreateDir: true,
		}
	}

	// Create directory if needed
	if opts.CreateDir {
		if err := os.MkdirAll(filepath.Dir(lockPath), 0755); err != nil {
			return nil, fmt.Errorf("failed to create lock directory: %w", err)
		}
	}

	return &FileLock{
		path:      lockPath,
		logger:    logger.GetLogger().WithComponent("filelock"),
		timeout:   opts.Timeout,
		exclusive: opts.Exclusive,
	}, nil
}

// Lock acquires the file lock with timeout
func (fl *FileLock) Lock(ctx context.Context) error {
	fl.mu.Lock()
	defer fl.mu.Unlock()

	if fl.locked {
		return fmt.Errorf("lock already acquired")
	}

	// Create context with timeout
	lockCtx, cancel := context.WithTimeout(ctx, fl.timeout)
	defer cancel()

	fl.logger.Debug().
		Str("lock_path", fl.path).
		Dur("timeout", fl.timeout).
		Bool("exclusive", fl.exclusive).
		Msg("Attempting to acquire file lock")

	// Try to acquire lock with timeout
	return fl.tryLockWithTimeout(lockCtx)
}

// TryLock attempts to acquire the lock without blocking
func (fl *FileLock) TryLock() error {
	fl.mu.Lock()
	defer fl.mu.Unlock()

	if fl.locked {
		return fmt.Errorf("lock already acquired")
	}

	return fl.tryLockOnce()
}

// Unlock releases the file lock
func (fl *FileLock) Unlock() error {
	fl.mu.Lock()
	defer fl.mu.Unlock()

	if !fl.locked {
		return nil // Already unlocked
	}

	fl.logger.Debug().
		Str("lock_path", fl.path).
		Msg("Releasing file lock")

	var err error
	if fl.file != nil {
		// Release the lock
		if unlockErr := fl.unlockFile(); unlockErr != nil {
			fl.logger.Warn().
				Err(unlockErr).
				Str("lock_path", fl.path).
				Msg("Failed to unlock file")
			err = unlockErr
		}

		// Close the file
		if closeErr := fl.file.Close(); closeErr != nil {
			fl.logger.Warn().
				Err(closeErr).
				Str("lock_path", fl.path).
				Msg("Failed to close lock file")
			if err == nil {
				err = closeErr
			}
		}

		fl.file = nil
	}

	fl.locked = false

	// Clean up lock file (best effort)
	if removeErr := os.Remove(fl.path); removeErr != nil && !os.IsNotExist(removeErr) {
		fl.logger.Debug().
			Err(removeErr).
			Str("lock_path", fl.path).
			Msg("Failed to remove lock file")
	}

	return err
}

// IsLocked returns whether the lock is currently held
func (fl *FileLock) IsLocked() bool {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	return fl.locked
}

// tryLockWithTimeout attempts to acquire lock with timeout and retry logic
func (fl *FileLock) tryLockWithTimeout(ctx context.Context) error {
	const retryInterval = 100 * time.Millisecond
	ticker := time.NewTicker(retryInterval)
	defer ticker.Stop()

	// Try immediately first
	if err := fl.tryLockOnce(); err == nil {
		return nil
	}

	// Retry with timeout
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("failed to acquire lock within timeout: %w", ctx.Err())
		case <-ticker.C:
			if err := fl.tryLockOnce(); err == nil {
				return nil
			}
			// Continue trying
		}
	}
}

// tryLockOnce attempts to acquire the lock once
func (fl *FileLock) tryLockOnce() error {
	// Open/create the lock file
	file, err := os.OpenFile(fl.path, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("failed to open lock file: %w", err)
	}

	// Try to acquire the lock
	if err := fl.lockFile(file); err != nil {
		file.Close()
		return err
	}

	// Write PID to lock file for debugging
	if _, err := file.WriteString(fmt.Sprintf("%d\n", os.Getpid())); err != nil {
		fl.unlockFile()
		file.Close()
		return fmt.Errorf("failed to write PID to lock file: %w", err)
	}

	fl.file = file
	fl.locked = true

	fl.logger.Debug().
		Str("lock_path", fl.path).
		Int("pid", os.Getpid()).
		Msg("Successfully acquired file lock")

	return nil
}

// lockFile performs the actual file locking system call
func (fl *FileLock) lockFile(file *os.File) error {
	var lockType int
	if fl.exclusive {
		lockType = syscall.LOCK_EX
	} else {
		lockType = syscall.LOCK_SH
	}

	// Try non-blocking lock
	if err := syscall.Flock(int(file.Fd()), lockType|syscall.LOCK_NB); err != nil {
		if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
			return fmt.Errorf("lock is held by another process")
		}
		return fmt.Errorf("failed to acquire file lock: %w", err)
	}

	return nil
}

// unlockFile releases the file lock
func (fl *FileLock) unlockFile() error {
	if fl.file == nil {
		return nil
	}

	if err := syscall.Flock(int(fl.file.Fd()), syscall.LOCK_UN); err != nil {
		return fmt.Errorf("failed to release file lock: %w", err)
	}

	return nil
}

// GetLockInfo returns information about the current lock holder
func (fl *FileLock) GetLockInfo() (*LockInfo, error) {
	if !fl.IsLocked() {
		return nil, fmt.Errorf("lock not held")
	}

	info := &LockInfo{
		Path:      fl.path,
		PID:       os.Getpid(),
		Exclusive: fl.exclusive,
		Acquired:  time.Now(), // Approximate
	}

	return info, nil
}

// LockInfo contains information about a file lock
type LockInfo struct {
	Path      string
	PID       int
	Exclusive bool
	Acquired  time.Time
}

// SearchIndexLock is a specialized lock for search index operations
type SearchIndexLock struct {
	lock   *FileLock
	logger *logger.Logger
}

// NewSearchIndexLock creates a new search index lock
func NewSearchIndexLock(indexPath string) (*SearchIndexLock, error) {
	baseDir := filepath.Dir(indexPath)
	lockPath := filepath.Join(baseDir, ".search_index.lock")

	lock, err := NewFileLock(lockPath, &FileLockOptions{
		Timeout:   30 * time.Second,
		Exclusive: true,
		CreateDir: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create search index lock: %w", err)
	}

	return &SearchIndexLock{
		lock:   lock,
		logger: logger.GetLogger().WithComponent("search-index-lock"),
	}, nil
}

// RLock acquires a read lock (uses exclusive lock for simplicity)
func (sil *SearchIndexLock) RLock(ctx context.Context) error {
	sil.logger.Debug().Msg("Acquiring read lock for search index")
	return sil.lock.Lock(ctx)
}

// RUnlock releases a read lock
func (sil *SearchIndexLock) RUnlock() error {
	sil.logger.Debug().Msg("Releasing read lock for search index")
	return sil.lock.Unlock()
}

// Lock acquires a write lock (exclusive)
func (sil *SearchIndexLock) Lock(ctx context.Context) error {
	sil.logger.Debug().Msg("Acquiring write lock for search index")
	return sil.lock.Lock(ctx)
}

// Unlock releases a write lock
func (sil *SearchIndexLock) Unlock() error {
	sil.logger.Debug().Msg("Releasing write lock for search index")
	return sil.lock.Unlock()
}

// Cleanup releases all locks
func (sil *SearchIndexLock) Cleanup() error {
	return sil.lock.Unlock()
}
