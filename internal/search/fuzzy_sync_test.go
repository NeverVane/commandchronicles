package search

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeverVane/commandchronicles/internal/storage"
)

// TestFuzzySearchEngine_ConcurrentAccess tests that multiple goroutines can safely access the search engine
func TestFuzzySearchEngine_ConcurrentAccess(t *testing.T) {
	tmpDir := t.TempDir()
	indexPath := filepath.Join(tmpDir, "test_concurrent_index")

	engine := NewFuzzySearchEngine(indexPath)
	require.NoError(t, engine.Initialize())
	defer engine.Close()

	// Create test records
	records := createTestRecords(100)
	require.NoError(t, engine.IndexCommands(records))

	// Test concurrent search operations
	const numGoroutines = 10
	const numOperations = 20

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*numOperations)

	// Concurrent search operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				query := fmt.Sprintf("test-%d", j%10)
				_, err := engine.Search(query, nil)
				if err != nil {
					errors <- fmt.Errorf("search error from goroutine %d: %w", id, err)
				}
			}
		}(i)
	}

	// Concurrent indexing operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				record := &storage.CommandRecord{
					Command:   fmt.Sprintf("concurrent-test-%d-%d", id, j),
					SessionID: fmt.Sprintf("session-%d", id),
					Timestamp: time.Now().UnixMilli(),
					ExitCode:  0,
				}
				err := engine.IndexCommand(record)
				if err != nil {
					errors <- fmt.Errorf("index error from goroutine %d: %w", id, err)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent operation failed: %v", err)
	}
}

// TestFuzzySearchEngine_ConcurrentRebuild tests that concurrent rebuild operations are handled safely
func TestFuzzySearchEngine_ConcurrentRebuild(t *testing.T) {
	tmpDir := t.TempDir()
	indexPath := filepath.Join(tmpDir, "test_rebuild_index")

	engine := NewFuzzySearchEngine(indexPath)
	require.NoError(t, engine.Initialize())
	defer engine.Close()

	// Create test records
	records := createTestRecords(50)

	// Test concurrent rebuild operations
	const numRebuildGoroutines = 5
	var wg sync.WaitGroup
	errors := make(chan error, numRebuildGoroutines)

	for i := 0; i < numRebuildGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			// Add some variation to the records for each goroutine
			testRecords := make([]*storage.CommandRecord, len(records))
			for j, record := range records {
				newRecord := *record // Copy the record
				newRecord.Command = fmt.Sprintf("%s-rebuild-%d", record.Command, id)
				testRecords[j] = &newRecord
			}

			err := engine.RebuildIndex(testRecords)
			if err != nil {
				errors <- fmt.Errorf("rebuild error from goroutine %d: %w", id, err)
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors - there should be no errors, even with concurrent rebuilds
	for err := range errors {
		t.Errorf("Concurrent rebuild failed: %v", err)
	}

	// Verify index is still functional after concurrent rebuilds
	results, err := engine.Search("test", nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, results)
}

// TestFuzzySearchEngine_RaceConditionScenario tests the specific race condition scenario
func TestFuzzySearchEngine_RaceConditionScenario(t *testing.T) {
	tmpDir := t.TempDir()
	indexPath := filepath.Join(tmpDir, "test_race_index")

	engine := NewFuzzySearchEngine(indexPath)
	require.NoError(t, engine.Initialize())
	defer engine.Close()

	// Create initial records
	records := createTestRecords(30)
	require.NoError(t, engine.IndexCommands(records))

	// Simulate the race condition scenario that caused corruption:
	// 1. One goroutine performs search operations
	// 2. Another goroutine rebuilds the index
	// 3. A third goroutine adds new records

	var wg sync.WaitGroup
	errors := make(chan error, 3)

	// Goroutine 1: Continuous search operations
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			query := fmt.Sprintf("test-%d", i%10)
			_, err := engine.Search(query, nil)
			if err != nil {
				errors <- fmt.Errorf("search operation failed: %w", err)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Goroutine 2: Index rebuild
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(100 * time.Millisecond) // Let searches start first

		newRecords := createTestRecords(40)
		err := engine.RebuildIndex(newRecords)
		if err != nil {
			errors <- fmt.Errorf("rebuild operation failed: %w", err)
		}
	}()

	// Goroutine 3: Continuous indexing
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			record := &storage.CommandRecord{
				Command:   fmt.Sprintf("race-test-%d", i),
				SessionID: "race-session",
				Timestamp: time.Now().UnixMilli(),
				ExitCode:  0,
			}
			err := engine.IndexCommand(record)
			if err != nil {
				errors <- fmt.Errorf("index operation failed: %w", err)
				return
			}
			time.Sleep(15 * time.Millisecond)
		}
	}()

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Race condition scenario failed: %v", err)
	}

	// Verify index is still functional
	results, err := engine.Search("test", nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, results)
}

// TestFuzzySearchEngine_DeepCopyTags tests that tags are properly deep copied
func TestFuzzySearchEngine_DeepCopyTags(t *testing.T) {
	tmpDir := t.TempDir()
	indexPath := filepath.Join(tmpDir, "test_deepcopy_index")

	engine := NewFuzzySearchEngine(indexPath)
	require.NoError(t, engine.Initialize())
	defer engine.Close()

	// Create a record with tags
	originalTags := []string{"tag1", "tag2", "tag3"}
	record := &storage.CommandRecord{
		Command:    "test-command-deepcopy",
		SessionID:  "test-session-deepcopy",
		Timestamp:  time.Now().UnixMilli(),
		ExitCode:   0,
		Tags:       originalTags,
		WorkingDir: "/test/dir",
		Hostname:   "test-host",
		User:       "test-user",
		Shell:      "bash",
	}

	// Index the record
	require.NoError(t, engine.IndexCommand(record))

	// Give the index a moment to process
	time.Sleep(100 * time.Millisecond)

	// Modify the original tags slice
	originalTags[0] = "modified-tag1"
	originalTags = append(originalTags, "new-tag")

	// Search for the record with more permissive options
	opts := &FuzzySearchOptions{
		Fuzziness:       2,
		MinScore:        0.01,
		MaxCandidates:   100,
		BoostExactMatch: 3.0,
	}
	results, err := engine.Search("test-command-deepcopy", opts)
	require.NoError(t, err)

	// If exact search fails, try partial match
	if len(results) == 0 {
		results, err = engine.Search("deepcopy", opts)
		require.NoError(t, err)
	}

	// If still no results, try match all
	if len(results) == 0 {
		results, err = engine.Search("", opts)
		require.NoError(t, err)
	}

	require.NotEmpty(t, results, "Should find at least one result")

	// Find our specific record
	var foundRecord *storage.CommandRecord
	for _, result := range results {
		if result.Record.Command == "test-command-deepcopy" {
			foundRecord = result.Record
			break
		}
	}

	require.NotNil(t, foundRecord, "Should find the specific test record")

	// Verify that the indexed record's tags were not affected by the modification
	assert.Equal(t, []string{"tag1", "tag2", "tag3"}, foundRecord.Tags)
	assert.NotEqual(t, originalTags, foundRecord.Tags)
}

// TestFileLock_ConcurrentProcesses tests the file locking mechanism
func TestFileLock_ConcurrentProcesses(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "test.lock")

	// Test concurrent lock acquisition
	const numGoroutines = 5
	var wg sync.WaitGroup
	acquired := make(chan int, numGoroutines)
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			lock, err := NewFileLock(lockPath, &FileLockOptions{
				Timeout:   5 * time.Second,
				Exclusive: true,
				CreateDir: true,
			})
			if err != nil {
				errors <- fmt.Errorf("failed to create lock %d: %w", id, err)
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err = lock.Lock(ctx)
			if err != nil {
				errors <- fmt.Errorf("failed to acquire lock %d: %w", id, err)
				return
			}

			acquired <- id
			time.Sleep(100 * time.Millisecond) // Hold lock briefly

			err = lock.Unlock()
			if err != nil {
				errors <- fmt.Errorf("failed to release lock %d: %w", id, err)
			}
		}(i)
	}

	wg.Wait()
	close(acquired)
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("File lock test failed: %v", err)
	}

	// Verify that locks were acquired (even if not all due to timeout)
	acquiredCount := 0
	for range acquired {
		acquiredCount++
	}
	assert.Greater(t, acquiredCount, 0, "At least one lock should have been acquired")
}

// TestSearchIndexLock_ReadWriteLocking tests the read/write locking mechanism
func TestSearchIndexLock_ReadWriteLocking(t *testing.T) {
	t.Skip("Skipping read/write lock test - now using single lock approach")

	tmpDir := t.TempDir()
	indexPath := filepath.Join(tmpDir, "test_index")

	searchLock, err := NewSearchIndexLock(indexPath)
	require.NoError(t, err)
	defer searchLock.Cleanup()

	// Test multiple readers can acquire read locks
	const numReaders = 3
	var wg sync.WaitGroup
	readersStarted := make(chan int, numReaders)
	errors := make(chan error, numReaders+1)

	// Start multiple readers
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err := searchLock.RLock(ctx)
			if err != nil {
				errors <- fmt.Errorf("reader %d failed to acquire read lock: %w", id, err)
				return
			}

			readersStarted <- id
			time.Sleep(200 * time.Millisecond) // Hold read lock

			err = searchLock.RUnlock()
			if err != nil {
				errors <- fmt.Errorf("reader %d failed to release read lock: %w", id, err)
			}
		}(i)
	}

	// Wait for readers to start
	time.Sleep(50 * time.Millisecond)

	// Try to acquire write lock (should wait for readers to finish)
	wg.Add(1)
	go func() {
		defer wg.Done()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		err := searchLock.Lock(ctx)
		if err != nil {
			errors <- fmt.Errorf("writer failed to acquire write lock: %w", err)
			return
		}

		time.Sleep(100 * time.Millisecond) // Hold write lock

		err = searchLock.Unlock()
		if err != nil {
			errors <- fmt.Errorf("writer failed to release write lock: %w", err)
		}
	}()

	wg.Wait()
	close(readersStarted)
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Search index lock test failed: %v", err)
	}

	// Verify readers started
	readersCount := 0
	for range readersStarted {
		readersCount++
	}
	assert.Equal(t, numReaders, readersCount, "All readers should have started")
}

// Helper function to create test records
func createTestRecords(count int) []*storage.CommandRecord {
	records := make([]*storage.CommandRecord, count)
	for i := 0; i < count; i++ {
		records[i] = &storage.CommandRecord{
			Command:    fmt.Sprintf("test-command-%d", i),
			SessionID:  fmt.Sprintf("session-%d", i/10),
			Timestamp:  time.Now().UnixMilli() - int64(i*1000),
			ExitCode:   i % 2, // Alternate between 0 and 1
			WorkingDir: fmt.Sprintf("/test/dir-%d", i),
			Hostname:   "test-host",
			User:       "test-user",
			Shell:      "bash",
			Duration:   int64(i * 100),
			Tags:       []string{fmt.Sprintf("tag-%d", i), "test-tag"},
			Note:       fmt.Sprintf("Test note for command %d", i),
		}
	}
	return records
}

// Benchmark tests to ensure performance isn't significantly impacted
func BenchmarkFuzzySearchEngine_ConcurrentSearchWithLocks(b *testing.B) {
	tmpDir := b.TempDir()
	indexPath := filepath.Join(tmpDir, "benchmark_index")

	engine := NewFuzzySearchEngine(indexPath)
	if err := engine.Initialize(); err != nil {
		b.Fatal(err)
	}
	defer engine.Close()

	// Index test records
	records := createTestRecords(1000)
	if err := engine.IndexCommands(records); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			query := fmt.Sprintf("test-%d", i%100)
			_, err := engine.Search(query, nil)
			if err != nil {
				b.Fatalf("Search failed: %v", err)
			}
			i++
		}
	})
}

func BenchmarkFuzzySearchEngine_ConcurrentIndexWithLocks(b *testing.B) {
	tmpDir := b.TempDir()
	indexPath := filepath.Join(tmpDir, "benchmark_index")

	engine := NewFuzzySearchEngine(indexPath)
	if err := engine.Initialize(); err != nil {
		b.Fatal(err)
	}
	defer engine.Close()

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			record := &storage.CommandRecord{
				Command:   fmt.Sprintf("benchmark-command-%d", i),
				SessionID: fmt.Sprintf("benchmark-session-%d", i/100),
				Timestamp: time.Now().UnixMilli(),
				ExitCode:  0,
			}
			if err := engine.IndexCommand(record); err != nil {
				b.Fatalf("Index failed: %v", err)
			}
			i++
		}
	})
}
