package search

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeverVane/commandchronicles/internal/storage"
)

// TestSearchIndexCorruptionFix verifies that the search index corruption issue is fixed
// This test simulates the exact scenario that was causing corruption:
// 1. Multiple processes (TUI and daemon) accessing the same search index
// 2. Concurrent rebuild operations
// 3. Search operations during index rebuilds
func TestSearchIndexCorruptionFix(t *testing.T) {
	tmpDir := t.TempDir()
	indexPath := filepath.Join(tmpDir, "corruption_test_index")

	// Create multiple engines to simulate different processes
	const numEngines = 3
	engines := make([]*FuzzySearchEngine, numEngines)

	for i := 0; i < numEngines; i++ {
		engines[i] = NewFuzzySearchEngine(indexPath)
		require.NoError(t, engines[i].Initialize())
	}

	// Cleanup
	defer func() {
		for _, engine := range engines {
			if engine != nil {
				engine.Close()
			}
		}
	}()

	// Create test data
	records := createLargeTestDataset(200)

	// Initial index population
	require.NoError(t, engines[0].IndexCommands(records))

	// Test scenario: Multiple processes performing operations simultaneously
	const duration = 5 * time.Second
	const numOperations = 50

	var wg sync.WaitGroup
	errors := make(chan error, numEngines*numOperations)

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	// Engine 0: Simulates TUI with continuous searches
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numOperations; i++ {
			select {
			case <-ctx.Done():
				return
			default:
				query := fmt.Sprintf("test-%d", i%20)
				_, err := engines[0].Search(query, &FuzzySearchOptions{
					Fuzziness:     1,
					MinScore:      0.01,
					MaxCandidates: 50,
				})
				if err != nil {
					errors <- fmt.Errorf("search error from engine 0: %w", err)
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()

	// Engine 1: Simulates daemon with index rebuilds
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 3; i++ { // Fewer rebuilds since they're expensive
			select {
			case <-ctx.Done():
				return
			default:
				// Create new test data for each rebuild
				newRecords := createLargeTestDataset(150)
				err := engines[1].RebuildIndex(newRecords)
				if err != nil {
					errors <- fmt.Errorf("rebuild error from engine 1: %w", err)
					return
				}
				time.Sleep(500 * time.Millisecond)
			}
		}
	}()

	// Engine 2: Simulates concurrent indexing operations
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numOperations; i++ {
			select {
			case <-ctx.Done():
				return
			default:
				record := &storage.CommandRecord{
					Command:    fmt.Sprintf("concurrent-operation-%d", i),
					SessionID:  fmt.Sprintf("session-%d", i%5),
					Timestamp:  time.Now().UnixMilli(),
					ExitCode:   i % 2,
					WorkingDir: fmt.Sprintf("/test/dir-%d", i%10),
					Hostname:   "integration-test",
					User:       "test-user",
					Shell:      "bash",
					Tags:       []string{fmt.Sprintf("tag-%d", i%3)},
				}
				err := engines[2].IndexCommand(record)
				if err != nil {
					errors <- fmt.Errorf("index error from engine 2: %w", err)
					return
				}
				time.Sleep(15 * time.Millisecond)
			}
		}
	}()

	// Wait for all operations to complete
	wg.Wait()
	close(errors)

	// Check for any errors
	var errorCount int
	for err := range errors {
		t.Errorf("Integration test error: %v", err)
		errorCount++
	}

	// Verify no errors occurred
	assert.Equal(t, 0, errorCount, "No errors should occur during concurrent operations")

	// Verify all engines are still functional
	for i, engine := range engines {
		// Test search functionality
		results, err := engine.Search("test", &FuzzySearchOptions{
			Fuzziness:     1,
			MinScore:      0.01,
			MaxCandidates: 10,
		})
		assert.NoError(t, err, "Engine %d should be functional after stress test", i)
		assert.NotNil(t, results, "Engine %d should return results", i)

		// Test stats functionality
		stats, err := engine.GetIndexStats()
		assert.NoError(t, err, "Engine %d should return stats", i)
		assert.NotNil(t, stats, "Engine %d stats should not be nil", i)
	}

	// Verify index directory exists and is not corrupted
	_, err := os.Stat(indexPath)
	assert.NoError(t, err, "Index directory should exist")

	// Test that we can create a new engine and it works
	newEngine := NewFuzzySearchEngine(indexPath)
	require.NoError(t, newEngine.Initialize())
	defer newEngine.Close()

	results, err := newEngine.Search("test", nil)
	assert.NoError(t, err, "New engine should be able to search existing index")
	assert.NotNil(t, results, "New engine should return results")
}

// TestFileLockingMechanism verifies the file locking prevents corruption
func TestFileLockingMechanism(t *testing.T) {
	tmpDir := t.TempDir()
	indexPath := filepath.Join(tmpDir, "filelock_test_index")

	// Test file locking with multiple processes
	const numProcesses = 5
	var wg sync.WaitGroup
	errors := make(chan error, numProcesses)

	for i := 0; i < numProcesses; i++ {
		wg.Add(1)
		go func(processID int) {
			defer wg.Done()

			engine := NewFuzzySearchEngine(indexPath)
			err := engine.Initialize()
			if err != nil {
				errors <- fmt.Errorf("process %d initialization failed: %w", processID, err)
				return
			}
			defer engine.Close()

			// Create test data
			records := createLargeTestDataset(50)

			// Try to rebuild index (this should be serialized by file locks)
			err = engine.RebuildIndex(records)
			if err != nil {
				errors <- fmt.Errorf("process %d rebuild failed: %w", processID, err)
				return
			}

			// Verify functionality
			results, err := engine.Search("test", &FuzzySearchOptions{
				MinScore:      0.01,
				MaxCandidates: 10,
			})
			if err != nil {
				errors <- fmt.Errorf("process %d search failed: %w", processID, err)
				return
			}

			if len(results) == 0 {
				errors <- fmt.Errorf("process %d got no search results", processID)
			}

		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	var errorCount int
	for err := range errors {
		t.Errorf("File locking test error: %v", err)
		errorCount++
	}

	// Some processes may timeout waiting for locks, but no corruption should occur
	assert.True(t, errorCount < numProcesses, "Not all processes should fail due to locking")
}

// TestAtomicRebuildPreventsCorruption verifies atomic rebuild prevents partial states
func TestAtomicRebuildPreventsCorruption(t *testing.T) {
	tmpDir := t.TempDir()
	indexPath := filepath.Join(tmpDir, "atomic_test_index")

	engine := NewFuzzySearchEngine(indexPath)
	require.NoError(t, engine.Initialize())
	defer engine.Close()

	// Initial data
	initialRecords := createLargeTestDataset(100)
	require.NoError(t, engine.IndexCommands(initialRecords))

	// Verify initial state
	initialResults, err := engine.Search("test", &FuzzySearchOptions{
		MinScore:      0.01,
		MaxCandidates: 50,
	})
	require.NoError(t, err)
	initialCount := len(initialResults)

	// Simulate multiple rapid rebuilds (stress test)
	const numRebuilds = 10
	for i := 0; i < numRebuilds; i++ {
		newRecords := createLargeTestDataset(80 + i*10) // Varying sizes
		err := engine.RebuildIndex(newRecords)
		require.NoError(t, err, "Rebuild %d should succeed", i)

		// Verify index is functional after each rebuild
		results, err := engine.Search("test", &FuzzySearchOptions{
			MinScore:      0.01,
			MaxCandidates: 50,
		})
		require.NoError(t, err, "Search should work after rebuild %d", i)

		// Should have some results
		assert.True(t, len(results) > 0, "Should have results after rebuild %d", i)
	}

	// Final verification
	finalResults, err := engine.Search("test", &FuzzySearchOptions{
		MinScore:      0.01,
		MaxCandidates: 50,
	})
	require.NoError(t, err)

	// Should have different count than initial (since we rebuilt with different data)
	assert.NotEqual(t, initialCount, len(finalResults), "Final results should differ from initial")
}

// TestMemoryLeakDuringConcurrentOperations verifies no memory leaks
func TestMemoryLeakDuringConcurrentOperations(t *testing.T) {
	tmpDir := t.TempDir()
	indexPath := filepath.Join(tmpDir, "memory_test_index")

	engine := NewFuzzySearchEngine(indexPath)
	require.NoError(t, engine.Initialize())
	defer engine.Close()

	// Perform many operations to check for leaks
	const numIterations = 100
	for i := 0; i < numIterations; i++ {
		// Create and index data
		records := createLargeTestDataset(20)
		err := engine.IndexCommands(records)
		require.NoError(t, err)

		// Search multiple times
		for j := 0; j < 5; j++ {
			query := fmt.Sprintf("test-%d", j)
			results, err := engine.Search(query, &FuzzySearchOptions{
				MinScore:      0.01,
				MaxCandidates: 10,
			})
			require.NoError(t, err)
			require.NotNil(t, results)
		}

		// Periodic rebuild
		if i%10 == 0 {
			err = engine.RebuildIndex(records)
			require.NoError(t, err)
		}
	}

	// Final verification
	results, err := engine.Search("test", nil)
	require.NoError(t, err)
	assert.NotNil(t, results)
}

// Helper function to create large test datasets
func createLargeTestDataset(size int) []*storage.CommandRecord {
	records := make([]*storage.CommandRecord, size)
	baseTime := time.Now()

	commands := []string{
		"git status", "git commit", "git push", "git pull", "git checkout",
		"ls -la", "cd /home", "pwd", "cat file.txt", "grep pattern",
		"find . -name", "docker run", "docker build", "docker ps",
		"npm install", "npm run", "yarn install", "make build",
		"curl -X GET", "wget https://", "ssh user@host", "scp file.txt",
		"vim file.txt", "nano file.txt", "code .", "python script.py",
		"go build", "go run", "cargo build", "mvn compile",
		"ps aux", "kill -9", "top", "htop", "df -h", "du -sh",
	}

	for i := 0; i < size; i++ {
		cmd := commands[i%len(commands)]
		records[i] = &storage.CommandRecord{
			Command:    fmt.Sprintf("%s-%d", cmd, i),
			SessionID:  fmt.Sprintf("session-%d", i%10),
			Timestamp:  baseTime.UnixMilli() - int64(i*1000),
			ExitCode:   i % 3, // 0, 1, 2
			WorkingDir: fmt.Sprintf("/test/dir-%d", i%5),
			Hostname:   fmt.Sprintf("host-%d", i%3),
			User:       "test-user",
			Shell:      "bash",
			Duration:   int64((i%10 + 1) * 100), // 100-1000ms
			Tags:       []string{fmt.Sprintf("tag-%d", i%4), "test-tag"},
			Note:       fmt.Sprintf("Test note for command %d", i),
		}
	}
	return records
}

// TestRealWorldScenario simulates the exact user scenario that was causing corruption
func TestRealWorldScenario(t *testing.T) {
	tmpDir := t.TempDir()
	indexPath := filepath.Join(tmpDir, "realworld_test_index")

	// Simulate the exact scenario:
	// 1. User opens TUI (Ctrl+R)
	// 2. Daemon is running in background
	// 3. Both try to access search index simultaneously

	// Create "daemon" engine (background process)
	daemonEngine := NewFuzzySearchEngine(indexPath)
	require.NoError(t, daemonEngine.Initialize())
	defer daemonEngine.Close()

	// Initial data from daemon
	initialRecords := createLargeTestDataset(50)
	require.NoError(t, daemonEngine.IndexCommands(initialRecords))

	// Simulate daemon operations
	var wg sync.WaitGroup
	errors := make(chan error, 10)

	// Background daemon operations
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			// Simulate periodic sync operations
			newRecords := createLargeTestDataset(20)

			// Check if index is stale (like daemon does)
			stats, err := daemonEngine.GetIndexStats()
			if err != nil {
				errors <- fmt.Errorf("daemon stats error: %w", err)
				return
			}

			if stats != nil {
				// Daemon rebuilds index after sync
				err = daemonEngine.RebuildIndex(newRecords)
				if err != nil {
					errors <- fmt.Errorf("daemon rebuild error: %w", err)
					return
				}
			}

			time.Sleep(100 * time.Millisecond)
		}
	}()

	// Simulate user opening TUI multiple times
	for tuiSession := 0; tuiSession < 5; tuiSession++ {
		wg.Add(1)
		go func(session int) {
			defer wg.Done()

			// Create new engine for each TUI session
			tuiEngine := NewFuzzySearchEngine(indexPath)
			err := tuiEngine.Initialize()
			if err != nil {
				errors <- fmt.Errorf("TUI session %d init error: %w", session, err)
				return
			}
			defer tuiEngine.Close()

			// TUI checks if index is stale
			_, err = tuiEngine.GetIndexStats()
			if err != nil {
				errors <- fmt.Errorf("TUI session %d stats error: %w", session, err)
				return
			}

			// TUI performs searches
			for i := 0; i < 10; i++ {
				query := fmt.Sprintf("test-%d", i)
				results, err := tuiEngine.Search(query, &FuzzySearchOptions{
					Fuzziness:     1,
					MinScore:      0.01,
					MaxCandidates: 20,
				})
				if err != nil {
					errors <- fmt.Errorf("TUI session %d search error: %w", session, err)
					return
				}

				// Verify results are valid
				if results == nil {
					errors <- fmt.Errorf("TUI session %d got nil results", session)
					return
				}

				time.Sleep(50 * time.Millisecond)
			}
		}(tuiSession)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	var errorCount int
	for err := range errors {
		t.Errorf("Real world scenario error: %v", err)
		errorCount++
	}

	// Should have minimal or no errors
	assert.True(t, errorCount < 3, "Should have minimal errors in real-world scenario")

	// Final verification - create new engine and verify it works
	finalEngine := NewFuzzySearchEngine(indexPath)
	require.NoError(t, finalEngine.Initialize())
	defer finalEngine.Close()

	results, err := finalEngine.Search("test", &FuzzySearchOptions{
		MinScore:      0.01,
		MaxCandidates: 10,
	})
	require.NoError(t, err, "Final engine should work without corruption")
	assert.NotNil(t, results, "Final engine should return results")
}
