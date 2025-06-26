package history

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/NeverVane/commandchronicles/internal/storage"
	secureStorage "github.com/NeverVane/commandchronicles/pkg/storage"
)

// ImportOptions contains options for history import operations
type ImportOptions struct {
	Deduplicate bool
	MaxRecords  int
	SkipErrors  bool
	SessionID   string
}

// ImportResult contains the result of an import operation
type ImportResult struct {
	TotalRecords    int
	ImportedRecords int
	SkippedRecords  int
	Errors          []error
}

// ExportOptions contains options for history export operations
type ExportOptions struct {
	Format    string
	OutputDir string
	Since     *time.Time
	Until     *time.Time
	SessionID string
}

// ImportBashHistory imports command history from a bash history file
func ImportBashHistory(store *secureStorage.SecureStorage, filePath string, opts *ImportOptions) (*ImportResult, error) {
	if opts == nil {
		opts = &ImportOptions{
			Deduplicate: true,
			SkipErrors:  true,
			SessionID:   "imported-bash",
		}
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open bash history file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	result := &ImportResult{}
	
	var timestamp time.Time
	var command string
	hostname := getHostname()
	sessionID := opts.SessionID
	if sessionID == "" {
		sessionID = "imported-bash"
	}

	seenCommands := make(map[string]bool)
	defaultTimestamp := time.Now().Add(-24 * time.Hour) // Default to 24 hours ago

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		result.TotalRecords++

		// Skip empty lines
		if line == "" {
			continue
		}

		// Check for timestamp line (starts with #)
		if strings.HasPrefix(line, "#") {
			// Parse timestamp
			timestampStr := strings.TrimPrefix(line, "#")
			if ts, err := strconv.ParseInt(timestampStr, 10, 64); err == nil {
				timestamp = time.Unix(ts, 0)
			}
			continue
		}

		// Regular command line
		command = line

		// Skip duplicates if requested
		if opts.Deduplicate {
			if seenCommands[command] {
				result.SkippedRecords++
				continue
			}
			seenCommands[command] = true
		}

		// Use default timestamp if none was set
		recordTimestamp := timestamp
		if recordTimestamp.IsZero() {
			recordTimestamp = defaultTimestamp
		}

		// Create record
		record := &storage.CommandRecord{
			Command:    command,
			ExitCode:   0,  // Unknown for imported commands
			Duration:   0,  // Unknown for imported commands
			WorkingDir: "", // Unknown for imported commands
			Timestamp:  recordTimestamp.UnixMilli(),
			SessionID:  sessionID,
			Hostname:   hostname,
			User:       getCurrentUser(),
			Shell:      "bash",
			Version:    1,
			CreatedAt:  time.Now().UnixMilli(),
		}

		// Store record
		if _, err := store.Store(record); err != nil {
			if opts.SkipErrors {
				result.Errors = append(result.Errors, fmt.Errorf("failed to store command %q: %w", command, err))
				result.SkippedRecords++
				continue
			}
			return result, fmt.Errorf("failed to store command %q: %w", command, err)
		}

		result.ImportedRecords++

		// Check max records limit
		if opts.MaxRecords > 0 && result.ImportedRecords >= opts.MaxRecords {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return result, fmt.Errorf("error reading bash history file: %w", err)
	}

	return result, nil
}

// ImportZshHistory imports command history from a zsh history file
func ImportZshHistory(store *secureStorage.SecureStorage, filePath string, opts *ImportOptions) (*ImportResult, error) {
	if opts == nil {
		opts = &ImportOptions{
			Deduplicate: true,
			SkipErrors:  true,
			SessionID:   "imported-zsh",
		}
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open zsh history file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	result := &ImportResult{}
	hostname := getHostname()
	sessionID := opts.SessionID
	if sessionID == "" {
		sessionID = "imported-zsh"
	}

	seenCommands := make(map[string]bool)
	defaultTimestamp := time.Now().Add(-24 * time.Hour) // Default to 24 hours ago

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		result.TotalRecords++

		// Skip empty lines
		if line == "" {
			continue
		}

		// Parse zsh history format: : timestamp:duration;command
		if strings.HasPrefix(line, ":") {
			parts := strings.SplitN(line, ";", 2)
			if len(parts) != 2 {
				if opts.SkipErrors {
					result.SkippedRecords++
					continue
				}
				return result, fmt.Errorf("invalid zsh history format: %s", line)
			}

			// Parse timestamp and duration
			timestampPart := strings.SplitN(parts[0], ":", 3)
			if len(timestampPart) < 2 {
				if opts.SkipErrors {
					result.SkippedRecords++
					continue
				}
				return result, fmt.Errorf("invalid zsh timestamp format: %s", parts[0])
			}

			ts, err := strconv.ParseInt(strings.TrimSpace(timestampPart[1]), 10, 64)
			if err != nil {
				if opts.SkipErrors {
					result.Errors = append(result.Errors, fmt.Errorf("invalid timestamp: %w", err))
					result.SkippedRecords++
					continue
				}
				return result, fmt.Errorf("invalid timestamp: %w", err)
			}

			// Parse duration if available
			var duration int64 = 0
			if len(timestampPart) >= 3 {
				if d, err := strconv.ParseInt(strings.TrimSpace(timestampPart[2]), 10, 64); err == nil {
					duration = d * 1000 // Convert seconds to milliseconds
				}
			}

			timestamp := time.Unix(ts, 0)
			command := parts[1]

			// Skip duplicates if requested
			if opts.Deduplicate {
				if seenCommands[command] {
					result.SkippedRecords++
					continue
				}
				seenCommands[command] = true
			}

			// Use default timestamp if none was set
			recordTimestamp := timestamp
			if recordTimestamp.IsZero() {
				recordTimestamp = defaultTimestamp
			}

			// Create record
			record := &storage.CommandRecord{
				Command:    command,
				ExitCode:   0, // Unknown for imported commands
				Duration:   duration,
				WorkingDir: "", // Unknown for imported commands
				Timestamp:  recordTimestamp.UnixMilli(),
				SessionID:  sessionID,
				Hostname:   hostname,
				User:       getCurrentUser(),
				Shell:      "zsh",
				Version:    1,
				CreatedAt:  time.Now().UnixMilli(),
			}

			// Store record
			if _, err := store.Store(record); err != nil {
				if opts.SkipErrors {
					result.Errors = append(result.Errors, fmt.Errorf("failed to store command %q: %w", command, err))
					result.SkippedRecords++
					continue
				}
				return result, fmt.Errorf("failed to store command %q: %w", command, err)
			}

			result.ImportedRecords++

			// Check max records limit
			if opts.MaxRecords > 0 && result.ImportedRecords >= opts.MaxRecords {
				break
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return result, fmt.Errorf("error reading zsh history file: %w", err)
	}

	return result, nil
}



// DetectHistoryFile attempts to detect and return the path to the shell history file
func DetectHistoryFile(shell string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}

	switch strings.ToLower(shell) {
	case "bash":
		candidates := []string{
			filepath.Join(homeDir, ".bash_history"),
			filepath.Join(homeDir, ".bashrc_history"),
		}
		for _, candidate := range candidates {
			if _, err := os.Stat(candidate); err == nil {
				return candidate, nil
			}
		}
		return "", fmt.Errorf("bash history file not found")

	case "zsh":
		candidates := []string{
			filepath.Join(homeDir, ".zsh_history"),
			filepath.Join(homeDir, ".zhistory"),
		}
		for _, candidate := range candidates {
			if _, err := os.Stat(candidate); err == nil {
				return candidate, nil
			}
		}
		return "", fmt.Errorf("zsh history file not found")

	default:
		return "", fmt.Errorf("unsupported shell: %s (supported: bash, zsh)", shell)
	}
}

// getHostname returns the current hostname or "unknown" if it cannot be determined
func getHostname() string {
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}
	return "unknown"
}

// getCurrentUser returns the current username or "unknown" if it cannot be determined
func getCurrentUser() string {
	if user := os.Getenv("USER"); user != "" {
		return user
	}
	if user := os.Getenv("USERNAME"); user != "" {
		return user
	}
	return "unknown"
}