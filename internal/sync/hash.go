package sync

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	
	"github.com/NeverVane/commandchronicles-cli/internal/storage"
)

// HashGenerator creates deterministic hashes for command records
type HashGenerator struct{}

// NewHashGenerator creates a new hash generator
func NewHashGenerator() *HashGenerator {
	return &HashGenerator{}
}

// GenerateRecordHash creates a deterministic hash for conflict detection
func (hg *HashGenerator) GenerateRecordHash(record *storage.CommandRecord) string {
	// Use command, timestamp, working directory, and exit code for hash
	// This ensures same command in different contexts gets different hash
	hashInput := fmt.Sprintf("%s|%d|%s|%d|%s|%s",
		record.Command,
		record.Timestamp,
		record.WorkingDir,
		record.ExitCode,
		record.Hostname,
		record.User,
	)
	
	// Include environment variables in sorted order for consistency
	if len(record.Environment) > 0 {
		var envPairs []string
		for k, v := range record.Environment {
			envPairs = append(envPairs, fmt.Sprintf("%s=%s", k, v))
		}
		sort.Strings(envPairs)
		hashInput += "|" + strings.Join(envPairs, "|")
	}
	
	hash := sha256.Sum256([]byte(hashInput))
	return fmt.Sprintf("%x", hash)
}

// CompareRecords checks if two records represent the same command execution
func (hg *HashGenerator) CompareRecords(r1, r2 *storage.CommandRecord) bool {
	return hg.GenerateRecordHash(r1) == hg.GenerateRecordHash(r2)
}