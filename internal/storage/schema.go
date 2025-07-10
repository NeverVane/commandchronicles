package storage

import (
	"fmt"
	"strings"
	"time"
)

// CommandRecord represents a single command execution with all contextual information
type CommandRecord struct {
	// Database identifier
	ID int64 `json:"id"` // Database record ID for deletion operations

	// Core command information
	Command   string            `json:"command"`              // The actual command text
	ExitCode  int               `json:"exit_code"`            // Command exit code
	Duration  int64             `json:"duration_ms"`          // Execution duration in milliseconds
	Note      string            `json:"note,omitempty"`       // Optional user note about the command
	Tags      []string          `json:"tags,omitempty"`       // Optional tags for command categorization
	TagColors map[string]string `json:"tag_colors,omitempty"` // Optional per-command tag colors (tag_name -> hex_color)

	// Context information
	WorkingDir string `json:"working_dir"`  // Directory where command was executed
	Timestamp  int64  `json:"timestamp_ms"` // Unix timestamp in milliseconds
	SessionID  string `json:"session_id"`   // Session UUID
	Hostname   string `json:"hostname"`     // Machine hostname

	// Optional context
	GitRoot   string `json:"git_root,omitempty"`   // Git repository root if applicable
	GitBranch string `json:"git_branch,omitempty"` // Git branch if applicable
	GitCommit string `json:"git_commit,omitempty"` // Git commit hash if applicable

	// Environment context
	User        string            `json:"user"`                  // Username
	Shell       string            `json:"shell"`                 // Shell type (bash, zsh, etc.)
	TTY         string            `json:"tty,omitempty"`         // TTY device
	Environment map[string]string `json:"environment,omitempty"` // Relevant environment variables

	// Metadata
	Version   int   `json:"version"`       // Schema version for future compatibility
	CreatedAt int64 `json:"created_at_ms"` // Record creation timestamp

	// NEW: Sync-related fields (backward compatible)
	DeviceID   string `json:"device_id,omitempty"`
	RecordHash string `json:"record_hash,omitempty"`
	LastSynced *int64 `json:"last_synced,omitempty"` // Unix timestamp in ms
	SyncStatus int    `json:"sync_status,omitempty"` // 0=local, 1=synced, 2=conflict
}

// EncryptedHistoryRecord represents a row in the history table
type EncryptedHistoryRecord struct {
	ID            int64  `db:"id"`
	EncryptedData []byte `db:"encrypted_data"` // Encrypted CommandRecord JSON
	Timestamp     int64  `db:"timestamp"`      // Unencrypted timestamp for indexing
	Session       string `db:"session"`        // Unencrypted session ID for filtering
	Hostname      string `db:"hostname"`       // Unencrypted hostname for filtering
	CreatedAt     int64  `db:"created_at"`     // Record insertion timestamp
}

// DatabaseSchema contains all SQL statements for database initialization
type DatabaseSchema struct {
	// Current schema version
	Version int

	// DDL statements
	Tables  []string
	Indexes []string

	// Migration statements for future use
	Migrations map[int][]string
}

// GetCurrentSchema returns the current database schema
func GetCurrentSchema() *DatabaseSchema {
	return &DatabaseSchema{
		Version: 3,
		Tables: []string{
			`CREATE TABLE IF NOT EXISTS history (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				encrypted_data BLOB NOT NULL,
				timestamp INTEGER NOT NULL,
				session TEXT NOT NULL,
				hostname TEXT NOT NULL,
				created_at INTEGER NOT NULL,
				device_id TEXT,
				record_hash TEXT,
				last_synced INTEGER,
				sync_status INTEGER DEFAULT 0
			)`,

			`CREATE TABLE IF NOT EXISTS schema_version (
				version INTEGER PRIMARY KEY,
				applied_at INTEGER NOT NULL,
				description TEXT
			)`,

			`CREATE TABLE IF NOT EXISTS session_metadata (
				session_id TEXT PRIMARY KEY,
				start_time INTEGER NOT NULL,
				end_time INTEGER,
				hostname TEXT NOT NULL,
				user_name TEXT NOT NULL,
				shell_type TEXT NOT NULL,
				created_at INTEGER NOT NULL
			)`,

			`CREATE TABLE IF NOT EXISTS devices (
				device_id TEXT PRIMARY KEY,
				hostname TEXT NOT NULL,
				platform TEXT NOT NULL,
				last_seen INTEGER NOT NULL,
				is_active BOOLEAN DEFAULT true,
				updated_at INTEGER NOT NULL
			)`,

			`CREATE TABLE IF NOT EXISTS device_aliases (
				device_id TEXT PRIMARY KEY,
				alias TEXT UNIQUE NOT NULL,
				is_enabled BOOLEAN DEFAULT true,
				created_at INTEGER NOT NULL,
				updated_at INTEGER NOT NULL,
				FOREIGN KEY (device_id) REFERENCES devices(device_id)
			)`,

			`CREATE TABLE IF NOT EXISTS sync_rules (
				id TEXT PRIMARY KEY,
				rule_data TEXT NOT NULL,
				active BOOLEAN DEFAULT true,
				created_at INTEGER NOT NULL
			)`,
		},

		Indexes: []string{
			`CREATE INDEX IF NOT EXISTS idx_history_timestamp ON history(timestamp)`,
			`CREATE INDEX IF NOT EXISTS idx_history_session ON history(session)`,
			`CREATE INDEX IF NOT EXISTS idx_history_hostname ON history(hostname)`,
			`CREATE INDEX IF NOT EXISTS idx_history_created_at ON history(created_at)`,
			`CREATE INDEX IF NOT EXISTS idx_history_timestamp_session ON history(timestamp, session)`,
			`CREATE INDEX IF NOT EXISTS idx_history_sync_status ON history(sync_status)`,
			`CREATE INDEX IF NOT EXISTS idx_history_device_id ON history(device_id)`,
			`CREATE INDEX IF NOT EXISTS idx_history_last_synced ON history(last_synced)`,

			`CREATE INDEX IF NOT EXISTS idx_session_start_time ON session_metadata(start_time)`,
			`CREATE INDEX IF NOT EXISTS idx_session_hostname ON session_metadata(hostname)`,
			`CREATE INDEX IF NOT EXISTS idx_session_user ON session_metadata(user_name)`,

			`CREATE INDEX IF NOT EXISTS idx_devices_active ON devices(is_active)`,
			`CREATE INDEX IF NOT EXISTS idx_device_aliases_enabled ON device_aliases(is_enabled)`,
			`CREATE INDEX IF NOT EXISTS idx_sync_rules_active ON sync_rules(active)`,
		},

		Migrations: map[int][]string{
			2: []string{
				`ALTER TABLE history ADD COLUMN device_id TEXT`,
				`ALTER TABLE history ADD COLUMN record_hash TEXT`,
				`ALTER TABLE history ADD COLUMN last_synced INTEGER`,
				`ALTER TABLE history ADD COLUMN sync_status INTEGER DEFAULT 0`,
				`CREATE INDEX IF NOT EXISTS idx_history_sync_status ON history(sync_status)`,
				`CREATE INDEX IF NOT EXISTS idx_history_device_id ON history(device_id)`,
				`CREATE INDEX IF NOT EXISTS idx_history_last_synced ON history(last_synced)`,
			},
			3: []string{
				`CREATE TABLE IF NOT EXISTS devices (
					device_id TEXT PRIMARY KEY,
					hostname TEXT NOT NULL,
					platform TEXT NOT NULL,
					last_seen INTEGER NOT NULL,
					is_active BOOLEAN DEFAULT true,
					updated_at INTEGER NOT NULL
				)`,
				`CREATE TABLE IF NOT EXISTS device_aliases (
					device_id TEXT PRIMARY KEY,
					alias TEXT UNIQUE NOT NULL,
					is_enabled BOOLEAN DEFAULT true,
					created_at INTEGER NOT NULL,
					updated_at INTEGER NOT NULL,
					FOREIGN KEY (device_id) REFERENCES devices(device_id)
				)`,
				`CREATE TABLE IF NOT EXISTS sync_rules (
					id TEXT PRIMARY KEY,
					rule_data TEXT NOT NULL,
					active BOOLEAN DEFAULT true,
					created_at INTEGER NOT NULL
				)`,
				`CREATE INDEX IF NOT EXISTS idx_devices_active ON devices(is_active)`,
				`CREATE INDEX IF NOT EXISTS idx_device_aliases_enabled ON device_aliases(is_enabled)`,
				`CREATE INDEX IF NOT EXISTS idx_sync_rules_active ON sync_rules(active)`,
			},
		},
	}
}

// SessionMetadata represents session tracking information
type SessionMetadata struct {
	SessionID string `db:"session_id"`
	StartTime int64  `db:"start_time"`
	EndTime   *int64 `db:"end_time"` // NULL until session ends
	Hostname  string `db:"hostname"`
	UserName  string `db:"user_name"`
	ShellType string `db:"shell_type"`
	CreatedAt int64  `db:"created_at"`
}

// SchemaVersion represents the schema version tracking
type SchemaVersion struct {
	Version     int    `db:"version"`
	AppliedAt   int64  `db:"applied_at"`
	Description string `db:"description"`
}

// NewCommandRecord creates a new command record with current timestamp
func NewCommandRecord(command string, exitCode int, duration int64, workingDir, sessionID, hostname string) *CommandRecord {
	now := time.Now().UnixMilli()

	return &CommandRecord{
		Command:    command,
		ExitCode:   exitCode,
		Duration:   duration,
		WorkingDir: workingDir,
		Timestamp:  now,
		SessionID:  sessionID,
		Hostname:   hostname,
		Version:    1,
		CreatedAt:  now,
	}
}

// IsValid validates that the command record has required fields
func (cr *CommandRecord) IsValid() bool {
	if cr.Command == "" || cr.SessionID == "" || cr.Hostname == "" || cr.Timestamp <= 0 || cr.CreatedAt <= 0 {
		return false
	}

	// Validate tags
	if len(cr.Tags) > MaxTagsPerCommand {
		return false
	}

	for _, tag := range cr.Tags {
		if len(strings.TrimSpace(tag)) > MaxTagLength {
			return false
		}
	}

	return true
}

// NeedsSync returns true if the record needs to be synced
func (cr *CommandRecord) NeedsSync() bool {
	return cr.SyncStatus == SyncStatusLocal
}

// MarkSynced marks the record as successfully synced
func (cr *CommandRecord) MarkSynced() {
	cr.SyncStatus = SyncStatusSynced
	now := time.Now().UnixMilli()
	cr.LastSynced = &now
}

// HasNote returns true if the command has a note
func (cr *CommandRecord) HasNote() bool {
	return strings.TrimSpace(cr.Note) != ""
}

// SetNote sets a note for the command with validation
func (cr *CommandRecord) SetNote(note string) error {
	trimmed := strings.TrimSpace(note)
	if len(trimmed) > MaxNoteLength {
		return fmt.Errorf("note exceeds maximum length of %d characters", MaxNoteLength)
	}
	cr.Note = trimmed
	return nil
}

// ClearNote removes the note from the command
func (cr *CommandRecord) ClearNote() {
	cr.Note = ""
}

// IsNoteValid validates the note length
func (cr *CommandRecord) IsNoteValid() bool {
	return len(strings.TrimSpace(cr.Note)) <= MaxNoteLength
}

// GetNotePreview returns a truncated preview of the note for display
func (cr *CommandRecord) GetNotePreview(maxLength int) string {
	if !cr.HasNote() {
		return ""
	}

	if maxLength <= 0 {
		maxLength = 100 // Default preview length
	}

	trimmed := strings.TrimSpace(cr.Note)
	if len(trimmed) <= maxLength {
		return trimmed
	}

	// Find the last complete word within the limit
	preview := trimmed[:maxLength]
	if lastSpace := strings.LastIndex(preview, " "); lastSpace > maxLength/2 {
		preview = preview[:lastSpace]
	}

	return preview + "..."
}

// HasTags returns true if the command has tags
func (cr *CommandRecord) HasTags() bool {
	return len(cr.Tags) > 0
}

// AddTag adds a tag to the command if it doesn't already exist
func (cr *CommandRecord) AddTag(tag string) error {
	trimmed := strings.TrimSpace(tag)
	if trimmed == "" {
		return fmt.Errorf("tag cannot be empty")
	}

	if len(trimmed) > MaxTagLength {
		return fmt.Errorf("tag exceeds maximum length of %d characters", MaxTagLength)
	}

	if len(cr.Tags) >= MaxTagsPerCommand {
		return fmt.Errorf("command cannot have more than %d tags", MaxTagsPerCommand)
	}

	// Check if tag already exists
	for _, existingTag := range cr.Tags {
		if existingTag == trimmed {
			return nil // Tag already exists, no error
		}
	}

	cr.Tags = append(cr.Tags, trimmed)
	return nil
}

// RemoveTag removes a tag from the command
func (cr *CommandRecord) RemoveTag(tag string) bool {
	trimmed := strings.TrimSpace(tag)
	for i, existingTag := range cr.Tags {
		if existingTag == trimmed {
			cr.Tags = append(cr.Tags[:i], cr.Tags[i+1:]...)
			return true
		}
	}
	return false
}

// HasTag checks if the command has a specific tag
func (cr *CommandRecord) HasTag(tag string) bool {
	trimmed := strings.TrimSpace(tag)
	for _, existingTag := range cr.Tags {
		if existingTag == trimmed {
			return true
		}
	}
	return false
}

// GetTagsString returns tags as a comma-separated string
func (cr *CommandRecord) GetTagsString() string {
	if len(cr.Tags) == 0 {
		return ""
	}
	return strings.Join(cr.Tags, ", ")
}

// SetTags sets the tags for the command with validation
func (cr *CommandRecord) SetTags(tags []string) error {
	var validTags []string
	for _, tag := range tags {
		trimmed := strings.TrimSpace(tag)
		// Skip empty tags, tags that are only dashes, or whitespace
		if trimmed != "" && trimmed != "-" && strings.TrimSpace(strings.ReplaceAll(trimmed, "-", "")) != "" {
			if len(trimmed) > MaxTagLength {
				return fmt.Errorf("tag '%s' exceeds maximum length of %d characters", trimmed, MaxTagLength)
			}
			validTags = append(validTags, trimmed)
		}
	}

	// Check tag count after filtering empty tags
	if len(validTags) > MaxTagsPerCommand {
		return fmt.Errorf("command cannot have more than %d tags", MaxTagsPerCommand)
	}

	cr.Tags = validTags
	return nil
}

// GetTagColor returns the color for a given tag name from this command's TagColors
func (cr *CommandRecord) GetTagColor(tagName string) string {
	if cr.TagColors != nil {
		if color, exists := cr.TagColors[tagName]; exists {
			return color
		}
	}
	return "" // Empty string means use global preference or default
}

// SetTagColor sets the color for a tag in this command's TagColors
func (cr *CommandRecord) SetTagColor(tagName, color string) {
	if cr.TagColors == nil {
		cr.TagColors = make(map[string]string)
	}
	cr.TagColors[tagName] = color
}

// ClearTagColor removes a tag's color from this command's TagColors
func (cr *CommandRecord) ClearTagColor(tagName string) {
	if cr.TagColors != nil {
		delete(cr.TagColors, tagName)
	}
}

// HasTagColor checks if this command has a specific color set for a tag
func (cr *CommandRecord) HasTagColor(tagName string) bool {
	if cr.TagColors == nil {
		return false
	}
	_, exists := cr.TagColors[tagName]
	return exists
}

// GetSearchableFields returns fields that can be searched without decryption
func (ehr *EncryptedHistoryRecord) GetSearchableFields() map[string]interface{} {
	return map[string]interface{}{
		"timestamp":  ehr.Timestamp,
		"session":    ehr.Session,
		"hostname":   ehr.Hostname,
		"created_at": ehr.CreatedAt,
	}
}

// Constants for database constraints and limits
const (
	MaxCommandLength    = 65536 // Maximum command text length
	MaxWorkingDirLength = 4096  // Maximum working directory path length
	MaxHostnameLength   = 253   // RFC 1035 hostname limit
	MaxSessionIDLength  = 36    // UUID length
	MaxEnvironmentVars  = 100   // Maximum number of environment variables to store
	MaxEnvironmentSize  = 8192  // Maximum total size of environment data
	MaxNoteLength       = 1000  // Maximum note text length
	MaxTagLength        = 50    // Maximum tag name length
	MaxTagsPerCommand   = 5     // Maximum number of tags per command

	// Schema version constants
	CurrentSchemaVersion = 2
	MinSupportedVersion  = 1
)

// Sync status constants
const (
	SyncStatusLocal    = 0
	SyncStatusSynced   = 1
	SyncStatusConflict = 2
)

// DatabaseConstraints defines database-level constraints
var DatabaseConstraints = map[string]interface{}{
	"max_command_length":     MaxCommandLength,
	"max_working_dir_length": MaxWorkingDirLength,
	"max_hostname_length":    MaxHostnameLength,
	"max_session_id_length":  MaxSessionIDLength,
	"max_note_length":        MaxNoteLength,
	"max_tag_length":         MaxTagLength,
	"max_tags_per_command":   MaxTagsPerCommand,
	"current_schema_version": CurrentSchemaVersion,
}
