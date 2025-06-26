package shell

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/NeverVane/commandchronicles-cli/internal/config"
	"github.com/NeverVane/commandchronicles-cli/internal/logger"
	"github.com/NeverVane/commandchronicles-cli/internal/storage"
)

// SessionManager handles session ID generation and persistence
type SessionManager struct {
	config     *config.Config
	logger     *logger.Logger
	sessionID  string
	sessionDir string
}

// NewSessionManager creates a new session manager
func NewSessionManager(cfg *config.Config) (*SessionManager, error) {
	sessionDir := filepath.Join(cfg.DataDir, "sessions")
	if err := os.MkdirAll(sessionDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create session directory: %w", err)
	}

	sm := &SessionManager{
		config:     cfg,
		logger:     logger.GetLogger().WithComponent("session"),
		sessionDir: sessionDir,
	}

	return sm, nil
}

// GetCurrentSessionID returns the current session ID, creating one if needed
func (sm *SessionManager) GetCurrentSessionID() (string, error) {
	if sm.sessionID != "" {
		return sm.sessionID, nil
	}

	// Try to load existing session from environment
	if envSessionID := os.Getenv("CCR_SESSION_ID"); envSessionID != "" {
		if sm.validateSessionID(envSessionID) {
			sm.sessionID = envSessionID
			return sm.sessionID, nil
		}
	}

	// Try to load from session file
	sessionFile := filepath.Join(sm.sessionDir, "current")
	if content, err := os.ReadFile(sessionFile); err == nil {
		sessionID := strings.TrimSpace(string(content))
		if sm.validateSessionID(sessionID) {
			sm.sessionID = sessionID
			return sm.sessionID, nil
		}
	}

	// Generate new session ID
	sessionID, err := sm.generateNewSession()
	if err != nil {
		return "", fmt.Errorf("failed to generate new session: %w", err)
	}

	sm.sessionID = sessionID
	return sm.sessionID, nil
}

// generateNewSession creates a new session ID and persists it
func (sm *SessionManager) generateNewSession() (string, error) {
	sessionID := generateUUID()
	
	// Create session metadata
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}

	username := "unknown"
	if user := os.Getenv("USER"); user != "" {
		username = user
	} else if user := os.Getenv("USERNAME"); user != "" {
		username = user
	}

	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "unknown"
	} else {
		shell = filepath.Base(shell)
	}

	metadata := &storage.SessionMetadata{
		SessionID: sessionID,
		StartTime: time.Now().UnixMilli(),
		Hostname:  hostname,
		UserName:  username,
		ShellType: shell,
		CreatedAt: time.Now().UnixMilli(),
	}

	// Store session metadata
	if err := sm.storeSessionMetadata(metadata); err != nil {
		sm.logger.WithError(err).Warn().Msg("Failed to store session metadata")
	}

	// Persist session ID to file
	sessionFile := filepath.Join(sm.sessionDir, "current")
	if err := os.WriteFile(sessionFile, []byte(sessionID), 0600); err != nil {
		sm.logger.WithError(err).Warn().Msg("Failed to persist session ID to file")
	}

	sm.logger.WithFields(map[string]interface{}{
		"session_id": sessionID,
		"hostname":   hostname,
		"username":   username,
		"shell":      shell,
	}).Info().Msg("New session created")

	return sessionID, nil
}

// EndCurrentSession marks the current session as ended
func (sm *SessionManager) EndCurrentSession() error {
	if sm.sessionID == "" {
		return nil
	}

	// Update session metadata with end time
	if err := sm.updateSessionEndTime(sm.sessionID); err != nil {
		sm.logger.WithError(err).Warn().Msg("Failed to update session end time")
	}

	// Remove current session file
	sessionFile := filepath.Join(sm.sessionDir, "current")
	if err := os.Remove(sessionFile); err != nil && !os.IsNotExist(err) {
		sm.logger.WithError(err).Warn().Msg("Failed to remove current session file")
	}

	sm.logger.WithField("session_id", sm.sessionID).Info().Msg("Session ended")
	sm.sessionID = ""

	return nil
}

// validateSessionID checks if a session ID is valid
func (sm *SessionManager) validateSessionID(sessionID string) bool {
	// Basic UUID format validation
	if len(sessionID) != 36 {
		return false
	}

	parts := strings.Split(sessionID, "-")
	if len(parts) != 5 {
		return false
	}

	expectedLengths := []int{8, 4, 4, 4, 12}
	for i, part := range parts {
		if len(part) != expectedLengths[i] {
			return false
		}
		// Check if part contains only hex characters
		for _, char := range part {
			if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
				return false
			}
		}
	}

	return true
}

// storeSessionMetadata stores session metadata (placeholder for database integration)
func (sm *SessionManager) storeSessionMetadata(metadata *storage.SessionMetadata) error {
	// TODO: Integrate with secure storage to store session metadata
	// For now, we'll just log it
	sm.logger.WithFields(map[string]interface{}{
		"session_id": metadata.SessionID,
		"start_time": metadata.StartTime,
		"hostname":   metadata.Hostname,
		"username":   metadata.UserName,
		"shell":      metadata.ShellType,
	}).Debug().Msg("Session metadata created")

	return nil
}

// updateSessionEndTime updates the session end time (placeholder for database integration)
func (sm *SessionManager) updateSessionEndTime(sessionID string) error {
	// TODO: Integrate with secure storage to update session end time
	sm.logger.WithFields(map[string]interface{}{
		"session_id": sessionID,
		"end_time":   time.Now().UnixMilli(),
	}).Debug().Msg("Session end time updated")

	return nil
}

// generateUUID generates a random UUID v4
func generateUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based UUID if crypto/rand fails
		now := time.Now().UnixNano()
		for i := 0; i < 8; i++ {
			b[i] = byte(now >> (i * 8))
		}
		for i := 8; i < 16; i++ {
			b[i] = byte(now >> ((i-8) * 8))
		}
	}

	// Set version (4) and variant bits
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant 10

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// GetSessionInfo returns current session information
func (sm *SessionManager) GetSessionInfo() map[string]interface{} {
	info := map[string]interface{}{
		"session_id": sm.sessionID,
	}

	if sm.sessionID != "" {
		sessionFile := filepath.Join(sm.sessionDir, "current")
		if stat, err := os.Stat(sessionFile); err == nil {
			info["session_start"] = stat.ModTime().Unix()
		}
	}

	return info
}