package sync

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	
	"github.com/NeverVane/commandchronicles/internal/config"
	"github.com/NeverVane/commandchronicles/internal/logger"
)

// DeviceManager handles device identification
type DeviceManager struct {
	config *config.Config
	logger *logger.Logger
}

// DeviceInfo contains information about this device
type DeviceInfo struct {
	DeviceID   string `json:"device_id"`
	Hostname   string `json:"hostname"`
	Platform   string `json:"platform"`
	UserAgent  string `json:"user_agent"`
	CreatedAt  int64  `json:"created_at"`
}

// NewDeviceManager creates a new device manager
func NewDeviceManager(cfg *config.Config) *DeviceManager {
	return &DeviceManager{
		config: cfg,
		logger: logger.GetLogger().WithComponent("device"),
	}
}

// GetDeviceID returns the device ID, generating one if it doesn't exist
func (dm *DeviceManager) GetDeviceID() (string, error) {
	devicePath := dm.getDeviceIDPath()
	
	// Try to read existing device ID
	if data, err := os.ReadFile(devicePath); err == nil {
		deviceID := strings.TrimSpace(string(data))
		if len(deviceID) > 0 {
			return deviceID, nil
		}
	}
	
	// Generate new device ID
	deviceID, err := dm.generateDeviceID()
	if err != nil {
		return "", fmt.Errorf("failed to generate device ID: %w", err)
	}
	
	// Save device ID
	if err := dm.saveDeviceID(deviceID); err != nil {
		return "", fmt.Errorf("failed to save device ID: %w", err)
	}
	
	dm.logger.Info().Str("device_id", deviceID).Msg("Generated new device ID")
	return deviceID, nil
}

// GetDeviceInfo returns comprehensive device information
func (dm *DeviceManager) GetDeviceInfo() (*DeviceInfo, error) {
	deviceID, err := dm.GetDeviceID()
	if err != nil {
		return nil, fmt.Errorf("failed to get device ID: %w", err)
	}
	
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	
	return &DeviceInfo{
		DeviceID:  deviceID,
		Hostname:  hostname,
		Platform:  runtime.GOOS,
		UserAgent: "CommandChronicles/1.0.0",
		CreatedAt: 0, // Will be set when first used
	}, nil
}

// generateDeviceID creates a new random device ID
func (dm *DeviceManager) generateDeviceID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	
	return fmt.Sprintf("ccr_%x", bytes), nil
}

// getDeviceIDPath returns the path where device ID is stored
func (dm *DeviceManager) getDeviceIDPath() string {
	configDir := filepath.Dir(dm.config.Database.Path)
	return filepath.Join(configDir, "device_id")
}

// saveDeviceID persists the device ID to disk
func (dm *DeviceManager) saveDeviceID(deviceID string) error {
	devicePath := dm.getDeviceIDPath()
	
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(devicePath), 0700); err != nil {
		return err
	}
	
	// Write device ID with secure permissions
	return os.WriteFile(devicePath, []byte(deviceID), 0600)
}

// RegenerateDeviceID creates a new device ID and saves it
func (dm *DeviceManager) RegenerateDeviceID() (string, error) {
	deviceID, err := dm.generateDeviceID()
	if err != nil {
		return "", fmt.Errorf("failed to generate device ID: %w", err)
	}
	
	if err := dm.saveDeviceID(deviceID); err != nil {
		return "", fmt.Errorf("failed to save device ID: %w", err)
	}
	
	dm.logger.Info().Str("device_id", deviceID).Msg("Regenerated device ID")
	return deviceID, nil
}

// ClearDeviceID removes the stored device ID
func (dm *DeviceManager) ClearDeviceID() error {
	devicePath := dm.getDeviceIDPath()
	
	if err := os.Remove(devicePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove device ID file: %w", err)
	}
	
	dm.logger.Info().Msg("Device ID cleared")
	return nil
}