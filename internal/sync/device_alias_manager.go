package sync

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/NeverVane/commandchronicles/internal/config"
	"github.com/NeverVane/commandchronicles/internal/logger"
	securestorage "github.com/NeverVane/commandchronicles/pkg/storage"
)

// DeviceAliasManager handles device aliases and management
type DeviceAliasManager struct {
	storage       *securestorage.SecureStorage
	config        *config.Config
	logger        *logger.Logger
	deviceManager *DeviceManager
}

// Device represents a device with its alias information
type Device struct {
	DeviceID  string `json:"device_id"`
	Hostname  string `json:"hostname"`
	Platform  string `json:"platform"`
	LastSeen  int64  `json:"last_seen"`
	IsActive  bool   `json:"is_active"`
	Alias     string `json:"alias,omitempty"`
	IsEnabled bool   `json:"is_enabled"`
	IsCurrent bool   `json:"is_current"`
	UpdatedAt int64  `json:"updated_at"`
}

// NewDeviceAliasManager creates a new device alias manager
func NewDeviceAliasManager(storage *securestorage.SecureStorage, cfg *config.Config) *DeviceAliasManager {
	return &DeviceAliasManager{
		storage:       storage,
		config:        cfg,
		logger:        logger.GetLogger().WithComponent("device-alias-manager"),
		deviceManager: NewDeviceManager(cfg),
	}
}

// UpdateDevicesList updates the local device list from server data
func (dam *DeviceAliasManager) UpdateDevicesList(devices []ServerDevice) error {
	dam.logger.Debug().Int("count", len(devices)).Msg("Updating devices list")

	// Start transaction
	tx, err := dam.storage.GetDatabase().GetDB().Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().UnixMilli()

	// Track which devices are still active
	activeDeviceIDs := make(map[string]bool)

	// Update or insert devices
	for _, serverDevice := range devices {
		activeDeviceIDs[serverDevice.DeviceID] = true

		// Parse last_seen timestamp
		lastSeen, err := time.Parse(time.RFC3339, serverDevice.LastSeen)
		if err != nil {
			dam.logger.Warn().Str("device_id", serverDevice.DeviceID).Str("last_seen", serverDevice.LastSeen).Msg("Failed to parse last_seen timestamp")
			lastSeen = time.Now()
		}

		// Upsert device
		query := `
			INSERT OR REPLACE INTO devices (device_id, hostname, platform, last_seen, is_active, updated_at)
			VALUES (?, ?, ?, ?, ?, ?)
		`
		_, err = tx.Exec(query, serverDevice.DeviceID, serverDevice.Hostname, serverDevice.Platform,
			lastSeen.UnixMilli(), serverDevice.IsActive, now)
		if err != nil {
			return fmt.Errorf("failed to upsert device %s: %w", serverDevice.DeviceID, err)
		}
	}

	// Deactivate devices that are no longer in the server response
	if err := dam.deactivateRemovedDevices(tx, activeDeviceIDs, now); err != nil {
		return fmt.Errorf("failed to deactivate removed devices: %w", err)
	}

	// Update alias states based on device activity
	if err := dam.updateAliasStates(tx, activeDeviceIDs, now); err != nil {
		return fmt.Errorf("failed to update alias states: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit device list update: %w", err)
	}

	dam.logger.Info().Int("devices_updated", len(devices)).Msg("Device list updated successfully")
	return nil
}

// GetDevices returns all devices with their alias information
func (dam *DeviceAliasManager) GetDevices() ([]Device, error) {
	currentDeviceID, err := dam.GetCurrentDeviceID()
	if err != nil {
		return nil, fmt.Errorf("failed to get current device ID: %w", err)
	}

	query := `
		SELECT
			d.device_id, d.hostname, d.platform, d.last_seen, d.is_active, d.updated_at,
			da.alias, da.is_enabled
		FROM devices d
		LEFT JOIN device_aliases da ON d.device_id = da.device_id
		ORDER BY d.is_active DESC, d.last_seen DESC
	`

	rows, err := dam.storage.GetDatabase().GetDB().Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query devices: %w", err)
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var device Device
		var alias sql.NullString
		var isEnabled sql.NullBool

		err := rows.Scan(&device.DeviceID, &device.Hostname, &device.Platform,
			&device.LastSeen, &device.IsActive, &device.UpdatedAt,
			&alias, &isEnabled)
		if err != nil {
			return nil, fmt.Errorf("failed to scan device row: %w", err)
		}

		if alias.Valid {
			device.Alias = alias.String
			device.IsEnabled = isEnabled.Bool
		}

		device.IsCurrent = device.DeviceID == currentDeviceID
		devices = append(devices, device)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating device rows: %w", err)
	}

	return devices, nil
}

// SetDeviceAlias sets an alias for a device
func (dam *DeviceAliasManager) SetDeviceAlias(deviceID, alias string) error {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return fmt.Errorf("alias cannot be empty")
	}

	if len(alias) > 50 {
		return fmt.Errorf("alias cannot exceed 50 characters")
	}

	// Validate alias format (alphanumeric, hyphens, underscores)
	if !isValidAlias(alias) {
		return fmt.Errorf("alias can only contain letters, numbers, hyphens, and underscores")
	}

	// Check if device exists and is active
	device, err := dam.getDevice(deviceID)
	if err != nil {
		return fmt.Errorf("failed to get device: %w", err)
	}

	if !device.IsActive {
		return fmt.Errorf("cannot set alias for inactive device")
	}

	now := time.Now().UnixMilli()

	// Insert or update alias
	query := `
		INSERT OR REPLACE INTO device_aliases (device_id, alias, is_enabled, created_at, updated_at)
		VALUES (?, ?, true,
			COALESCE((SELECT created_at FROM device_aliases WHERE device_id = ?), ?),
			?)
	`

	_, err = dam.storage.GetDatabase().GetDB().Exec(query, deviceID, alias, deviceID, now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("alias '%s' is already in use", alias)
		}
		return fmt.Errorf("failed to set device alias: %w", err)
	}

	dam.logger.Info().Str("device_id", deviceID).Str("alias", alias).Msg("Device alias set")
	return nil
}

// RemoveDeviceAlias removes an alias for a device
func (dam *DeviceAliasManager) RemoveDeviceAlias(deviceID string) error {
	query := `DELETE FROM device_aliases WHERE device_id = ?`

	result, err := dam.storage.GetDatabase().GetDB().Exec(query, deviceID)
	if err != nil {
		return fmt.Errorf("failed to remove device alias: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no alias found for device %s", deviceID)
	}

	dam.logger.Info().Str("device_id", deviceID).Msg("Device alias removed")
	return nil
}

// ResolveAlias resolves an alias or device ID to a device ID
func (dam *DeviceAliasManager) ResolveAlias(aliasOrID string) (string, error) {
	aliasOrID = strings.TrimSpace(aliasOrID)
	if aliasOrID == "" {
		return "", fmt.Errorf("alias or device ID cannot be empty")
	}

	// If it looks like a device ID, return it directly
	if strings.HasPrefix(aliasOrID, "ccr_") {
		// Verify device exists
		device, err := dam.getDevice(aliasOrID)
		if err != nil {
			return "", fmt.Errorf("device not found: %w", err)
		}
		return device.DeviceID, nil
	}

	// Try to resolve as alias
	query := `
		SELECT da.device_id
		FROM device_aliases da
		JOIN devices d ON da.device_id = d.device_id
		WHERE da.alias = ? AND da.is_enabled = true AND d.is_active = true
	`

	var deviceID string
	err := dam.storage.GetDatabase().GetDB().QueryRow(query, aliasOrID).Scan(&deviceID)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("alias '%s' not found or disabled", aliasOrID)
		}
		return "", fmt.Errorf("failed to resolve alias: %w", err)
	}

	return deviceID, nil
}

// GetCurrentDeviceID returns the current device's ID
func (dam *DeviceAliasManager) GetCurrentDeviceID() (string, error) {
	// Use the existing device manager
	return dam.deviceManager.GetDeviceID()
}

// getDevice gets a single device by ID
func (dam *DeviceAliasManager) getDevice(deviceID string) (*Device, error) {
	query := `
		SELECT device_id, hostname, platform, last_seen, is_active, updated_at
		FROM devices
		WHERE device_id = ?
	`

	var device Device
	err := dam.storage.GetDatabase().GetDB().QueryRow(query, deviceID).Scan(
		&device.DeviceID, &device.Hostname, &device.Platform,
		&device.LastSeen, &device.IsActive, &device.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("device %s not found", deviceID)
		}
		return nil, fmt.Errorf("failed to query device: %w", err)
	}

	return &device, nil
}

// deactivateRemovedDevices marks devices as inactive if they're no longer in the server response
func (dam *DeviceAliasManager) deactivateRemovedDevices(tx *sql.Tx, activeDeviceIDs map[string]bool, now int64) error {
	// Get all currently active devices
	query := `SELECT device_id FROM devices WHERE is_active = true`
	rows, err := tx.Query(query)
	if err != nil {
		return fmt.Errorf("failed to query active devices: %w", err)
	}
	defer rows.Close()

	var devicesToDeactivate []string
	for rows.Next() {
		var deviceID string
		if err := rows.Scan(&deviceID); err != nil {
			return fmt.Errorf("failed to scan device ID: %w", err)
		}

		if !activeDeviceIDs[deviceID] {
			devicesToDeactivate = append(devicesToDeactivate, deviceID)
		}
	}

	// Deactivate removed devices
	for _, deviceID := range devicesToDeactivate {
		updateQuery := `UPDATE devices SET is_active = false, updated_at = ? WHERE device_id = ?`
		if _, err := tx.Exec(updateQuery, now, deviceID); err != nil {
			return fmt.Errorf("failed to deactivate device %s: %w", deviceID, err)
		}

		dam.logger.Info().Str("device_id", deviceID).Msg("Device deactivated")
	}

	return nil
}

// updateAliasStates updates alias enabled states based on device activity
func (dam *DeviceAliasManager) updateAliasStates(tx *sql.Tx, activeDeviceIDs map[string]bool, now int64) error {
	// Enable aliases for active devices
	enableQuery := `
		UPDATE device_aliases
		SET is_enabled = true, updated_at = ?
		WHERE device_id IN (
			SELECT device_id FROM devices WHERE is_active = true
		) AND device_id IN (` + strings.Repeat("?,", len(activeDeviceIDs)-1) + "?)"

	args := []interface{}{now}
	for deviceID := range activeDeviceIDs {
		args = append(args, deviceID)
	}

	if len(activeDeviceIDs) > 0 {
		if _, err := tx.Exec(enableQuery, args...); err != nil {
			return fmt.Errorf("failed to enable aliases for active devices: %w", err)
		}
	}

	// Disable aliases for inactive devices
	disableQuery := `
		UPDATE device_aliases
		SET is_enabled = false, updated_at = ?
		WHERE device_id IN (
			SELECT device_id FROM devices WHERE is_active = false
		)
	`

	if _, err := tx.Exec(disableQuery, now); err != nil {
		return fmt.Errorf("failed to disable aliases for inactive devices: %w", err)
	}

	return nil
}

// isValidAlias checks if an alias contains only valid characters
func isValidAlias(alias string) bool {
	if len(alias) == 0 {
		return false
	}

	for _, char := range alias {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '_') {
			return false
		}
	}

	return true
}

// GetDeviceAlias returns the alias for a device if it exists
func (dam *DeviceAliasManager) GetDeviceAlias(deviceID string) (string, error) {
	query := `SELECT alias FROM device_aliases WHERE device_id = ? AND is_enabled = true`

	var alias string
	err := dam.storage.GetDatabase().GetDB().QueryRow(query, deviceID).Scan(&alias)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("no alias found for device %s", deviceID)
		}
		return "", fmt.Errorf("failed to get device alias: %w", err)
	}

	return alias, nil
}

// DeactivateDevice marks a device as inactive
func (dam *DeviceAliasManager) DeactivateDevice(deviceID string) error {
	now := time.Now().UnixMilli()

	tx, err := dam.storage.GetDatabase().GetDB().Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Deactivate device
	deviceQuery := `UPDATE devices SET is_active = false, updated_at = ? WHERE device_id = ?`
	if _, err := tx.Exec(deviceQuery, now, deviceID); err != nil {
		return fmt.Errorf("failed to deactivate device: %w", err)
	}

	// Disable alias
	aliasQuery := `UPDATE device_aliases SET is_enabled = false, updated_at = ? WHERE device_id = ?`
	if _, err := tx.Exec(aliasQuery, now, deviceID); err != nil {
		return fmt.Errorf("failed to disable device alias: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit device deactivation: %w", err)
	}

	dam.logger.Info().Str("device_id", deviceID).Msg("Device deactivated")
	return nil
}

// ReactivateDevice marks a device as active
func (dam *DeviceAliasManager) ReactivateDevice(deviceID string) error {
	now := time.Now().UnixMilli()

	tx, err := dam.storage.GetDatabase().GetDB().Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Reactivate device
	deviceQuery := `UPDATE devices SET is_active = true, updated_at = ? WHERE device_id = ?`
	if _, err := tx.Exec(deviceQuery, now, deviceID); err != nil {
		return fmt.Errorf("failed to reactivate device: %w", err)
	}

	// Re-enable alias if it exists
	aliasQuery := `UPDATE device_aliases SET is_enabled = true, updated_at = ? WHERE device_id = ?`
	if _, err := tx.Exec(aliasQuery, now, deviceID); err != nil {
		return fmt.Errorf("failed to re-enable device alias: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit device reactivation: %w", err)
	}

	dam.logger.Info().Str("device_id", deviceID).Msg("Device reactivated")
	return nil
}
