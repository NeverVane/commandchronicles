package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/NeverVane/commandchronicles/internal/config"
	"github.com/NeverVane/commandchronicles/internal/logger"
)

// Manager handles daemon lifecycle and service management
type Manager struct {
	config         *config.Config
	logger         *logger.Logger
	pidManager     *PIDManager
	serviceManager *ServiceManager
}

// NewManager creates a new daemon manager instance
func NewManager(cfg *config.Config) *Manager {
	return &Manager{
		config:         cfg,
		logger:         logger.GetLogger().WithComponent("daemon-manager"),
		pidManager:     NewPIDManager(cfg.Daemon.PIDFile),
		serviceManager: NewServiceManager(cfg),
	}
}

// SetupBackgroundSync sets up background sync during initialization
// This is called during 'ccr init' when sync is enabled
func (m *Manager) SetupBackgroundSync() error {
	fmt.Print("Setting up background sync...")

	// Try to create system service first (preferred method)
	if err := m.serviceManager.CreateSystemService(); err == nil {
		// System service created successfully
		m.config.Daemon.SystemService = true
		m.config.Daemon.AutoStart = false // System service handles startup

		if err := m.saveConfig(); err != nil {
			m.logger.WithError(err).Warn().Msg("Failed to save config after service creation")
		}

		fmt.Printf(" [OK] System service created\n")
		fmt.Println("[OK] Background sync will start automatically on boot!")

		m.logger.Info().
			Str("platform", runtime.GOOS).
			Msg("System service created successfully")

		return nil
	}

	// System service creation failed, fallback to auto-start mechanism
	m.config.Daemon.SystemService = false
	m.config.Daemon.AutoStart = true

	if err := m.saveConfig(); err != nil {
		m.logger.WithError(err).Warn().Msg("Failed to save config after auto-start setup")
	}

	fmt.Printf(" [WARN] System service unavailable, using auto-start mode\n")
	fmt.Println("[OK] Background sync will start automatically when you use ccr")

	// Start daemon immediately for this session
	if err := m.StartDaemon(); err != nil {
		m.logger.WithError(err).Warn().Msg("Failed to start daemon immediately")
		fmt.Printf("[WARN] Warning: Could not start daemon for this session: %v\n", err)
		fmt.Println("Daemon will start automatically when you use ccr commands")
	}

	m.logger.Info().Msg("Auto-start fallback configured")
	return nil
}

// StartDaemon starts the daemon using the configured method
func (m *Manager) StartDaemon() error {
	// Clean up any stale PID files first
	if err := m.pidManager.ValidatePIDFile(); err != nil {
		m.logger.WithError(err).Debug().Msg("Cleaned up stale PID file")
	}

	// Check if already running
	if m.pidManager.IsRunning() {
		existingPID, _ := m.pidManager.ReadPID()
		m.logger.Info().
			Int("pid", existingPID).
			Msg("Daemon already running")
		return nil
	}

	// If system service is enabled, try to start via service manager
	if m.config.Daemon.SystemService && m.serviceManager.IsSystemServiceInstalled() {
		if err := m.serviceManager.StartSystemService(); err == nil {
			m.logger.Info().Msg("Started daemon via system service")
			return nil
		} else {
			m.logger.WithError(err).Warn().Msg("Failed to start via system service, falling back to direct start")
		}
	}

	// Fallback to direct process start
	return m.startDaemonProcess()
}

// startDaemonProcess starts the daemon as a direct child process
func (m *Manager) startDaemonProcess() error {
	// Get current executable path
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Prepare daemon command
	cmd := exec.Command(execPath, "daemon")

	// Set up process attributes for better daemonization
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, // Create new session
	}

	// Set up logging if log file is specified
	if m.config.Daemon.LogFile != "" {
		// Ensure log directory exists
		logDir := filepath.Dir(m.config.Daemon.LogFile)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			m.logger.WithError(err).Warn().Msg("Failed to create log directory")
		} else {
			// Open log file for daemon output
			logFile, err := os.OpenFile(m.config.Daemon.LogFile,
				os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				m.logger.WithError(err).Warn().Msg("Failed to open log file")
			} else {
				cmd.Stdout = logFile
				cmd.Stderr = logFile
				// Note: logFile will be closed by the child process
			}
		}
	}

	// Start the daemon process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start daemon process: %w", err)
	}

	m.logger.Info().
		Int("pid", cmd.Process.Pid).
		Str("method", "direct").
		Msg("Daemon process started")

	// Give the process a moment to start and write its PID file
	time.Sleep(2 * time.Second)

	// Verify it's actually running
	if !m.pidManager.IsRunning() {
		return fmt.Errorf("daemon process failed to start properly")
	}

	return nil
}

// StopDaemon stops the daemon
func (m *Manager) StopDaemon() error {
	// If system service is enabled, try to stop via service manager
	if m.config.Daemon.SystemService && m.serviceManager.IsSystemServiceInstalled() {
		if err := m.serviceManager.StopSystemService(); err == nil {
			m.logger.Info().Msg("Stopped daemon via system service")
			return nil
		} else {
			m.logger.WithError(err).Warn().Msg("Failed to stop via system service, falling back to direct kill")
		}
	}

	// Fallback to direct process termination
	if !m.pidManager.IsRunning() {
		m.logger.Info().Msg("Daemon not running")
		return nil
	}

	return m.pidManager.KillDaemon()
}

// RestartDaemon restarts the daemon
func (m *Manager) RestartDaemon() error {
	m.logger.Info().Msg("Restarting daemon")

	// Stop daemon first
	if err := m.StopDaemon(); err != nil {
		m.logger.WithError(err).Warn().Msg("Failed to stop daemon during restart")
	}

	// Give it a moment to fully stop
	time.Sleep(3 * time.Second)

	// Start daemon
	return m.StartDaemon()
}

// GetStatus returns comprehensive daemon status
func (m *Manager) GetStatus() (*ComprehensiveStatus, error) {
	status := &ComprehensiveStatus{
		Daemon:  &DaemonStatus{},
		Service: &ServiceStatus{},
		Config:  m.getDaemonConfigStatus(),
	}

	// Get PID status
	pidStatus, err := m.pidManager.GetStatus()
	if err != nil {
		return nil, fmt.Errorf("failed to get PID status: %w", err)
	}

	// Populate daemon status
	status.Daemon.Running = pidStatus.Running
	status.Daemon.PID = pidStatus.PID
	status.Daemon.Uptime = pidStatus.Uptime
	status.Daemon.SyncInterval = m.config.Daemon.SyncInterval
	status.Daemon.AutoStart = m.config.Daemon.AutoStart
	status.Daemon.SystemService = m.config.Daemon.SystemService

	// Get service status
	serviceStatus, err := m.serviceManager.GetServiceStatus()
	if err != nil {
		m.logger.WithError(err).Warn().Msg("Failed to get service status")
	} else {
		status.Service = serviceStatus
	}

	return status, nil
}

// InstallSystemService installs the system service
func (m *Manager) InstallSystemService() error {
	if m.serviceManager.IsSystemServiceInstalled() {
		return fmt.Errorf("system service already installed")
	}

	// Create the system service
	if err := m.serviceManager.CreateSystemService(); err != nil {
		return fmt.Errorf("failed to create system service: %w", err)
	}

	// Update configuration
	m.config.Daemon.SystemService = true
	m.config.Daemon.AutoStart = false // System service handles startup

	if err := m.saveConfig(); err != nil {
		m.logger.WithError(err).Warn().Msg("Failed to save config after service installation")
	}

	m.logger.Info().Msg("System service installed successfully")
	return nil
}

// RemoveSystemService removes the system service
func (m *Manager) RemoveSystemService() error {
	if !m.serviceManager.IsSystemServiceInstalled() {
		return fmt.Errorf("system service not installed")
	}

	// Stop the service first
	if err := m.serviceManager.StopSystemService(); err != nil {
		m.logger.WithError(err).Warn().Msg("Failed to stop service before removal")
	}

	// Remove the system service
	if err := m.serviceManager.RemoveSystemService(); err != nil {
		return fmt.Errorf("failed to remove system service: %w", err)
	}

	// Update configuration to use auto-start fallback
	m.config.Daemon.SystemService = false
	m.config.Daemon.AutoStart = true

	if err := m.saveConfig(); err != nil {
		m.logger.WithError(err).Warn().Msg("Failed to save config after service removal")
	}

	m.logger.Info().Msg("System service removed, switched to auto-start mode")
	return nil
}

// IsAutoStartNeeded checks if auto-start should be triggered
func (m *Manager) IsAutoStartNeeded() bool {
	// Only auto-start if configured to do so
	if !m.config.Daemon.AutoStart {
		return false
	}

	// Only auto-start if sync is enabled
	if !m.config.Sync.Enabled {
		return false
	}

	// Don't auto-start if daemon is already running
	if m.pidManager.IsRunning() {
		return false
	}

	// Don't auto-start if system service should handle it
	if m.config.Daemon.SystemService && m.serviceManager.IsSystemServiceInstalled() {
		return false
	}

	return true
}

// TriggerAutoStart starts the daemon if auto-start conditions are met
func (m *Manager) TriggerAutoStart() error {
	if !m.IsAutoStartNeeded() {
		return nil
	}

	m.logger.Debug().Msg("Triggering auto-start of daemon")

	// Start daemon in background (non-blocking)
	go func() {
		if err := m.StartDaemon(); err != nil {
			m.logger.WithError(err).Debug().Msg("Auto-start failed")
		} else {
			m.logger.Debug().Msg("Auto-start successful")
		}
	}()

	return nil
}

// saveConfig saves the current configuration
func (m *Manager) saveConfig() error {
	// This would typically call the config save method
	// For now, we'll implement a basic version
	configPath := filepath.Join(m.config.ConfigDir, "config.toml")

	// Ensure config directory exists
	if err := os.MkdirAll(m.config.ConfigDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// TODO: Implement proper config serialization
	// This is a placeholder - the actual implementation would serialize the config to TOML
	m.logger.Debug().Str("config_path", configPath).Msg("Config save requested")

	return nil
}

// getDaemonConfigStatus returns daemon configuration status
func (m *Manager) getDaemonConfigStatus() *DaemonConfigStatus {
	return &DaemonConfigStatus{
		SyncInterval:  m.config.Daemon.SyncInterval,
		AutoStart:     m.config.Daemon.AutoStart,
		SystemService: m.config.Daemon.SystemService,
		PIDFile:       m.config.Daemon.PIDFile,
		LogFile:       m.config.Daemon.LogFile,
		LogLevel:      m.config.Daemon.LogLevel,
	}
}

// ComprehensiveStatus contains all daemon status information
type ComprehensiveStatus struct {
	Daemon  *DaemonStatus       `json:"daemon"`
	Service *ServiceStatus      `json:"service"`
	Config  *DaemonConfigStatus `json:"config"`
}

// DaemonConfigStatus contains daemon configuration information
type DaemonConfigStatus struct {
	SyncInterval  time.Duration `json:"sync_interval"`
	AutoStart     bool          `json:"auto_start"`
	SystemService bool          `json:"system_service"`
	PIDFile       string        `json:"pid_file"`
	LogFile       string        `json:"log_file"`
	LogLevel      string        `json:"log_level"`
}

// Close cleans up manager resources
func (m *Manager) Close() error {
	// Nothing to close currently, but method exists for future use
	return nil
}
