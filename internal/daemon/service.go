package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/NeverVane/commandchronicles-cli/internal/config"
	"github.com/NeverVane/commandchronicles-cli/internal/logger"
)

// ServiceManager handles system service integration for daemon auto-start
type ServiceManager struct {
	config *config.Config
	logger *logger.Logger
}

// NewServiceManager creates a new service manager instance
func NewServiceManager(cfg *config.Config) *ServiceManager {
	return &ServiceManager{
		config: cfg,
		logger: logger.GetLogger().WithComponent("service-manager"),
	}
}

// CreateSystemService creates an OS-appropriate system service
func (sm *ServiceManager) CreateSystemService() error {
	switch runtime.GOOS {
	case "linux":
		return sm.createSystemdService()
	case "darwin":
		return sm.createLaunchdService()
	case "windows":
		return sm.createWindowsService()
	default:
		return fmt.Errorf("system service not supported on %s", runtime.GOOS)
	}
}

// createSystemdService creates a systemd user service for Linux
func (sm *ServiceManager) createSystemdService() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	serviceContent := `[Unit]
Description=CommandChronicles Sync Daemon
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=%s daemon
Restart=always
RestartSec=10
Environment=HOME=%s
Environment=PATH=%s
Environment=XDG_CONFIG_HOME=%s/.config
Environment=XDG_DATA_HOME=%s/.local/share

[Install]
WantedBy=default.target`

	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		pathEnv = "/usr/local/bin:/usr/bin:/bin"
	}

	content := fmt.Sprintf(serviceContent, execPath, homeDir, pathEnv, homeDir, homeDir)

	// Create systemd user directory
	serviceDir := filepath.Join(homeDir, ".config/systemd/user")
	if err := os.MkdirAll(serviceDir, 0755); err != nil {
		return fmt.Errorf("failed to create systemd directory: %w", err)
	}

	// Write service file
	servicePath := filepath.Join(serviceDir, "ccr-sync.service")
	if err := os.WriteFile(servicePath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	sm.logger.Info().Str("service_path", servicePath).Msg("systemd service file created")

	// Reload systemd and enable service
	commands := [][]string{
		{"systemctl", "--user", "daemon-reload"},
		{"systemctl", "--user", "enable", "ccr-sync.service"},
		{"systemctl", "--user", "start", "ccr-sync.service"},
	}

	for i, cmd := range commands {
		if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
			sm.logger.WithError(err).Warn().
				Strs("command", cmd).
				Int("step", i+1).
				Msg("systemctl command failed")

			// For the first two commands (daemon-reload, enable), continue
			// For start command, it's okay if it fails (daemon might be running)
			if i < 2 {
				continue
			}
		}
	}

	sm.logger.Info().Msg("systemd service created and enabled")
	return nil
}

// createLaunchdService creates a launchd agent for macOS
func (sm *ServiceManager) createLaunchdService() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	logDir := filepath.Join(homeDir, ".local/share/commandchronicles")
	logFile := filepath.Join(logDir, "sync-daemon.log")

	// Ensure log directory exists
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	plistContent := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>dev.commandchronicles.sync</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>daemon</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardErrorPath</key>
	<string>%s</string>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>WorkingDirectory</key>
	<string>%s</string>
	<key>EnvironmentVariables</key>
	<dict>
		<key>HOME</key>
		<string>%s</string>
		<key>PATH</key>
		<string>/usr/local/bin:/usr/bin:/bin</string>
	</dict>
</dict>
</plist>`

	content := fmt.Sprintf(plistContent, execPath, logFile, logFile, homeDir, homeDir)

	// Create LaunchAgents directory
	launchDir := filepath.Join(homeDir, "Library/LaunchAgents")
	if err := os.MkdirAll(launchDir, 0755); err != nil {
		return fmt.Errorf("failed to create LaunchAgents directory: %w", err)
	}

	// Write plist file
	plistPath := filepath.Join(launchDir, "dev.commandchronicles.sync.plist")
	if err := os.WriteFile(plistPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write plist file: %w", err)
	}

	sm.logger.Info().Str("plist_path", plistPath).Msg("launchd plist file created")

	// Load service
	if err := exec.Command("launchctl", "load", plistPath).Run(); err != nil {
		sm.logger.WithError(err).Warn().Msg("launchctl load failed")
		// Don't return error, plist file is created successfully
	}

	sm.logger.Info().Msg("launchd service created and loaded")
	return nil
}

// createWindowsService creates a Windows service (placeholder for future implementation)
func (sm *ServiceManager) createWindowsService() error {
	// TODO: Implement Windows service integration
	return fmt.Errorf("Windows service integration not yet implemented")
}

// RemoveSystemService removes the system service
func (sm *ServiceManager) RemoveSystemService() error {
	switch runtime.GOOS {
	case "linux":
		return sm.removeSystemdService()
	case "darwin":
		return sm.removeLaunchdService()
	case "windows":
		return sm.removeWindowsService()
	default:
		return fmt.Errorf("system service not supported on %s", runtime.GOOS)
	}
}

// removeSystemdService removes the systemd user service
func (sm *ServiceManager) removeSystemdService() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	servicePath := filepath.Join(homeDir, ".config/systemd/user/ccr-sync.service")

	// Stop and disable service (ignore errors)
	exec.Command("systemctl", "--user", "stop", "ccr-sync.service").Run()
	exec.Command("systemctl", "--user", "disable", "ccr-sync.service").Run()
	exec.Command("systemctl", "--user", "daemon-reload").Run()

	// Remove service file
	if err := os.Remove(servicePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove service file: %w", err)
	}

	sm.logger.Info().Msg("systemd service removed")
	return nil
}

// removeLaunchdService removes the launchd agent
func (sm *ServiceManager) removeLaunchdService() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	plistPath := filepath.Join(homeDir, "Library/LaunchAgents/dev.commandchronicles.sync.plist")

	// Unload service (ignore errors)
	exec.Command("launchctl", "unload", plistPath).Run()

	// Remove plist file
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove plist file: %w", err)
	}

	sm.logger.Info().Msg("launchd service removed")
	return nil
}

// removeWindowsService removes the Windows service (placeholder)
func (sm *ServiceManager) removeWindowsService() error {
	return fmt.Errorf("Windows service integration not yet implemented")
}

// IsSystemServiceInstalled checks if the system service is installed
func (sm *ServiceManager) IsSystemServiceInstalled() bool {
	switch runtime.GOOS {
	case "linux":
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return false
		}
		servicePath := filepath.Join(homeDir, ".config/systemd/user/ccr-sync.service")
		_, err = os.Stat(servicePath)
		return err == nil

	case "darwin":
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return false
		}
		plistPath := filepath.Join(homeDir, "Library/LaunchAgents/dev.commandchronicles.sync.plist")
		_, err = os.Stat(plistPath)
		return err == nil

	case "windows":
		// TODO: Implement Windows service check
		return false

	default:
		return false
	}
}

// GetServiceStatus returns the status of the system service
func (sm *ServiceManager) GetServiceStatus() (*ServiceStatus, error) {
	status := &ServiceStatus{
		Installed: sm.IsSystemServiceInstalled(),
		Platform:  runtime.GOOS,
	}

	if !status.Installed {
		return status, nil
	}

	switch runtime.GOOS {
	case "linux":
		return sm.getSystemdServiceStatus(status)
	case "darwin":
		return sm.getLaunchdServiceStatus(status)
	case "windows":
		// TODO: Implement Windows service status
		return status, nil
	default:
		return status, nil
	}
}

// getSystemdServiceStatus gets systemd service status
func (sm *ServiceManager) getSystemdServiceStatus(status *ServiceStatus) (*ServiceStatus, error) {
	// Check if service is enabled
	cmd := exec.Command("systemctl", "--user", "is-enabled", "ccr-sync.service")
	if output, err := cmd.Output(); err == nil {
		status.Enabled = strings.TrimSpace(string(output)) == "enabled"
	}

	// Check if service is active
	cmd = exec.Command("systemctl", "--user", "is-active", "ccr-sync.service")
	if output, err := cmd.Output(); err == nil {
		status.Running = strings.TrimSpace(string(output)) == "active"
	}

	return status, nil
}

// getLaunchdServiceStatus gets launchd service status
func (sm *ServiceManager) getLaunchdServiceStatus(status *ServiceStatus) (*ServiceStatus, error) {
	// Check if service is loaded
	cmd := exec.Command("launchctl", "list")
	if output, err := cmd.Output(); err == nil {
		status.Running = strings.Contains(string(output), "dev.commandchronicles.sync")
		status.Enabled = status.Running // For launchd, loaded means enabled
	}

	return status, nil
}

// StartSystemService starts the system service
func (sm *ServiceManager) StartSystemService() error {
	if !sm.IsSystemServiceInstalled() {
		return fmt.Errorf("system service not installed")
	}

	switch runtime.GOOS {
	case "linux":
		return exec.Command("systemctl", "--user", "start", "ccr-sync.service").Run()
	case "darwin":
		homeDir, _ := os.UserHomeDir()
		plistPath := filepath.Join(homeDir, "Library/LaunchAgents/dev.commandchronicles.sync.plist")
		return exec.Command("launchctl", "load", plistPath).Run()
	case "windows":
		return fmt.Errorf("Windows service not yet implemented")
	default:
		return fmt.Errorf("system service not supported on %s", runtime.GOOS)
	}
}

// StopSystemService stops the system service
func (sm *ServiceManager) StopSystemService() error {
	if !sm.IsSystemServiceInstalled() {
		return fmt.Errorf("system service not installed")
	}

	switch runtime.GOOS {
	case "linux":
		return exec.Command("systemctl", "--user", "stop", "ccr-sync.service").Run()
	case "darwin":
		homeDir, _ := os.UserHomeDir()
		plistPath := filepath.Join(homeDir, "Library/LaunchAgents/dev.commandchronicles.sync.plist")
		return exec.Command("launchctl", "unload", plistPath).Run()
	case "windows":
		return fmt.Errorf("Windows service not yet implemented")
	default:
		return fmt.Errorf("system service not supported on %s", runtime.GOOS)
	}
}

// ServiceStatus represents the status of the system service
type ServiceStatus struct {
	Installed bool   `json:"installed"`
	Enabled   bool   `json:"enabled"`
	Running   bool   `json:"running"`
	Platform  string `json:"platform"`
}

// RestartSystemService restarts the system service
func (sm *ServiceManager) RestartSystemService() error {
	if err := sm.StopSystemService(); err != nil {
		sm.logger.WithError(err).Warn().Msg("Failed to stop service during restart")
	}

	// Give it a moment to stop
	time.Sleep(2 * time.Second)

	return sm.StartSystemService()
}
