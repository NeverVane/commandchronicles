package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// PIDManager handles PID file operations for daemon lifecycle management
type PIDManager struct {
	pidFile string
}

// NewPIDManager creates a new PID manager instance
func NewPIDManager(pidFile string) *PIDManager {
	return &PIDManager{
		pidFile: pidFile,
	}
}

// WritePID writes the current process PID to the PID file
func (pm *PIDManager) WritePID() error {
	// Ensure directory exists
	dir := filepath.Dir(pm.pidFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create PID directory %s: %w", dir, err)
	}

	// Check if PID file already exists and process is running
	if pm.IsRunning() {
		existingPID, _ := pm.ReadPID()
		return fmt.Errorf("daemon already running with PID %d", existingPID)
	}

	// Write current PID
	pid := os.Getpid()
	content := fmt.Sprintf("%d\n", pid)

	// Write atomically by creating temp file and renaming
	tempFile := pm.pidFile + ".tmp"
	if err := os.WriteFile(tempFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write temporary PID file: %w", err)
	}

	if err := os.Rename(tempFile, pm.pidFile); err != nil {
		os.Remove(tempFile) // Clean up temp file
		return fmt.Errorf("failed to rename PID file: %w", err)
	}

	return nil
}

// ReadPID reads the PID from the PID file
func (pm *PIDManager) ReadPID() (int, error) {
	content, err := os.ReadFile(pm.pidFile)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, fmt.Errorf("PID file does not exist")
		}
		return 0, fmt.Errorf("failed to read PID file: %w", err)
	}

	// Parse PID from content
	pidStr := strings.TrimSpace(string(content))
	if pidStr == "" {
		return 0, fmt.Errorf("PID file is empty")
	}

	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, fmt.Errorf("invalid PID in file: %s", pidStr)
	}

	if pid <= 0 {
		return 0, fmt.Errorf("invalid PID value: %d", pid)
	}

	return pid, nil
}

// IsRunning checks if the daemon process is currently running
func (pm *PIDManager) IsRunning() bool {
	pid, err := pm.ReadPID()
	if err != nil {
		return false
	}

	return pm.IsProcessRunning(pid)
}

// IsProcessRunning checks if a process with the given PID is running
func (pm *PIDManager) IsProcessRunning(pid int) bool {
	// Try to find the process
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// Send signal 0 to check if process exists and is accessible
	// Signal 0 doesn't actually send a signal, just checks if we can signal the process
	err = process.Signal(syscall.Signal(0))

	// If no error, process exists and is running
	if err == nil {
		return true
	}

	// Check specific error types
	if errno, ok := err.(syscall.Errno); ok {
		switch errno {
		case syscall.ESRCH:
			// Process does not exist
			return false
		case syscall.EPERM:
			// Process exists but we don't have permission (still running)
			return true
		default:
			// Other errors, assume not running
			return false
		}
	}

	return false
}

// RemovePID removes the PID file
func (pm *PIDManager) RemovePID() error {
	err := os.Remove(pm.pidFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove PID file: %w", err)
	}
	return nil
}

// KillDaemon gracefully kills the daemon process
func (pm *PIDManager) KillDaemon() error {
	pid, err := pm.ReadPID()
	if err != nil {
		return fmt.Errorf("failed to read PID: %w", err)
	}

	if !pm.IsProcessRunning(pid) {
		// Process not running, just clean up PID file
		pm.RemovePID()
		return nil
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process %d: %w", pid, err)
	}

	// Try graceful shutdown first (SIGTERM)
	if err := process.Signal(syscall.SIGTERM); err != nil {
		// If SIGTERM fails, try SIGKILL
		if err := process.Signal(syscall.SIGKILL); err != nil {
			return fmt.Errorf("failed to kill process %d: %w", pid, err)
		}
	}

	// Wait for process to exit (with timeout)
	timeout := time.After(10 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			// Force kill if graceful shutdown takes too long
			process.Signal(syscall.SIGKILL)
			time.Sleep(1 * time.Second) // Give it a moment
			break
		case <-ticker.C:
			if !pm.IsProcessRunning(pid) {
				// Process has exited
				return pm.RemovePID()
			}
		}
	}

	// Final cleanup
	return pm.RemovePID()
}

// GetPIDFile returns the path to the PID file
func (pm *PIDManager) GetPIDFile() string {
	return pm.pidFile
}

// GetStatus returns status information about the daemon
func (pm *PIDManager) GetStatus() (*PIDStatus, error) {
	status := &PIDStatus{
		PIDFile: pm.pidFile,
		Running: false,
	}

	// Check if PID file exists
	if _, err := os.Stat(pm.pidFile); err != nil {
		if os.IsNotExist(err) {
			status.Error = "PID file does not exist"
			return status, nil
		}
		status.Error = fmt.Sprintf("Cannot access PID file: %v", err)
		return status, nil
	}

	// Read PID
	pid, err := pm.ReadPID()
	if err != nil {
		status.Error = fmt.Sprintf("Cannot read PID: %v", err)
		return status, nil
	}

	status.PID = pid

	// Check if process is running
	status.Running = pm.IsProcessRunning(pid)

	if !status.Running {
		status.Error = "Process not running (stale PID file)"
	}

	// Get process start time if available
	if status.Running {
		if startTime, err := pm.getProcessStartTime(pid); err == nil {
			status.StartTime = startTime
			status.Uptime = time.Since(startTime)
		}
	}

	return status, nil
}

// getProcessStartTime attempts to get the start time of a process
func (pm *PIDManager) getProcessStartTime(pid int) (time.Time, error) {
	// Try to read from /proc filesystem (Linux)
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	if data, err := os.ReadFile(statPath); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 21 {
			// Field 22 is starttime in clock ticks since boot
			if startTicks, err := strconv.ParseInt(fields[21], 10, 64); err == nil {
				// Convert ticks to time (approximation)
				// This is not precise but gives a rough idea
				ticksPerSecond := int64(100) // Typical value, but can vary
				bootTime := time.Now().Add(-time.Duration(startTicks/ticksPerSecond) * time.Second)
				return bootTime, nil
			}
		}
	}

	// Fallback: use PID file modification time as approximation
	if stat, err := os.Stat(pm.pidFile); err == nil {
		return stat.ModTime(), nil
	}

	return time.Time{}, fmt.Errorf("cannot determine process start time")
}

// PIDStatus contains status information about the daemon process
type PIDStatus struct {
	PIDFile   string        `json:"pid_file"`
	PID       int           `json:"pid"`
	Running   bool          `json:"running"`
	StartTime time.Time     `json:"start_time,omitempty"`
	Uptime    time.Duration `json:"uptime,omitempty"`
	Error     string        `json:"error,omitempty"`
}

// CleanupStalePIDFile removes PID file if the process is not running
func (pm *PIDManager) CleanupStalePIDFile() error {
	if !pm.IsRunning() {
		// Check if PID file exists
		if _, err := os.Stat(pm.pidFile); err == nil {
			return pm.RemovePID()
		}
	}
	return nil
}

// ValidatePIDFile checks if the PID file is valid and cleans up if necessary
func (pm *PIDManager) ValidatePIDFile() error {
	// If PID file doesn't exist, nothing to validate
	if _, err := os.Stat(pm.pidFile); os.IsNotExist(err) {
		return nil
	}

	// Try to read PID
	pid, err := pm.ReadPID()
	if err != nil {
		// Invalid PID file, remove it
		pm.RemovePID()
		return fmt.Errorf("removed invalid PID file: %w", err)
	}

	// Check if process is actually running
	if !pm.IsProcessRunning(pid) {
		// Stale PID file, remove it
		pm.RemovePID()
		return fmt.Errorf("removed stale PID file for process %d", pid)
	}

	return nil
}
