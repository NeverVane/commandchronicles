package updater

// CommandChronicles CLI Updater - Built for Unix Systems Only
//
// "Unix is simple. It just takes a genius to understand its simplicity." - Dennis Ritchie
//
// This updater proudly supports only Unix-based systems (Linux & macOS).
// We believe in the superiority of Unix philosophy and refuse to pollute
// our codebase with inferior operating system support. 🐧🍎
//
// Long live Unix! Down with proprietary bloatware! ⚡

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/NeverVane/commandchronicles/internal/config"
	"github.com/NeverVane/commandchronicles/internal/daemon"
	"github.com/NeverVane/commandchronicles/internal/logger"
)

// UpdateInfo represents information about an available update
type UpdateInfo struct {
	Version     string    `json:"version"`
	DownloadURL string    `json:"download_url"`
	Checksum    string    `json:"checksum"`
	ReleaseDate time.Time `json:"release_date"`
	Changelog   string    `json:"changelog"`
	Critical    bool      `json:"critical"`
	AssetName   string    `json:"asset_name"`
	AssetSize   int64     `json:"asset_size"`
	PreRelease  bool      `json:"pre_release"`
}

// GitHubRelease represents a GitHub release response
type GitHubRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	CreatedAt   time.Time `json:"created_at"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
		ContentType        string `json:"content_type"`
	} `json:"assets"`
}

// Updater handles application updates
type Updater struct {
	config         *config.Config
	logger         *logger.Logger
	currentVersion string
	httpClient     *http.Client
	repoOwner      string
	repoName       string
	githubToken    string // Optional for private repos
}

// UpdaterConfig holds configuration for the updater
type UpdaterConfig struct {
	RepoOwner   string
	RepoName    string
	GithubToken string // Optional for private repos
	Timeout     time.Duration
}

// NewUpdater creates a new updater instance
func NewUpdater(cfg *config.Config, logger *logger.Logger, currentVersion string, updaterConfig UpdaterConfig) *Updater {
	timeout := updaterConfig.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	httpClient := &http.Client{
		Timeout: timeout,
	}

	return &Updater{
		config:         cfg,
		logger:         logger,
		currentVersion: currentVersion,
		httpClient:     httpClient,
		repoOwner:      updaterConfig.RepoOwner,
		repoName:       updaterConfig.RepoName,
		githubToken:    updaterConfig.GithubToken,
	}
}

// CheckForUpdate checks if a new version is available
func (u *Updater) CheckForUpdate(ctx context.Context) (*UpdateInfo, error) {
	u.logger.Debug().Msg("Checking for updates")

	// Get latest release from GitHub
	release, err := u.getLatestRelease(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest release: %w", err)
	}

	// Parse versions
	currentVer, err := semver.NewVersion(u.currentVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid current version '%s': %w", u.currentVersion, err)
	}

	// Clean the tag name (remove 'v' prefix if present)
	latestVersionStr := strings.TrimPrefix(release.TagName, "v")
	latestVer, err := semver.NewVersion(latestVersionStr)
	if err != nil {
		return nil, fmt.Errorf("invalid latest version '%s': %w", latestVersionStr, err)
	}

	// Check if update is needed
	if !latestVer.GreaterThan(currentVer) {
		u.logger.Debug().
			Str("current", currentVer.String()).
			Str("latest", latestVer.String()).
			Msg("No update available")
		return nil, nil // No update available
	}

	// Find appropriate asset for current platform
	asset, err := u.findAssetForPlatform(release)
	if err != nil {
		return nil, fmt.Errorf("failed to find asset for platform: %w", err)
	}

	// Check if this is a critical update (could be determined by release notes keywords)
	critical := u.isCriticalUpdate(release.Body)

	updateInfo := &UpdateInfo{
		Version:     latestVer.String(),
		DownloadURL: asset.BrowserDownloadURL,
		Checksum:    "", // Will be populated if checksum file is found
		ReleaseDate: release.PublishedAt,
		Changelog:   release.Body,
		Critical:    critical,
		AssetName:   asset.Name,
		AssetSize:   asset.Size,
		PreRelease:  release.Prerelease,
	}

	// Try to get checksum if available
	checksum, err := u.getAssetChecksum(ctx, release, asset.Name)
	if err != nil {
		u.logger.Warn().Err(err).Msg("Could not retrieve checksum")
	} else {
		updateInfo.Checksum = checksum
	}

	u.logger.Info().
		Str("current", currentVer.String()).
		Str("latest", latestVer.String()).
		Bool("critical", critical).
		Msg("Update available")

	return updateInfo, nil
}

// Update performs the actual update process
func (u *Updater) Update(ctx context.Context, updateInfo *UpdateInfo) error {
	u.logger.Info().
		Str("version", updateInfo.Version).
		Str("asset", updateInfo.AssetName).
		Msg("Starting update process")

	// Create temporary directory for update
	tempDir, err := os.MkdirTemp("", "ccr-update-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Download the new binary
	downloadPath := filepath.Join(tempDir, updateInfo.AssetName)
	if err := u.downloadBinary(ctx, updateInfo.DownloadURL, downloadPath); err != nil {
		return fmt.Errorf("failed to download binary: %w", err)
	}

	// Verify checksum if available
	if updateInfo.Checksum != "" {
		if err := u.verifyChecksum(downloadPath, updateInfo.Checksum); err != nil {
			return fmt.Errorf("checksum verification failed: %w", err)
		}
	}

	// Replace the current executable
	if err := u.replaceExecutable(downloadPath); err != nil {
		return fmt.Errorf("failed to replace executable: %w", err)
	}

	u.logger.Info().
		Str("version", updateInfo.Version).
		Msg("Update completed successfully")

	// Handle daemon restart if daemon is running
	if err := u.handleDaemonRestart(updateInfo.Version); err != nil {
		// Log warning but don't fail the update - binary is already updated
		u.logger.Warn().Err(err).Msg("Failed to restart daemon, manual restart may be needed")
	}

	return nil
}

// getLatestRelease retrieves the latest release from GitHub
func (u *Updater) getLatestRelease(ctx context.Context) (*GitHubRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", u.repoOwner, u.repoName)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authentication if token is provided
	if u.githubToken != "" {
		req.Header.Set("Authorization", "token "+u.githubToken)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &release, nil
}

// findAssetForPlatform finds the appropriate asset for the current platform
func (u *Updater) findAssetForPlatform(release *GitHubRelease) (*struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
	ContentType        string `json:"content_type"`
}, error) {
	platformName := u.getPlatformName()
	archName := u.getArchName()

	// Look for asset that matches platform and architecture
	for _, asset := range release.Assets {
		if u.matchesPlatform(asset.Name, platformName, archName) {
			return &asset, nil
		}
	}

	return nil, fmt.Errorf("no asset found for platform %s/%s", platformName, archName)
}

// getPlatformName returns the platform name for asset matching (Unix systems only)
func (u *Updater) getPlatformName() string {
	switch runtime.GOOS {
	case "linux":
		return "linux"
	case "darwin":
		return "darwin"
	default:
		return runtime.GOOS
	}
}

// getArchName returns the architecture name for asset matching
func (u *Updater) getArchName() string {
	switch runtime.GOARCH {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	case "386":
		return "386"
	default:
		return runtime.GOARCH
	}
}

// matchesPlatform checks if an asset name matches the current platform
func (u *Updater) matchesPlatform(assetName, platform, arch string) bool {
	name := strings.ToLower(assetName)

	// Check for architecture match first
	if !strings.Contains(name, arch) {
		return false
	}

	// Check for platform match with alternative names
	platformMatches := false

	// Direct platform match
	if strings.Contains(name, platform) {
		platformMatches = true
	}

	// Handle alternative platform names
	switch platform {
	case "darwin":
		if strings.Contains(name, "macos") || strings.Contains(name, "osx") {
			platformMatches = true
		}
	}

	return platformMatches
}

// isCriticalUpdate determines if an update is critical based on release notes
func (u *Updater) isCriticalUpdate(releaseNotes string) bool {
	criticalKeywords := []string{
		"critical", "security", "vulnerability", "urgent", "hotfix",
		"CRITICAL", "SECURITY", "VULNERABILITY", "URGENT", "HOTFIX",
	}

	notes := strings.ToLower(releaseNotes)
	for _, keyword := range criticalKeywords {
		if strings.Contains(notes, strings.ToLower(keyword)) {
			return true
		}
	}

	return false
}

// getAssetChecksum tries to get the checksum for an asset
func (u *Updater) getAssetChecksum(ctx context.Context, release *GitHubRelease, assetName string) (string, error) {
	// Look for checksum files (common patterns)
	checksumFiles := []string{
		"checksums.txt", "checksums.sha256", "SHA256SUMS",
		assetName + ".sha256", assetName + ".checksum",
	}

	for _, checksumFile := range checksumFiles {
		for _, asset := range release.Assets {
			if strings.EqualFold(asset.Name, checksumFile) {
				return u.downloadChecksum(ctx, asset.BrowserDownloadURL, assetName)
			}
		}
	}

	return "", fmt.Errorf("no checksum file found")
}

// downloadChecksum downloads and parses checksum file
func (u *Updater) downloadChecksum(ctx context.Context, url, assetName string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	if u.githubToken != "" {
		req.Header.Set("Authorization", "token "+u.githubToken)
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Parse checksum file to find the hash for our asset
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Handle different checksum formats
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			hash := parts[0]
			filename := parts[1]

			// Remove any leading path separators or asterisks
			filename = strings.TrimPrefix(filename, "./")
			filename = strings.TrimPrefix(filename, "*")

			if strings.Contains(filename, assetName) || strings.Contains(assetName, filename) {
				return hash, nil
			}
		}
	}

	return "", fmt.Errorf("checksum not found for asset %s", assetName)
}

// downloadBinary downloads the binary from the given URL
func (u *Updater) downloadBinary(ctx context.Context, url, destPath string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	if u.githubToken != "" {
		req.Header.Set("Authorization", "token "+u.githubToken)
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	// Make the binary executable (Unix systems only)
	if err := os.Chmod(destPath, 0755); err != nil {
		return fmt.Errorf("failed to make binary executable: %w", err)
	}

	return nil
}

// verifyChecksum verifies the checksum of a downloaded file
func (u *Updater) verifyChecksum(filePath, expectedChecksum string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return err
	}

	actualChecksum := hex.EncodeToString(hasher.Sum(nil))

	if !strings.EqualFold(actualChecksum, expectedChecksum) {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
	}

	return nil
}

// replaceExecutable atomically replaces the current executable with the new one
func (u *Updater) replaceExecutable(newBinaryPath string) error {
	// Get current executable path
	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable path: %w", err)
	}

	// Create backup
	backupPath := currentExe + ".backup"
	if err := u.copyFile(currentExe, backupPath); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	// Ensure cleanup of backup on success
	defer func() {
		if err := os.Remove(backupPath); err != nil {
			u.logger.Warn().Err(err).Msg("Failed to remove backup file")
		}
	}()

	// Use atomic replacement to avoid "text file busy" error
	if err := u.atomicReplaceFile(newBinaryPath, currentExe); err != nil {
		// Restore from backup on failure
		if restoreErr := u.copyFile(backupPath, currentExe); restoreErr != nil {
			u.logger.Error().Err(restoreErr).Msg("Failed to restore backup after update failure")
		}
		return fmt.Errorf("failed to replace executable: %w", err)
	}

	return nil
}

// atomicReplaceFile atomically replaces dst with src using a temporary file and rename
func (u *Updater) atomicReplaceFile(src, dst string) error {
	// Get source file info for permissions
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("failed to stat source file: %w", err)
	}

	// Get destination file info for permissions (if it exists)
	dstInfo, err := os.Stat(dst)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to stat destination file: %w", err)
	}

	// Create a temporary file in the same directory as the destination
	// This ensures the rename operation is atomic (same filesystem)
	tempFile, err := os.CreateTemp(filepath.Dir(dst), filepath.Base(dst)+".tmp.*")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	tempPath := tempFile.Name()

	// Ensure cleanup of temp file on failure
	defer func() {
		tempFile.Close()
		if err := os.Remove(tempPath); err != nil && !os.IsNotExist(err) {
			u.logger.Warn().Err(err).Str("temp_file", tempPath).Msg("Failed to remove temporary file")
		}
	}()

	// Copy source file to temporary file
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	if _, err := io.Copy(tempFile, srcFile); err != nil {
		return fmt.Errorf("failed to copy file content: %w", err)
	}

	// Sync to ensure data is written to disk
	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync temporary file: %w", err)
	}

	// Close temporary file before setting permissions and renaming
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %w", err)
	}

	// Set permissions (prefer destination file permissions, fall back to source)
	var perm os.FileMode = 0755 // Default executable permissions
	if dstInfo != nil {
		perm = dstInfo.Mode()
	} else if srcInfo != nil {
		perm = srcInfo.Mode()
	}

	if err := os.Chmod(tempPath, perm); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	// Atomically replace the destination file
	if err := os.Rename(tempPath, dst); err != nil {
		return fmt.Errorf("failed to rename temporary file: %w", err)
	}

	// If we get here, the rename succeeded, so don't delete the temp file in defer
	tempPath = ""
	return nil
}

// copyFile copies a file from src to dst
func (u *Updater) copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// Get source file info for permissions
	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	// Set the same permissions as the source file
	if err := os.Chmod(dst, srcInfo.Mode()); err != nil {
		return err
	}

	return nil
}

// GetCurrentVersion returns the current version
func (u *Updater) GetCurrentVersion() string {
	return u.currentVersion
}

// SetGithubToken sets the GitHub token for private repositories
func (u *Updater) SetGithubToken(token string) {
	u.githubToken = token
}

// handleDaemonRestart detects and restarts all daemon processes if running
func (u *Updater) handleDaemonRestart(newVersion string) error {
	// Find all running daemon processes (gracefully handles ps unavailability)
	daemonPIDs, err := u.findAllDaemonProcesses()
	if err != nil {
		u.logger.Debug().Err(err).Msg("Could not find daemon processes")
		return nil // No daemons found, nothing to do
	}

	if len(daemonPIDs) == 0 {
		u.logger.Debug().Msg("No daemon processes running, skipping restart")
		return nil
	}

	if len(daemonPIDs) > 1 {
		u.logger.Warn().Int("count", len(daemonPIDs)).Ints("pids", daemonPIDs).Msg("Multiple daemon processes detected, terminating all")
	} else {
		u.logger.Info().Int("pid", daemonPIDs[0]).Msg("Detected running daemon, performing graceful restart")
	}

	// Gracefully shutdown all daemon processes
	for _, pid := range daemonPIDs {
		if err := u.gracefulShutdownDaemon(pid); err != nil {
			u.logger.Warn().Err(err).Int("pid", pid).Msg("Graceful shutdown failed, attempting force termination")
			if err := u.forceKillProcess(pid); err != nil {
				u.logger.Error().Err(err).Int("pid", pid).Msg("Failed to force terminate daemon process")
			}
		}
	}

	// Clean up any stale PID files
	pidFile := filepath.Join(u.config.DataDir, "daemon.pid")
	pidManager := daemon.NewPIDManager(pidFile)
	pidManager.CleanupStalePIDFile()

	// Start new daemon with updated binary
	if err := u.startNewDaemon(); err != nil {
		return fmt.Errorf("failed to start new daemon: %w", err)
	}

	u.logger.Info().Str("version", newVersion).Msg("Daemon successfully restarted with new version")
	return nil
}

// gracefulShutdownDaemon sends SIGTERM and waits for graceful shutdown
func (u *Updater) gracefulShutdownDaemon(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find daemon process %d: %w", pid, err)
	}

	// Send SIGTERM for graceful shutdown
	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to send SIGTERM to daemon: %w", err)
	}

	// Wait for process to exit with timeout
	timeout := time.After(30 * time.Second) // Give daemon time to finish sync
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	pidManager := daemon.NewPIDManager(filepath.Join(u.config.DataDir, "daemon.pid"))

	for {
		select {
		case <-timeout:
			return fmt.Errorf("daemon did not shutdown gracefully within 30 seconds")
		case <-ticker.C:
			if !pidManager.IsProcessRunning(pid) {
				u.logger.Debug().Msg("Daemon stopped gracefully")
				return nil
			}
		}
	}
}

// startNewDaemon starts a new daemon process with the updated binary
func (u *Updater) startNewDaemon() error {
	// Get path to the ccr binary (updated binary)
	ccrBinary, err := u.findCCRBinary()
	if err != nil {
		return fmt.Errorf("failed to find ccr binary: %w", err)
	}

	u.logger.Info().Str("binary", ccrBinary).Msg("Starting new daemon process")

	// Use os.StartProcess for better control
	attr := &os.ProcAttr{
		Files: []*os.File{nil, nil, nil}, // Detach from current process stdio
		Dir:   "",                        // Use current directory
		Sys:   nil,                       // Use default system attributes
	}

	proc, err := os.StartProcess(ccrBinary, []string{ccrBinary, "daemon"}, attr)
	if err != nil {
		return fmt.Errorf("failed to start daemon process with binary %s: %w", ccrBinary, err)
	}

	// Release the process so it can run independently
	proc.Release()

	// Wait and verify daemon started successfully with retries
	pidManager := daemon.NewPIDManager(filepath.Join(u.config.DataDir, "daemon.pid"))

	for i := 0; i < 10; i++ {
		time.Sleep(500 * time.Millisecond)
		if pidManager.IsRunning() {
			u.logger.Info().Int("attempts", i+1).Msg("New daemon started successfully")
			return nil
		}
		u.logger.Debug().Int("attempt", i+1).Msg("Waiting for daemon to start")
	}

	return fmt.Errorf("daemon failed to start within 5 seconds using binary: %s", ccrBinary)
}

// findCCRBinary attempts to find the ccr binary path
func (u *Updater) findCCRBinary() (string, error) {
	// Try common locations for ccr binary
	candidates := []string{
		"/usr/local/bin/ccr", // Most common installation
		"/usr/bin/ccr",       // Alternative system location
		"./ccr",              // Current directory (for testing)
	}

	// First try to get the current executable (works for normal updates)
	if currentExe, err := os.Executable(); err == nil {
		// If we're running from ccr binary itself, use that
		if strings.Contains(currentExe, "ccr") && !strings.Contains(currentExe, "test") {
			candidates = append([]string{currentExe}, candidates...)
		}
	}

	// Test each candidate
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			// Check if it's executable
			if info.Mode()&0111 != 0 {
				u.logger.Debug().Str("binary", candidate).Msg("Found ccr binary")
				return candidate, nil
			}
		}
	}

	return "", fmt.Errorf("ccr binary not found in common locations: %v", candidates)
}

// TestDaemonRestart is a public method for testing daemon restart functionality
func (u *Updater) TestDaemonRestart(testVersion string) error {
	return u.handleDaemonRestart(testVersion)
}

// findAllDaemonProcesses finds all running ccr daemon processes
func (u *Updater) findAllDaemonProcesses() ([]int, error) {
	var allPids []int

	// Method 1 (Primary): Check PID file - most reliable and portable
	pidFile := filepath.Join(u.config.DataDir, "daemon.pid")
	pidManager := daemon.NewPIDManager(pidFile)
	if status, err := pidManager.GetStatus(); err == nil && status.Running {
		allPids = append(allPids, status.PID)
		u.logger.Debug().Int("pid", status.PID).Msg("Found daemon via PID file")
	}

	// Method 2 (Optional): Use ps command for additional detection
	// This is a best-effort attempt - gracefully degrades if ps is unavailable
	if additionalPids := u.findDaemonProcessesViaPS(); len(additionalPids) > 0 {
		for _, pid := range additionalPids {
			// Avoid duplicates from PID file method
			found := false
			for _, existingPID := range allPids {
				if existingPID == pid {
					found = true
					break
				}
			}
			if !found && u.verifyDaemonProcess(pid) {
				allPids = append(allPids, pid)
				u.logger.Debug().Int("pid", pid).Msg("Found additional daemon via ps")
			}
		}
	}

	u.logger.Debug().Int("total_daemons", len(allPids)).Ints("pids", allPids).Msg("Daemon detection completed")
	return allPids, nil
}

// findDaemonProcessesViaPS attempts to find daemon processes using ps command
// Returns empty slice if ps is unavailable or fails - this is a best-effort method
func (u *Updater) findDaemonProcessesViaPS() []int {
	var pids []int

	// Try different ps command locations and syntaxes for portability
	psCommands := []struct {
		path string
		args []string
	}{
		{"/bin/ps", []string{"ps", "aux"}},     // Linux standard
		{"/usr/bin/ps", []string{"ps", "aux"}}, // Alternative location
		{"/bin/ps", []string{"ps", "-ef"}},     // POSIX standard
		{"/usr/bin/ps", []string{"ps", "-ef"}}, // POSIX alternative
	}

	for _, psCmd := range psCommands {
		// Check if ps command exists at this path
		if _, err := os.Stat(psCmd.path); os.IsNotExist(err) {
			continue
		}

		// Try executing ps command
		cmd := &exec.Cmd{
			Path:   psCmd.path,
			Args:   psCmd.args,
			Stdout: &bytes.Buffer{},
			Stderr: &bytes.Buffer{},
		}

		output, err := cmd.Output()
		if err != nil {
			u.logger.Debug().Err(err).Str("ps_path", psCmd.path).Msg("ps command failed, trying next option")
			continue
		}

		// Parse ps output to find ccr daemon processes
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "ccr daemon") && !strings.Contains(line, "grep") {
				fields := strings.Fields(line)
				// Handle different ps output formats
				var pidField int
				if len(fields) >= 2 {
					// Try field 1 first (common for 'ps aux')
					if pid, err := strconv.Atoi(fields[1]); err == nil && pid > 0 {
						pidField = 1
					} else if len(fields) >= 3 {
						// Try field 2 (common for 'ps -ef')
						if pid, err := strconv.Atoi(fields[2]); err == nil && pid > 0 {
							pidField = 2
						}
					}

					if pidField > 0 {
						if pid, err := strconv.Atoi(fields[pidField]); err == nil && pid > 0 {
							pids = append(pids, pid)
						}
					}
				}
			}
		}

		// If we found processes with one ps variant, use those results
		if len(pids) > 0 {
			u.logger.Debug().Str("ps_command", psCmd.path).Int("found_pids", len(pids)).Msg("Successfully used ps for daemon detection")
			break
		}
	}

	if len(pids) == 0 {
		u.logger.Debug().Msg("ps command unavailable or found no additional daemons - relying on PID file method")
	}

	return pids
}

// verifyDaemonProcess verifies that a PID is actually a ccr daemon process
func (u *Updater) verifyDaemonProcess(pid int) bool {
	// Check if process is running
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// Send signal 0 to check if process exists
	if err := process.Signal(syscall.Signal(0)); err != nil {
		return false
	}

	// Additional verification could be added here (e.g., check command line)
	return true
}

// forceKillProcess forcibly terminates a process
func (u *Updater) forceKillProcess(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process %d: %w", pid, err)
	}

	// Send SIGKILL
	if err := process.Signal(syscall.SIGKILL); err != nil {
		return fmt.Errorf("failed to send SIGKILL to process %d: %w", pid, err)
	}

	// Wait briefly for process to exit
	time.Sleep(1 * time.Second)

	pidManager := daemon.NewPIDManager(filepath.Join(u.config.DataDir, "daemon.pid"))
	if pidManager.IsProcessRunning(pid) {
		return fmt.Errorf("process %d still running after SIGKILL", pid)
	}

	return nil
}
