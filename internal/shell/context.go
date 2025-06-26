package shell

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/NeverVane/commandchronicles-cli/internal/logger"
	"github.com/NeverVane/commandchronicles-cli/internal/storage"
)

// ContextCapture handles capturing rich context for command records
type ContextCapture struct {
	logger *logger.Logger
}

// NewContextCapture creates a new context capture instance
func NewContextCapture() *ContextCapture {
	return &ContextCapture{
		logger: logger.GetLogger().WithComponent("context"),
	}
}

// EnrichRecord enriches a command record with additional context
func (cc *ContextCapture) EnrichRecord(record *storage.CommandRecord) {
	start := time.Now()
	
	// Capture git context
	cc.captureGitContext(record)
	
	// Capture environment context
	cc.captureEnvironmentContext(record)
	
	// Capture TTY info
	record.TTY = os.Getenv("TTY")
	if record.TTY == "" {
		if tty := os.Getenv("SSH_TTY"); tty != "" {
			record.TTY = tty
		}
	}
	
	duration := time.Since(start)
	if duration > 5*time.Millisecond {
		cc.logger.WithField("duration_ms", duration.Milliseconds()).
			Warn().Msg("Context capture took longer than expected")
	}
}

// captureGitContext captures git repository information
func (cc *ContextCapture) captureGitContext(record *storage.CommandRecord) {
	gitRoot := cc.findGitRoot(record.WorkingDir)
	if gitRoot == "" {
		return
	}
	
	record.GitRoot = gitRoot
	record.GitBranch = cc.getGitBranch(gitRoot)
	record.GitCommit = cc.getGitCommit(gitRoot)
}

// captureEnvironmentContext captures relevant environment variables
func (cc *ContextCapture) captureEnvironmentContext(record *storage.CommandRecord) {
	// List of environment variables that might be relevant for context
	relevantVars := []string{
		"PATH",
		"HOME",
		"USER",
		"USERNAME",
		"SHELL",
		"TERM",
		"LANG",
		"LC_ALL",
		"SSH_CLIENT",
		"SSH_CONNECTION",
		"DISPLAY",
		"XDG_SESSION_TYPE",
		"VIRTUAL_ENV",
		"CONDA_DEFAULT_ENV",
		"NODE_ENV",
		"RAILS_ENV",
		"GOPATH",
		"GOROOT",
		"JAVA_HOME",
		"PYTHON_PATH",
		"RUST_LOG",
		"DEBUG",
	}
	
	env := make(map[string]string)
	totalSize := 0
	maxSize := 8192 // Max 8KB for environment data
	
	for _, varName := range relevantVars {
		if value := os.Getenv(varName); value != "" {
			// Check size constraints
			entrySize := len(varName) + len(value) + 2 // +2 for key=value structure
			if totalSize+entrySize > maxSize {
				break
			}
			
			// Truncate very long values
			if len(value) > 1024 {
				value = value[:1021] + "..."
			}
			
			env[varName] = value
			totalSize += entrySize
			
			// Limit number of environment variables
			if len(env) >= 50 {
				break
			}
		}
	}
	
	if len(env) > 0 {
		record.Environment = env
	}
}

// findGitRoot finds the git repository root directory
func (cc *ContextCapture) findGitRoot(startDir string) string {
	dir := startDir
	maxDepth := 10 // Prevent infinite loops
	
	for depth := 0; depth < maxDepth; depth++ {
		gitDir := filepath.Join(dir, ".git")
		if stat, err := os.Stat(gitDir); err == nil {
			if stat.IsDir() {
				return dir
			}
			// Handle .git files (worktrees, submodules)
			if content, err := os.ReadFile(gitDir); err == nil {
				gitDirContent := strings.TrimSpace(string(content))
				if strings.HasPrefix(gitDirContent, "gitdir: ") {
					// This is a git worktree or submodule
					return dir
				}
			}
		}
		
		parent := filepath.Dir(dir)
		if parent == dir {
			break // Reached filesystem root
		}
		dir = parent
	}
	return ""
}

// getGitBranch gets the current git branch
func (cc *ContextCapture) getGitBranch(gitRoot string) string {
	// Try reading HEAD file first (fastest method)
	headFile := filepath.Join(gitRoot, ".git", "HEAD")
	if content, err := os.ReadFile(headFile); err == nil {
		head := strings.TrimSpace(string(content))
		if strings.HasPrefix(head, "ref: refs/heads/") {
			return strings.TrimPrefix(head, "ref: refs/heads/")
		}
	}
	
	// Fallback to git command (slower but more reliable)
	return cc.runGitCommand(gitRoot, "rev-parse", "--abbrev-ref", "HEAD")
}

// getGitCommit gets the current git commit hash (short)
func (cc *ContextCapture) getGitCommit(gitRoot string) string {
	// Try reading HEAD file first
	headFile := filepath.Join(gitRoot, ".git", "HEAD")
	if content, err := os.ReadFile(headFile); err == nil {
		head := strings.TrimSpace(string(content))
		if strings.HasPrefix(head, "ref: ") {
			// It's a reference, read the ref file
			refPath := strings.TrimPrefix(head, "ref: ")
			refFile := filepath.Join(gitRoot, ".git", refPath)
			if refContent, err := os.ReadFile(refFile); err == nil {
				commit := strings.TrimSpace(string(refContent))
				if len(commit) >= 7 {
					return commit[:7] // Return short hash
				}
			}
		} else if len(head) >= 7 {
			// It's a direct commit hash (detached HEAD)
			return head[:7]
		}
	}
	
	// Fallback to git command
	return cc.runGitCommand(gitRoot, "rev-parse", "--short", "HEAD")
}

// runGitCommand runs a git command with timeout
func (cc *ContextCapture) runGitCommand(gitRoot string, args ...string) string {
	ctx := exec.Command("git", args...)
	ctx.Dir = gitRoot
	
	// Set a short timeout to avoid blocking shell execution
	done := make(chan struct{})
	var output []byte
	var err error
	
	go func() {
		defer close(done)
		output, err = ctx.Output()
	}()
	
	// Wait for command or timeout
	select {
	case <-done:
		if err != nil {
			return ""
		}
		result := strings.TrimSpace(string(output))
		// Limit output length
		if len(result) > 256 {
			result = result[:256]
		}
		return result
	case <-time.After(100 * time.Millisecond):
		// Kill the process if it takes too long
		if ctx.Process != nil {
			ctx.Process.Kill()
		}
		cc.logger.Warn().Msg("Git command timed out")
		return ""
	}
}

// GetWorkingDirectoryInfo returns additional working directory context
func (cc *ContextCapture) GetWorkingDirectoryInfo(workingDir string) map[string]interface{} {
	info := make(map[string]interface{})
	
	// Check if it's a symbolic link
	if linkTarget, err := os.Readlink(workingDir); err == nil {
		info["symlink_target"] = linkTarget
	}
	
	// Check directory permissions
	if stat, err := os.Stat(workingDir); err == nil {
		info["permissions"] = stat.Mode().String()
	}
	
	// Check if it's a mounted filesystem
	if mountPoint := cc.findMountPoint(workingDir); mountPoint != "" && mountPoint != "/" {
		info["mount_point"] = mountPoint
	}
	
	return info
}

// findMountPoint finds the mount point for a directory (Unix-specific)
func (cc *ContextCapture) findMountPoint(dir string) string {
	// This is a simplified implementation
	// In a production system, you might want to parse /proc/mounts
	for {
		parent := filepath.Dir(dir)
		if parent == dir {
			return dir // Root directory
		}
		
		// Check if crossing filesystem boundary
		dirStat, err1 := os.Stat(dir)
		parentStat, err2 := os.Stat(parent)
		
		if err1 != nil || err2 != nil {
			break
		}
		
		// Compare device IDs (this is platform-specific)
		// This is a simplified check that may not work on all systems
		if dirStat.Sys() != parentStat.Sys() {
			return dir
		}
		
		dir = parent
	}
	
	return ""
}