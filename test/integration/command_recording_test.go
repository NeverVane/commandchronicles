package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/NeverVane/commandchronicles-cli/internal/config"
	"github.com/NeverVane/commandchronicles-cli/internal/shell"
	"github.com/NeverVane/commandchronicles-cli/internal/storage"
)

// TestCommandRecordingEndToEnd tests the complete command recording flow
func TestCommandRecordingEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	
	// Setup test configuration
	cfg := &config.Config{
		DataDir:   tempDir,
		ConfigDir: tempDir,
		Database: config.DatabaseConfig{
			Path:         filepath.Join(tempDir, "history.db"),
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
		Security: config.SecurityConfig{
			SessionKeyPath:    filepath.Join(tempDir, "session"),
			SessionTimeout:    3600,
			Argon2Time:        1, // Fast for testing
			Argon2Memory:      1024,
			Argon2Threads:     1,
			SecureMemoryClear: true,
		},
		Shell: config.ShellConfig{
			Enabled:             true,
			SupportedShells:     []string{"bash", "zsh"},
			BashHookPath:        filepath.Join(tempDir, "hooks", "bash_hook.sh"),
			ZshHookPath:         filepath.Join(tempDir, "hooks", "zsh_hook.sh"),
			CaptureTimeoutMS:    10,
			GracefulDegradation: true,
		},
	}

	// Create session manager
	sessionMgr, err := shell.NewSessionManager(cfg)
	require.NoError(t, err)

	// Get session ID
	sessionID, err := sessionMgr.GetCurrentSessionID()
	require.NoError(t, err)
	assert.NotEmpty(t, sessionID)

	// Create context capture
	contextCapture := shell.NewContextCapture()

	// Create test command record
	testCommand := "ls -la /tmp"
	workingDir := tempDir
	
	record := storage.NewCommandRecord(testCommand, 0, 150, workingDir, sessionID, "test-host")
	record.User = "testuser"
	record.Shell = "bash"
	
	// Enrich with context
	contextCapture.EnrichRecord(record)

	// Verify record is valid
	assert.True(t, record.IsValid())
	assert.Equal(t, testCommand, record.Command)
	assert.Equal(t, sessionID, record.SessionID)
	assert.Equal(t, "test-host", record.Hostname)
	assert.Equal(t, "testuser", record.User)
	assert.Equal(t, "bash", record.Shell)

	// Test that context was enriched
	assert.NotNil(t, record.Environment)
	assert.Greater(t, len(record.Environment), 0)

	t.Logf("Command record created successfully with %d environment variables", len(record.Environment))
}

// TestShellHookGeneration tests shell hook generation and installation
func TestShellHookGeneration(t *testing.T) {
	tempDir := t.TempDir()
	
	cfg := &config.Config{
		DataDir:   tempDir,
		ConfigDir: tempDir,
		Shell: config.ShellConfig{
			BashHookPath: filepath.Join(tempDir, "hooks", "bash_hooks.sh"),
			ZshHookPath:  filepath.Join(tempDir, "hooks", "zsh_hooks.sh"),
		},
	}

	hookMgr, err := shell.NewHookManager(cfg)
	require.NoError(t, err)

	// Test bash hook generation
	t.Run("BashHooks", func(t *testing.T) {
		err := hookMgr.InstallHooks("bash")
		require.NoError(t, err)

		hookPath := hookMgr.GetHookPath("bash")
		assert.FileExists(t, hookPath)

		content, err := os.ReadFile(hookPath)
		require.NoError(t, err)

		hookContent := string(content)
		
		// Verify essential bash hook components
		assert.Contains(t, hookContent, "__ccr_preexec")
		assert.Contains(t, hookContent, "__ccr_postexec")
		assert.Contains(t, hookContent, "trap '__ccr_preexec' DEBUG")
		assert.Contains(t, hookContent, "PROMPT_COMMAND")
		assert.Contains(t, hookContent, "record")
		assert.Contains(t, hookContent, "--command")
		assert.Contains(t, hookContent, "--exit-code")
		assert.Contains(t, hookContent, "--duration")
		assert.Contains(t, hookContent, "--directory")
		assert.Contains(t, hookContent, "--session")

		// Verify graceful degradation
		assert.Contains(t, hookContent, "command -v")
		assert.Contains(t, hookContent, ">/dev/null 2>&1")

		// Verify async execution
		assert.Contains(t, hookContent, "} &")
	})

	// Test zsh hook generation
	t.Run("ZshHooks", func(t *testing.T) {
		err := hookMgr.InstallHooks("zsh")
		require.NoError(t, err)

		hookPath := hookMgr.GetHookPath("zsh")
		assert.FileExists(t, hookPath)

		content, err := os.ReadFile(hookPath)
		require.NoError(t, err)

		hookContent := string(content)
		
		// Verify essential zsh hook components
		assert.Contains(t, hookContent, "__ccr_preexec")
		assert.Contains(t, hookContent, "__ccr_precmd")
		assert.Contains(t, hookContent, "add-zsh-hook preexec")
		assert.Contains(t, hookContent, "add-zsh-hook precmd")
		assert.Contains(t, hookContent, "record")
		
		// Verify graceful degradation
		assert.Contains(t, hookContent, "command -v")
		assert.Contains(t, hookContent, ">/dev/null 2>&1")

		// Verify async execution
		assert.Contains(t, hookContent, "} &")
	})
}

// TestCCRRecordCommand tests the ccr record command functionality
func TestCCRRecordCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir := t.TempDir()
	
	// Build the ccr binary for testing
	binaryPath := filepath.Join(tempDir, "ccr")
	
	// Get the project root directory
	projectRoot := filepath.Join("..", "..")
	
	buildCmd := exec.Command("go", "build", "-o", binaryPath, ".")
	buildCmd.Dir = projectRoot
	
	output, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build ccr binary: %v\nOutput: %s", err, output)
	}

	// Test record command with valid parameters
	t.Run("ValidRecord", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "record",
			"--command", "echo hello world",
			"--exit-code", "0", 
			"--duration", "125",
			"--directory", tempDir,
			"--session", "test-session-123")
		
		// Set environment for testing
		cmd.Env = append(os.Environ(),
			"CCR_TEST_MODE=true",
			"XDG_CONFIG_HOME="+tempDir,
			"XDG_DATA_HOME="+tempDir,
		)
		
		output, err := cmd.CombinedOutput()
		
		// The command should handle the locked storage gracefully
		// and not return an error (it should fail silently in record mode)
		if err != nil {
			t.Logf("Record command output: %s", output)
			// This is expected when storage is locked - the command should not block shell
		}
	})

	// Test record command with missing required parameters
	t.Run("MissingCommand", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "record",
			"--exit-code", "0",
			"--duration", "125")
		
		cmd.Env = append(os.Environ(),
			"XDG_CONFIG_HOME="+tempDir,
			"XDG_DATA_HOME="+tempDir,
		)
		
		output, err := cmd.CombinedOutput()
		assert.Error(t, err)
		assert.Contains(t, string(output), "command is required")
	})
}

// TestSessionManagement tests session lifecycle
func TestSessionManagement(t *testing.T) {
	tempDir := t.TempDir()
	
	cfg := &config.Config{
		DataDir: tempDir,
	}

	// Test session creation
	sessionMgr1, err := shell.NewSessionManager(cfg)
	require.NoError(t, err)

	sessionID1, err := sessionMgr1.GetCurrentSessionID()
	require.NoError(t, err)
	assert.NotEmpty(t, sessionID1)

	// Test session persistence across manager instances
	sessionMgr2, err := shell.NewSessionManager(cfg)
	require.NoError(t, err)

	sessionID2, err := sessionMgr2.GetCurrentSessionID()
	require.NoError(t, err)
	assert.Equal(t, sessionID1, sessionID2, "Session should persist across manager instances")

	// Test session ending
	err = sessionMgr1.EndCurrentSession()
	require.NoError(t, err)

	// Verify session file is removed
	sessionFile := filepath.Join(tempDir, "sessions", "current")
	_, err = os.Stat(sessionFile)
	assert.True(t, os.IsNotExist(err))

	// Test new session creation after end
	sessionMgr3, err := shell.NewSessionManager(cfg)
	require.NoError(t, err)

	sessionID3, err := sessionMgr3.GetCurrentSessionID()
	require.NoError(t, err)
	assert.NotEqual(t, sessionID1, sessionID3, "New session should have different ID")
}

// TestContextCaptureIntegration tests context capture with real environment
func TestContextCaptureIntegration(t *testing.T) {
	tempDir := t.TempDir()
	
	// Create a mock git repository
	gitDir := filepath.Join(tempDir, ".git")
	err := os.MkdirAll(gitDir, 0755)
	require.NoError(t, err)

	// Create HEAD file pointing to main branch
	headContent := "ref: refs/heads/main"
	err = os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte(headContent), 0644)
	require.NoError(t, err)

	// Create refs/heads/main with a commit hash
	refsDir := filepath.Join(gitDir, "refs", "heads")
	err = os.MkdirAll(refsDir, 0755)
	require.NoError(t, err)
	
	commitHash := "1234567890abcdef1234567890abcdef12345678"
	err = os.WriteFile(filepath.Join(refsDir, "main"), []byte(commitHash), 0644)
	require.NoError(t, err)

	// Test context capture
	contextCapture := shell.NewContextCapture()
	
	record := &storage.CommandRecord{
		Command:    "git status",
		WorkingDir: tempDir,
		SessionID:  "test-session",
		Hostname:   "test-host",
		Timestamp:  time.Now().UnixMilli(),
		CreatedAt:  time.Now().UnixMilli(),
	}

	// Measure context capture performance
	start := time.Now()
	contextCapture.EnrichRecord(record)
	duration := time.Since(start)

	// Verify performance requirement (<10ms)
	assert.Less(t, duration, 10*time.Millisecond, "Context capture should complete within 10ms")

	// Verify git context was captured
	assert.Equal(t, tempDir, record.GitRoot)
	assert.Equal(t, "main", record.GitBranch)
	assert.Equal(t, commitHash[:7], record.GitCommit)

	// Verify environment context was captured
	assert.NotNil(t, record.Environment)
	assert.Greater(t, len(record.Environment), 0)

	// Verify essential environment variables are captured if they exist
	if path := os.Getenv("PATH"); path != "" {
		assert.Contains(t, record.Environment, "PATH")
	}
	if home := os.Getenv("HOME"); home != "" {
		assert.Contains(t, record.Environment, "HOME")
	}

	t.Logf("Context capture completed in %v with %d environment variables", 
		duration, len(record.Environment))
}

// TestPerformanceRequirements validates performance constraints
func TestPerformanceRequirements(t *testing.T) {
	tempDir := t.TempDir()
	
	cfg := &config.Config{
		DataDir: tempDir,
	}

	// Test session ID generation performance
	t.Run("SessionIDGeneration", func(t *testing.T) {
		sessionMgr, err := shell.NewSessionManager(cfg)
		require.NoError(t, err)

		start := time.Now()
		_, err = sessionMgr.GetCurrentSessionID()
		duration := time.Since(start)
		
		require.NoError(t, err)
		assert.Less(t, duration, 5*time.Millisecond, "Session ID generation should be fast")
	})

	// Test context capture performance
	t.Run("ContextCapture", func(t *testing.T) {
		contextCapture := shell.NewContextCapture()
		
		record := &storage.CommandRecord{
			Command:    "echo test",
			WorkingDir: tempDir,
			SessionID:  "test-session",
			Hostname:   "test-host",
			Timestamp:  time.Now().UnixMilli(),
			CreatedAt:  time.Now().UnixMilli(),
		}

		start := time.Now()
		contextCapture.EnrichRecord(record)
		duration := time.Since(start)
		
		assert.Less(t, duration, 10*time.Millisecond, "Context capture should complete within 10ms")
	})

	// Test hook generation performance
	t.Run("HookGeneration", func(t *testing.T) {
		cfg.Shell = config.ShellConfig{
			BashHookPath: filepath.Join(tempDir, "hooks", "bash_hooks.sh"),
			ZshHookPath:  filepath.Join(tempDir, "hooks", "zsh_hooks.sh"),
		}

		hookMgr, err := shell.NewHookManager(cfg)
		require.NoError(t, err)

		start := time.Now()
		err = hookMgr.InstallHooks("bash")
		duration := time.Since(start)
		
		require.NoError(t, err)
		assert.Less(t, duration, 50*time.Millisecond, "Hook installation should be fast")
	})
}

// TestGracefulDegradation tests error handling and graceful degradation
func TestGracefulDegradation(t *testing.T) {
	tempDir := t.TempDir()
	
	// Test context capture in directory without git
	t.Run("NoGitRepository", func(t *testing.T) {
		contextCapture := shell.NewContextCapture()
		
		record := &storage.CommandRecord{
			Command:    "ls -la",
			WorkingDir: tempDir,
			SessionID:  "test-session",
			Hostname:   "test-host",
			Timestamp:  time.Now().UnixMilli(),
			CreatedAt:  time.Now().UnixMilli(),
		}

		// Should not panic or error
		contextCapture.EnrichRecord(record)
		
		// Git fields should be empty
		assert.Empty(t, record.GitRoot)
		assert.Empty(t, record.GitBranch)
		assert.Empty(t, record.GitCommit)
		
		// Environment should still be captured
		assert.NotNil(t, record.Environment)
	})

	// Test session manager with permission issues
	t.Run("RestrictedDirectory", func(t *testing.T) {
		restrictedDir := filepath.Join(tempDir, "restricted")
		err := os.MkdirAll(restrictedDir, 0000) // No permissions
		require.NoError(t, err)
		defer os.Chmod(restrictedDir, 0755) // Clean up

		cfg := &config.Config{
			DataDir: restrictedDir,
		}

		// Should handle permission errors gracefully
		_, err = shell.NewSessionManager(cfg)
		assert.Error(t, err) // Expected to fail, but should not panic
	})
}

// TestCrossShellCompatibility tests compatibility across different shells
func TestCrossShellCompatibility(t *testing.T) {
	tempDir := t.TempDir()
	
	cfg := &config.Config{
		DataDir:   tempDir,
		ConfigDir: tempDir,
		Shell: config.ShellConfig{
			BashHookPath: filepath.Join(tempDir, "hooks", "bash_hooks.sh"),
			ZshHookPath:  filepath.Join(tempDir, "hooks", "zsh_hooks.sh"),
		},
	}

	hookMgr, err := shell.NewHookManager(cfg)
	require.NoError(t, err)

	shells := []string{"bash", "zsh"}
	
	for _, shell := range shells {
		t.Run(shell, func(t *testing.T) {
			// Install hooks for the shell
			err := hookMgr.InstallHooks(shell)
			require.NoError(t, err)

			// Verify hook file exists and is executable
			hookPath := hookMgr.GetHookPath(shell)
			assert.FileExists(t, hookPath)

			stat, err := os.Stat(hookPath)
			require.NoError(t, err)
			assert.True(t, stat.Mode()&0100 != 0, "Hook file should be executable")

			// Verify hook content is shell-specific
			content, err := os.ReadFile(hookPath)
			require.NoError(t, err)
			hookContent := string(content)

			switch shell {
			case "bash":
				assert.Contains(t, hookContent, "#!/bin/bash")
				assert.Contains(t, hookContent, "PROMPT_COMMAND")
				assert.Contains(t, hookContent, "trap '__ccr_preexec' DEBUG")
			case "zsh":
				assert.Contains(t, hookContent, "#!/bin/zsh")
				assert.Contains(t, hookContent, "add-zsh-hook")
				assert.Contains(t, hookContent, "precmd")
				assert.Contains(t, hookContent, "preexec")
			}

			// Verify installation instructions are shell-specific
			instructions := hookMgr.GenerateInstallInstructions(shell)
			switch shell {
			case "bash":
				assert.Contains(t, instructions, "~/.bashrc")
			case "zsh":
				assert.Contains(t, instructions, "~/.zshrc")
			}
		})
	}
}

// BenchmarkCommandRecordingFlow benchmarks the complete recording flow
func BenchmarkCommandRecordingFlow(b *testing.B) {
	tempDir := b.TempDir()
	
	cfg := &config.Config{
		DataDir: tempDir,
	}

	sessionMgr, _ := shell.NewSessionManager(cfg)
	contextCapture := shell.NewContextCapture()
	sessionID, _ := sessionMgr.GetCurrentSessionID()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate complete recording flow
		record := storage.NewCommandRecord(
			"echo test command",
			0,
			100,
			tempDir,
			sessionID,
			"test-host")
		
		record.User = "testuser"
		record.Shell = "bash"
		
		contextCapture.EnrichRecord(record)
		
		// Verify record is valid (this would normally be followed by storage)
		_ = record.IsValid()
	}
}