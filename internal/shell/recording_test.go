package shell

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/NeverVane/commandchronicles/internal/config"
	"github.com/NeverVane/commandchronicles/internal/storage"
)

func TestSessionManager_GetCurrentSessionID(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DataDir: tempDir,
	}

	sm, err := NewSessionManager(cfg)
	require.NoError(t, err)

	// Test first call generates new session
	sessionID1, err := sm.GetCurrentSessionID()
	require.NoError(t, err)
	assert.NotEmpty(t, sessionID1)
	assert.Len(t, sessionID1, 36) // UUID length

	// Test second call returns same session
	sessionID2, err := sm.GetCurrentSessionID()
	require.NoError(t, err)
	assert.Equal(t, sessionID1, sessionID2)
}

func TestSessionManager_ValidateSessionID(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DataDir: tempDir,
	}

	sm, err := NewSessionManager(cfg)
	require.NoError(t, err)

	tests := []struct {
		name      string
		sessionID string
		valid     bool
	}{
		{
			name:      "valid UUID",
			sessionID: "550e8400-e29b-41d4-a716-446655440000",
			valid:     true,
		},
		{
			name:      "invalid length",
			sessionID: "550e8400-e29b-41d4-a716-44665544000",
			valid:     false,
		},
		{
			name:      "invalid format",
			sessionID: "550e8400e29b41d4a716446655440000",
			valid:     false,
		},
		{
			name:      "empty string",
			sessionID: "",
			valid:     false,
		},
		{
			name:      "invalid characters",
			sessionID: "550e8400-e29b-41d4-a716-44665544000g",
			valid:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sm.validateSessionID(tt.sessionID)
			assert.Equal(t, tt.valid, result)
		})
	}
}

func TestSessionManager_EndCurrentSession(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DataDir: tempDir,
	}

	sm, err := NewSessionManager(cfg)
	require.NoError(t, err)

	// Generate a session first
	sessionID, err := sm.GetCurrentSessionID()
	require.NoError(t, err)
	assert.NotEmpty(t, sessionID)

	// End the session
	err = sm.EndCurrentSession()
	require.NoError(t, err)

	// Verify session file is removed
	sessionFile := filepath.Join(sm.sessionDir, "current")
	_, err = os.Stat(sessionFile)
	assert.True(t, os.IsNotExist(err))

	// Verify session ID is cleared
	assert.Empty(t, sm.sessionID)
}

func TestContextCapture_EnrichRecord(t *testing.T) {
	tempDir := t.TempDir()
	
	// Create a test git repository
	gitDir := filepath.Join(tempDir, ".git")
	err := os.MkdirAll(gitDir, 0755)
	require.NoError(t, err)

	// Create HEAD file
	headContent := "ref: refs/heads/main"
	err = os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte(headContent), 0644)
	require.NoError(t, err)

	// Create refs/heads/main file
	refsDir := filepath.Join(gitDir, "refs", "heads")
	err = os.MkdirAll(refsDir, 0755)
	require.NoError(t, err)
	
	commitHash := "abcdef1234567890abcdef1234567890abcdef12"
	err = os.WriteFile(filepath.Join(refsDir, "main"), []byte(commitHash), 0644)
	require.NoError(t, err)

	cc := NewContextCapture()
	record := &storage.CommandRecord{
		Command:    "git status",
		WorkingDir: tempDir,
	}

	// Set some environment variables for testing
	originalPath := os.Getenv("PATH")
	os.Setenv("TEST_VAR", "test_value")
	defer func() {
		os.Setenv("PATH", originalPath)
		os.Unsetenv("TEST_VAR")
	}()

	cc.EnrichRecord(record)

	// Verify git context was captured
	assert.Equal(t, tempDir, record.GitRoot)
	assert.Equal(t, "main", record.GitBranch)
	assert.Equal(t, commitHash[:7], record.GitCommit)

	// Verify environment context was captured
	assert.NotNil(t, record.Environment)
	assert.Contains(t, record.Environment, "PATH")
}

func TestContextCapture_FindGitRoot(t *testing.T) {
	tempDir := t.TempDir()
	cc := NewContextCapture()

	// Test case: no git repository
	gitRoot := cc.findGitRoot(tempDir)
	assert.Empty(t, gitRoot)

	// Test case: git repository in current directory
	gitDir := filepath.Join(tempDir, ".git")
	err := os.MkdirAll(gitDir, 0755)
	require.NoError(t, err)

	gitRoot = cc.findGitRoot(tempDir)
	assert.Equal(t, tempDir, gitRoot)

	// Test case: git repository in parent directory
	subDir := filepath.Join(tempDir, "subdir")
	err = os.MkdirAll(subDir, 0755)
	require.NoError(t, err)

	gitRoot = cc.findGitRoot(subDir)
	assert.Equal(t, tempDir, gitRoot)
}

func TestContextCapture_CaptureEnvironmentContext(t *testing.T) {
	cc := NewContextCapture()
	record := &storage.CommandRecord{}

	// Set test environment variables
	os.Setenv("TEST_VAR1", "value1")
	os.Setenv("TEST_VAR2", "value2")
	defer func() {
		os.Unsetenv("TEST_VAR1")
		os.Unsetenv("TEST_VAR2")
	}()

	cc.captureEnvironmentContext(record)

	// Should have captured some environment variables
	assert.NotNil(t, record.Environment)
	
	// Should include common environment variables if they exist
	if path := os.Getenv("PATH"); path != "" {
		assert.Contains(t, record.Environment, "PATH")
	}
	if home := os.Getenv("HOME"); home != "" {
		assert.Contains(t, record.Environment, "HOME")
	}
}

func TestHookManager_GenerateBashHooks(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DataDir: tempDir,
		Shell: config.ShellConfig{
			BashHookPath: filepath.Join(tempDir, "hooks", "bash_hooks.sh"),
		},
	}

	hm, err := NewHookManager(cfg)
	require.NoError(t, err)

	hookContent, err := hm.generateBashHooks()
	require.NoError(t, err)

	// Verify hook content contains expected elements
	assert.Contains(t, hookContent, "__ccr_preexec")
	assert.Contains(t, hookContent, "__ccr_postexec")
	assert.Contains(t, hookContent, "trap '__ccr_preexec' DEBUG")
	assert.Contains(t, hookContent, "PROMPT_COMMAND")
	assert.Contains(t, hookContent, hm.binaryPath)
}

func TestHookManager_GenerateZshHooks(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DataDir: tempDir,
		Shell: config.ShellConfig{
			ZshHookPath: filepath.Join(tempDir, "hooks", "zsh_hooks.sh"),
		},
	}

	hm, err := NewHookManager(cfg)
	require.NoError(t, err)

	hookContent, err := hm.generateZshHooks()
	require.NoError(t, err)

	// Verify hook content contains expected elements
	assert.Contains(t, hookContent, "__ccr_preexec")
	assert.Contains(t, hookContent, "__ccr_precmd")
	assert.Contains(t, hookContent, "add-zsh-hook preexec")
	assert.Contains(t, hookContent, "add-zsh-hook precmd")
	assert.Contains(t, hookContent, hm.binaryPath)
}

func TestHookManager_InstallHooks(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DataDir: tempDir,
		Shell: config.ShellConfig{
			BashHookPath: filepath.Join(tempDir, "hooks", "bash_hooks.sh"),
			ZshHookPath:  filepath.Join(tempDir, "hooks", "zsh_hooks.sh"),
		},
	}

	hm, err := NewHookManager(cfg)
	require.NoError(t, err)

	// Test bash hook installation
	err = hm.InstallHooks("bash")
	require.NoError(t, err)

	bashHookPath := hm.GetHookPath("bash")
	assert.FileExists(t, bashHookPath)

	content, err := os.ReadFile(bashHookPath)
	require.NoError(t, err)
	assert.Contains(t, string(content), "__ccr_preexec")

	// Test zsh hook installation
	err = hm.InstallHooks("zsh")
	require.NoError(t, err)

	zshHookPath := hm.GetHookPath("zsh")
	assert.FileExists(t, zshHookPath)

	content, err = os.ReadFile(zshHookPath)
	require.NoError(t, err)
	assert.Contains(t, string(content), "__ccr_precmd")

	// Test unsupported shell
	err = hm.InstallHooks("fish")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported shell")
}

func TestHookManager_GenerateInstallInstructions(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DataDir: tempDir,
		Shell: config.ShellConfig{
			BashHookPath: filepath.Join(tempDir, "hooks", "bash_hooks.sh"),
			ZshHookPath:  filepath.Join(tempDir, "hooks", "zsh_hooks.sh"),
		},
	}

	hm, err := NewHookManager(cfg)
	require.NoError(t, err)

	// Test bash instructions
	bashInstructions := hm.GenerateInstallInstructions("bash")
	assert.Contains(t, bashInstructions, "~/.bashrc")
	assert.Contains(t, bashInstructions, "source")
	assert.Contains(t, bashInstructions, cfg.Shell.BashHookPath)

	// Test zsh instructions
	zshInstructions := hm.GenerateInstallInstructions("zsh")
	assert.Contains(t, zshInstructions, "~/.zshrc")
	assert.Contains(t, zshInstructions, "source")
	assert.Contains(t, zshInstructions, cfg.Shell.ZshHookPath)

	// Test unsupported shell
	unsupportedInstructions := hm.GenerateInstallInstructions("fish")
	assert.Contains(t, unsupportedInstructions, "not supported")
}

func TestGenerateUUID(t *testing.T) {
	uuid1 := generateUUID()
	uuid2 := generateUUID()

	// UUIDs should be different
	assert.NotEqual(t, uuid1, uuid2)

	// UUIDs should be valid format
	assert.Len(t, uuid1, 36)
	assert.Len(t, uuid2, 36)

	// Should contain 4 hyphens
	assert.Equal(t, 4, strings.Count(uuid1, "-"))
	assert.Equal(t, 4, strings.Count(uuid2, "-"))

	// Should have correct structure (8-4-4-4-12)
	parts1 := strings.Split(uuid1, "-")
	assert.Len(t, parts1, 5)
	assert.Len(t, parts1[0], 8)
	assert.Len(t, parts1[1], 4)
	assert.Len(t, parts1[2], 4)
	assert.Len(t, parts1[3], 4)
	assert.Len(t, parts1[4], 12)
}

func TestSessionManager_GetSessionInfo(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DataDir: tempDir,
	}

	sm, err := NewSessionManager(cfg)
	require.NoError(t, err)

	// Test without session
	info := sm.GetSessionInfo()
	assert.Empty(t, info["session_id"])

	// Test with session
	sessionID, err := sm.GetCurrentSessionID()
	require.NoError(t, err)

	info = sm.GetSessionInfo()
	assert.Equal(t, sessionID, info["session_id"])
	assert.Contains(t, info, "session_start")
}

func TestContextCapture_Performance(t *testing.T) {
	tempDir := t.TempDir()
	cc := NewContextCapture()
	
	record := &storage.CommandRecord{
		Command:    "echo test",
		WorkingDir: tempDir,
	}

	// Measure enrichment time
	start := time.Now()
	cc.EnrichRecord(record)
	duration := time.Since(start)

	// Should complete within reasonable time (much less than 10ms requirement)
	assert.Less(t, duration, 10*time.Millisecond)
}

func BenchmarkContextCapture_EnrichRecord(b *testing.B) {
	tempDir := b.TempDir()
	cc := NewContextCapture()
	
	record := &storage.CommandRecord{
		Command:    "echo test",
		WorkingDir: tempDir,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Create a fresh record for each iteration
		testRecord := *record
		cc.EnrichRecord(&testRecord)
	}
}

func BenchmarkSessionManager_GetCurrentSessionID(b *testing.B) {
	tempDir := b.TempDir()
	cfg := &config.Config{
		DataDir: tempDir,
	}

	sm, _ := NewSessionManager(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sm.GetCurrentSessionID()
	}
}

func BenchmarkGenerateUUID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = generateUUID()
	}
}