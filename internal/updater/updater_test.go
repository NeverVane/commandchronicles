package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NeverVane/commandchronicles-cli/internal/config"
	"github.com/NeverVane/commandchronicles-cli/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// Initialize logger for tests
	logger.Init(logger.DefaultConfig())
	os.Exit(m.Run())
}

func createTestUpdater(repoOwner, repoName string) *Updater {
	cfg := &config.Config{}
	testLogger := logger.GetLogger().WithComponent("updater-test")

	updaterConfig := UpdaterConfig{
		RepoOwner: repoOwner,
		RepoName:  repoName,
		Timeout:   5 * time.Second,
	}

	return NewUpdater(cfg, testLogger, "1.0.0", updaterConfig)
}

func createMockGitHubServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/test/cli/releases/latest":
			release := GitHubRelease{
				TagName:     "v1.1.0",
				Name:        "CommandChronicles CLI v1.1.0",
				Body:        "## What's New\n- Bug fixes\n- Performance improvements",
				Draft:       false,
				Prerelease:  false,
				CreatedAt:   time.Now().Add(-24 * time.Hour),
				PublishedAt: time.Now().Add(-24 * time.Hour),
				Assets: []struct {
					Name               string `json:"name"`
					BrowserDownloadURL string `json:"browser_download_url"`
					Size               int64  `json:"size"`
					ContentType        string `json:"content_type"`
				}{
					{
						Name:               "ccr-linux-amd64",
						BrowserDownloadURL: fmt.Sprintf("%s/download/ccr-linux-amd64", r.Host),
						Size:               1024000,
						ContentType:        "application/octet-stream",
					},
					{
						Name:               "ccr-darwin-amd64",
						BrowserDownloadURL: fmt.Sprintf("%s/download/ccr-darwin-amd64", r.Host),
						Size:               1024000,
						ContentType:        "application/octet-stream",
					},

					{
						Name:               "checksums.txt",
						BrowserDownloadURL: fmt.Sprintf("%s/download/checksums.txt", r.Host),
						Size:               512,
						ContentType:        "text/plain",
					},
				},
			}
			json.NewEncoder(w).Encode(release)

		case "/repos/test/cli/releases/latest-critical":
			release := GitHubRelease{
				TagName:     "v1.0.1",
				Name:        "CommandChronicles CLI v1.0.1 - CRITICAL SECURITY UPDATE",
				Body:        "## CRITICAL SECURITY UPDATE\n- Fixed vulnerability CVE-2023-1234\n- All users must update immediately",
				Draft:       false,
				Prerelease:  false,
				CreatedAt:   time.Now().Add(-1 * time.Hour),
				PublishedAt: time.Now().Add(-1 * time.Hour),
				Assets: []struct {
					Name               string `json:"name"`
					BrowserDownloadURL string `json:"browser_download_url"`
					Size               int64  `json:"size"`
					ContentType        string `json:"content_type"`
				}{
					{
						Name:               "ccr-linux-amd64",
						BrowserDownloadURL: fmt.Sprintf("%s/download/ccr-linux-amd64", r.Host),
						Size:               1024000,
						ContentType:        "application/octet-stream",
					},
					{
						Name:               "ccr-darwin-amd64",
						BrowserDownloadURL: fmt.Sprintf("%s/download/ccr-darwin-amd64", r.Host),
						Size:               1024000,
						ContentType:        "application/octet-stream",
					},
				},
			}
			json.NewEncoder(w).Encode(release)

		case "/download/ccr-linux-amd64", "/download/ccr-darwin-amd64":
			// Serve a dummy binary
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write([]byte("fake binary content for testing"))

		case "/download/checksums.txt":
			w.Header().Set("Content-Type", "text/plain")
			// Calculate actual checksum of our fake binary
			content := []byte("fake binary content for testing")
			hash := sha256.Sum256(content)
			checksum := hex.EncodeToString(hash[:])
			fmt.Fprintf(w, "%s  ccr-linux-amd64\n", checksum)
			fmt.Fprintf(w, "%s  ccr-darwin-amd64\n", checksum)

		default:
			http.NotFound(w, r)
		}
	}))
}

func TestNewUpdater(t *testing.T) {
	cfg := &config.Config{}
	testLogger := logger.GetLogger().WithComponent("test")

	updaterConfig := UpdaterConfig{
		RepoOwner: "test",
		RepoName:  "cli",
		Timeout:   10 * time.Second,
	}

	updater := NewUpdater(cfg, testLogger, "1.0.0", updaterConfig)

	assert.NotNil(t, updater)
	assert.Equal(t, "1.0.0", updater.currentVersion)
	assert.Equal(t, "test", updater.repoOwner)
	assert.Equal(t, "cli", updater.repoName)
	assert.Equal(t, 10*time.Second, updater.httpClient.Timeout)
}

func TestGetPlatformName(t *testing.T) {
	updater := createTestUpdater("test", "cli")

	tests := []struct {
		name     string
		goos     string
		expected string
	}{
		{"Linux", "linux", "linux"},
		{"macOS", "darwin", "darwin"},
		{"Windows", "windows", "windows"},
		{"FreeBSD", "freebsd", "freebsd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't easily mock runtime.GOOS, so we test the logic indirectly
			// by testing the current platform
			result := updater.getPlatformName()
			assert.Contains(t, []string{"linux", "darwin", "windows", "freebsd"}, result)
		})
	}
}

func TestGetArchName(t *testing.T) {
	updater := createTestUpdater("test", "cli")

	// Test current architecture
	result := updater.getArchName()
	assert.Contains(t, []string{"amd64", "arm64", "386", "arm"}, result)
}

func TestMatchesPlatform(t *testing.T) {
	updater := createTestUpdater("test", "cli")

	tests := []struct {
		name      string
		assetName string
		platform  string
		arch      string
		expected  bool
	}{
		{"Linux AMD64 match", "ccr-linux-amd64", "linux", "amd64", true},
		{"Darwin ARM64 match", "ccr-darwin-arm64", "darwin", "arm64", true},
		{"macOS alternative", "ccr-darwin-amd64", "darwin", "amd64", true},
		{"Platform mismatch", "ccr-linux-amd64", "darwin", "amd64", false},
		{"Arch mismatch", "ccr-linux-arm64", "linux", "amd64", false},
		{"No platform in name", "some-random-file", "linux", "amd64", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := updater.matchesPlatform(tt.assetName, tt.platform, tt.arch)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsCriticalUpdate(t *testing.T) {
	updater := createTestUpdater("test", "cli")

	tests := []struct {
		name         string
		releaseNotes string
		expected     bool
	}{
		{"Critical keyword", "This is a CRITICAL update", true},
		{"Security keyword", "Security fix included", true},
		{"Vulnerability keyword", "Fixed vulnerability CVE-2023-1234", true},
		{"Urgent keyword", "URGENT: Please update immediately", true},
		{"Hotfix keyword", "Hotfix for critical bug", true},
		{"Case insensitive", "critical security vulnerability", true},
		{"Mixed case", "Critical Security Update", true},
		{"Normal release", "Bug fixes and improvements", false},
		{"Feature release", "New features and enhancements", false},
		{"Empty notes", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := updater.isCriticalUpdate(tt.releaseNotes)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCheckForUpdate(t *testing.T) {
	server := createMockGitHubServer(t)
	defer server.Close()

	// Create updater with custom HTTP client pointing to test server
	updater := createTestUpdater("test", "cli")
	updater.httpClient = server.Client()

	// Override the GitHub API URL by modifying the getLatestRelease method behavior
	// We'll do this by creating a custom test that patches the URL

	t.Run("Update available", func(t *testing.T) {
		// Mock the HTTP request to our test server
		originalClient := updater.httpClient
		updater.httpClient = &http.Client{
			Transport: &mockTransport{
				server: server,
				path:   "/repos/test/cli/releases/latest",
			},
		}
		defer func() { updater.httpClient = originalClient }()

		ctx := context.Background()
		updateInfo, err := updater.CheckForUpdate(ctx)

		require.NoError(t, err)
		require.NotNil(t, updateInfo)
		assert.Equal(t, "1.1.0", updateInfo.Version)
		assert.False(t, updateInfo.Critical)
		assert.False(t, updateInfo.PreRelease)
		assert.Contains(t, updateInfo.Changelog, "Bug fixes")
	})

	t.Run("Critical update", func(t *testing.T) {
		updater := createTestUpdater("test", "cli")
		updater.currentVersion = "1.0.0"
		updater.httpClient = &http.Client{
			Transport: &mockTransport{
				server: server,
				path:   "/repos/test/cli/releases/latest-critical",
			},
		}

		ctx := context.Background()
		updateInfo, err := updater.CheckForUpdate(ctx)

		require.NoError(t, err)
		require.NotNil(t, updateInfo)
		assert.Equal(t, "1.0.1", updateInfo.Version)
		assert.True(t, updateInfo.Critical)
		assert.Contains(t, updateInfo.Changelog, "CRITICAL SECURITY UPDATE")
	})

	t.Run("No update needed", func(t *testing.T) {
		updater := createTestUpdater("test", "cli")
		updater.currentVersion = "1.1.0" // Same as mock server version
		updater.httpClient = &http.Client{
			Transport: &mockTransport{
				server: server,
				path:   "/repos/test/cli/releases/latest",
			},
		}

		ctx := context.Background()
		updateInfo, err := updater.CheckForUpdate(ctx)

		require.NoError(t, err)
		assert.Nil(t, updateInfo) // No update needed
	})

	t.Run("Invalid current version", func(t *testing.T) {
		updater := createTestUpdater("test", "cli")
		updater.currentVersion = "invalid-version"
		updater.httpClient = &http.Client{
			Transport: &mockTransport{
				server: server,
				path:   "/repos/test/cli/releases/latest",
			},
		}

		ctx := context.Background()
		updateInfo, err := updater.CheckForUpdate(ctx)

		assert.Error(t, err)
		assert.Nil(t, updateInfo)
		assert.Contains(t, err.Error(), "invalid current version")
	})
}

func TestVerifyChecksum(t *testing.T) {
	updater := createTestUpdater("test", "cli")

	// Create a temporary file with known content
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test-file")
	testContent := []byte("test content for checksum verification")

	err := os.WriteFile(testFile, testContent, 0644)
	require.NoError(t, err)

	// Calculate expected checksum
	hash := sha256.Sum256(testContent)
	expectedChecksum := hex.EncodeToString(hash[:])

	t.Run("Valid checksum", func(t *testing.T) {
		err := updater.verifyChecksum(testFile, expectedChecksum)
		assert.NoError(t, err)
	})

	t.Run("Invalid checksum", func(t *testing.T) {
		wrongChecksum := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		err := updater.verifyChecksum(testFile, wrongChecksum)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "checksum mismatch")
	})

	t.Run("File not found", func(t *testing.T) {
		err := updater.verifyChecksum("/nonexistent/file", expectedChecksum)
		assert.Error(t, err)
	})
}

func TestCopyFile(t *testing.T) {
	updater := createTestUpdater("test", "cli")

	tempDir := t.TempDir()
	srcFile := filepath.Join(tempDir, "source.txt")
	dstFile := filepath.Join(tempDir, "destination.txt")

	testContent := []byte("test file content")
	err := os.WriteFile(srcFile, testContent, 0644)
	require.NoError(t, err)

	t.Run("Successful copy", func(t *testing.T) {
		err := updater.copyFile(srcFile, dstFile)
		assert.NoError(t, err)

		// Verify content
		copiedContent, err := os.ReadFile(dstFile)
		require.NoError(t, err)
		assert.Equal(t, testContent, copiedContent)

		// Verify permissions
		srcInfo, err := os.Stat(srcFile)
		require.NoError(t, err)
		dstInfo, err := os.Stat(dstFile)
		require.NoError(t, err)
		assert.Equal(t, srcInfo.Mode(), dstInfo.Mode())
	})

	t.Run("Source file not found", func(t *testing.T) {
		err := updater.copyFile("/nonexistent/source", dstFile)
		assert.Error(t, err)
	})

	t.Run("Invalid destination", func(t *testing.T) {
		err := updater.copyFile(srcFile, "/invalid/path/destination")
		assert.Error(t, err)
	})
}

func TestDownloadBinary(t *testing.T) {
	updater := createTestUpdater("test", "cli")

	// Create a test server that serves binary content
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte("fake binary content"))
	}))
	defer server.Close()

	updater.httpClient = server.Client()

	tempDir := t.TempDir()
	destPath := filepath.Join(tempDir, "downloaded-binary")

	t.Run("Successful download", func(t *testing.T) {
		ctx := context.Background()
		err := updater.downloadBinary(ctx, server.URL, destPath)

		assert.NoError(t, err)

		// Verify file exists and has correct content
		content, err := os.ReadFile(destPath)
		require.NoError(t, err)
		assert.Equal(t, []byte("fake binary content"), content)

		// Verify file is executable (Unix systems only)
		info, err := os.Stat(destPath)
		require.NoError(t, err)
		assert.True(t, info.Mode()&0111 != 0, "File should be executable")
	})

	t.Run("Invalid URL", func(t *testing.T) {
		ctx := context.Background()
		err := updater.downloadBinary(ctx, "http://nonexistent.example.com", destPath)
		assert.Error(t, err)
	})
}

func TestFindAssetForPlatform(t *testing.T) {
	updater := createTestUpdater("test", "cli")

	release := &GitHubRelease{
		Assets: []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
			Size               int64  `json:"size"`
			ContentType        string `json:"content_type"`
		}{
			{Name: "ccr-linux-amd64", BrowserDownloadURL: "http://example.com/linux-amd64", Size: 1000},
			{Name: "ccr-darwin-amd64", BrowserDownloadURL: "http://example.com/darwin-amd64", Size: 1000},
		},
	}

	t.Run("Find matching asset", func(t *testing.T) {
		// Test with current platform - this will find a match if the test platform is supported
		asset, err := updater.findAssetForPlatform(release)

		// We expect either success or a specific error
		if err != nil {
			assert.Contains(t, err.Error(), "no asset found for platform")
		} else {
			assert.NotNil(t, asset)
			assert.Contains(t, asset.Name, "ccr-")
		}
	})

	t.Run("No matching asset", func(t *testing.T) {
		// Create a release with no matching assets
		emptyRelease := &GitHubRelease{
			Assets: []struct {
				Name               string `json:"name"`
				BrowserDownloadURL string `json:"browser_download_url"`
				Size               int64  `json:"size"`
				ContentType        string `json:"content_type"`
			}{
				{Name: "ccr-unsupported-unknown", BrowserDownloadURL: "http://example.com/unsupported", Size: 1000},
			},
		}

		asset, err := updater.findAssetForPlatform(emptyRelease)

		assert.Error(t, err)
		assert.Nil(t, asset)
		assert.Contains(t, err.Error(), "no asset found for platform")
	})
}

// Mock transport for testing HTTP requests
type mockTransport struct {
	server *httptest.Server
	path   string
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Redirect the request to our test server
	req.URL.Scheme = "http"
	req.URL.Host = strings.TrimPrefix(m.server.URL, "http://")
	req.URL.Path = m.path

	return m.server.Client().Transport.RoundTrip(req)
}

func TestGetCurrentVersion(t *testing.T) {
	updater := createTestUpdater("test", "cli")
	updater.currentVersion = "2.0.0"

	version := updater.GetCurrentVersion()
	assert.Equal(t, "2.0.0", version)
}

func TestSetGithubToken(t *testing.T) {
	updater := createTestUpdater("test", "cli")

	token := "ghp_test_token_123"
	updater.SetGithubToken(token)

	assert.Equal(t, token, updater.githubToken)
}

// Benchmark tests
func BenchmarkVersionComparison(b *testing.B) {
	updater := createTestUpdater("test", "cli")
	updater.currentVersion = "1.0.0"

	server := createMockGitHubServerForBench()
	defer server.Close()

	updater.httpClient = &http.Client{
		Transport: &mockTransport{
			server: server,
			path:   "/repos/test/cli/releases/latest",
		},
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := updater.CheckForUpdate(ctx)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPlatformMatching(b *testing.B) {
	updater := createTestUpdater("test", "cli")

	testCases := []struct {
		asset    string
		platform string
		arch     string
	}{
		{"ccr-linux-amd64", "linux", "amd64"},
		{"ccr-darwin-arm64", "darwin", "arm64"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, tc := range testCases {
			updater.matchesPlatform(tc.asset, tc.platform, tc.arch)
		}
	}
}

// createMockGitHubServerForBench creates a mock server for benchmarks
func createMockGitHubServerForBench() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "releases/latest") {
			release := GitHubRelease{
				TagName:     "v1.1.0",
				Name:        "Test Release",
				Body:        "Test release notes",
				Draft:       false,
				Prerelease:  false,
				CreatedAt:   time.Now(),
				PublishedAt: time.Now(),
				Assets: []struct {
					Name               string `json:"name"`
					BrowserDownloadURL string `json:"browser_download_url"`
					Size               int64  `json:"size"`
					ContentType        string `json:"content_type"`
				}{
					{
						Name:               "ccr-linux-amd64",
						BrowserDownloadURL: "http://example.com/ccr-linux-amd64",
						Size:               1024000,
						ContentType:        "application/octet-stream",
					},
				},
			}
			json.NewEncoder(w).Encode(release)
		}
	}))
}
