package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/NeverVane/commandchronicles/internal/auth"
	"github.com/NeverVane/commandchronicles/internal/cache"
	"github.com/NeverVane/commandchronicles/internal/config"
	"github.com/NeverVane/commandchronicles/internal/daemon"
	"github.com/NeverVane/commandchronicles/internal/deletion"
	"github.com/NeverVane/commandchronicles/internal/logger"
	"github.com/NeverVane/commandchronicles/internal/login"
	"github.com/NeverVane/commandchronicles/internal/output"
	"github.com/NeverVane/commandchronicles/internal/search"
	"github.com/NeverVane/commandchronicles/internal/sentry"
	"github.com/NeverVane/commandchronicles/internal/shell"
	"github.com/NeverVane/commandchronicles/internal/stats"
	"github.com/NeverVane/commandchronicles/internal/storage"
	"github.com/NeverVane/commandchronicles/internal/sync"
	"github.com/NeverVane/commandchronicles/internal/tui"
	"github.com/NeverVane/commandchronicles/internal/updater"
	"github.com/NeverVane/commandchronicles/pkg/history"
	"github.com/NeverVane/commandchronicles/pkg/security"
	securestorage "github.com/NeverVane/commandchronicles/pkg/storage"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	_ "modernc.org/sqlite"
)

var (
	version = "0.3.1"
	commit  = "release"
	date    = "2025-07-09"
	author  = "Leonardo Zanobi"
	website = "https://commandchronicles.dev"
)

func main() {
	// Add panic recovery for better error reporting
	defer func() {
		if r := recover(); r != nil {
			if sentry.IsEnabled() {
				sentry.CaptureError(fmt.Errorf("panic: %v", r), "main", "panic_recovery")
				sentry.Flush(2 * time.Second)
			}
			fmt.Fprintf(os.Stderr, "CommandChronicles CLI encountered a fatal error: %v\n", r)
			os.Exit(1)
		}
	}()

	// Load configuration
	cfg, err := config.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize Sentry error monitoring
	if err := sentry.Initialize(cfg, version, commit, date, author); err != nil {
		// Don't fail the application if Sentry initialization fails
		fmt.Fprintf(os.Stderr, "Warning: Failed to initialize error monitoring: %v\n", err)
	}

	// Ensure Sentry cleanup on exit
	defer func() {
		if sentry.IsEnabled() {
			sentry.Flush(2 * time.Second)
			sentry.Close()
		}
	}()

	// Override data directory if CCR_DATA_DIR environment variable is set
	// This is essential for:
	// - Docker containers and Kubernetes deployments
	// - CI/CD pipelines with isolated environments
	// - Testing with temporary directories
	// - Multi-user systems with custom data locations
	// - Corporate environments with specific data policies
	if dataDir := os.Getenv("CCR_DATA_DIR"); dataDir != "" {
		// Validate the custom data directory path
		if !filepath.IsAbs(dataDir) {
			fmt.Fprintf(os.Stderr, "CCR_DATA_DIR must be an absolute path, got: %s\n", dataDir)
			os.Exit(1)
		}

		// Security check: ensure path doesn't contain suspicious patterns
		cleanPath := filepath.Clean(dataDir)
		if cleanPath != dataDir {
			fmt.Fprintf(os.Stderr, "CCR_DATA_DIR contains invalid path components: %s\n", dataDir)
			os.Exit(1)
		}

		// Apply the custom data directory override
		originalDataDir := cfg.DataDir
		cfg.DataDir = dataDir
		cfg.ConfigDir = dataDir // Use same dir for both config and data in isolated environments
		cfg.Database.Path = filepath.Join(dataDir, "history.db")
		cfg.Security.SessionKeyPath = filepath.Join(dataDir, "session")
		cfg.Shell.BashHookPath = filepath.Join(dataDir, "hooks", "bash_hook.sh")
		cfg.Shell.ZshHookPath = filepath.Join(dataDir, "hooks", "zsh_hook.sh")

		// Create the custom data directory with secure permissions
		if err := os.MkdirAll(dataDir, 0700); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create custom data directory %s: %v\n", dataDir, err)
			os.Exit(1)
		}

		// Create hooks subdirectory
		hooksDir := filepath.Join(dataDir, "hooks")
		if err := os.MkdirAll(hooksDir, 0700); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create hooks directory %s: %v\n", hooksDir, err)
			os.Exit(1)
		}

		// Log the data directory override for transparency
		if os.Getenv("CCR_VERBOSE") != "" || os.Getenv("CCR_DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "CCR_DATA_DIR override: %s -> %s\n", originalDataDir, dataDir)
		}
	}

	// Initialize logger
	loggerConfig := &logger.Config{
		Level:     "error",
		Output:    "stderr",
		Color:     true,
		Timestamp: true,
		Caller:    false,
	}

	if err := logger.Init(loggerConfig); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	rootCmd := &cobra.Command{
		Use:   "ccr",
		Short: "CommandChronicles CLI - Enhanced shell history management",
		Long: `
===================================================================
              CommandChronicles CLI (ccr) v` + version + `
===================================================================

  🚀 A modern shell history management tool that supercharges
     your command line experience with intelligent search
                and secure local storage

===================================================================

CommandChronicles CLI transforms your shell history into a powerful knowledge
base, capturing rich context for every command and providing lightning-fast
search capabilities through an intuitive TUI interface.

Key Features:
  • Military-grade encryption (XChaCha20-Poly1305) for your command history
  • Blazing-fast fuzzy search with real-time interactive TUI (Ctrl+R)
  • Rich command metadata (exit codes, duration, working directory, git info)
  • Seamless shell integration for bash and zsh with automatic setup
  • Secure key derivation (Argon2id) and session management
  • Smart caching system for instant search results
  • Beautiful command statistics and usage analytics

Author: Leonardo Zanobi
License: MIT
Homepage: https://commandchronicles.dev

Get started:
  ccr init                    Initialize CommandChronicles
  ccr install-hooks --auto    Set up shell integration automatically
  ccr search                  Search your command history
  ccr stats                   View command usage statistics
  ccr help                    Show all available commands`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Handle verbose flag
			verbose, _ := cmd.Flags().GetBool("verbose")
			if verbose {
				// Reinitialize logger with debug level
				loggerConfig.Level = "debug"
				return logger.Init(loggerConfig)
			}
			return nil
		},
	}

	// Global flags
	rootCmd.PersistentFlags().Bool("verbose", false, "Enable verbose output")
	rootCmd.PersistentFlags().Bool("no-color", false, "Disable colored output")
	rootCmd.PersistentFlags().String("config", "", "Config file (default: ~/.config/commandchronicles/config.toml)")

	// Disable auto-generated completion command (not yet implemented)
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	// Add subcommands with configuration
	rootCmd.AddCommand(initCmd(cfg))
	rootCmd.AddCommand(loginCmd(cfg))
	rootCmd.AddCommand(statusCmd(cfg))
	rootCmd.AddCommand(searchCmd(cfg))
	rootCmd.AddCommand(importCmd(cfg))
	rootCmd.AddCommand(exportCmd(cfg))
	rootCmd.AddCommand(statsCmd(cfg))
	rootCmd.AddCommand(noteCmd(cfg))
	rootCmd.AddCommand(tagCmd(cfg))
	rootCmd.AddCommand(lockCmd(cfg))
	rootCmd.AddCommand(unlockCmd(cfg))
	rootCmd.AddCommand(changePasswordCmd(cfg))
	rootCmd.AddCommand(recordCmd(cfg))
	rootCmd.AddCommand(sessionEndCmd(cfg))
	rootCmd.AddCommand(installHooksCmd(cfg))
	rootCmd.AddCommand(uninstallHooksCmd(cfg))
	rootCmd.AddCommand(tuiCmd(cfg))
	rootCmd.AddCommand(deleteCmd(cfg))
	rootCmd.AddCommand(wipeCmd(cfg))
	rootCmd.AddCommand(syncCmd(cfg))
	rootCmd.AddCommand(devicesCmd(cfg))
	rootCmd.AddCommand(rulesCmd(cfg))
	rootCmd.AddCommand(cancelSubscriptionCmd(cfg))
	rootCmd.AddCommand(daemonCmd(cfg))
	rootCmd.AddCommand(daemonControlCmd(cfg))
	rootCmd.AddCommand(updateCmd(cfg))
	rootCmd.AddCommand(checkUpdateCmd(cfg))
	rootCmd.AddCommand(versionCmd(cfg))

	rootCmd.AddCommand(debugCmd(cfg))

	// Ensure daemon is running before executing commands (if auto-start enabled)
	ensureDaemonRunning(cfg)

	// Perform auto-update check in background (non-blocking)
	checkAutoUpdate(cfg)

	// Execute the root command
	if err := rootCmd.Execute(); err != nil {
		// Commands handle their own error display via formatter
		os.Exit(1)
	}
}

// initCmd initializes the CommandChronicles system
func initCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize CommandChronicles with user credentials and setup",
		Long: `Initialize CommandChronicles by setting up user credentials, creating the database,
and optionally configuring remote sync. This command must be run before using other features.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := logger.GetLogger().WithComponent("init")
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			if verbose {
				log.Info().Msg("Initializing CommandChronicles...")
			}

			// Create login manager
			loginMgr, err := login.NewLoginManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize login manager: %w", err)
			}
			defer loginMgr.Close()

			// Set up status callback for formatted progress updates
			loginMgr.StatusCallback = func(message string, success bool) {
				if success {
					formatter.Success(message)
				} else {
					formatter.Info(message)
				}
			}

			// Check if user already exists
			if loginMgr.AuthManager.UserExists() {
				formatter.Info("CommandChronicles is already initialized.")
				formatter.Tip("Use 'ccr login' to unlock your session.")
				return nil
			}

			// Ensure directories are created
			if err := cfg.EnsureDirectories(); err != nil {
				return fmt.Errorf("failed to create directories: %w", err)
			}

			// Ask if user already has an account FIRST
			clearScreen()
			formatter.Setup("Account Setup")
			fmt.Print("Do you already have a CommandChronicles account? [y/N]: ")
			var hasAccountResponse string
			fmt.Scanln(&hasAccountResponse)

			if strings.ToLower(hasAccountResponse) == "y" || strings.ToLower(hasAccountResponse) == "yes" {
				// Existing user login flow
				formatter.Separator()
				formatter.Setup("Login to Existing Account")

				// Get email for existing account
				var email string
				fmt.Print("Email address: ")
				if _, err := fmt.Scanln(&email); err != nil {
					return fmt.Errorf("failed to read email: %w", err)
				}

				// Validate email format
				if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
					return fmt.Errorf("invalid email format")
				}

				// Get password for existing account
				password, err := promptForPassword("Password: ")
				if err != nil {
					return fmt.Errorf("failed to get password: %w", err)
				}
				defer secureClearString(&password)

				// Perform initialization with existing account (login + sync down)
				clearScreen()
				formatter.Setup("Setting up CommandChronicles for %s...", email)

				if err := loginMgr.InitExistingUser(email, password); err != nil {
					return fmt.Errorf("login to existing account failed: %w", err)
				}

				formatter.Success("Successfully logged in and synced your command history!")

				// Enhanced init flow for existing users
				time.Sleep(2 * time.Second) // Brief pause to let user see success message
				promptAndInstallHooks(cfg, formatter)
				promptAndEnableSync(cfg, formatter)
				promptAndImportHistory(cfg, formatter)

				formatter.Separator()
				formatter.Done("CommandChronicles is now ready!")
				formatter.Info("Use 'ccr search <query>' or press Ctrl+R to start searching your commands.")

				return nil
			}

			// New user registration flow
			formatter.Separator()
			formatter.Setup("Create New Account")

			// Get email from flag or prompt
			email, _ := cmd.Flags().GetString("username") // Keep flag name for compatibility
			if email == "" {
				fmt.Print("Email address: ")
				if _, err := fmt.Scanln(&email); err != nil {
					return fmt.Errorf("failed to read email: %w", err)
				}
			}

			// Validate email format
			if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
				return fmt.Errorf("invalid email format")
			}

			// Create username from email (part before @)
			username := strings.Split(email, "@")[0]
			if username == "" {
				username = "user"
			}

			// Prompt for password
			password, err := promptForPassword("Create password (min 8 characters): ")
			if err != nil {
				return fmt.Errorf("failed to get password: %w", err)
			}
			defer secureClearString(&password)

			if len(password) < 8 {
				return fmt.Errorf("password must be at least 8 characters long")
			}

			// Confirm password
			confirmPassword, err := promptForPassword("Confirm password: ")
			if err != nil {
				return fmt.Errorf("failed to get password confirmation: %w", err)
			}
			defer secureClearString(&confirmPassword)

			if password != confirmPassword {
				return fmt.Errorf("passwords do not match")
			}

			// Ask about remote sync setup
			formatter.Separator()
			formatter.Setup("Remote Sync Setup")
			formatter.Info("Would you like to set up remote synchronization? (recommended)")
			formatter.IfVerbose(func() {
				formatter.Info("Server: %s", cfg.GetSyncServerURL())
			})

			setupRemote := false

			fmt.Print("Set up remote sync now? [Y/n]: ")
			var response string
			fmt.Scanln(&response)

			if response == "" || strings.ToLower(response) == "y" || strings.ToLower(response) == "yes" {
				setupRemote = true
				formatter.IfVerbose(func() {
					formatter.Info("Using email: %s", email)
				})
			}

			// Perform initialization
			clearScreen()
			formatter.Setup("Initializing CommandChronicles for %s...", username)

			if err := loginMgr.InitUser(username, password, setupRemote, email); err != nil {
				return fmt.Errorf("initialization failed: %w", err)
			}

			formatter.Success("Account created and initialized successfully!")

			// Enhanced init flow for new users
			time.Sleep(2 * time.Second) // Brief pause to let user see success message
			promptAndInstallHooks(cfg, formatter)
			if !setupRemote {
				promptAndEnableSync(cfg, formatter)
			}
			promptAndImportHistory(cfg, formatter)

			formatter.Separator()
			formatter.Done("CommandChronicles is now ready!")
			formatter.Info("Use 'ccr search <query>' or press Ctrl+R to start searching your commands.")

			if verbose {
				log.Info().Msg("CommandChronicles initialization completed successfully")
			}
			return nil
		},
	}

	cmd.Flags().String("username", "", "Email address (only for new accounts when not prompted)")
	return cmd
}

func loginCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Login to both local storage and remote sync",
		Long: `Unified login command that unlocks local storage and authenticates with remote server.
Can also be used to set up remote sync for existing local installations.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := logger.GetLogger().WithComponent("login")
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			// Create login manager
			loginMgr, err := login.NewLoginManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize login manager: %w", err)
			}
			defer loginMgr.Close()

			// Check if initialized
			if !loginMgr.AuthManager.UserExists() {
				return fmt.Errorf("not initialized - run 'ccr init' first")
			}

			// Check setup-sync flag
			setupSync, _ := cmd.Flags().GetBool("setup-sync")

			if setupSync {
				// Setting up sync for existing local user
				formatter.Setup("Setting up remote sync...")

				// Get email
				var email string
				fmt.Print("Email address: ")
				if _, err := fmt.Scanln(&email); err != nil {
					return fmt.Errorf("failed to read email: %w", err)
				}

				// Get password
				password, err := promptForPassword("Password: ")
				if err != nil {
					return fmt.Errorf("failed to get password: %w", err)
				}
				defer secureClearString(&password)

				// Setup sync
				if err := loginMgr.SetupSync(email, password); err != nil {
					return fmt.Errorf("sync setup failed: %w", err)
				}

				return nil
			}

			// Regular login flow
			// Check if already logged in
			if localOK, remoteOK := loginMgr.IsLoggedIn(); localOK {
				email := cfg.Sync.Email
				if cfg.Sync.Enabled && email != "" {
					if remoteOK {
						formatter.Success("Both local and remote sessions active")
						return nil
					} else {
						formatter.Warning("Local session active, remote session expired")
						if verbose {
							fmt.Println("Continuing with fresh login...")
						}
					}
				} else {
					formatter.Success("Local session active")
					if email == "" && verbose {
						formatter.Tip("To set up remote sync: ccr login --setup-sync")
					} else if email == "" {
						return nil
					}
				}
			}

			// Prompt for password
			password, err := promptForPassword("Password: ")
			if err != nil {
				return fmt.Errorf("failed to get password: %w", err)
			}
			defer secureClearString(&password)

			// Perform login
			user, _ := loginMgr.AuthManager.GetUser()
			formatter.Auth("Logging in as %s...", user.Username)
			formatter.IfVerbose(func() {
				if cfg.Sync.Enabled && cfg.Sync.Email != "" {
					formatter.Info("Server: %s", cfg.GetSyncServerURL())
					formatter.Info("Email: %s", cfg.Sync.Email)
				}
			})

			result, err := loginMgr.Login(password)
			if err != nil {
				return fmt.Errorf("login failed: %w", err)
			}

			// Show result
			formatter.Success(result.Message)

			// Show status if sync is configured (only in verbose mode)
			formatter.IfVerbose(func() {
				if cfg.Sync.Enabled && cfg.Sync.Email != "" {
					status := loginMgr.GetAuthStatus()
					formatter.Separator()
					formatter.Stats("Status:")
					formatter.Println("  Local Storage: %s", formatBoolStatus(status["local_authenticated"].(bool)))
					formatter.Println("  Remote Sync:   %s", formatBoolStatus(status["remote_authenticated"].(bool)))
					formatter.Println("  Email:         %s", status["email"])
				} else if cfg.Sync.Email == "" {
					formatter.Separator()
					formatter.Tip("To set up remote sync: ccr login --setup-sync")
				}
			})

			if verbose {
				log.WithFields(map[string]interface{}{
					"local_success":  result.LocalSuccess,
					"remote_success": result.RemoteSuccess,
				}).Info().Msg("Login completed")
			}

			return nil
		},
	}

	cmd.Flags().Bool("setup-sync", false, "Set up remote sync for existing local installation")
	return cmd
}

// Helper function for status display
func formatBoolStatus(status bool) string {
	if status {
		return "Active"
	}
	return "Inactive"
}

func statusCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show CommandChronicles status",
		Long:  "Display current status including authentication, sync configuration, and session information",
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			// Create login manager to access auth status
			loginMgr, err := login.NewLoginManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to create login manager: %w", err)
			}
			defer loginMgr.Close()

			// Check if initialized
			if !loginMgr.AuthManager.UserExists() {
				formatter.Error("CommandChronicles not initialized")
				if verbose {
					formatter.Tip("Run 'ccr init' to get started")
				}
				return nil
			}

			// Get comprehensive status
			status := loginMgr.GetAuthStatus()

			// Show minimal status by default
			localOK := status["local_authenticated"].(bool)
			remoteOK := status["remote_authenticated"].(bool)
			syncEnabled := status["sync_enabled"].(bool)

			if !verbose {
				// Concise output - essential status with context
				if localOK {
					formatter.Success("Local Storage: Active")
				} else {
					formatter.Error("Local Storage: Inactive")
				}
				if cfg.Sync.Enabled && cfg.Sync.Email != "" {
					if remoteOK {
						formatter.Success("Remote Sync: Active")
					} else {
						formatter.Error("Remote Sync: Inactive")
					}
					formatter.Print("Email: %s", cfg.Sync.Email)
				} else {
					formatter.Print("Remote Sync: Not configured")
				}
				return nil
			}

			// Verbose output - detailed information
			formatter.Header("CommandChronicles Status")

			// Local status
			formatter.Println("Local Storage:    %s", formatBoolStatus(status["local_authenticated"].(bool)))
			if username, ok := status["username"].(string); ok {
				formatter.Println("Username:         %s", username)
			}
			if remaining, ok := status["local_session_remaining"].(string); ok {
				formatter.Println("Session Expires:  %s", remaining)
			}

			formatter.Separator()

			// Remote status
			if cfg.Sync.Enabled && cfg.Sync.Email != "" {
				formatter.Println("Remote Sync:      %s", formatBoolStatus(status["remote_authenticated"].(bool)))
				formatter.Println("Email:            %s", cfg.Sync.Email)
				formatter.Println("Server:           %s", cfg.GetSyncServerURL())
				if lastSync, ok := status["last_sync"].(string); ok && lastSync != "" {
					formatter.Println("Last Sync:        %s", lastSync)
				}
			} else {
				formatter.Println("Remote Sync:      Not configured")
				formatter.Tip("Run 'ccr login --setup-sync' to enable remote sync")
				formatter.Info("Purchase subscription: https://commandchronicles.dev/pricing")
			}

			formatter.Separator()

			// Next steps
			if !localOK {
				formatter.Tip("Next step: ccr login")
			} else if status["email"].(string) != "" && !remoteOK {
				formatter.Tip("Next step: ccr login (remote authentication needed)")
			} else if status["email"].(string) != "" && remoteOK && !syncEnabled {
				formatter.Tip("Next step: ccr sync enable")
			} else if status["email"].(string) == "" {
				formatter.Tip("Next step: ccr login --setup-sync (to enable remote sync)")
			} else {
				formatter.Success("All systems operational!")
			}

			return nil
		},
	}

	return cmd
}

func promptForUsername() (string, error) {
	fmt.Print("Enter username: ")
	reader := bufio.NewReader(os.Stdin)
	username, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(username), nil
}

// promptForPassword prompts the user for a password without echoing
func promptForPassword(prompt string) (string, error) {
	fmt.Print(prompt)

	fd := int(syscall.Stdin)
	if !term.IsTerminal(fd) {
		// Fallback for non-terminal input
		reader := bufio.NewReader(os.Stdin)
		password, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(password), nil
	}

	password, err := term.ReadPassword(fd)
	fmt.Println() // Print newline after password input
	if err != nil {
		return "", err
	}

	return string(password), nil
}

// secureClearString overwrites a string's memory with zeros for security
// Deprecated: Use security.SecureWipeString for enhanced security
func secureClearString(s *string) {
	security.SecureWipeString(s)
}

// secureClearBytes overwrites a byte slice with zeros for security
// Deprecated: Use security.SecureWipe for enhanced security
func secureClearBytes(b []byte) {
	security.SecureWipe(b)
}

// searchCmd provides command line search functionality
func searchCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "search [query]",
		Short: "Search command history",
		Long: `Search through your encrypted command history with optional filters.
Use without arguments to search all commands. Use --tui flag to open interactive interface.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := logger.GetLogger().WithComponent("search")

			// Check if TUI mode is requested
			tuiMode, _ := cmd.Flags().GetBool("tui")
			if tuiMode {
				// Get launch options from flags
				initialQuery := ""
				if len(args) > 0 {
					initialQuery = args[0]
				}

				fuzzyEnabled, _ := cmd.Flags().GetBool("fuzzy")
				maxResults, _ := cmd.Flags().GetInt("limit")

				// Create TUI options
				opts := &tui.TUIOptions{
					InitialQuery: initialQuery,
					FuzzyEnabled: fuzzyEnabled,
					MaxResults:   maxResults,
					Version:      version,
				}

				// Launch TUI with proper initialization
				return tui.Launch(cfg, opts)
			}

			// Initialize auth manager for proper session management
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authMgr.Close()

			// Get session key using proper session management
			sessionKey, err := getSearchSessionKey(authMgr, log)
			if err != nil {
				return fmt.Errorf("failed to get session key: %w", err)
			}

			// Initialize storage
			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:              cfg,
				CreateIfMissing:     true,
				ValidatePermissions: true,
				EnableSecureDelete:  true,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			// Unlock storage with session key
			if err := storage.UnlockWithKey(sessionKey); err != nil {
				return fmt.Errorf("failed to unlock storage: %w", err)
			}

			// Initialize hybrid cache
			hybridCache := cache.NewCache(&cfg.Cache, storage)
			defer hybridCache.Close()

			// Parse command flags first to determine if fuzzy search is needed
			directory, _ := cmd.Flags().GetString("directory")
			hostname, _ := cmd.Flags().GetString("hostname")
			sessionID, _ := cmd.Flags().GetString("session")
			exitCode, _ := cmd.Flags().GetInt("exit-code")
			sinceStr, _ := cmd.Flags().GetString("since")
			untilStr, _ := cmd.Flags().GetString("until")
			limit, _ := cmd.Flags().GetInt("limit")
			useFuzzy, _ := cmd.Flags().GetBool("fuzzy")
			fuzziness, _ := cmd.Flags().GetInt("fuzziness")
			exactMatch, _ := cmd.Flags().GetBool("exact")
			verboseOutput, _ := cmd.Flags().GetBool("verbose-output")
			tags, _ := cmd.Flags().GetStringSlice("tags")
			excludeTags, _ := cmd.Flags().GetStringSlice("exclude-tags")
			tagMode, _ := cmd.Flags().GetString("tag-mode")

			// Initialize search service
			searchService := search.NewSearchService(hybridCache, storage, cfg)
			defer searchService.Close()

			// Initialize search service with cache warmup and fuzzy search if requested
			searchOpts := &search.SearchOptions{
				EnableCache:       true,
				DefaultLimit:      50,
				DefaultMaxBatches: 10,
				DefaultTimeout:    30 * time.Second,
				WarmupCache:       true,
				EnableFuzzySearch: useFuzzy,
				FuzzyIndexPath:    filepath.Join(cfg.DataDir, "search_index"),
				RebuildFuzzyIndex: useFuzzy, // Rebuild index if fuzzy search is requested
			}
			if err := searchService.Initialize(searchOpts); err != nil {
				log.Warn().Err(err).Msg("Failed to initialize search service")
			}

			// TUI is only launched when explicitly requested with --tui flag
			// Default behavior is always CLI search, even with empty query

			var query string
			if len(args) > 0 {
				query = args[0]
			}
			log.Debug().Str("query", query).Msg("Performing CLI search")

			// Parse time filters
			var since, until *time.Time
			if sinceStr != "" {
				if duration, err := time.ParseDuration(sinceStr); err == nil {
					sinceTime := time.Now().Add(-duration)
					since = &sinceTime
				} else {
					log.Warn().Str("since", sinceStr).Msg("Invalid since duration")
				}
			}
			if untilStr != "" {
				if duration, err := time.ParseDuration(untilStr); err == nil {
					untilTime := time.Now().Add(-duration)
					until = &untilTime
				} else {
					log.Warn().Str("until", untilStr).Msg("Invalid until duration")
				}
			}

			// Build search request
			searchReq := &search.SearchRequest{
				Query:          query,
				Limit:          limit,
				WorkingDir:     directory,
				Hostname:       hostname,
				SessionID:      sessionID,
				Since:          since,
				Until:          until,
				UseCache:       true,
				MaxBatches:     10,
				IncludeGit:     true,
				UseFuzzySearch: useFuzzy && query != "",
				ExactMatch:     exactMatch,
				Tags:           tags,
				ExcludeTags:    excludeTags,
				TagMode:        tagMode,
			}

			// Configure fuzzy search options if enabled
			if searchReq.UseFuzzySearch {
				searchReq.FuzzyOptions = &search.FuzzySearchOptions{
					Fuzziness:       fuzziness,
					PrefixLength:    1,
					BoostRecent:     1.5,
					BoostFrequent:   1.3,
					BoostExactMatch: 3.0,
					BoostPrefix:     2.0,
					MinScore:        0.1,
					IncludeWorkDir:  true,
					IncludeGitInfo:  true,
					AnalyzeCommand:  true,
					MaxCandidates:   limit * 3,
					SearchTimeout:   10 * time.Second,
				}
			}

			if exitCode >= 0 {
				searchReq.ExitCode = &exitCode
			}

			// Color styles for search output
			headerStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("6")).Bold(true)
			successStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
			errorStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
			commandStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("15")).Bold(true)
			metaStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
			separatorStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
			indexStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("6"))

			// Perform search
			fmt.Printf("%s %s\n", headerStyle.Render("Searching for:"), query)
			response, err := searchService.Search(searchReq)
			if err != nil {
				return fmt.Errorf("search failed: %w", err)
			}

			// Display results
			if len(response.Records) == 0 {
				fmt.Println("No results found.")
				return nil
			}

			fmt.Printf("\n%s %d result(s) in %v\n", headerStyle.Render("Found"), response.TotalMatches, response.SearchTime)

			// Display cache info only
			if response.FromCache > 0 {
				fmt.Printf("   %d from cache, %d from database (%.1f%% cache hit ratio)\n",
					response.FromCache, response.FromBatches, response.CacheHitRatio*100)
			}

			// Show applied filters
			if len(response.AppliedFilters) > 0 {
				fmt.Printf("   Filters: ")
				var filters []string
				for key, value := range response.AppliedFilters {
					filters = append(filters, fmt.Sprintf("%s=%v", key, value))
				}
				fmt.Printf("%s\n", strings.Join(filters, ", "))
			}

			fmt.Println()

			// Display command records
			for i, record := range response.Records {
				if verboseOutput {
					// Detailed format
					fmt.Printf("[%d] %s", record.ID, record.Command)

					// Add tags if present
					if record.HasTags() {
						fmt.Printf(" ")
						for idx, tag := range record.Tags {
							if idx > 0 {
								fmt.Printf(" ")
							}
							fmt.Printf("#%s", tag)
						}
					}

					fmt.Printf("\n")

					fmt.Printf("    %s", record.WorkingDir)
					if record.GitBranch != "" {
						fmt.Printf(" (git: %s)", record.GitBranch)
					}
					fmt.Printf("\n    %v", time.UnixMilli(record.Timestamp).Format("2006-01-02 15:04:05"))
					if record.Duration > 0 {
						fmt.Printf(" (%dms)", record.Duration)
					}
					if record.ExitCode != 0 {
						fmt.Printf(" exit: %d", record.ExitCode)
					} else {
						fmt.Printf(" ok")
					}
					if record.Hostname != "" {
						fmt.Printf(" %s", record.Hostname)
					}
					fmt.Printf("\n")
					if i < len(response.Records)-1 {
						fmt.Println("    ─────────────────────────────────────────")
					}
				} else {
					// Compact format
					timestamp := time.UnixMilli(record.Timestamp).Format("Jan 02 15:04")

					// Status indicator with color
					var status string
					if record.ExitCode == 0 {
						status = successStyle.Render("✓")
					} else {
						status = errorStyle.Render(fmt.Sprintf("✗ %d", record.ExitCode))
					}

					// Build compact metadata
					var parts []string
					parts = append(parts, timestamp)
					parts = append(parts, status)

					// Add working directory (abbreviated)
					if record.WorkingDir != "" {
						workingDir := record.WorkingDir
						if len(workingDir) > 25 {
							pathParts := strings.Split(workingDir, "/")
							if len(pathParts) > 1 {
								workingDir = "~/" + pathParts[len(pathParts)-1]
							}
							if len(workingDir) > 25 {
								workingDir = workingDir[:22] + "..."
							}
						}
						parts = append(parts, workingDir)
					}

					// Add git branch if available
					if record.GitBranch != "" {
						branch := record.GitBranch
						if len(branch) > 12 {
							branch = branch[:9] + "..."
						}
						parts = append(parts, branch)
					}

					// Add tags if available
					if record.HasTags() {
						var tagsPart []string
						for _, tag := range record.Tags {
							tagsPart = append(tagsPart, "#"+tag)
						}
						tagsStr := strings.Join(tagsPart, " ")
						if len(tagsStr) > 20 {
							tagsStr = tagsStr[:17] + "..."
						}
						parts = append(parts, tagsStr)
					}

					metadata := metaStyle.Render(strings.Join(parts, " · "))

					// Compact single line with consistent spacing and colors
					fmt.Printf("  %s %s %-60s %s %s\n",
						indexStyle.Render(fmt.Sprintf("%d", record.ID)),
						separatorStyle.Render("│"),
						commandStyle.Render(record.Command),
						separatorStyle.Render("│"),
						metadata)
				}
			}

			if response.HasMore {
				fmt.Printf("\n")
				formatter := output.NewFormatter(cfg)
				formatter.Tip("Use --limit %d to see more results", limit*2)
			}

			return nil
		},
	}

	cmd.Flags().String("directory", "", "Filter by working directory")
	cmd.Flags().String("hostname", "", "Filter by hostname")
	cmd.Flags().String("session", "", "Filter by session ID")
	cmd.Flags().Int("exit-code", -1, "Filter by exit code")
	cmd.Flags().String("since", "", "Filter by time (e.g., '1h', '2d', '1w')")
	cmd.Flags().String("until", "", "Filter by time (e.g., '1h', '2d', '1w')")
	cmd.Flags().Int("limit", cfg.Cache.HotCacheSize, "Limit number of results")
	cmd.Flags().Bool("fuzzy", true, "Use fuzzy search for better matching")
	cmd.Flags().Int("fuzziness", 1, "Fuzzy search edit distance (0-2)")
	cmd.Flags().Bool("exact", false, "Use exact matching only")
	cmd.Flags().Bool("tui", false, "Launch interactive TUI search interface")
	cmd.Flags().Bool("verbose-output", false, "Show detailed output instead of compact format")
	cmd.Flags().StringSlice("tags", nil, "Filter by tags (comma-separated)")
	cmd.Flags().StringSlice("exclude-tags", nil, "Exclude commands with these tags (comma-separated)")
	cmd.Flags().String("tag-mode", "any", "Tag matching mode: 'any' or 'all'")

	return cmd
}

// importCmd imports history from existing shell history files
func importCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import [source]",
		Short: "Import history from existing shell history files",
		Long: `Import command history from existing shell history files (bash, zsh)
into the encrypted CommandChronicles database.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			source := "auto"
			if len(args) > 0 {
				source = args[0]
			}

			// Get flags
			format, _ := cmd.Flags().GetString("format")
			filePath, _ := cmd.Flags().GetString("file")
			deduplicate, _ := cmd.Flags().GetBool("deduplicate")
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			// Initialize database and storage
			db, err := storage.NewDatabase(cfg, nil)
			if err != nil {
				return fmt.Errorf("failed to initialize database: %w", err)
			}
			defer db.Close()

			// Initialize auth manager to handle session
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authMgr.Close()

			// Check if session is active
			if !authMgr.IsSessionActive() {
				return fmt.Errorf("no active session found, please unlock first using 'ccr unlock'")
			}

			// Load session key
			sessionKey, err := authMgr.LoadSessionKey()
			if err != nil {
				return fmt.Errorf("failed to load session key: %w", err)
			}

			// Initialize secure storage
			store, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:          cfg,
				CreateIfMissing: true,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize secure storage: %w", err)
			}
			defer store.Close()

			// Unlock storage with session key
			if err := store.UnlockWithKey(sessionKey); err != nil {
				return fmt.Errorf("failed to unlock storage: %w", err)
			}

			// Determine shell format and file path
			shell := format
			if shell == "auto" {
				if source != "auto" {
					shell = source
				} else {
					// Try to detect from environment
					shell = os.Getenv("SHELL")
					if shell != "" {
						shell = filepath.Base(shell)
					} else {
						shell = "bash" // Default to bash
					}
				}
			}

			// Determine file path
			if filePath == "" {
				var err error
				filePath, err = history.DetectHistoryFile(shell)
				if err != nil {
					return fmt.Errorf("failed to detect history file for %s: %w", shell, err)
				}
			}

			// Verify file exists
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				return fmt.Errorf("history file not found: %s", filePath)
			}

			formatter.Setup("Importing %s history from: %s", shell, filePath)

			// Import options
			opts := &history.ImportOptions{
				Deduplicate: deduplicate,
				SkipErrors:  true,
				SessionID:   fmt.Sprintf("imported-%s", shell),
			}

			// Perform import based on shell type
			var result *history.ImportResult
			switch strings.ToLower(shell) {
			case "bash":
				result, err = history.ImportBashHistory(store, filePath, opts)
			case "zsh":
				result, err = history.ImportZshHistory(store, filePath, opts)
			default:
				return fmt.Errorf("unsupported shell format: %s (supported: bash, zsh)", shell)
			}

			if err != nil {
				return fmt.Errorf("import failed: %w", err)
			}

			// Report results
			formatter.Separator()
			formatter.Success("Import completed successfully!")
			formatter.Stats("Total records processed: %d", result.TotalRecords)
			formatter.Stats("Records imported: %d", result.ImportedRecords)
			formatter.Stats("Records skipped: %d", result.SkippedRecords)

			if len(result.Errors) > 0 {
				formatter.Warning("Errors encountered: %d", len(result.Errors))
				if len(result.Errors) <= 5 {
					formatter.Info("Error details:")
					for _, err := range result.Errors {
						formatter.Info("  - %s", err.Error())
					}
				} else {
					formatter.Info("First 5 errors:")
					for i := 0; i < 5; i++ {
						formatter.Info("  - %s", result.Errors[i].Error())
					}
					formatter.Info("  ... and %d more errors", len(result.Errors)-5)
				}
			}

			return nil
		},
	}

	cmd.Flags().String("format", "auto", "Source format (auto, bash, zsh)")
	cmd.Flags().String("file", "", "Specific history file to import")
	cmd.Flags().Bool("deduplicate", true, "Remove duplicate commands during import")

	return cmd
}

// exportCmd exports history to various formats
func exportCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export [format]",
		Short: "Export command history to various formats",
		Long: `Export your encrypted command history to various formats for backup
or migration purposes.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			format := "json"
			if len(args) > 0 {
				format = args[0]
			}

			// Get flags
			outputFile, _ := cmd.Flags().GetString("output")
			sinceStr, _ := cmd.Flags().GetString("since")
			untilStr, _ := cmd.Flags().GetString("until")
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			// Validate export format
			exportFormat, err := history.ValidateExportFormat(format)
			if err != nil {
				return err
			}

			// Initialize database and storage
			db, err := storage.NewDatabase(cfg, nil)
			if err != nil {
				return fmt.Errorf("failed to initialize database: %w", err)
			}
			defer db.Close()

			// Initialize auth manager to handle session
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authMgr.Close()

			// Check if session is active
			if !authMgr.IsSessionActive() {
				return fmt.Errorf("no active session found, please unlock first using 'ccr unlock'")
			}

			// Load session key
			sessionKey, err := authMgr.LoadSessionKey()
			if err != nil {
				return fmt.Errorf("failed to load session key: %w", err)
			}

			// Initialize secure storage
			store, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:          cfg,
				CreateIfMissing: true,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize secure storage: %w", err)
			}
			defer store.Close()

			// Unlock storage with session key
			if err := store.UnlockWithKey(sessionKey); err != nil {
				return fmt.Errorf("failed to unlock storage: %w", err)
			}

			// Parse time filters
			var since, until *time.Time
			if sinceStr != "" {
				t, err := time.Parse(time.RFC3339, sinceStr)
				if err != nil {
					return fmt.Errorf("invalid since time format, use RFC3339 (e.g., 2023-01-01T00:00:00Z): %w", err)
				}
				since = &t
			}
			if untilStr != "" {
				t, err := time.Parse(time.RFC3339, untilStr)
				if err != nil {
					return fmt.Errorf("invalid until time format, use RFC3339 (e.g., 2023-12-31T23:59:59Z): %w", err)
				}
				until = &t
			}

			// Generate default output path if not specified
			if outputFile == "" {
				outputFile = history.GenerateDefaultOutputPath(exportFormat, ".")
			}

			// Export options
			opts := &history.ExportOptions{
				Format:    string(exportFormat),
				OutputDir: filepath.Dir(outputFile),
				Since:     since,
				Until:     until,
			}

			formatter.Setup("Exporting history to %s format...", exportFormat)

			// Perform export
			result, err := history.ExportHistory(store, exportFormat, outputFile, opts)
			if err != nil {
				return fmt.Errorf("export failed: %w", err)
			}

			// Report results
			formatter.Separator()
			formatter.Success("Export completed successfully!")
			formatter.Stats("Records exported: %d", result.ExportedRecords)
			formatter.Stats("Output file: %s", result.OutputFile)
			formatter.Stats("Format: %s", result.Format)
			formatter.Stats("Bytes written: %d", result.BytesWritten)
			formatter.Stats("Exported at: %s", result.ExportedAt.Format(time.RFC3339))

			return nil
		},
	}

	cmd.Flags().String("output", "", "Output file (default: stdout)")
	cmd.Flags().String("since", "", "Export entries since time")
	cmd.Flags().String("until", "", "Export entries until time")

	return cmd
}

// statsCmd displays statistics and analytics
func statsCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Display command history statistics and analytics",
		Long: `Display comprehensive statistics about your command history including
frequency analysis, success rates, directory usage, and time patterns.

Examples:
  ccr stats                    # Show overall statistics
  ccr stats --period=1d        # Show last 24 hours
  ccr stats --detailed         # Show detailed breakdown
  ccr stats --top=5            # Show top 5 commands
  ccr stats --format=json      # Output as JSON`,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := logger.GetLogger()

			// Parse flags
			period, _ := cmd.Flags().GetString("period")
			detailed, _ := cmd.Flags().GetBool("detailed")
			top, _ := cmd.Flags().GetInt("top")
			format, _ := cmd.Flags().GetString("format")
			session, _ := cmd.Flags().GetString("session")
			hostname, _ := cmd.Flags().GetString("hostname")
			directory, _ := cmd.Flags().GetString("directory")
			command, _ := cmd.Flags().GetString("command")
			minOccurrences, _ := cmd.Flags().GetInt("min-occurrences")
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			log.Info().
				Str("period", period).
				Bool("detailed", detailed).
				Int("top", top).
				Msg("Generating command statistics")

			// Validate period
			var statsPeriod stats.StatsPeriod
			switch period {
			case "all":
				statsPeriod = stats.PeriodAll
			case "1d":
				statsPeriod = stats.PeriodDay
			case "1w":
				statsPeriod = stats.PeriodWeek
			case "1m":
				statsPeriod = stats.PeriodMonth
			case "1y":
				statsPeriod = stats.PeriodYear
			default:
				return fmt.Errorf("invalid period: %s (must be: all, 1d, 1w, 1m, 1y)", period)
			}

			// Initialize components
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authMgr.Close()

			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:          cfg,
				CreateIfMissing: false,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize secure storage: %w", err)
			}

			// Load session key and unlock storage
			sessionKey, err := authMgr.LoadSessionKey()
			if err != nil {
				return fmt.Errorf("failed to load session key: %w", err)
			}

			// Unlock storage with session key
			if err := storage.UnlockWithKey(sessionKey); err != nil {
				return fmt.Errorf("failed to unlock storage: %w", err)
			}

			// Create stats engine
			statsEngine := stats.NewStatsEngine(cfg, storage, authMgr)

			// Generate statistics
			opts := &stats.StatsOptions{
				Period:          statsPeriod,
				TopN:            top,
				MinOccurrences:  minOccurrences,
				SessionFilter:   session,
				HostnameFilter:  hostname,
				DirectoryFilter: directory,
				CommandFilter:   command,
			}

			result, err := statsEngine.GenerateStats(opts)
			if err != nil {
				return fmt.Errorf("failed to generate statistics: %w", err)
			}

			// Output results
			switch format {
			case "json":
				return outputStatsJSON(result)
			default:
				return outputStatsText(result, detailed, formatter)
			}
		},
	}

	cmd.Flags().String("period", "all", "Time period for stats (1d, 1w, 1m, 1y, all)")
	cmd.Flags().Bool("detailed", false, "Show detailed breakdown")
	cmd.Flags().Int("top", 10, "Number of top items to show")
	cmd.Flags().String("format", "text", "Output format (text, json)")
	cmd.Flags().String("session", "", "Filter by session ID")
	cmd.Flags().String("hostname", "", "Filter by hostname")
	cmd.Flags().String("directory", "", "Filter by working directory")
	cmd.Flags().String("command", "", "Filter by command pattern")
	cmd.Flags().Int("min-occurrences", 1, "Minimum occurrences to include")

	return cmd
}

// outputStatsJSON outputs statistics in JSON format
func outputStatsJSON(result *stats.StatsResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// outputStatsText outputs statistics in human-readable format
func outputStatsText(result *stats.StatsResult, detailed bool, formatter *output.Formatter) error {
	formatter.Header("Command History Statistics")

	// Overall statistics
	formatter.Stats("Overall Summary")
	formatter.Stats("├─ Total Commands: %d", result.Overall.TotalCommands)
	formatter.Stats("├─ Unique Commands: %d", result.Overall.UniqueCommands)
	formatter.Stats("├─ Success Rate: %.1f%%", result.Overall.OverallSuccessRate)
	formatter.Stats("├─ Avg Duration: %dms", result.Overall.AvgDuration)
	formatter.Stats("├─ Total Directories: %d", result.Overall.TotalDirectories)
	formatter.Stats("├─ Total Sessions: %d", result.Overall.TotalSessions)

	if !result.Overall.EarliestCommand.IsZero() && !result.Overall.LatestCommand.IsZero() {
		formatter.Stats("├─ Time Span: %s to %s",
			result.Overall.EarliestCommand.Format("2006-01-02 15:04"),
			result.Overall.LatestCommand.Format("2006-01-02 15:04"))
		formatter.Stats("└─ Period Analyzed: %s", string(result.Period))
	} else {
		formatter.Stats("└─ Period Analyzed: %s", string(result.Period))
	}

	// Top commands
	if len(result.TopCommands) > 0 {
		formatter.Separator()
		formatter.Stats("[TOP] Most Used Commands")
		for i, cmd := range result.TopCommands {
			formatter.Stats("%2d. %-15s %4d uses  %.1f%% success  %dms avg",
				i+1, cmd.Command, cmd.Count, cmd.SuccessRate, cmd.AvgDuration)
		}
	}

	// Top directories
	if len(result.TopDirectories) > 0 && detailed {
		formatter.Separator()
		formatter.Stats("[DIR] Most Active Directories")
		for i, dir := range result.TopDirectories {
			displayDir := dir.Directory
			if len(displayDir) > 50 {
				displayDir = "..." + displayDir[len(displayDir)-47:]
			}
			formatter.Stats("%2d. %-50s %4d commands  %.1f%% success",
				i+1, displayDir, dir.Count, dir.SuccessRate)
		}
	}

	// Time patterns
	// Hourly and daily patterns
	if detailed {
		formatter.Separator()
		formatter.Stats("[TIME] Activity by Hour of Day")
		for _, hour := range result.HourlyPattern {
			if hour.Count > 0 {
				bar := strings.Repeat("█", hour.Count/10+1)
				formatter.Stats("%2d:00 %4d │%s", hour.Hour, hour.Count, bar)
			}
		}

		formatter.Separator()
		formatter.Stats("[DATE] Activity by Day of Week")
		for _, day := range result.DailyPattern {
			if day.Count > 0 {
				bar := strings.Repeat("█", day.Count/10+1)
				formatter.Stats("%-9s %4d │%s", day.DayName, day.Count, bar)
			}
		}
	}

	// Sessions
	// Session analysis
	if len(result.Sessions) > 0 && detailed {
		formatter.Separator()
		formatter.Stats("[SESSION] Session Activity")
		for i, session := range result.Sessions {
			if i >= 5 { // Limit to top 5 sessions
				break
			}
			formatter.Stats("Session %s: %d commands, %.1f%% success, %s duration",
				session.SessionID[:8]+"...", session.CommandCount, session.SuccessRate,
				time.Duration(session.Duration*int64(time.Millisecond)).String())
		}
	}

	formatter.Separator()
	formatter.Info("Statistics generated at %s", result.GeneratedAt.Format("2006-01-02 15:04:05"))
	formatter.Info("Records analyzed: %d", result.RecordsAnalyzed)

	return nil
}

// lockCmd locks the session and requires password re-entry
func lockCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lock",
		Short: "Lock the session and require password re-entry",
		Long: `Lock the current session, clearing any cached encryption keys
and requiring password re-entry for subsequent operations.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := logger.GetLogger().WithComponent("lock")
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			// Create auth manager
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize authentication: %w", err)
			}

			// Check if user exists
			if !authMgr.UserExists() {
				fmt.Println("CommandChronicles not initialized. Run 'ccr init' first.")
				return nil
			}

			// Check if session is active
			if !authMgr.IsSessionActive() {
				formatter.Info("Session is already locked.")
				return nil
			}

			// Lock session
			if err := authMgr.LockSession(); err != nil {
				return fmt.Errorf("failed to lock session: %w", err)
			}

			formatter.Success("Session locked successfully.")
			formatter.IfVerbose(func() {
				formatter.Tip("Use 'ccr unlock' to unlock your session.")
			})

			log.Info().Msg("Session locked successfully")
			return nil
		},
	}

	return cmd
}

// unlockCmd unlocks the session with password entry
func unlockCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "unlock",
		Short: "Unlock the session with password entry",
		Long: `Unlock the session by entering your password and deriving the encryption key.
This will cache the key for future operations until timeout or manual lock.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := logger.GetLogger().WithComponent("unlock")
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			// Create auth manager
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize authentication: %w", err)
			}

			// Check if user exists
			if !authMgr.UserExists() {
				fmt.Println("CommandChronicles not initialized. Run 'ccr init' first.")
				return nil
			}

			// Cleanup expired sessions before checking active status
			if err := authMgr.CleanupExpiredSessions(); err != nil {
				log.WithError(err).Debug().Msg("Failed to cleanup expired sessions")
			}

			// Check if session is already active
			if authMgr.IsSessionActive() {
				fmt.Println("Session is already unlocked.")
				return nil
			}

			// Get user info
			user, err := authMgr.GetUser()
			if err != nil {
				return fmt.Errorf("failed to get user info: %w", err)
			}

			// Prompt for password
			password, err := promptForPassword(fmt.Sprintf("Enter password for %s: ", user.Username))
			if err != nil {
				return fmt.Errorf("failed to get password: %w", err)
			}
			defer security.SecureWipeString(&password)

			// Verify password and get key
			keys, err := authMgr.VerifyPassword(user.Username, password)
			if err != nil {
				formatter.Error("Invalid password.")
				return nil
			}

			// Store session key
			// Store session key for subsequent operations
			if err := authMgr.StoreSessionKey(keys.LocalKey); err != nil {
				return fmt.Errorf("failed to store session key: %w", err)
			}

			formatter.Success("Session unlocked successfully.")
			if verbose {
				fmt.Println("Your commands will now be recorded until the session expires or is locked.")
			}

			log.Info().Msg("Session unlocked successfully")
			return nil
		},
	}

	return cmd
}

// changePasswordCmd changes the user's password
func changePasswordCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "change-password",
		Short: "Change your password",
		Long: `Change your password and re-encrypt stored data with the new key.
This will require entering your current password and setting a new one.
If sync is enabled, this will also change your remote password.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := logger.GetLogger().WithComponent("change-password")
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			// Initialize auth manager for proper session management
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authMgr.Close()

			// Check if user exists
			if !authMgr.UserExists() {
				fmt.Println("CommandChronicles not initialized. Run 'ccr init' first.")
				return nil
			}

			// Get user info
			user, err := authMgr.GetUser()
			if err != nil {
				return fmt.Errorf("failed to get user info: %w", err)
			}

			fmt.Printf("Changing password for user '%s'\n", user.Username)
			if cfg.Sync.Enabled && cfg.Sync.Email != "" {
				fmt.Printf("This will also update your remote password.\n")
			}
			fmt.Println()

			// Prompt for current password
			currentPassword, err := promptForPassword("Enter current password: ")
			if err != nil {
				return fmt.Errorf("failed to get current password: %w", err)
			}
			defer secureClearString(&currentPassword)

			// Prompt for new password
			newPassword, err := promptForPassword("Enter new password (min 8 characters): ")
			if err != nil {
				return fmt.Errorf("failed to get new password: %w", err)
			}
			defer secureClearString(&newPassword)

			if len(newPassword) < 8 {
				return fmt.Errorf("new password must be at least 8 characters long")
			}

			// Confirm new password
			confirmPassword, err := promptForPassword("Confirm new password: ")
			if err != nil {
				return fmt.Errorf("failed to get password confirmation: %w", err)
			}
			defer secureClearString(&confirmPassword)

			if newPassword != confirmPassword {
				return fmt.Errorf("passwords do not match")
			}

			// Get session key using proper session management
			sessionKey, err := getSearchSessionKey(authMgr, log)
			if err != nil {
				return fmt.Errorf("failed to get session key: %w", err)
			}

			// Initialize storage
			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:              cfg,
				CreateIfMissing:     true,
				ValidatePermissions: true,
				EnableSecureDelete:  true,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			// Unlock storage with session key
			if err := storage.UnlockWithKey(sessionKey); err != nil {
				return fmt.Errorf("failed to unlock storage: %w", err)
			}

			// Create login manager with the unlocked storage
			loginMgr, err := login.NewLoginManagerWithStorage(cfg, storage)
			if err != nil {
				return fmt.Errorf("failed to initialize login manager: %w", err)
			}
			defer loginMgr.Close()

			// Change password using login manager
			fmt.Println("\nChanging password...")
			if err := loginMgr.ChangePassword(currentPassword, newPassword); err != nil {
				if strings.Contains(err.Error(), "invalid current password") {
					formatter.Error("Current password is incorrect.")
					return nil
				}
				if strings.Contains(err.Error(), "local password already changed") {
					formatter.Warning("Local password was changed but remote password update failed.")
					if verbose {
						fmt.Println("Your local password has been changed. You may need to manually sync or retry.")
					}
					return nil
				}
				return fmt.Errorf("failed to change password: %w", err)
			}

			// Session is automatically updated by LoginManager
			formatter.Success("Your session remains active with the new password.")

			log.Info().Msg("Password changed successfully")
			return nil
		},
	}

	return cmd
}

// applyAutoTags applies auto-tagging rules to a command record based on configuration
func applyAutoTags(record *storage.CommandRecord, cfg *config.Config) {
	log := logger.GetLogger().WithComponent("auto-tag")

	log.Debug().
		Bool("tags_enabled", cfg.Tags.Enabled).
		Bool("auto_tagging", cfg.Tags.AutoTagging).
		Str("command", record.Command).
		Int("rule_count", len(cfg.Tags.AutoTagRules)).
		Msg("Processing auto-tagging")

	if !cfg.Tags.Enabled || !cfg.Tags.AutoTagging {
		log.Debug().Msg("Auto-tagging disabled")

		return
	}

	command := strings.TrimSpace(record.Command)
	if command == "" {
		log.Debug().Msg("Empty command, skipping auto-tagging")
		return
	}

	// Apply auto-tagging rules from configuration
	appliedTags := 0
	for prefix, tag := range cfg.Tags.AutoTagRules {
		if strings.HasPrefix(command, prefix) {
			log.Debug().
				Str("prefix", prefix).
				Str("tag", tag).
				Msg("Auto-tag rule matched, adding tag")

			// Add tag if it doesn't already exist
			if err := record.AddTag(tag); err != nil {
				log.Warn().
					Err(err).
					Str("tag", tag).
					Msg("Failed to add auto-tag")

			} else {
				appliedTags++
			}
		}
	}

	log.Debug().
		Int("applied_tags", appliedTags).
		Strs("final_tags", record.Tags).
		Msg("Auto-tagging completed")
}

// recordCmd records a command to history (used by shell hooks)
func recordCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:    "record",
		Short:  "Record a command to history (internal use by shell hooks)",
		Hidden: true, // Hide from help since it's for internal use
		RunE: func(cmd *cobra.Command, args []string) error {
			log := logger.GetLogger().WithComponent("record")

			// Get flag values
			command, _ := cmd.Flags().GetString("command")
			exitCode, _ := cmd.Flags().GetInt("exit-code")
			duration, _ := cmd.Flags().GetInt64("duration")
			workingDir, _ := cmd.Flags().GetString("directory")
			sessionID, _ := cmd.Flags().GetString("session")

			// Validate required fields
			if command == "" {
				return fmt.Errorf("command is required")
			}

			if workingDir == "" {
				if wd, err := os.Getwd(); err == nil {
					workingDir = wd
				} else {
					return fmt.Errorf("failed to get working directory: %w", err)
				}
			}

			// Get or generate session ID using session manager
			if sessionID == "" {
				sessionMgr, err := shell.NewSessionManager(cfg)
				if err != nil {
					log.WithError(err).Warn().Msg("Failed to create session manager, using fallback")
					sessionID = generateSessionID()
				} else {
					if sid, err := sessionMgr.GetCurrentSessionID(); err == nil {
						sessionID = sid
					} else {
						sessionID = generateSessionID()
					}
				}
			}

			// Capture additional context
			hostname, err := os.Hostname()
			if err != nil {
				log.WithError(err).Warn().Msg("Failed to get hostname, using localhost")
				hostname = "localhost"
			}

			currentUser, err := user.Current()
			userName := "unknown"
			if err == nil {
				userName = currentUser.Username
			}

			shellType := os.Getenv("SHELL")
			if shellType == "" {
				shellType = "unknown"
			} else {
				shellType = filepath.Base(shellType)
			}

			// Create command record
			record := storage.NewCommandRecord(command, exitCode, duration, workingDir, sessionID, hostname)
			record.User = userName
			record.Shell = shellType
			record.TTY = os.Getenv("TTY")

			// Enrich record with additional context
			contextCapture := shell.NewContextCapture()
			contextCapture.EnrichRecord(record)

			// Apply auto-tagging if enabled (do this BEFORE storage operations to avoid early exits)
			applyAutoTags(record, cfg)

			// Store the record
			secStorage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:              cfg,
				CreateIfMissing:     true,
				ValidatePermissions: true,
			})
			if err != nil {
				log.WithError(err).Debug().Msg("Failed to initialize secure storage")
				return nil // Fail silently to not block shell
			}
			defer secStorage.Close()

			// Try to unlock storage with existing session from auth system
			if secStorage.IsLocked() {
				log.Debug().Msg("Storage is locked, attempting to load session key from auth system")

				// Create auth manager
				authMgr, err := auth.NewAuthManager(cfg)
				if err != nil {
					log.WithError(err).Debug().Msg("Failed to create auth manager")
					return nil // Fail silently for shell hooks
				}

				// Cleanup expired sessions before loading
				if err := authMgr.CleanupExpiredSessions(); err != nil {
					log.WithError(err).Debug().Msg("Failed to cleanup expired sessions")
				}

				// Try to load session key from auth system (this automatically renews the session)
				key, err := authMgr.LoadSessionKey()
				if err != nil {
					log.WithError(err).Debug().Msg("No active session for recording")
					return nil // Fail silently for shell hooks
				}

				// Log session status for debugging
				if remaining, err := authMgr.GetSessionTimeRemaining(); err == nil {
					log.WithField("session_remaining", remaining.String()).Debug().Msg("Session renewed during command recording")
				}

				// Unlock storage with auth-provided key
				if err := secStorage.UnlockWithKey(key); err != nil {
					log.WithError(err).Debug().Msg("Failed to unlock storage with session key")
					return nil // Fail silently for shell hooks
				}
			}

			// Store the record
			result, err := secStorage.Store(record)
			if err != nil {
				log.WithError(err).Error().Msg("Failed to store command record")
				return fmt.Errorf("failed to store record: %w", err)
			}

			log.WithFields(map[string]interface{}{
				"record_id":      result.RecordID,
				"bytes_stored":   result.BytesStored,
				"command_length": len(command),
			}).Debug().Msg("Command recorded successfully")

			return nil
		},
	}

	cmd.Flags().String("command", "", "Command text to record")
	cmd.Flags().Int("exit-code", 0, "Exit code of the command")
	cmd.Flags().Int64("duration", 0, "Command duration in milliseconds")
	cmd.Flags().String("directory", "", "Working directory")
	cmd.Flags().String("session", "", "Session ID")

	return cmd
}

// sessionEndCmd handles ending a shell session
func sessionEndCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:    "session-end [session-id]",
		Short:  "End a shell session (internal use by shell hooks)",
		Hidden: true, // Hide from help since it's for internal use
		RunE: func(cmd *cobra.Command, args []string) error {
			log := logger.GetLogger().WithComponent("session-end")

			sessionID := ""
			if len(args) > 0 {
				sessionID = args[0]
			}

			// If no session ID provided, try to get from environment
			if sessionID == "" {
				sessionID = os.Getenv("CCR_SESSION_ID")
			}

			if sessionID == "" {
				log.Debug().Msg("No session ID provided for session end")
				return nil // Fail silently
			}

			// Create session manager and end the session
			sessionMgr, err := shell.NewSessionManager(cfg)
			if err != nil {
				log.WithError(err).Debug().Msg("Failed to create session manager")
				return nil // Fail silently
			}

			if err := sessionMgr.EndCurrentSession(); err != nil {
				log.WithError(err).Debug().Msg("Failed to end session")
				return nil // Fail silently
			}

			log.WithField("session_id", sessionID).Debug().Msg("Session ended")
			return nil
		},
	}

	return cmd
}

// installHooksCmd installs shell integration hooks
func uninstallHooksCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall-hooks [shell]",
		Short: "Remove shell integration hooks for command recording",
		Long: `Remove shell integration hooks and source lines from shell configuration files.
Supports bash and zsh shells. If no shell is specified, auto-detects current shell.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := logger.GetLogger().WithComponent("uninstall-hooks")
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			// Determine target shell
			targetShell := ""
			if len(args) > 0 {
				targetShell = args[0]
			} else {
				// Auto-detect shell
				shellPath := os.Getenv("SHELL")
				if shellPath != "" {
					targetShell = filepath.Base(shellPath)
				}
			}

			if targetShell == "" {
				return fmt.Errorf("could not determine shell type. Please specify: bash or zsh")
			}

			// Validate shell
			if targetShell != "bash" && targetShell != "zsh" {
				return fmt.Errorf("unsupported shell: %s. Supported shells: bash, zsh", targetShell)
			}

			// Create hook manager
			hookMgr, err := shell.NewHookManager(cfg)
			if err != nil {
				log.WithError(err).Error().Msg("Failed to create hook manager")
				return fmt.Errorf("failed to initialize hook manager: %w", err)
			}

			// Check if installed
			configPath, err := hookMgr.GetShellConfigPath(targetShell)
			if err != nil {
				log.WithError(err).Error().Msg("Failed to detect shell config")
				return fmt.Errorf("failed to detect shell configuration: %w", err)
			}

			installed, err := hookMgr.IsAlreadyInstalled(configPath)
			if err != nil {
				log.WithError(err).Error().Msg("Failed to check installation status")
				return fmt.Errorf("failed to check installation status: %w", err)
			}

			if !installed {
				formatter.Warning("CommandChronicles is not installed in %s", configPath)
				if verbose {
					fmt.Println("Nothing to uninstall.")
				}
				return nil
			}

			// Uninstall hooks
			if err := hookMgr.UninstallHooks(targetShell); err != nil {
				log.WithError(err).Error().Msg("Failed to uninstall hooks")
				return fmt.Errorf("failed to uninstall %s hooks: %w", targetShell, err)
			}

			formatter.Success("%s hooks uninstalled successfully!", strings.Title(targetShell))
			if verbose {
				fmt.Printf("Removed CommandChronicles integration from: %s\n", configPath)
			}
			fmt.Println()
			fmt.Println("Restart your shell or run the following to apply changes:")
			switch targetShell {
			case "bash":
				fmt.Println("source ~/.bashrc")
			case "zsh":
				fmt.Println("source ~/.zshrc")
			}

			log.WithField("shell", targetShell).Info().Msg("Shell hooks uninstalled successfully")
			return nil
		},
	}

	return cmd
}

func installHooksCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install-hooks [shell]",
		Short: "Install shell integration hooks for command recording",
		Long: `Install shell integration hooks to enable automatic command recording.
Supports bash and zsh shells. If no shell is specified, auto-detects current shell.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := logger.GetLogger().WithComponent("install-hooks")
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			// Get flags
			autoInstall, _ := cmd.Flags().GetBool("auto")
			force, _ := cmd.Flags().GetBool("force")
			dryRun, _ := cmd.Flags().GetBool("dry-run")
			backupDir, _ := cmd.Flags().GetString("backup-dir")
			noBackup, _ := cmd.Flags().GetBool("no-backup")

			// Determine target shell
			targetShell := ""
			if len(args) > 0 {
				targetShell = args[0]
			} else {
				// Auto-detect shell
				shellPath := os.Getenv("SHELL")
				if shellPath != "" {
					targetShell = filepath.Base(shellPath)
				}
			}

			if targetShell == "" {
				return fmt.Errorf("could not determine shell type. Please specify: bash or zsh")
			}

			// Validate shell
			if targetShell != "bash" && targetShell != "zsh" {
				return fmt.Errorf("unsupported shell: %s. Supported shells: bash, zsh", targetShell)
			}

			// Apply backup directory configuration if specified
			if backupDir != "" {
				cfg.Shell.BackupDir = backupDir
			}

			// Create hook manager
			hookMgr, err := shell.NewHookManager(cfg)
			if err != nil {
				log.WithError(err).Error().Msg("Failed to create hook manager")
				return fmt.Errorf("failed to initialize hook manager: %w", err)
			}

			// Handle automatic installation
			if autoInstall {
				if dryRun {
					// Show what would be done
					configPath, err := hookMgr.GetShellConfigPath(targetShell)
					if err != nil {
						return fmt.Errorf("failed to detect shell config: %w", err)
					}

					fmt.Printf("[INFO] Dry run - would perform the following actions:\n\n")
					fmt.Printf("1. Generate %s hook script\n", targetShell)
					fmt.Printf("2. Detect shell config: %s\n", configPath)

					if !noBackup {
						fmt.Printf("3. Create backup of %s\n", configPath)
					}

					hookPath := hookMgr.GetHookPath(targetShell)
					fmt.Printf("4. Add source line to %s:\n", configPath)
					fmt.Printf("   source \"%s\"\n", hookPath)
					fmt.Printf("\nNo actual changes made (dry run mode).\n")
					return nil
				}

				// Validate backup requirement
				if noBackup {
					formatter.Warning("--no-backup specified. Configuration will be modified without backup.")
					fmt.Printf("Continue? (y/N): ")
					var response string
					fmt.Scanln(&response)
					if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
						fmt.Println("Installation cancelled.")
						return nil
					}
				}

				// Perform automatic installation
				fmt.Printf("Detecting shell configuration...\n")

				if err := hookMgr.InstallHooksAutomatically(targetShell, force); err != nil {
					log.WithError(err).Error().Msg("Automatic installation failed")
					formatter.Error("Automatic installation failed: %v", err)
					formatter.Warning("Falling back to manual installation...")

					// Fallback to manual installation
					if err := hookMgr.InstallHooks(targetShell); err != nil {
						return fmt.Errorf("failed to install %s hooks: %w", targetShell, err)
					}

					instructions := hookMgr.GenerateInstallInstructions(targetShell)
					fmt.Println(instructions)
					return nil
				}

				// Success message for automatic installation
				configPath, _ := hookMgr.GetShellConfigPath(targetShell)
				formatter.Done("Installation complete!")
				fmt.Printf("CommandChronicles is now active in your %s shell.\n", targetShell)
				fmt.Printf("Start a new shell session or run: source %s\n\n", configPath)
				fmt.Printf("Features enabled:\n")
				fmt.Printf("• Automatic command recording with metadata\n")
				fmt.Printf("• Press CTRL+R to launch interactive TUI search\n")
				fmt.Printf("• Graceful fallback to standard history if TUI unavailable\n")

				log.WithField("shell", targetShell).Info().Msg("Shell hooks installed automatically")
				return nil
			}

			// Manual installation (original behavior)
			if err := hookMgr.InstallHooks(targetShell); err != nil {
				log.WithError(err).Error().Msg("Failed to install hooks")
				return fmt.Errorf("failed to install %s hooks: %w", targetShell, err)
			}

			// Generate installation instructions
			instructions := hookMgr.GenerateInstallInstructions(targetShell)

			formatter.Success("%s hooks installed successfully!", strings.Title(targetShell))
			fmt.Println(instructions)
			if verbose {
				fmt.Println()
				fmt.Println("After adding the source line and restarting your shell, CommandChronicles will")
				fmt.Println("automatically record all your commands with rich context information.")
			}

			log.WithField("shell", targetShell).Info().Msg("Shell hooks installed successfully")
			return nil
		},
	}

	cmd.Flags().Bool("auto", false, "Automatically modify shell configuration files")
	cmd.Flags().Bool("force", false, "Overwrite existing hook files")
	cmd.Flags().Bool("dry-run", false, "Show what would be installed without actually installing")
	cmd.Flags().String("backup-dir", "", "Custom directory for configuration backups")
	cmd.Flags().Bool("no-backup", false, "Skip creating backup before modification (dangerous)")

	return cmd
}

func tuiCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tui [query]",
		Short: "Launch interactive TUI for command search",
		Long: `Launch the interactive Terminal User Interface (TUI) for searching command history.
The TUI provides real-time fuzzy search with rich metadata display and keyboard navigation.
This is the same interface activated by pressing the up arrow key in the shell.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get launch options from flags
			initialQuery := ""
			if len(args) > 0 {
				initialQuery = args[0]
			}

			fuzzyEnabled, _ := cmd.Flags().GetBool("fuzzy")
			maxResults, _ := cmd.Flags().GetInt("limit")

			// Create TUI options
			opts := &tui.TUIOptions{
				InitialQuery: initialQuery,
				FuzzyEnabled: fuzzyEnabled,
				MaxResults:   maxResults,
				Version:      version,
			}

			// Launch TUI with proper initialization
			return tui.Launch(cfg, opts)
		},
	}

	cmd.Flags().Bool("fuzzy", true, "Enable fuzzy search")
	cmd.Flags().Int("limit", cfg.Cache.HotCacheSize, "Maximum number of results to show")
	cmd.Flags().Bool("syntax", true, "Enable syntax highlighting")

	return cmd
}

// versionCmd displays detailed version information
func versionCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Display version information",
		Long:  "Display detailed version information about CommandChronicles CLI",
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			formatter.Print(`
===================================================================
                  CommandChronicles CLI
                      Version %s
===================================================================

Version:     %s
Build Date:  %s
Commit:      %s
Author:      %s
Homepage:    %s
  License:     MIT

  System Information:
  OS/Arch:     %s/%s
  Go Version:  %s

  Features:
  ✓ XChaCha20-Poly1305 encryption
  ✓ Argon2id key derivation
  ✓ Fuzzy search with Bleve
  ✓ Interactive TUI with Bubble Tea
  ✓ Shell integration (bash/zsh)
  ✓ Command metadata tracking
  ✓ Session management

`, version, version, date, commit, author, website,
				runtime.GOOS, runtime.GOARCH, runtime.Version())
			return nil
		},
	}

	return cmd
}

func debugCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "debug",
		Short: "Show debug information about the storage system",
		Long: `Display debug information including database status, record counts,
and storage system health. Useful for verifying command recording is working.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := logger.GetLogger().WithComponent("debug")
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			formatter.Header("CommandChronicles Debug Information")

			// Check database file
			dbPath := filepath.Join(cfg.DataDir, "history.db")
			if stat, err := os.Stat(dbPath); err == nil {
				formatter.Success("Database file exists: %s", dbPath)
				if verbose {
					fmt.Printf("   Size: %d bytes\n", stat.Size())
					fmt.Printf("   Modified: %s\n", stat.ModTime().Format("2006-01-02 15:04:05"))
				}
			} else {
				formatter.Error("Database file not found: %s", dbPath)
				return nil
			}

			// Try to initialize storage (read-only check)
			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:              cfg,
				CreateIfMissing:     false,
				ValidatePermissions: true,
			})
			if err != nil {
				formatter.Error("Failed to initialize storage: %v", err)
				return nil
			}
			defer storage.Close()

			// Check if storage is locked
			if storage.IsLocked() {
				formatter.Warning("Storage is locked (normal - requires authentication)")
			} else {
				formatter.Success("Storage is unlocked")

				if verbose {
					// Try to get basic stats if unlocked
					stats := storage.GetStats()
					formatter.Stats("Records stored: %d", stats.RecordsStored)
					formatter.Stats("Records retrieved: %d", stats.RecordsRetrieved)
					formatter.Stats("Bytes encrypted: %d", stats.BytesEncrypted)
					formatter.Stats("Security violations: %d", stats.SecurityViolations)
					if !stats.LastOperation.IsZero() {
						formatter.Stats("Last operation: %s", stats.LastOperation.Format("2006-01-02 15:04:05"))
					}
				}
			}

			// Check authentication and session status
			formatter.Separator()
			formatter.Stats("Authentication & Session Status:")
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				formatter.Error("Failed to create auth manager: %v", err)
			} else {
				defer authMgr.Close()

				if !authMgr.UserExists() {
					formatter.Error("User not initialized - run 'ccr init' first")
				} else {
					if user, err := authMgr.GetUser(); err == nil && verbose {
						formatter.Info("User: %s", user.Username)
						formatter.Info("Created: %s", user.CreatedAt.Format("2006-01-02 15:04:05"))
						formatter.Info("Last access: %s", user.LastAccess.Format("2006-01-02 15:04:05"))
					}

					if authMgr.IsSessionActive() {
						formatter.Success("Session is active")
						if remaining, err := authMgr.GetSessionTimeRemaining(); err == nil && verbose {
							if remaining > 0 {
								formatter.Info("Session expires in: %s", remaining.String())
							} else {
								formatter.Warning("Session has expired (will be cleaned up)")
							}
						}
					} else {
						formatter.Warning("Session is locked")
					}

					// Show session timeout configuration
					if verbose {
						timeoutSeconds := cfg.Security.SessionTimeout
						if timeoutSeconds > 0 {
							maxLifetime := time.Duration(timeoutSeconds) * time.Second
							activityTimeout := time.Duration(30*24*60*60) * time.Second // 1 month
							formatter.Info("Activity timeout: %s (renewable)", activityTimeout.String())
							formatter.Info("Maximum lifetime: %s (not renewable)", maxLifetime.String())
						} else {
							formatter.Info("Session timeout: disabled")
						}
					}
				}
			}

			// Raw database inspection (works even when locked)
			formatter.Separator()
			formatter.Stats("Database Contents (Raw):")
			db, err := sql.Open("sqlite", dbPath)
			if err != nil {
				formatter.Error("Failed to open database: %v", err)
			} else {
				defer db.Close()

				// Check record count
				var count int
				err = db.QueryRow("SELECT COUNT(*) FROM history").Scan(&count)
				if err != nil {
					formatter.Warning("Failed to count records: %v", err)
				} else {
					formatter.Stats("Total encrypted records: %d", count)
				}

				// Check table info
				var tableInfo string
				err = db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='history'").Scan(&tableInfo)
				if err != nil {
					formatter.Warning("Failed to get table info: %v", err)
				} else {
					formatter.Success("Table structure confirmed")
				}

				// Show recent activity (timestamps only, data is encrypted)
				if count > 0 {
					rows, err := db.Query("SELECT timestamp, session, hostname, created_at FROM history ORDER BY created_at DESC LIMIT 5")
					if err != nil {
						formatter.Warning("Failed to query recent records: %v", err)
					} else {
						defer rows.Close()
						if verbose {
							formatter.Info("Recent activity (last 5 records):")
							for rows.Next() {
								var timestamp, createdAt int64
								var session, hostname string
								if err := rows.Scan(&timestamp, &session, &hostname, &createdAt); err == nil {
									t := time.Unix(timestamp/1000, 0)
									fmt.Printf("   %s - Session: %s, Host: %s\n",
										t.Format("2006-01-02 15:04:05"), session, hostname)
								}
							}
						}
					}
				}
			}

			// Check session files
			sessionDir := filepath.Join(cfg.DataDir, "sessions")
			if stat, err := os.Stat(sessionDir); err == nil && stat.IsDir() {
				formatter.Success("Session directory exists: %s", sessionDir)

				if verbose {
					// Check for current session file
					sessionFile := filepath.Join(sessionDir, "current")
					if _, err := os.Stat(sessionFile); err == nil {
						if content, err := os.ReadFile(sessionFile); err == nil {
							formatter.Info("Current session: %s", strings.TrimSpace(string(content)))
						}
					} else {
						formatter.Info("No active session file")
					}
				}
			} else {
				formatter.Warning("Session directory not found: %s", sessionDir)
			}

			// Show hook installation status
			formatter.Separator()
			formatter.Stats("Hook Installation Status:")
			if _, err := os.Stat(cfg.Shell.BashHookPath); err == nil {
				formatter.Success("Bash hooks installed: %s", cfg.Shell.BashHookPath)
			} else {
				formatter.Error("Bash hooks not installed")
			}

			if _, err := os.Stat(cfg.Shell.ZshHookPath); err == nil {
				formatter.Success("Zsh hooks installed: %s", cfg.Shell.ZshHookPath)
			} else {
				formatter.Error("Zsh hooks not installed")
			}

			// Environment info
			formatter.Separator()
			formatter.Stats("Environment:")
			if verbose {
				formatter.Info("Config dir: %s", filepath.Dir(cfg.Shell.BashHookPath))
				formatter.Info("Data dir: %s", filepath.Dir(cfg.Database.Path))
			}
			if sessionID := os.Getenv("CCR_SESSION_ID"); sessionID != "" {
				formatter.Info("Shell session ID: %s", sessionID)
			} else {
				formatter.Info("Not in a hooked shell session")
			}

			formatter.Separator()
			formatter.Info("To test command recording:")
			formatter.Info("1. Run: ccr install-hooks bash")
			formatter.Info("2. Start new shell: bash")
			formatter.Info("3. Source hooks: source ~/.config/commandchronicles/hooks/bash_hooks.sh")
			formatter.Info("4. Run commands and check this debug output again")

			log.Info().Msg("Debug information displayed")
			return nil
		},
	}

	return cmd
}

// generateSessionID creates a new UUID-based session identifier
func generateSessionID() string {
	// Simple UUID v4 generation using crypto/rand
	b := make([]byte, 16)
	if _, err := os.ReadFile("/dev/urandom"); err == nil {
		if f, err := os.Open("/dev/urandom"); err == nil {
			defer f.Close()
			f.Read(b)
		}
	}

	// Set version (4) and variant bits
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant 10

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Helper functions for enhanced init flow

// clearScreen clears the terminal screen for better UX
func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

// promptAndInstallHooks asks user if they want to install hooks and does it
func promptAndInstallHooks(cfg *config.Config, formatter *output.Formatter) {
	clearScreen()
	formatter.Setup("Shell Hooks Installation")
	formatter.Info("CommandChronicles requires shell hooks to function properly.")
	formatter.Info("Without hooks, commands won't be automatically recorded.")

	fmt.Print("Install shell hooks automatically? [Y/n]: ")
	var response string
	fmt.Scanln(&response)

	if response == "" || strings.ToLower(response) == "y" || strings.ToLower(response) == "yes" {
		// Auto-detect shell
		targetShell := ""
		shellPath := os.Getenv("SHELL")
		if shellPath != "" {
			targetShell = filepath.Base(shellPath)
		}

		if targetShell == "" || (targetShell != "bash" && targetShell != "zsh") {
			targetShell = "bash" // Default to bash
		}

		// Create hook manager
		hookMgr, err := shell.NewHookManager(cfg)
		if err != nil {
			formatter.Warning("Failed to initialize hook manager: %v", err)
			formatter.Info("You can install hooks later with: ccr install-hooks")
			return
		}

		// Try automatic installation
		err = hookMgr.InstallHooksAutomatically(targetShell, false)
		if err != nil {
			formatter.Warning("Automatic installation failed: %v", err)
			formatter.Info("You can install hooks manually with: ccr install-hooks")
		} else {
			formatter.Success("Shell hooks installed successfully!")
			configPath, _ := hookMgr.GetShellConfigPath(targetShell)
			formatter.Info("Start a new shell session or run: source %s", configPath)
		}
	} else {
		formatter.Info("Skipped hooks installation. Install later with: ccr install-hooks")
	}
}

// promptAndEnableSync asks user if they want to enable background sync
func promptAndEnableSync(cfg *config.Config, formatter *output.Formatter) {
	clearScreen()
	formatter.Setup("Background Synchronization")
	formatter.Info("Enable background sync to keep your commands synchronized across devices.")
	formatter.Warning("Note: A subscription is required for sync functionality.")
	formatter.Info("Purchase subscription: https://commandchronicles.dev/pricing")
	formatter.Info("Learn more at: https://commandchronicles.dev")

	fmt.Print("Enable background synchronization? [Y/n]: ")
	var response string
	fmt.Scanln(&response)

	if response == "" || strings.ToLower(response) == "y" || strings.ToLower(response) == "yes" {
		if cfg.Sync.Email == "" {
			formatter.Warning("Sync not configured. Use 'ccr login --setup-sync' to configure sync.")
			formatter.Info("Purchase subscription: https://commandchronicles.dev/pricing")
			return
		}

		// Enable sync in config
		cfg.Sync.Enabled = true

		// Save configuration
		if err := saveConfigFile(cfg); err != nil {
			formatter.Warning("Failed to save sync configuration: %v", err)
			formatter.Info("Sync enabled for this session only")
		} else {
			formatter.Success("Background sync enabled successfully!")
		}
	} else {
		formatter.Info("Skipped sync setup. Enable later with: ccr sync enable")
	}
}

// promptAndImportHistory asks user if they want to import existing shell history
func promptAndImportHistory(cfg *config.Config, formatter *output.Formatter) {
	clearScreen()
	formatter.Setup("History Import")
	formatter.Info("Import your existing bash/zsh history to get started quickly.")

	fmt.Print("Import existing shell history? [Y/n]: ")
	var response string
	fmt.Scanln(&response)

	if response == "" || strings.ToLower(response) == "y" || strings.ToLower(response) == "yes" {
		// Auto-detect shell
		shell := ""
		shellPath := os.Getenv("SHELL")
		if shellPath != "" {
			shell = filepath.Base(shellPath)
		}

		if shell == "" || (shell != "bash" && shell != "zsh") {
			shell = "bash" // Default to bash
		}

		// Try to detect history file
		filePath, err := history.DetectHistoryFile(shell)
		if err != nil {
			formatter.Warning("Could not detect %s history file: %v", shell, err)
			formatter.Info("You can import history later with: ccr import")
			return
		}

		// Check if file exists
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			formatter.Warning("History file not found: %s", filePath)
			formatter.Info("You can import history later with: ccr import")
			return
		}

		// Initialize database and storage for import
		db, err := storage.NewDatabase(cfg, nil)
		if err != nil {
			formatter.Warning("Failed to initialize database for import: %v", err)
			formatter.Info("You can import history later with: ccr import")
			return
		}
		defer db.Close()

		// Initialize auth manager to handle session
		authMgr, err := auth.NewAuthManager(cfg)
		if err != nil {
			formatter.Warning("Failed to initialize auth manager for import: %v", err)
			formatter.Info("You can import history later with: ccr import")
			return
		}
		defer authMgr.Close()

		// Check if session is active
		if !authMgr.IsSessionActive() {
			formatter.Warning("No active session found for import")
			formatter.Info("You can import history later with: ccr import")
			return
		}

		// Load session key
		sessionKey, err := authMgr.LoadSessionKey()
		if err != nil {
			formatter.Warning("Failed to load session key for import: %v", err)
			formatter.Info("You can import history later with: ccr import")
			return
		}

		// Initialize secure storage
		store, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
			Config:          cfg,
			CreateIfMissing: true,
		})
		if err != nil {
			formatter.Warning("Failed to initialize storage for import: %v", err)
			formatter.Info("You can import history later with: ccr import")
			return
		}
		defer store.Close()

		// Unlock storage with session key
		if err := store.UnlockWithKey(sessionKey); err != nil {
			formatter.Warning("Failed to unlock storage for import: %v", err)
			formatter.Info("You can import history later with: ccr import")
			return
		}

		formatter.Setup("Importing %s history from: %s", shell, filePath)

		// Import options
		opts := &history.ImportOptions{
			Deduplicate: true,
			SkipErrors:  true,
			SessionID:   fmt.Sprintf("imported-%s", shell),
		}

		// Perform import
		var result *history.ImportResult
		switch strings.ToLower(shell) {
		case "bash":
			result, err = history.ImportBashHistory(store, filePath, opts)
		case "zsh":
			result, err = history.ImportZshHistory(store, filePath, opts)
		default:
			formatter.Warning("Unsupported shell: %s", shell)
			formatter.Info("You can import history later with: ccr import")
			return
		}

		if err != nil {
			formatter.Warning("Import failed: %v", err)
			formatter.Info("You can try importing manually with: ccr import")
		} else {
			formatter.Success("Import completed successfully!")
			formatter.Stats("Records imported: %d", result.ImportedRecords)
			if result.SkippedRecords > 0 {
				formatter.Stats("Records skipped: %d", result.SkippedRecords)
			}
		}
	} else {
		formatter.Info("Skipped history import. Import later with: ccr import")
	}
}

// getSearchSessionKey handles session key retrieval or authentication for CLI search
func getSearchSessionKey(authMgr *auth.AuthManager, log *logger.Logger) ([]byte, error) {
	// Clean up expired sessions
	if err := authMgr.CleanupExpiredSessions(); err != nil {
		log.WithError(err).Debug().Msg("Failed to cleanup expired sessions")
	}

	// Check if session is active
	if authMgr.IsSessionActive() {
		log.Debug().Msg("Active session found, loading session key")
		return authMgr.LoadSessionKey()
	}

	// No active session, need to authenticate
	log.Debug().Msg("No active session, authentication required")

	// Get user info
	user, err := authMgr.GetUser()
	if err != nil {
		return nil, fmt.Errorf("no user found - please run 'ccr init' first: %w", err)
	}

	// Prompt for password
	fmt.Printf("Enter password for %s: ", user.Username)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}

	// Verify password and get session key
	keys, err := authMgr.VerifyPassword(user.Username, string(password))
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Clear password from memory
	secureClearBytes(password)

	return keys.LocalKey, nil
}

// deleteCmd deletes command records by ID or pattern
func deleteCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete [ID|pattern]",
		Short: "Delete command records by ID or pattern",
		Long: `Delete command records from history by ID or pattern.

Examples:
  ccr delete 12847                    # Delete record with ID 12847
  ccr delete --pattern "git *"        # Delete all commands starting with "git"
  ccr delete --pattern "ls *" --dry-run  # Preview what would be deleted`,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := logger.GetLogger().WithComponent("delete")
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			// Get flags
			pattern, _ := cmd.Flags().GetString("pattern")
			dryRun, _ := cmd.Flags().GetBool("dry-run")
			force, _ := cmd.Flags().GetBool("force")

			// Initialize auth manager and get session
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authMgr.Close()

			sessionKey, err := getSearchSessionKey(authMgr, log)
			if err != nil {
				return fmt.Errorf("failed to get session key: %w", err)
			}

			// Initialize storage
			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:              cfg,
				CreateIfMissing:     true,
				ValidatePermissions: true,
				EnableSecureDelete:  true,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			if err := storage.UnlockWithKey(sessionKey); err != nil {
				return fmt.Errorf("failed to unlock storage: %w", err)
			}

			// Initialize cache and search service
			hybridCache := cache.NewCache(&cfg.Cache, storage)
			defer hybridCache.Close()

			searchService := search.NewSearchService(hybridCache, storage, cfg)
			defer searchService.Close()

			// Initialize deletion service
			deletionService := deletion.NewDeletionService(storage, hybridCache, searchService, authMgr, cfg)

			// Determine deletion type
			if pattern != "" {
				// Pattern deletion
				if err := deletionService.ValidatePattern(pattern); err != nil {
					return fmt.Errorf("invalid pattern: %w", err)
				}

				// Get preview stats
				stats, err := deletionService.GetDeletionStats(&deletion.DeletionRequest{
					Type:    deletion.DeletePattern,
					Pattern: pattern,
					DryRun:  true,
				})
				if err != nil {
					return fmt.Errorf("failed to get deletion stats: %w", err)
				}

				// Show preview
				formatter.Info("Pattern: %s", pattern)
				formatter.Stats("Matches: %d records", stats.TotalMatches)
				if stats.TotalMatches > 0 {
					formatter.Info("Range: %s to %s",
						stats.OldestRecord.Format("2006-01-02 15:04"),
						stats.NewestRecord.Format("2006-01-02 15:04"))
					fmt.Printf("Commands: ")
					first := true
					for cmd, count := range stats.Patterns {
						if !first {
							fmt.Printf(", ")
						}
						fmt.Printf("%s(%d)", cmd, count)
						first = false
					}
					fmt.Printf("\n")
				}

				if dryRun {
					formatter.Success("Dry-run completed. Use --force to confirm deletion.")
					return nil
				}

				// Confirm deletion
				if !force && stats.TotalMatches > 0 {
					fmt.Printf("\n")
					formatter.Warning("This will permanently delete %d records.", stats.TotalMatches)
					fmt.Printf("Continue? (y/N): ")
					var response string
					fmt.Scanln(&response)
					if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
						formatter.Error("Deletion cancelled.")
						return nil
					}
				}

				// Execute deletion
				result, err := deletionService.DeletePattern(pattern, false, force)
				if err != nil {
					return fmt.Errorf("pattern deletion failed: %w", err)
				}

				formatter.Success("Deleted %d records in %v", result.DeletedCount, result.Duration)

			} else if len(args) == 1 {
				// Single record deletion by ID
				recordID, err := strconv.ParseInt(args[0], 10, 64)
				if err != nil {
					return fmt.Errorf("invalid record ID '%s': must be a number", args[0])
				}

				// Confirm deletion
				if !force {
					formatter.Warning("Delete record ID %d?", recordID)
					fmt.Printf("(y/N): ")
					var response string
					fmt.Scanln(&response)
					if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
						formatter.Error("Deletion cancelled.")
						return nil
					}
				}

				// Execute deletion
				result, err := deletionService.DeleteRecord(recordID, force)
				if err != nil {
					return fmt.Errorf("record deletion failed: %w", err)
				}

				formatter.Success("Deleted record %d in %v", recordID, result.Duration)

			} else {
				return fmt.Errorf("specify either a record ID or use --pattern flag")
			}

			return nil
		},
	}

	cmd.Flags().String("pattern", "", "Delete all records matching pattern (e.g., 'git *')")
	cmd.Flags().Bool("dry-run", false, "Preview what would be deleted without actually deleting")
	cmd.Flags().Bool("force", false, "Skip confirmation prompts")

	return cmd
}

// wipeCmd wipes all command history
func wipeCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "wipe",
		Short: "Wipe all command history",
		Long: `Completely wipe all command history from the database.
This operation is irreversible and will delete ALL stored commands.

Use with caution and consider exporting your history first.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := logger.GetLogger().WithComponent("wipe")
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			// Get flags
			exportFirst, _ := cmd.Flags().GetString("export")
			force, _ := cmd.Flags().GetBool("force")

			// Initialize auth manager and get session
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authMgr.Close()

			sessionKey, err := getSearchSessionKey(authMgr, log)
			if err != nil {
				return fmt.Errorf("failed to get session key: %w", err)
			}

			// Initialize storage
			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:              cfg,
				CreateIfMissing:     true,
				ValidatePermissions: true,
				EnableSecureDelete:  true,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			if err := storage.UnlockWithKey(sessionKey); err != nil {
				return fmt.Errorf("failed to unlock storage: %w", err)
			}

			// Initialize cache and search service
			hybridCache := cache.NewCache(&cfg.Cache, storage)
			defer hybridCache.Close()

			searchService := search.NewSearchService(hybridCache, storage, cfg)
			defer searchService.Close()

			// Initialize deletion service
			deletionService := deletion.NewDeletionService(storage, hybridCache, searchService, authMgr, cfg)

			// Get statistics
			stats, err := deletionService.GetDeletionStats(&deletion.DeletionRequest{
				Type:   deletion.DeleteAll,
				DryRun: true,
			})
			if err != nil {
				return fmt.Errorf("failed to get deletion stats: %w", err)
			}

			// Show what will be deleted
			formatter.Warning("WIPE ALL COMMAND HISTORY")
			formatter.Stats("Total records: %d", stats.TotalMatches)
			if stats.TotalMatches > 0 && verbose {
				formatter.Info("Range: %s to %s",
					stats.OldestRecord.Format("2006-01-02 15:04"),
					stats.NewestRecord.Format("2006-01-02 15:04"))
			}

			if stats.TotalMatches == 0 {
				formatter.Success("No records found to delete.")
				return nil
			}

			// Strong confirmation required
			if !force {
				fmt.Printf("\n")
				formatter.Warning("This will PERMANENTLY DELETE ALL %d command records!", stats.TotalMatches)
				fmt.Printf("Type 'DELETE ALL' to confirm: ")
				reader := bufio.NewReader(os.Stdin)
				response, err := reader.ReadString('\n')
				if err != nil {
					formatter.Error("Failed to read input.")
					return nil
				}
				response = strings.TrimSpace(response)
				if response != "DELETE ALL" {
					formatter.Error("Wipe cancelled.")
					return nil
				}
			}

			// Execute wipe
			result, err := deletionService.DeleteAll(exportFirst, force)
			if err != nil {
				return fmt.Errorf("wipe failed: %w", err)
			}

			formatter.Success("Wiped %d records in %v", result.DeletedCount, result.Duration)
			if result.ExportedTo != "" && verbose {
				formatter.Info("Backup saved to: %s", result.ExportedTo)
			}

			return nil
		},
	}

	cmd.Flags().String("export", "", "Export history to file before wiping")
	cmd.Flags().Bool("force", false, "Skip confirmation prompts")

	return cmd
}

func syncCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Manage command history synchronization",
		Long: `Configure and control synchronization of command history across devices.

Note: Synchronization requires a premium subscription.
Purchase at: https://commandchronicles.dev/pricing`,
	}

	cmd.AddCommand(syncRegisterCmd(cfg))
	cmd.AddCommand(syncEnableCmd(cfg))
	cmd.AddCommand(syncDisableCmd(cfg))
	cmd.AddCommand(syncStatusCmd(cfg))
	cmd.AddCommand(syncNowCmd(cfg))
	cmd.AddCommand(syncIntegrityCmd(cfg))

	return cmd
}

func syncRegisterCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register with sync server using your credentials",
		Long:  "Register with sync server using the same credentials from your initialization.",
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			// 1. Create login manager
			loginMgr, err := login.NewLoginManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize login manager: %w", err)
			}
			defer loginMgr.Close()

			// 2. Get stored email
			storedEmail := cfg.Sync.Email
			if storedEmail == "" {
				return fmt.Errorf("no email found - please run 'ccr init' first")
			}

			// 3. Check if sync already enabled
			if cfg.Sync.Enabled {
				formatter.Success("Sync already enabled for %s", cfg.Sync.Email)
				return nil
			}

			formatter.Auth("Setting up sync for CommandChronicles")
			if verbose {
				fmt.Printf("Server: %s\n", cfg.GetSyncServerURL())
			}

			// 4. Prompt for email (with stored default)
			fmt.Printf("Email address [%s]: ", storedEmail)
			var inputEmail string
			fmt.Scanln(&inputEmail)
			if inputEmail == "" {
				inputEmail = storedEmail
			}

			// 5. Prompt for password
			password, err := promptForPassword("Password: ")
			if err != nil {
				return fmt.Errorf("failed to get password: %w", err)
			}
			defer secureClearString(&password)

			// 6. Register using LoginManager method
			formatter.Setup("Verifying credentials and setting up remote sync...")
			if verbose {
				fmt.Printf("Server: %s\n", cfg.GetSyncServerURL())
				fmt.Printf("Email: %s\n", inputEmail)
			}

			fmt.Print("Setting up remote sync...")
			response, err := loginMgr.RegisterRemoteSync(inputEmail, password)
			if err != nil {
				formatter.Error("Failed")
				if strings.Contains(err.Error(), "password doesn't match") {
					formatter.Tip("Please use the same password you used during 'ccr init'")
					if verbose {
						fmt.Printf("   (You can change your password later using 'ccr change-password')\n")
					}
				} else if strings.Contains(err.Error(), "cancelled") {
					formatter.Tip("Sync registration cancelled")
				}
				return err
			}
			formatter.Success("Success")

			// 7. Get user info for display
			user, err := loginMgr.AuthManager.GetUser()
			if err != nil {
				return fmt.Errorf("failed to get user info: %w", err)
			}

			// 8. Success summary
			formatter.Success("Setup complete!")
			if verbose {
				fmt.Printf("Username: %s\n", user.Username)
				fmt.Printf("Email: %s\n", inputEmail)
			}
			if response.UserID != "existing" {
				fmt.Printf("User ID: %s\n", response.UserID)
			}
			if response.DeviceID != "existing" {
				fmt.Printf("Device ID: %s\n", response.DeviceID)
			}
			if verbose {
				fmt.Printf("Server: %s\n", cfg.GetSyncServerURL())
			}
			formatter.Done("You're ready to use CommandChronicles with sync!")
			if verbose {
				fmt.Printf("\nNext steps:\n")
				fmt.Printf("  ccr sync now      - Start syncing your commands\n")
				fmt.Printf("  ccr sync status   - Check sync status\n")
			}

			return nil
		},
	}

	// No flags needed!
	return cmd
}

func syncEnableCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable command history synchronization",
		Long: `Enable synchronization using stored credentials.
Run 'ccr login' first to authenticate if you haven't already.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			// Create login manager to check auth status
			loginMgr, err := login.NewLoginManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize login manager: %w", err)
			}
			defer loginMgr.Close()

			// Check authentication status
			localOK, remoteOK := loginMgr.IsLoggedIn()

			if !localOK {
				formatter.Error("Not logged in")
				formatter.Tip("Run 'ccr login' first")
				return fmt.Errorf("not logged in")
			}

			if cfg.Sync.Email == "" {
				formatter.Error("Sync not configured")
				formatter.Tip("Run 'ccr login --setup-sync' first")
				return fmt.Errorf("sync not configured")
			}

			if !remoteOK {
				formatter.Error("Remote authentication required")
				formatter.Tip("Run 'ccr login' first")
				return fmt.Errorf("remote authentication required")
			}

			// Enable sync in config
			cfg.Sync.Enabled = true

			// Save configuration
			if err := saveConfigFile(cfg); err != nil {
				formatter.Warning("Failed to save configuration: %v", err)
				formatter.IfVerbose(func() {
					formatter.Info("Sync enabled for this session only")
				})
			} else {
				formatter.Success("Sync enabled successfully!")
			}

			formatter.Stats("Email: %s", cfg.Sync.Email)
			formatter.Stats("Server: %s", cfg.GetSyncServerURL())

			formatter.IfVerbose(func() {
				formatter.Separator()
				formatter.Info("Available commands:")
				formatter.Info("  ccr sync now      - Manual sync")
				formatter.Info("  ccr sync status   - Check sync status")
				formatter.Info("  ccr sync disable  - Disable sync")
			})

			return nil
		},
	}

	return cmd
}

// Helper function to save config file
func saveConfigFile(cfg *config.Config) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to determine home directory: %w", err)
	}

	configPath := filepath.Join(homeDir, ".config", "commandchronicles", "config.toml")
	return cfg.Save(configPath)
}

func syncDisableCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable command history synchronization",
		Long:  "Disable synchronization and clear stored sync credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			if !cfg.Sync.Enabled {
				formatter.Warning("Sync is already disabled")
				return nil
			}

			// Initialize auth manager for credential clearing
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				formatter.Warning("Failed to initialize auth manager: %v", err)
				return nil
			}
			defer authMgr.Close()

			// Clear sync credentials
			syncService := sync.NewSyncService(cfg, nil, authMgr)
			if err := syncService.Logout(); err != nil {
				formatter.Warning("Failed to clear credentials: %v", err)
			}

			// Clear device ID if requested
			clearDevice, _ := cmd.Flags().GetBool("clear-device")
			if clearDevice {
				deviceManager := sync.NewDeviceManager(cfg)
				if err := deviceManager.ClearDeviceID(); err != nil {
					formatter.Warning("Failed to clear device ID: %v", err)
				} else {
					formatter.Success("Device ID cleared")
				}
			}

			cfg.Sync.Enabled = false

			formatter.Success("Sync disabled and credentials cleared")
			return nil
		},
	}

	cmd.Flags().Bool("clear-device", false, "Also clear the device ID")
	return cmd
}

func syncStatusCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Display sync status and connection information",
		Long:  "Display current sync configuration and connection status",
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			if !cfg.Sync.Enabled {
				formatter.Error("Sync: Disabled")
				formatter.Tip("Use 'ccr sync enable' to enable synchronization")
				formatter.Info("Purchase subscription: https://commandchronicles.dev/pricing")
				return nil
			}

			formatter.Success("Sync: Enabled")
			formatter.Stats("Server: %s", cfg.GetSyncServerURL())
			formatter.Stats("Email: %s", cfg.Sync.Email)

			formatter.IfVerbose(func() {
				formatter.Stats("Interval: %v", cfg.GetSyncInterval())
				formatter.Stats("Batch Size: %d", cfg.Sync.BatchSize)
				formatter.Stats("Max Retries: %d", cfg.Sync.MaxRetries)
				formatter.Stats("Timeout: %v", cfg.GetSyncTimeout())
			})

			// Initialize auth manager for status checking
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				formatter.Warning("Failed to initialize auth manager: %v", err)
				return nil
			}
			defer authMgr.Close()

			// Get sync service status
			syncService := sync.NewSyncService(cfg, nil, authMgr)
			stats := syncService.GetSyncStats()

			formatter.Separator()
			if stats.IsAuthenticated {
				formatter.Success("Authentication: Valid")
			} else {
				formatter.Error("Authentication: Invalid/Expired")
			}

			if stats.LastSyncTime > 0 {
				lastSync := time.Unix(stats.LastSyncTime/1000, 0)
				formatter.Stats("Last Sync: %s", lastSync.Format("2006-01-02 15:04:05"))
			} else {
				formatter.Stats("Last Sync: Never")
			}

			// Test connection
			testConn, _ := cmd.Flags().GetBool("test")
			if testConn {
				formatter.Separator()
				formatter.Info("Testing connection...")
				if err := syncService.TestConnection(); err != nil {
					formatter.Error("Connection test failed: %v", err)
				} else {
					formatter.Success("Connection test successful")
				}
			}

			return nil
		},
	}

	cmd.Flags().Bool("test", false, "Test connection to sync server")
	return cmd
}

func syncNowCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "now",
		Short: "Perform immediate synchronization",
		Long:  "Perform immediate bidirectional synchronization with the remote server",
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)
			if !cfg.Sync.Enabled {
				formatter.Error("Sync is not enabled")
				formatter.Tip("Use 'ccr sync enable' first")
				formatter.Info("Purchase subscription: https://commandchronicles.dev/pricing")
				return fmt.Errorf("sync not enabled")
			}

			formatter.Sync("Starting manual sync...")
			start := time.Now()

			// Initialize auth manager for session management
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authMgr.Close()

			// Get session key
			sessionKey, err := authMgr.LoadSessionKey()
			if err != nil {
				return fmt.Errorf("failed to load session - please unlock storage first: %w", err)
			}

			// Initialize storage
			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:              cfg,
				CreateIfMissing:     true,
				ValidatePermissions: true,
				EnableSecureDelete:  true,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			// Unlock storage with session key
			if err := storage.UnlockWithKey(sessionKey); err != nil {
				return fmt.Errorf("failed to unlock storage: %w", err)
			}

			// Initialize sync service with real storage and auth manager
			syncService := sync.NewSyncService(cfg, storage, authMgr)
			defer syncService.Close()

			if !syncService.GetSyncStats().IsAuthenticated {
				return fmt.Errorf("not authenticated - please run 'ccr sync enable' again")
			}

			// Test connection first
			formatter.IfVerbose(func() {
				formatter.Info("Testing connection...")
			})
			if err := syncService.TestConnection(); err != nil {
				formatter.Error("Connection test failed")
				return fmt.Errorf("connection test failed: %w", err)
			}
			formatter.IfVerbose(func() {
				formatter.Success("Connection test successful")
			})

			// Perform sync using Perfect Sync if enabled
			if cfg.IsPerfectSyncEnabled() {
				formatter.IfVerbose(func() {
					formatter.Info("Performing integrity sync...")
				})
				if err := syncService.PerformIntegritySync(); err != nil {
					formatter.Error("Sync failed")
					return fmt.Errorf("sync failed: %w", err)
				}
			} else {
				formatter.IfVerbose(func() {
					formatter.Info("Performing sync...")
				})
				if err := syncService.PerformSync(); err != nil {
					formatter.Error("Sync failed")
					return fmt.Errorf("sync failed: %w", err)
				}
			}
			formatter.Success("Sync completed successfully")

			formatter.IfVerbose(func() {
				formatter.Stats("Sync completed in %v", time.Since(start))
			})

			return nil
		},
	}

	return cmd
}

func syncIntegrityCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "integrity",
		Short: "Check local storage integrity",
		Long:  "Validate the integrity of local command history storage and hashes",
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			fmt.Println("Starting storage integrity check...")
			start := time.Now()

			// Initialize auth manager for session management
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authMgr.Close()

			// Get session key
			sessionKey, err := authMgr.LoadSessionKey()
			if err != nil {
				return fmt.Errorf("failed to load session - please unlock storage first: %w", err)
			}

			// Initialize storage
			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:              cfg,
				CreateIfMissing:     true,
				ValidatePermissions: true,
				EnableSecureDelete:  true,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			// Unlock storage with session key
			if err := storage.UnlockWithKey(sessionKey); err != nil {
				return fmt.Errorf("failed to unlock storage: %w", err)
			}

			// Initialize sync service for hash provider injection
			syncService := sync.NewSyncService(cfg, storage, authMgr)
			defer syncService.Close()

			// Perform integrity validation
			fmt.Print("Validating storage integrity...")
			report, err := storage.ValidateHashIntegrity()
			if err != nil {
				formatter.Error("Failed")
				return fmt.Errorf("integrity validation failed: %w", err)
			}
			formatter.Success("Complete")

			// Display results
			fmt.Printf("\n")
			formatter.Stats("Integrity Report:")
			fmt.Printf("  Total Records: %d\n", report.TotalRecords)
			fmt.Printf("  Records with Hashes: %d\n", report.RecordsWithHashes)
			fmt.Printf("  Missing Hashes: %d\n", report.MissingHashes)
			fmt.Printf("  Invalid Hashes: %d\n", len(report.InvalidHashes))
			fmt.Printf("  Integrity Score: %.2f%%\n", report.IntegrityScore*100)

			if len(report.InvalidHashes) > 0 {
				fmt.Printf("\n")
				formatter.Warning("Invalid Hash Details:")
				for _, invalid := range report.InvalidHashes {
					fmt.Printf("  Record ID %d: stored=%s computed=%s\n",
						invalid.RecordID, invalid.StoredHash[:8]+"...", invalid.ComputedHash[:8]+"...")
				}
			}

			duration := time.Since(start)
			fmt.Printf("\nIntegrity check completed in %v\n", duration)

			if report.IntegrityScore < 1.0 {
				fmt.Printf("\n")
				formatter.Tip("Consider running 'ccr sync now' to resolve integrity issues")
			}

			return nil
		},
	}
}

// ensureDaemonRunning checks if daemon should be auto-started and starts it if needed
func ensureDaemonRunning(cfg *config.Config) {
	// Skip if sync not enabled
	if !cfg.Sync.Enabled {
		return
	}

	// Skip for daemon command itself
	if len(os.Args) > 1 && os.Args[1] == "daemon" {
		return
	}

	// Skip for daemon-control commands
	if len(os.Args) > 1 && (os.Args[1] == "daemon-control" || os.Args[1] == "dc") {
		return
	}

	// Create daemon manager
	manager := daemon.NewManager(cfg)
	defer manager.Close()

	// Check if auto-start is needed and trigger it
	if err := manager.TriggerAutoStart(); err != nil {
		// Silently fail - don't interrupt user's command
		logger.GetLogger().WithError(err).Debug().Msg("Failed to trigger auto-start")
	}
}

func daemonCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:    "daemon",
		Short:  "Run sync daemon",
		Hidden: true, // Hidden from normal help
		Long:   "Run the CommandChronicles sync daemon process",
		RunE: func(cmd *cobra.Command, args []string) error {
			daemon, err := daemon.NewDaemon(cfg)
			if err != nil {
				return fmt.Errorf("failed to create daemon: %w", err)
			}

			return daemon.Start()
		},
	}

	return cmd
}

func updateCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update CommandChronicles CLI to the latest version",
		Long: `Update CommandChronicles CLI to the latest version.

This command will:
- Check for the latest version on GitHub releases
- Download and verify the new binary
- Replace the current executable with the new version
- Preserve all your data and configuration

Example:
  ccr update                    # Update to latest version
  ccr update --force           # Force update even if no newer version
  ccr update --check-only      # Only check for updates, don't install`,
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			// Get flags
			force, _ := cmd.Flags().GetBool("force")
			checkOnly, _ := cmd.Flags().GetBool("check-only")
			repoOwner, _ := cmd.Flags().GetString("repo-owner")
			repoName, _ := cmd.Flags().GetString("repo-name")
			githubToken := os.Getenv("GITHUB_TOKEN")

			// Create logger with component
			loggerInstance := logger.GetLogger().WithComponent("updater")

			// Create updater
			updaterConfig := updater.UpdaterConfig{
				RepoOwner:   repoOwner,
				RepoName:    repoName,
				GithubToken: githubToken,
			}

			u := updater.NewUpdater(cfg, loggerInstance, version, updaterConfig)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			// Check for updates
			formatter.Info("Checking for updates...")
			updateInfo, err := u.CheckForUpdate(ctx)
			if err != nil {
				formatter.Error("Failed to check for updates")
				return fmt.Errorf("failed to check for updates: %w", err)
			}

			if updateInfo == nil && !force {
				formatter.Success("You're already running the latest version (%s)", version)
				return nil
			}

			if updateInfo != nil {
				formatter.Success("Update found")
				formatter.Separator()
				formatter.Info("New version available!")
				formatter.Info("   Current: %s", version)
				formatter.Info("   Latest:  %s", updateInfo.Version)
				formatter.Info("   Size:    %.1f MB", float64(updateInfo.AssetSize)/(1024*1024))
				formatter.Info("   Date:    %s", updateInfo.ReleaseDate.Format("2006-01-02"))

				if updateInfo.Critical {
					formatter.Warning("   CRITICAL UPDATE - Security fix included")
				}

				if updateInfo.PreRelease {
					formatter.Warning("   Pre-release version")
				}

				if updateInfo.Changelog != "" {
					formatter.Info("Release Notes:")
					lines := strings.Split(updateInfo.Changelog, "\n")
					for i, line := range lines {
						if i >= 10 { // Limit to first 10 lines
							formatter.Info("   ... (view full notes at GitHub)")
							break
						}
						if strings.TrimSpace(line) != "" {
							formatter.Info("   %s", line)
						}
					}
				}
			}

			if checkOnly {
				return nil
			}

			// Confirm update
			if !force && updateInfo != nil {
				fmt.Printf("\nProceed with update? [y/N]: ")
				var response string
				fmt.Scanln(&response)
				if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
					fmt.Println("Update cancelled.")
					return nil
				}
			}

			if updateInfo == nil && force {
				formatter.Warning("Force update requested, but no update information available")
				return fmt.Errorf("cannot force update without available update information")
			}

			// Perform update
			formatter.Separator()
			formatter.Info("Starting update process...")
			if err := u.Update(ctx, updateInfo); err != nil {
				return fmt.Errorf("update failed: %w", err)
			}

			fmt.Printf("\n✅ Update completed successfully!\n")
			fmt.Printf("🎉 CommandChronicles CLI is now version %s\n", updateInfo.Version)
			fmt.Printf("\nPlease restart any running shells to use the new version.\n")

			return nil
		},
	}

	cmd.Flags().Bool("force", false, "Force update even if no newer version is available")
	cmd.Flags().Bool("check-only", false, "Only check for updates, don't install")
	cmd.Flags().String("repo-owner", "NeverVane", "GitHub repository owner")
	cmd.Flags().String("repo-name", "commandchronicles", "GitHub repository name")

	return cmd
}

func checkUpdateCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check-update",
		Short: "Check if a new version is available",
		Long: `Check if a new version of CommandChronicles CLI is available.

This command will query the GitHub releases API to see if there's a newer
version available, but won't install it.

Example:
  ccr check-update              # Check for updates
  ccr check-update --pre        # Include pre-release versions`,
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			includePre, _ := cmd.Flags().GetBool("pre")
			repoOwner, _ := cmd.Flags().GetString("repo-owner")
			repoName, _ := cmd.Flags().GetString("repo-name")
			githubToken := os.Getenv("GITHUB_TOKEN")

			// Create logger with component
			loggerInstance := logger.GetLogger().WithComponent("updater")

			// Create updater
			updaterConfig := updater.UpdaterConfig{
				RepoOwner:   repoOwner,
				RepoName:    repoName,
				GithubToken: githubToken,
			}

			u := updater.NewUpdater(cfg, loggerInstance, version, updaterConfig)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Check for updates
			formatter.Info("Checking for updates...")
			updateInfo, err := u.CheckForUpdate(ctx)
			if err != nil {
				formatter.Error("Failed to check for updates")
				return fmt.Errorf("failed to check for updates: %w", err)
			}

			if updateInfo == nil {
				formatter.Success("Up to date")
				formatter.Separator()
				formatter.Success("You're running the latest version (%s)", version)
				return nil
			}

			// Skip pre-releases unless explicitly requested
			if updateInfo.PreRelease && !includePre {
				formatter.Success("Up to date")
				formatter.Separator()
				formatter.Success("You're running the latest stable version (%s)", version)
				formatter.Tip("Use --pre flag to include pre-release versions")
				return nil
			}

			formatter.Success("Update available")
			formatter.Separator()
			formatter.Info("New version available!")
			formatter.Info("   Current: %s", version)
			formatter.Info("   Latest:  %s", updateInfo.Version)
			formatter.Info("   Size:    %.1f MB", float64(updateInfo.AssetSize)/(1024*1024))
			formatter.Info("   Date:    %s", updateInfo.ReleaseDate.Format("2006-01-02"))

			if updateInfo.Critical {
				formatter.Warning("   CRITICAL UPDATE - Security fix included")
			}

			if updateInfo.PreRelease {
				formatter.Warning("   Pre-release version")
			}

			if updateInfo.Changelog != "" {
				formatter.Info("Release Notes:")
				lines := strings.Split(updateInfo.Changelog, "\n")
				for i, line := range lines {
					if i >= 15 { // Show more lines for check-only
						formatter.Info("   ... (view full notes at GitHub)")
						break
					}
					if strings.TrimSpace(line) != "" {
						formatter.Info("   %s", line)
					}
				}
			}

			fmt.Printf("\n💡 Run 'ccr update' to install the latest version\n")

			return nil
		},
	}

	cmd.Flags().Bool("pre", false, "Include pre-release versions")
	cmd.Flags().String("repo-owner", "NeverVane", "GitHub repository owner")
	cmd.Flags().String("repo-name", "commandchronicles", "GitHub repository name")

	return cmd
}

// checkAutoUpdate performs a background check for updates and shows notifications
func checkAutoUpdate(cfg *config.Config) {
	// Skip auto-update check if disabled or in certain conditions
	if os.Getenv("CCR_SKIP_UPDATE_CHECK") == "true" {
		return
	}

	// Skip update warning if TUI is being launched (it has its own update display)
	for _, arg := range os.Args {
		if arg == "tui" || arg == "--tui" {
			return
		}
	}

	// Only check periodically (not on every command)
	// This is a simple implementation - in production you'd want to track last check time
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Silently handle any panics in auto-update check
				logger.GetLogger().WithComponent("auto-update").
					WithField("error", r).
					Debug().Msg("Auto-update check failed")
			}
		}()

		// Create logger for auto-update
		updateLogger := logger.GetLogger().WithComponent("auto-update")

		// Create updater with default GitHub repository
		updaterConfig := updater.UpdaterConfig{
			RepoOwner:   "NeverVane",
			RepoName:    "commandchronicles",
			GithubToken: os.Getenv("GITHUB_TOKEN"),
			Timeout:     10 * time.Second, // Short timeout for background check
		}

		u := updater.NewUpdater(cfg, updateLogger, version, updaterConfig)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		updateInfo, err := u.CheckForUpdate(ctx)
		if err != nil {
			// Silently fail for auto-check
			updateLogger.Debug().Err(err).Msg("Auto-update check failed")
			return
		}

		if updateInfo != nil {
			// Show non-intrusive notification using formatter
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(false, false, false) // Default settings for background notification

			if updateInfo.Critical {
				formatter.Warning("IMPORTANT UPDATE AVAILABLE: v%s", updateInfo.Version)
				//formatter.Warning("Security fix - Run 'ccr update' immediately")
				fmt.Fprintf(os.Stderr, "\n")
			} else {
				formatter.Info("Update available: v%s - Run 'ccr update' to upgrade", updateInfo.Version)
				fmt.Fprintf(os.Stderr, "\n")
			}
		}
	}()
}

func daemonControlCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "daemon-control",
		Short:   "Control sync daemon",
		Aliases: []string{"dc"},
		Long:    "Control the CommandChronicles sync daemon lifecycle and configuration",
	}

	manager := daemon.NewManager(cfg)

	// Start daemon
	cmd.AddCommand(&cobra.Command{
		Use:   "start",
		Short: "Start sync daemon",
		Long:  "Start the CommandChronicles sync daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("🚀 Starting sync daemon...")
			if err := manager.StartDaemon(); err != nil {
				return fmt.Errorf("failed to start daemon: %w", err)
			}
			fmt.Println("✅ Sync daemon started successfully!")
			return nil
		},
	})

	// Stop daemon
	cmd.AddCommand(&cobra.Command{
		Use:   "stop",
		Short: "Stop sync daemon",
		Long:  "Stop the CommandChronicles sync daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("🛑 Stopping sync daemon...")
			if err := manager.StopDaemon(); err != nil {
				return fmt.Errorf("failed to stop daemon: %w", err)
			}
			fmt.Println("✅ Sync daemon stopped successfully!")
			return nil
		},
	})

	// Restart daemon
	cmd.AddCommand(&cobra.Command{
		Use:   "restart",
		Short: "Restart sync daemon",
		Long:  "Restart the CommandChronicles sync daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			formatter.Sync("Restarting sync daemon...")
			if err := manager.RestartDaemon(); err != nil {
				return fmt.Errorf("failed to restart daemon: %w", err)
			}
			formatter.Success("Sync daemon restarted successfully!")
			return nil
		},
	})

	// Status
	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show daemon status",
		Long:  "Show detailed status information about the sync daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			status, err := manager.GetStatus()
			if err != nil {
				return fmt.Errorf("failed to get daemon status: %w", err)
			}

			formatter.Stats("CommandChronicles Daemon Status")
			fmt.Printf("================================\n")
			if status.Daemon.Running {
				formatter.Success("Daemon Status: Running")
			} else {
				formatter.Error("Daemon Status: Stopped")
			}

			if status.Daemon.Running {
				fmt.Printf("PID: %d\n", status.Daemon.PID)
				if status.Daemon.Uptime > 0 {
					fmt.Printf("Uptime: %v\n", status.Daemon.Uptime)
				}
			}

			// Show service integration status
			if status.Service.Installed {
				formatter.Success("System Service: Installed (%s)", status.Service.Platform)
				if status.Service.Enabled {
					formatter.Success("Service Enabled: Yes")
				} else {
					formatter.Error("Service Enabled: No")
				}
				if status.Service.Running {
					formatter.Success("Service Running: Yes")
				} else {
					formatter.Error("Service Running: No")
				}
				formatter.Success("Auto-start: On boot")
			} else if status.Config.AutoStart {
				formatter.Error("System Service: Not installed")
				formatter.Success("Auto-start: On command usage")
			} else {
				formatter.Error("System Service: Not installed")
				formatter.Error("Auto-start: Manual start required")
			}

			fmt.Printf("Sync Interval: %v\n", status.Config.SyncInterval)

			return nil
		},
	})

	// Install service
	cmd.AddCommand(&cobra.Command{
		Use:   "install-service",
		Short: "Install system service for automatic startup",
		Long:  "Install a system service (systemd/launchd) for automatic daemon startup on boot",
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			formatter.Setup("Installing system service...")
			if err := manager.InstallSystemService(); err != nil {
				return fmt.Errorf("failed to install system service: %w", err)
			}

			formatter.Success("System service installed successfully!")
			formatter.Info("Daemon will now start automatically on boot.")
			return nil
		},
	})

	// Remove service
	cmd.AddCommand(&cobra.Command{
		Use:   "remove-service",
		Short: "Remove system service",
		Long:  "Remove the system service and switch to auto-start mode",
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			formatter.Info("Removing system service...")
			if err := manager.RemoveSystemService(); err != nil {
				return fmt.Errorf("failed to remove system service: %w", err)
			}

			formatter.Success("System service removed successfully!")
			formatter.Sync("Daemon will now use auto-start mode.")
			return nil
		},
	})

	return cmd
}

// cancelSubscriptionCmd cancels the user's premium subscription
func noteCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "note",
		Short: "Manage notes for command history",
		Long: `Add, edit, view, and search notes for your command history.

Notes help you document important commands with context, explanations,
or reminders about why you ran specific commands.`,
	}

	cmd.AddCommand(noteAddCmd(cfg))
	cmd.AddCommand(noteEditCmd(cfg))
	cmd.AddCommand(noteDeleteCmd(cfg))
	cmd.AddCommand(noteShowCmd(cfg))
	cmd.AddCommand(noteListCmd(cfg))
	cmd.AddCommand(noteSearchCmd(cfg))

	return cmd
}

func noteAddCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "add <command-id> <note>",
		Short: "Add a note to a command",
		Long: `Add a note to a specific command in your history.

The command ID can be found using 'ccr search' or 'ccr tui'.
Notes are limited to 1000 characters.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Initialize auth manager
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authMgr.Close()

			log := logger.GetLogger().WithComponent("note")

			// Get session key
			sessionKey, err := getSearchSessionKey(authMgr, log)
			if err != nil {
				return fmt.Errorf("failed to get session key: %w", err)
			}

			// Parse record ID
			recordID, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid command ID: %s", args[0])
			}

			note := args[1]

			// Initialize secure storage
			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:              cfg,
				CreateIfMissing:     false,
				ValidatePermissions: true,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			// Unlock storage
			if err := storage.UnlockWithKey(sessionKey); err != nil {
				return fmt.Errorf("failed to unlock storage: %w", err)
			}

			// Add note
			if err := storage.AddNote(recordID, note); err != nil {
				return fmt.Errorf("failed to add note: %w", err)
			}

			fmt.Printf("Note added to command %d\n", recordID)
			return nil
		},
	}
}

func noteEditCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "edit <command-id> <note>",
		Short: "Edit a note for a command",
		Long: `Edit an existing note for a specific command in your history.

The command ID can be found using 'ccr search' or 'ccr tui'.
Notes are limited to 1000 characters.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Initialize auth manager
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authMgr.Close()

			log := logger.GetLogger().WithComponent("note")

			// Get session key
			sessionKey, err := getSearchSessionKey(authMgr, log)
			if err != nil {
				return fmt.Errorf("failed to get session key: %w", err)
			}

			// Parse record ID
			recordID, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid command ID: %s", args[0])
			}

			note := args[1]

			// Initialize secure storage
			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:              cfg,
				CreateIfMissing:     false,
				ValidatePermissions: true,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			// Unlock storage
			if err := storage.UnlockWithKey(sessionKey); err != nil {
				return fmt.Errorf("failed to unlock storage: %w", err)
			}

			// Update note
			if err := storage.UpdateNote(recordID, note); err != nil {
				return fmt.Errorf("failed to update note: %w", err)
			}

			fmt.Printf("Note updated for command %d\n", recordID)
			return nil
		},
	}
}

func noteDeleteCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <command-id>",
		Short: "Delete a note from a command",
		Long: `Remove the note from a specific command in your history.

The command ID can be found using 'ccr search' or 'ccr tui'.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Initialize auth manager
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authMgr.Close()

			log := logger.GetLogger().WithComponent("note")

			// Get session key
			sessionKey, err := getSearchSessionKey(authMgr, log)
			if err != nil {
				return fmt.Errorf("failed to get session key: %w", err)
			}

			// Parse record ID
			recordID, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid command ID: %s", args[0])
			}

			// Initialize secure storage
			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:              cfg,
				CreateIfMissing:     false,
				ValidatePermissions: true,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			// Unlock storage
			if err := storage.UnlockWithKey(sessionKey); err != nil {
				return fmt.Errorf("failed to unlock storage: %w", err)
			}

			// Delete note
			if err := storage.DeleteNote(recordID); err != nil {
				return fmt.Errorf("failed to delete note: %w", err)
			}

			fmt.Printf("Note deleted from command %d\n", recordID)
			return nil
		},
	}
}

func noteShowCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "show <command-id>",
		Short: "Show the note for a command",
		Long: `Display the note for a specific command in your history.

The command ID can be found using 'ccr search' or 'ccr tui'.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Initialize auth manager
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authMgr.Close()

			log := logger.GetLogger().WithComponent("note")

			// Get session key
			sessionKey, err := getSearchSessionKey(authMgr, log)
			if err != nil {
				return fmt.Errorf("failed to get session key: %w", err)
			}

			// Parse record ID
			recordID, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid command ID: %s", args[0])
			}

			// Initialize secure storage
			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:              cfg,
				CreateIfMissing:     false,
				ValidatePermissions: true,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			// Unlock storage
			if err := storage.UnlockWithKey(sessionKey); err != nil {
				return fmt.Errorf("failed to unlock storage: %w", err)
			}

			// Get note
			note, err := storage.GetNote(recordID)
			if err != nil {
				return fmt.Errorf("failed to get note: %w", err)
			}

			if note == "" {
				fmt.Printf("No note found for command %d\n", recordID)
			} else {
				fmt.Printf("Note for command %d:\n%s\n", recordID, note)
			}
			return nil
		},
	}
}

func noteListCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all commands with notes",
		Long: `Display all commands that have notes attached.

This helps you see which commands you've documented with notes.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Initialize auth manager
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authMgr.Close()

			log := logger.GetLogger().WithComponent("note")

			// Get session key
			sessionKey, err := getSearchSessionKey(authMgr, log)
			if err != nil {
				return fmt.Errorf("failed to get session key: %w", err)
			}

			// Initialize secure storage
			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:              cfg,
				CreateIfMissing:     false,
				ValidatePermissions: true,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			// Unlock storage
			if err := storage.UnlockWithKey(sessionKey); err != nil {
				return fmt.Errorf("failed to unlock storage: %w", err)
			}

			// Get all noted commands
			result, err := storage.GetAllNotedCommands(&securestorage.QueryOptions{
				Limit: 100,
			})
			if err != nil {
				return fmt.Errorf("failed to get noted commands: %w", err)
			}

			if len(result.Records) == 0 {
				fmt.Println("No commands with notes found")
				return nil
			}

			fmt.Printf("Found %d commands with notes:\n\n", len(result.Records))
			for _, record := range result.Records {
				fmt.Printf("ID: %d\n", record.ID)
				fmt.Printf("Command: %s\n", record.Command)
				fmt.Printf("Note: %s\n", record.GetNotePreview(100))
				fmt.Println("---")
			}

			return nil
		},
	}
}

func noteSearchCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "search <query>",
		Short: "Search notes for specific text",
		Long: `Search through all notes for commands containing specific text.

This helps you find commands by searching their notes content.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Initialize auth manager
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authMgr.Close()

			log := logger.GetLogger().WithComponent("note")

			// Get session key
			sessionKey, err := getSearchSessionKey(authMgr, log)
			if err != nil {
				return fmt.Errorf("failed to get session key: %w", err)
			}

			query := args[0]

			// Initialize secure storage
			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:              cfg,
				CreateIfMissing:     false,
				ValidatePermissions: true,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			// Unlock storage
			if err := storage.UnlockWithKey(sessionKey); err != nil {
				return fmt.Errorf("failed to unlock storage: %w", err)
			}

			// Search notes
			result, err := storage.SearchNotes(query, &securestorage.QueryOptions{
				Limit: 100,
			})
			if err != nil {
				return fmt.Errorf("failed to search notes: %w", err)
			}

			if len(result.Records) == 0 {
				fmt.Printf("No notes found matching '%s'\n", query)
				return nil
			}

			fmt.Printf("Found %d commands with notes matching '%s':\n\n", len(result.Records), query)
			for _, record := range result.Records {
				fmt.Printf("ID: %d\n", record.ID)
				fmt.Printf("Command: %s\n", record.Command)
				fmt.Printf("Note: %s\n", record.GetNotePreview(100))
				fmt.Println("---")
			}

			return nil
		},
	}
}

func tagCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tag",
		Short: "Manage tags for command history",
		Long: `Add, remove, and manage tags for your command history.

Tags help you categorize and organize your commands for easier searching
and better organization of your command history.`,
	}

	cmd.AddCommand(tagAddCmd(cfg))
	cmd.AddCommand(tagRemoveCmd(cfg))
	cmd.AddCommand(tagListCmd(cfg))
	cmd.AddCommand(tagShowCmd(cfg))
	cmd.AddCommand(tagSearchCmd(cfg))

	return cmd
}

func tagAddCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "add <command-id> <tag>",
		Short: "Add a tag to a command",
		Long: `Add a tag to a specific command in your history.

The command ID can be found using 'ccr search' or 'ccr tui'.
Tags are limited to 50 characters and commands can have up to 10 tags.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Initialize auth manager
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authMgr.Close()

			// Get session key
			sessionKey, err := getSearchSessionKey(authMgr, logger.GetLogger())
			if err != nil {
				return err
			}

			// Initialize secure storage
			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:              cfg,
				CreateIfMissing:     false,
				ValidatePermissions: true,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}

			// Unlock storage with session key
			if err := storage.UnlockWithKey(sessionKey); err != nil {
				return fmt.Errorf("failed to unlock storage: %w", err)
			}

			// Parse command ID
			commandID := args[0]
			tag := args[1]

			// Get command by ID
			record, err := storage.GetCommandByID(commandID)
			if err != nil {
				return fmt.Errorf("failed to get command: %w", err)
			}

			// Add tag to command
			if err := record.AddTag(tag); err != nil {
				return fmt.Errorf("failed to add tag: %w", err)
			}

			// Update command in storage
			if err := storage.UpdateCommand(record); err != nil {
				return fmt.Errorf("failed to update command: %w", err)
			}

			fmt.Printf("✓ Tag '%s' added to command\n", tag)
			return nil
		},
	}
}

func tagRemoveCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <command-id> <tag>",
		Short: "Remove a tag from a command",
		Long: `Remove a tag from a specific command in your history.

The command ID can be found using 'ccr search' or 'ccr tui'.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Initialize auth manager
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authMgr.Close()

			// Get session key
			sessionKey, err := getSearchSessionKey(authMgr, logger.GetLogger())
			if err != nil {
				return err
			}

			// Initialize secure storage
			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:              cfg,
				CreateIfMissing:     false,
				ValidatePermissions: true,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}

			// Unlock storage with session key
			if err := storage.UnlockWithKey(sessionKey); err != nil {
				return fmt.Errorf("failed to unlock storage: %w", err)
			}

			// Parse command ID
			commandID := args[0]
			tag := args[1]

			// Get command by ID
			record, err := storage.GetCommandByID(commandID)
			if err != nil {
				return fmt.Errorf("failed to get command: %w", err)
			}

			// Remove tag from command
			if removed := record.RemoveTag(tag); !removed {
				return fmt.Errorf("tag '%s' not found on command", tag)
			}

			// Update command in storage
			if err := storage.UpdateCommand(record); err != nil {
				return fmt.Errorf("failed to update command: %w", err)
			}

			fmt.Printf("✓ Tag '%s' removed from command\n", tag)
			return nil
		},
	}
}

func tagListCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "list <command-id>",
		Short: "List tags for a command",
		Long: `List all tags for a specific command in your history.

The command ID can be found using 'ccr search' or 'ccr tui'.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Initialize auth manager
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authMgr.Close()

			// Get session key
			sessionKey, err := getSearchSessionKey(authMgr, logger.GetLogger())
			if err != nil {
				return err
			}

			// Initialize secure storage
			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:              cfg,
				CreateIfMissing:     false,
				ValidatePermissions: true,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}

			// Unlock storage with session key
			if err := storage.UnlockWithKey(sessionKey); err != nil {
				return fmt.Errorf("failed to unlock storage: %w", err)
			}

			// Parse command ID
			commandID := args[0]

			// Get command by ID
			record, err := storage.GetCommandByID(commandID)
			if err != nil {
				return fmt.Errorf("failed to get command: %w", err)
			}

			// Display command and tags
			fmt.Printf("Command: %s\n", record.Command)
			if record.HasTags() {
				fmt.Printf("Tags: %s\n", record.GetTagsString())
			} else {
				fmt.Println("No tags found.")
			}

			return nil
		},
	}
}

func tagShowCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show all commands with tags",
		Long: `Show all commands in your history that have tags.

This provides an overview of your tagged commands.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Initialize auth manager
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authMgr.Close()

			// Get session key
			sessionKey, err := getSearchSessionKey(authMgr, logger.GetLogger())
			if err != nil {
				return err
			}

			// Initialize secure storage
			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:              cfg,
				CreateIfMissing:     false,
				ValidatePermissions: true,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}

			// Unlock storage with session key
			if err := storage.UnlockWithKey(sessionKey); err != nil {
				return fmt.Errorf("failed to unlock storage: %w", err)
			}

			// Search for commands with tags
			records, err := storage.SearchCommandsWithTags()
			if err != nil {
				return fmt.Errorf("failed to search commands: %w", err)
			}

			if len(records) == 0 {
				fmt.Println("No tagged commands found.")
				return nil
			}

			fmt.Printf("Found %d tagged commands:\n\n", len(records))
			for _, record := range records {
				fmt.Printf("ID: %d\n", record.ID)
				fmt.Printf("Command: %s\n", record.Command)
				fmt.Printf("Tags: %s\n", record.GetTagsString())
				fmt.Println("---")
			}

			return nil
		},
	}
}

func tagSearchCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "search <tag>",
		Short: "Search commands by tag",
		Long: `Search for commands that have a specific tag.

This shows all commands that are tagged with the specified tag.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Initialize auth manager
			authMgr, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authMgr.Close()

			// Get session key
			sessionKey, err := getSearchSessionKey(authMgr, logger.GetLogger())
			if err != nil {
				return err
			}

			// Initialize secure storage
			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:              cfg,
				CreateIfMissing:     false,
				ValidatePermissions: true,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}

			// Unlock storage with session key
			if err := storage.UnlockWithKey(sessionKey); err != nil {
				return fmt.Errorf("failed to unlock storage: %w", err)
			}

			// Search for commands with the specified tag
			tag := args[0]
			records, err := storage.SearchCommandsByTag(tag)
			if err != nil {
				return fmt.Errorf("failed to search commands: %w", err)
			}

			if len(records) == 0 {
				fmt.Printf("No commands found with tag '%s'.\n", tag)
				return nil
			}

			fmt.Printf("Found %d commands with tag '%s':\n\n", len(records), tag)
			for _, record := range records {
				fmt.Printf("ID: %d\n", record.ID)
				fmt.Printf("Command: %s\n", record.Command)
				fmt.Printf("Tags: %s\n", record.GetTagsString())
				fmt.Println("---")
			}

			return nil
		},
	}
}

func devicesCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "devices",
		Short: "Manage devices and aliases",
		Long: `List devices and manage human-readable aliases for sync rules.

Devices are automatically discovered during sync operations. You can assign
friendly names (aliases) to make device management easier when creating sync rules.`,
	}

	cmd.AddCommand(devicesShowCmd(cfg))
	cmd.AddCommand(devicesAliasCmd(cfg))
	cmd.AddCommand(devicesRemoveAliasCmd(cfg))

	return cmd
}

func devicesShowCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "List all devices with aliases",
		Long: `Display all devices in your account with their current status and aliases.

Shows device information including:
- Device ID and alias (if set)
- Hostname and platform
- Last seen timestamp
- Active status`,
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:          cfg,
				CreateIfMissing: false,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			// Initialize auth manager
			authManager, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authManager.Close()

			// Check if authenticated
			if !authManager.IsSessionActive() {
				return fmt.Errorf("please unlock your storage first with 'ccr unlock'")
			}

			// Initialize sync service to get device manager
			syncService := sync.NewSyncService(cfg, storage, authManager)
			deviceAliasManager := syncService.GetDeviceAliasManager()

			// Get devices
			devices, err := deviceAliasManager.GetDevices()
			if err != nil {
				return fmt.Errorf("failed to get devices: %w", err)
			}

			if len(devices) == 0 {
				formatter.Info("No devices found. Run 'ccr sync now' to update device list.")
				return nil
			}

			// Display devices
			formatter.Header("Your Devices:")
			for _, device := range devices {
				status := "active"
				if !device.IsActive {
					status = "inactive"
				}

				displayName := device.DeviceID
				if device.Alias != "" && device.IsEnabled {
					displayName = fmt.Sprintf("%s (%s)", device.Alias, device.DeviceID)
				}

				currentMark := ""
				if device.IsCurrent {
					currentMark = " [current]"
				}

				lastSeen := time.Unix(device.LastSeen/1000, 0)
				formatter.Print("  %s%s - %s on %s - %s - last seen %s",
					displayName, currentMark, device.Hostname, device.Platform,
					status, formatTimeAgo(lastSeen))
			}

			return nil
		},
	}
}

func devicesAliasCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "alias <device-id> <alias>",
		Short: "Set device alias",
		Long: `Set a human-readable alias for a device.

The alias must be unique and can contain letters, numbers, hyphens, and underscores.
Use device aliases in sync rules instead of remembering device IDs.

Examples:
  ccr devices alias ccr_a1b2c3d4e5f6 work-laptop
  ccr devices alias ccr_e5f6g7h8i9j0 home-desktop`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			deviceID := args[0]
			alias := args[1]

			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:          cfg,
				CreateIfMissing: false,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			// Initialize auth manager
			authManager, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authManager.Close()

			// Check if authenticated
			if !authManager.IsSessionActive() {
				return fmt.Errorf("please unlock your storage first with 'ccr unlock'")
			}

			// Initialize sync service to get device manager
			syncService := sync.NewSyncService(cfg, storage, authManager)
			deviceAliasManager := syncService.GetDeviceAliasManager()

			// Set alias
			if err := deviceAliasManager.SetDeviceAlias(deviceID, alias); err != nil {
				return fmt.Errorf("failed to set device alias: %w", err)
			}

			formatter.Success("Set alias '%s' for device %s", alias, deviceID)
			return nil
		},
	}
}

func devicesRemoveAliasCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "remove-alias <device-id>",
		Short: "Remove device alias",
		Long: `Remove the alias for a device.

The device will be identified by its device ID after the alias is removed.

Example:
  ccr devices remove-alias ccr_a1b2c3d4e5f6`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			deviceID := args[0]

			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:          cfg,
				CreateIfMissing: false,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			// Initialize auth manager
			authManager, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authManager.Close()

			// Check if authenticated
			if !authManager.IsSessionActive() {
				return fmt.Errorf("please unlock your storage first with 'ccr unlock'")
			}

			// Initialize sync service to get device manager
			syncService := sync.NewSyncService(cfg, storage, authManager)
			deviceAliasManager := syncService.GetDeviceAliasManager()

			// Remove alias
			if err := deviceAliasManager.RemoveDeviceAlias(deviceID); err != nil {
				return fmt.Errorf("failed to remove device alias: %w", err)
			}

			formatter.Success("Removed alias for device %s", deviceID)
			return nil
		},
	}
}

func rulesCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage sync rules",
		Long: `Create and manage rules for controlling command synchronization.

Rules allow you to control which commands are synced to which devices.
You can create allow or deny rules based on devices and conditions.`,
	}

	cmd.AddCommand(rulesListCmd(cfg))
	cmd.AddCommand(rulesAllowCmd(cfg))
	cmd.AddCommand(rulesDenyCmd(cfg))
	cmd.AddCommand(rulesDeleteCmd(cfg))
	cmd.AddCommand(rulesEnableCmd(cfg))
	cmd.AddCommand(rulesDisableCmd(cfg))
	cmd.AddCommand(rulesSimulateCmd(cfg))
	cmd.AddCommand(rulesTestCmd(cfg))
	cmd.AddCommand(rulesStatusCmd(cfg))

	return cmd
}

func rulesListCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all sync rules",
		Long: `Display all sync rules with their status and configuration.

Shows rule information including:
- Rule ID and name
- Action (allow/deny)
- Target device
- Active status`,
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:          cfg,
				CreateIfMissing: false,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			// Initialize auth manager
			authManager, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authManager.Close()

			// Check if authenticated
			if !authManager.IsSessionActive() {
				return fmt.Errorf("please unlock your storage first with 'ccr unlock'")
			}

			// Initialize sync service to get rules manager
			syncService := sync.NewSyncService(cfg, storage, authManager)
			rulesManager := syncService.GetRulesManager()

			// Get rules
			rules, err := rulesManager.ListRules()
			if err != nil {
				return fmt.Errorf("failed to list rules: %w", err)
			}

			if len(rules) == 0 {
				formatter.Info("No sync rules found.")
				formatter.Tip("Create rules with 'ccr rules allow <device>' or 'ccr rules deny <device>'")
				return nil
			}

			// Get device alias manager for resolving device names
			deviceAliasManager := syncService.GetDeviceAliasManager()

			// Display rules
			formatter.Header("Sync Rules:")
			for _, rule := range rules {
				status := "active"
				if !rule.Active {
					status = "inactive"
				}

				// Try to get device alias
				deviceDisplay := rule.TargetDevice
				if alias, err := deviceAliasManager.GetDeviceAlias(rule.TargetDevice); err == nil {
					deviceDisplay = fmt.Sprintf("%s (%s)", alias, rule.TargetDevice)
				}

				formatter.Print("  %s (%s) - %s %s [%s]",
					rule.Name, rule.ID[:8], rule.Action, deviceDisplay, status)

				if rule.Description != "" {
					formatter.Print("    %s", rule.Description)
				}
			}

			return nil
		},
	}
}

func rulesAllowCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "allow <device>",
		Short: "Create allow rule for device",
		Long: `Create a rule to allow command sync to a specific device.

The device can be specified by device ID or alias.

Examples:
  ccr rules allow work-laptop
  ccr rules allow ccr_a1b2c3d4e5f6`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			device := args[0]

			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:          cfg,
				CreateIfMissing: false,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			// Initialize auth manager
			authManager, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authManager.Close()

			// Check if authenticated
			if !authManager.IsSessionActive() {
				return fmt.Errorf("please unlock your storage first with 'ccr unlock'")
			}

			// Initialize sync service to get rules manager
			syncService := sync.NewSyncService(cfg, storage, authManager)
			rulesManager := syncService.GetRulesManager()

			// Create allow rule
			if err := rulesManager.CreateAllowRule(device); err != nil {
				return fmt.Errorf("failed to create allow rule: %w", err)
			}

			formatter.Success("Created allow rule for device %s", device)
			return nil
		},
	}
}

func rulesDenyCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "deny <device>",
		Short: "Create deny rule for device",
		Long: `Create a rule to deny command sync to a specific device.

The device can be specified by device ID or alias.

Examples:
  ccr rules deny personal-phone
  ccr rules deny ccr_e5f6g7h8i9j0`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			device := args[0]

			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:          cfg,
				CreateIfMissing: false,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			// Initialize auth manager
			authManager, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authManager.Close()

			// Check if authenticated
			if !authManager.IsSessionActive() {
				return fmt.Errorf("please unlock your storage first with 'ccr unlock'")
			}

			// Initialize sync service to get rules manager
			syncService := sync.NewSyncService(cfg, storage, authManager)
			rulesManager := syncService.GetRulesManager()

			// Create deny rule
			if err := rulesManager.CreateDenyRule(device); err != nil {
				return fmt.Errorf("failed to create deny rule: %w", err)
			}

			formatter.Success("Created deny rule for device %s", device)
			return nil
		},
	}
}

func rulesDeleteCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <rule-id>",
		Short: "Delete sync rule",
		Long: `Delete a sync rule by its ID.

Use 'ccr rules list' to see rule IDs.

Example:
  ccr rules delete 12345678`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ruleID := args[0]

			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:          cfg,
				CreateIfMissing: false,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			// Initialize auth manager
			authManager, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authManager.Close()

			// Check if authenticated
			if !authManager.IsSessionActive() {
				return fmt.Errorf("please unlock your storage first with 'ccr unlock'")
			}

			// Initialize sync service to get rules manager
			syncService := sync.NewSyncService(cfg, storage, authManager)
			rulesManager := syncService.GetRulesManager()

			// Delete rule
			if err := rulesManager.DeleteRule(ruleID); err != nil {
				return fmt.Errorf("failed to delete rule: %w", err)
			}

			formatter.Success("Deleted rule %s", ruleID)
			return nil
		},
	}
}

func rulesEnableCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "enable <rule-id>",
		Short: "Enable sync rule",
		Long: `Enable a sync rule by its ID.

Use 'ccr rules list' to see rule IDs.

Example:
  ccr rules enable 12345678`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ruleID := args[0]

			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:          cfg,
				CreateIfMissing: false,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			// Initialize auth manager
			authManager, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authManager.Close()

			// Check if authenticated
			if !authManager.IsSessionActive() {
				return fmt.Errorf("please unlock your storage first with 'ccr unlock'")
			}

			// Initialize sync service to get rules manager
			syncService := sync.NewSyncService(cfg, storage, authManager)
			rulesManager := syncService.GetRulesManager()

			// Enable rule
			if err := rulesManager.ToggleRule(ruleID, true); err != nil {
				return fmt.Errorf("failed to enable rule: %w", err)
			}

			formatter.Success("Enabled rule %s", ruleID)
			return nil
		},
	}
}

func rulesDisableCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "disable <rule-id>",
		Short: "Disable sync rule",
		Long: `Disable a sync rule by its ID.

Use 'ccr rules list' to see rule IDs.

Example:
  ccr rules disable 12345678`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ruleID := args[0]

			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:          cfg,
				CreateIfMissing: false,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			// Initialize auth manager
			authManager, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authManager.Close()

			// Check if authenticated
			if !authManager.IsSessionActive() {
				return fmt.Errorf("please unlock your storage first with 'ccr unlock'")
			}

			// Initialize sync service to get rules manager
			syncService := sync.NewSyncService(cfg, storage, authManager)
			rulesManager := syncService.GetRulesManager()

			// Disable rule
			if err := rulesManager.ToggleRule(ruleID, false); err != nil {
				return fmt.Errorf("failed to disable rule: %w", err)
			}

			formatter.Success("Disabled rule %s", ruleID)
			return nil
		},
	}
}

func rulesSimulateCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "simulate <command>",
		Short: "Simulate rule evaluation for a command",
		Long: `Test how sync rules would be applied to a specific command.

This shows which devices the command would be synced to based on current rules.

Examples:
  ccr rules simulate "docker ps"
  ccr rules simulate "git status" --dir /work
  ccr rules simulate "npm install" --tag nodejs`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			command := args[0]
			workingDir, _ := cmd.Flags().GetString("dir")
			tagStr, _ := cmd.Flags().GetString("tag")
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			var tags []string
			if tagStr != "" {
				tags = []string{tagStr}
			}

			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:          cfg,
				CreateIfMissing: false,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			// Initialize auth manager
			authManager, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authManager.Close()

			// Check if authenticated
			if !authManager.IsSessionActive() {
				return fmt.Errorf("please unlock your storage first with 'ccr unlock'")
			}

			// Initialize sync service to get rule engine
			syncService := sync.NewSyncService(cfg, storage, authManager)
			ruleEngine := syncService.GetRuleEngine()
			deviceAliasManager := syncService.GetDeviceAliasManager()

			// Simulate rule evaluation
			result, err := ruleEngine.SimulateRuleEvaluation(command, workingDir, tags)
			if err != nil {
				return fmt.Errorf("failed to simulate rule evaluation: %w", err)
			}

			// Display results
			formatter.Print("Command: %s", command)
			if workingDir != "" {
				formatter.Print("Working Directory: %s", workingDir)
			}
			if len(tags) > 0 {
				formatter.Print("Tags: %s", strings.Join(tags, ", "))
			}
			formatter.Print("")

			formatter.Print("Would sync to %d device(s):", len(result.TargetDevices))
			if len(result.TargetDevices) == 0 {
				formatter.Print("  No devices (command would be local only)")
			} else {
				for _, deviceID := range result.TargetDevices {
					// Try to get device alias
					deviceDisplay := deviceID
					if alias, err := deviceAliasManager.GetDeviceAlias(deviceID); err == nil {
						deviceDisplay = fmt.Sprintf("%s (%s)", alias, deviceID)
					}
					formatter.Print("  - %s", deviceDisplay)
				}
			}

			if len(result.RulesApplied) > 0 {
				formatter.Print("")
				formatter.Print("Rules applied: %d", len(result.RulesApplied))
				for _, ruleID := range result.RulesApplied {
					formatter.Print("  - %s", ruleID[:8])
				}
			}

			if result.DefaultUsed {
				formatter.Print("")
				formatter.Info("Using default behavior (no specific rules matched)")
			}

			if result.Explanation != "" {
				formatter.Print("")
				formatter.Info("Explanation: %s", result.Explanation)
			}

			return nil
		},
	}

	cmd.Flags().String("dir", "", "Working directory for simulation")
	cmd.Flags().String("tag", "", "Tag for simulation")

	return cmd
}

func rulesTestCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Test rule system diagnostics",
		Long: `Run comprehensive diagnostics on the sync rules system.

This command analyzes the current rule configuration, validates rule logic,
and provides detailed information about how rules would be applied.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:          cfg,
				CreateIfMissing: false,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			// Initialize auth manager
			authManager, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authManager.Close()

			// Check if authenticated
			if !authManager.IsSessionActive() {
				return fmt.Errorf("please unlock your storage first with 'ccr unlock'")
			}

			// Initialize sync service to get rule engine
			syncService := sync.NewSyncService(cfg, storage, authManager)
			ruleEngine := syncService.GetRuleEngine()

			formatter.Header("Sync Rules System Diagnostics")
			formatter.Print("")

			// Get evaluation diagnostics
			diagnostics, err := ruleEngine.GetEvaluationDiagnostics()
			if err != nil {
				return fmt.Errorf("failed to get diagnostics: %w", err)
			}

			// Display basic information
			formatter.Println("Has Rules: %v", diagnostics["has_rules"])
			formatter.Println("Total Devices: %v", diagnostics["total_devices"])
			formatter.Println("Active Devices: %v", diagnostics["active_devices"])

			if diagnostics["has_rules"].(bool) {
				if summary, ok := diagnostics["rules_summary"]; ok {
					formatter.Print("")
					formatter.Stats("Rules Summary:")
					formatter.Println("  Total: %v", summary.(*sync.RuleSummary).TotalRules)
					formatter.Println("  Active: %v", summary.(*sync.RuleSummary).ActiveRules)
					formatter.Println("  Allow: %v", summary.(*sync.RuleSummary).AllowRules)
					formatter.Println("  Deny: %v", summary.(*sync.RuleSummary).DenyRules)
				}

				// Show rule evaluation stats
				stats, err := ruleEngine.GetRuleEvaluationStats()
				if err != nil {
					formatter.Warning("Could not get evaluation stats: %v", err)
				} else {
					formatter.Print("")
					formatter.Stats("Rule Distribution:")
					if actionDist, ok := stats["action_distribution"].(map[string]int); ok {
						for action, count := range actionDist {
							formatter.Println("  %s rules: %d", action, count)
						}
					}
				}
			}

			// Show warnings
			if warnings, ok := diagnostics["rule_warnings"].([]string); ok && len(warnings) > 0 {
				formatter.Print("")
				formatter.Warning("Rule Warnings:")
				for _, warning := range warnings {
					formatter.Println("  - %s", warning)
				}
			} else {
				formatter.Success("No rule conflicts detected")
			}

			// Test basic rule evaluation functionality
			formatter.Separator()
			formatter.Stats("Rule Evaluation Test:")
			result, err := ruleEngine.SimulateRuleEvaluation("test-command", "", []string{})
			if err != nil {
				formatter.Error("Error testing rule evaluation: %v", err)
			} else {
				message := fmt.Sprintf("Test command would sync to %d device(s)", len(result.TargetDevices))
				if result.DefaultUsed {
					message += " (using default behavior)"
				}
				formatter.Println(message)
			}

			formatter.Separator()
			formatter.Stats("System Status:")
			if diagnostics["total_devices"].(int) == 0 {
				formatter.Info("No devices found. Run 'ccr sync now' to populate device list.")
			}

			if !diagnostics["has_rules"].(bool) {
				formatter.Info("No rules configured. All commands will sync to all devices by default.")
				formatter.Tip("Create rules with: ccr rules allow <device> or ccr rules deny <device>")
			}

			return nil
		},
	}
}

func rulesStatusCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show rules summary",
		Long:  `Display a summary of all sync rules and their current status.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
				Config:          cfg,
				CreateIfMissing: false,
			})
			if err != nil {
				return fmt.Errorf("failed to initialize storage: %w", err)
			}
			defer storage.Close()

			// Initialize auth manager
			authManager, err := auth.NewAuthManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize auth manager: %w", err)
			}
			defer authManager.Close()

			// Check if authenticated
			if !authManager.IsSessionActive() {
				return fmt.Errorf("please unlock your storage first with 'ccr unlock'")
			}

			// Initialize sync service to get rules manager
			syncService := sync.NewSyncService(cfg, storage, authManager)
			rulesManager := syncService.GetRulesManager()

			// Get summary
			summary, err := rulesManager.GetRulesSummary()
			if err != nil {
				return fmt.Errorf("failed to get rules summary: %w", err)
			}

			// Display summary
			formatter.Header("Sync Rules Summary:")
			formatter.Println("  Total rules: %d", summary.TotalRules)
			formatter.Println("  Active rules: %d", summary.ActiveRules)
			formatter.Println("  Allow rules: %d", summary.AllowRules)
			formatter.Println("  Deny rules: %d", summary.DenyRules)

			if summary.TotalRules == 0 {
				formatter.Separator()
				formatter.Info("No rules configured. Commands will sync to all devices by default.")
				formatter.Tip("Create rules with 'ccr rules allow <device>' or 'ccr rules deny <device>'")
			}

			return nil
		},
	}
}

func formatTimeAgo(t time.Time) string {
	duration := time.Since(t)

	if duration < time.Minute {
		return "just now"
	} else if duration < time.Hour {
		minutes := int(duration.Minutes())
		if minutes == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", minutes)
	} else if duration < 24*time.Hour {
		hours := int(duration.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	} else {
		days := int(duration.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	}
}

func cancelSubscriptionCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cancel-subscription",
		Short: "Cancel your premium subscription",
		Long: `Cancel your premium subscription and downgrade to Community edition.

	This will:
	- Stop billing at the end of your current period
	- Preserve all your data and basic CLI functionality
	- Remove cloud sync features only
	- Keep your premium access until the billing period ends

	You can resubscribe anytime to restore full sync functionality.
	Your command history remains encrypted - the server can never decrypt your commands.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, _ := cmd.Flags().GetBool("verbose")
			noColor, _ := cmd.Flags().GetBool("no-color")
			force, _ := cmd.Flags().GetBool("force")

			// Create formatter for colored output
			formatter := output.NewFormatter(cfg)
			formatter.SetFlags(verbose, false, noColor)

			// Create login manager to check auth status
			loginMgr, err := login.NewLoginManager(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize login manager: %w", err)
			}
			defer loginMgr.Close()

			// Check authentication status
			localOK, remoteOK := loginMgr.IsLoggedIn()
			if !localOK || !remoteOK {
				formatter.Error("Authentication required")
				formatter.Tip("Run 'ccr login' first")
				return fmt.Errorf("not authenticated")
			}

			if cfg.Sync.Email == "" {
				formatter.Error("No subscription found")
				formatter.Info("You're already using the Community edition")
				return nil
			}

			// Show confirmation unless force flag is used
			if !force {
				clearScreen()
				formatter.Setup("Cancel Premium Subscription")
				formatter.Warning("You are about to cancel your premium subscription.")

				formatter.Separator()
				formatter.Println("What happens next:")
				formatter.Println("• No refund will be issued")
				formatter.Println("• You'll keep premium access until your billing period ends")
				formatter.Println("• After that, you'll switch to Community edition")
				formatter.Println("• Your command history stays encrypted (server cannot decrypt)")
				formatter.Println("• Re-subscription is always possible and will restore sync")

				formatter.Separator()
				formatter.Println("Account: %s", cfg.Sync.Email)
				formatter.Println("Learn more: https://commandchronicles.dev")

				fmt.Print("\nType 'CANCEL SUBSCRIPTION' to confirm: ")
				reader := bufio.NewReader(os.Stdin)
				response, err := reader.ReadString('\n')
				if err != nil {
					return fmt.Errorf("failed to read input: %w", err)
				}
				response = strings.TrimSpace(response)

				if response != "CANCEL SUBSCRIPTION" {
					formatter.Info("Subscription cancellation cancelled.")
					return nil
				}
			}

			formatter.Setup("Cancelling subscription...")

			// Create remote authenticator
			remoteAuth := sync.NewRemoteAuthenticator(cfg, loginMgr.AuthManager)

			// Call the cancellation API
			result, err := remoteAuth.CancelSubscription()
			if err != nil {
				formatter.Error("Cancellation failed: %v", err)
				return err
			}

			// Display success message and details
			formatter.Success(result.Message)

			if result.EffectiveDate != "" {
				formatter.Info("Premium access until: %s", result.EffectiveDate)
			}

			if result.AccessInfo != "" {
				formatter.Info("%s", result.AccessInfo)
			}

			formatter.Separator()
			formatter.Info("You can resubscribe anytime at: https://commandchronicles.dev")
			formatter.Info("Your command history remains secure and encrypted.")

			return nil
		},
	}

	cmd.Flags().Bool("force", false, "Skip confirmation prompt")
	return cmd
}
