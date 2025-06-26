package login

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/NeverVane/commandchronicles-cli/internal/auth"
	"github.com/NeverVane/commandchronicles-cli/internal/config"
	"github.com/NeverVane/commandchronicles-cli/internal/daemon"
	"github.com/NeverVane/commandchronicles-cli/internal/logger"
	"github.com/NeverVane/commandchronicles-cli/internal/sync"
	securestorage "github.com/NeverVane/commandchronicles-cli/pkg/storage"
)

// StatusCallback is a function type for reporting status updates during operations
type StatusCallback func(message string, success bool)

// LoginManager orchestrates local and remote authentication
type LoginManager struct {
	config         *config.Config
	AuthManager    *auth.AuthManager
	remoteAuth     *sync.RemoteAuthenticator
	syncService    *sync.SyncService
	logger         *logger.Logger
	StatusCallback StatusCallback
}

// LoginResult contains the results of a login operation
type LoginResult struct {
	LocalSuccess  bool   `json:"local_success"`
	RemoteSuccess bool   `json:"remote_success"`
	Message       string `json:"message"`
}

// NewLoginManager creates a new login manager instance
func NewLoginManager(cfg *config.Config) (*LoginManager, error) {
	return NewLoginManagerWithStorage(cfg, nil)
}

// NewLoginManagerWithStorage creates a new login manager instance with optional storage
func NewLoginManagerWithStorage(cfg *config.Config, storage *securestorage.SecureStorage) (*LoginManager, error) {
	authMgr, err := auth.NewAuthManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth manager: %w", err)
	}

	// Create secure storage if not provided
	if storage == nil {
		storage, err = securestorage.NewSecureStorage(&securestorage.StorageOptions{
			Config:              cfg,
			AutoLockTimeout:     0, // Use default
			EnableSecureDelete:  true,
			ValidatePermissions: true,
			CreateIfMissing:     true,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create secure storage: %w", err)
		}
	}

	remoteAuth := sync.NewRemoteAuthenticator(cfg, authMgr)
	syncService := sync.NewSyncService(cfg, storage, authMgr)

	return &LoginManager{
		config:      cfg,
		AuthManager: authMgr,
		remoteAuth:  remoteAuth,
		syncService: syncService,
		logger:      logger.GetLogger().WithComponent("login-manager"),
	}, nil
}

// EnsureStorageUnlocked ensures the storage is unlocked for password change operations
func (lm *LoginManager) EnsureStorageUnlocked() error {
	// Check if storage is already unlocked
	if lm.AuthManager.IsSessionActive() {
		return nil
	}

	// If not unlocked, we need to unlock it
	// This should not happen in normal flow since change-password requires current password
	return fmt.Errorf("storage is locked - please run 'ccr unlock' first")
}

// InitUser creates local user and optionally sets up remote account
func (lm *LoginManager) InitUser(username, password string, setupRemote bool, email string) error {
	lm.logger.Info().
		Str("username", username).
		Bool("setup_remote", setupRemote).
		Msg("Starting user initialization")

	// 1. Check if local user already exists
	if lm.AuthManager.UserExists() {
		return fmt.Errorf("CommandChronicles is already initialized")
	}

	// 2. Initialize local user and get derived keys
	_, keys, err := lm.AuthManager.InitUser(username, password)
	if err != nil {
		return fmt.Errorf("failed to initialize local user: %w", err)
	}

	fmt.Println("[OK] Local storage created")

	// 3. Store local session key
	if err := lm.AuthManager.StoreSessionKey(keys.LocalKey); err != nil {
		return fmt.Errorf("failed to store local session: %w", err)
	}

	fmt.Println("[OK] Local storage unlocked")

	// 4. Initialize secure storage to create database
	storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
		Config:              lm.config,
		CreateIfMissing:     true,
		ValidatePermissions: true,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize secure storage: %w", err)
	}
	defer storage.Close()

	// 5. Unlock storage with the derived key
	if err := storage.UnlockWithKey(keys.LocalKey); err != nil {
		return fmt.Errorf("failed to unlock storage: %w", err)
	}

	// 6. Set up remote if requested
	if setupRemote {
		if email == "" {
			return fmt.Errorf("email required for remote setup")
		}

		// Validate email format (basic check)
		if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
			return fmt.Errorf("invalid email format")
		}

		if lm.StatusCallback != nil {
			lm.StatusCallback("Setting up remote sync for "+email+"...", false)
			lm.StatusCallback("Server: "+lm.config.GetSyncServerURL(), false)
		}

		// Register remote account with derived key subset
		if lm.StatusCallback != nil {
			lm.StatusCallback("Creating remote account...", false)
		}
		response, err := lm.remoteAuth.RegisterWithDerivedKey(email, keys.RemoteAuthKey)
		if err != nil {
			if lm.StatusCallback != nil {
				lm.StatusCallback("Creating remote account... [FAIL] Failed", false)
			}
			return fmt.Errorf("failed to register remote account: %w", err)
		}
		if lm.StatusCallback != nil {
			lm.StatusCallback("Creating remote account... [OK] Success", true)
		}

		// Authenticate with remote to store credentials
		if lm.StatusCallback != nil {
			lm.StatusCallback("Authenticating with remote server...", false)
		}
		if err := lm.remoteAuth.AuthenticateWithDerivedKey(email, keys.RemoteAuthKey); err != nil {
			if lm.StatusCallback != nil {
				lm.StatusCallback("Authenticating with remote server... [FAIL] Failed", false)
			}
			return fmt.Errorf("failed to authenticate with remote: %w", err)
		}
		if lm.StatusCallback != nil {
			lm.StatusCallback("Authenticating with remote server... [OK] Success", true)
		}

		// Update config
		lm.config.Sync.Email = email
		lm.config.Sync.Enabled = true

		// Save configuration
		if err := lm.saveConfig(); err != nil {
			lm.logger.WithError(err).Warn().Msg("Failed to save configuration")
			fmt.Printf("[WARN] Warning: Failed to save configuration: %v\n", err)
		}

		// Setup background sync daemon
		daemonManager := daemon.NewManager(lm.config)
		if err := daemonManager.SetupBackgroundSync(); err != nil {
			lm.logger.WithError(err).Warn().Msg("Failed to setup background sync")
			fmt.Printf("[WARN] Warning: Failed to setup background sync: %v\n", err)
			fmt.Println("You can set it up later with: ccr daemon-control install-service")
		}
		daemonManager.Close()

		// Success summary
		fmt.Printf("\n[OK] Setup complete!\n")
		fmt.Printf("Username: %s\n", username)
		fmt.Printf("Email: %s\n", email)
		fmt.Printf("User ID: %s\n", response.UserID)
		fmt.Printf("Device ID: %s\n", response.DeviceID)
		fmt.Printf("Server: %s\n", lm.config.GetSyncServerURL())
		fmt.Printf("\n[DONE] You're ready to use CommandChronicles with sync!\n")

		lm.logger.WithFields(map[string]interface{}{
			"username":  username,
			"email":     email,
			"user_id":   response.UserID,
			"device_id": response.DeviceID,
		}).Info().Msg("Full initialization completed successfully")
	} else {
		// Store email even for local-only setup (for future sync registration)
		lm.config.Sync.Email = email
		lm.config.Sync.Enabled = false // Explicitly disabled for now

		// Save configuration
		if err := lm.saveConfig(); err != nil {
			lm.logger.WithError(err).Warn().Msg("Failed to save configuration")
			fmt.Printf("[WARN] Warning: Failed to save configuration: %v\n", err)
		}

		fmt.Printf("\n[OK] Local setup complete!\n")
		fmt.Printf("Username: %s\n", username)
		fmt.Printf("Email: %s (saved for future sync)\n", email)
		fmt.Printf("\n[DONE] You're ready to use CommandChronicles!\n")
		fmt.Printf("\nTo enable sync later, run: ccr sync register\n")

		lm.logger.WithField("username", username).Info().Msg("Local-only initialization completed successfully")
	}

	return nil
}

// Login authenticates both local and remote systems with smart password change recovery
func (lm *LoginManager) Login(password string) (*LoginResult, error) {
	result := &LoginResult{}

	// 1. Check if local user exists
	if !lm.AuthManager.UserExists() {
		return nil, fmt.Errorf("not initialized - run 'ccr init' first")
	}

	// Get user info
	user, err := lm.AuthManager.GetUser()
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Get email from config
	email := lm.config.Sync.Email

	lm.logger.Info().
		Str("username", user.Username).
		Str("email", email).
		Msg("Starting smart login process")

	// 2. SMART FLOW: Try remote authentication first (if sync enabled)
	var keys *auth.KeyDerivationResult
	var remoteAuthSucceeded bool

	if lm.config.Sync.Enabled && email != "" {
		// Derive keys for remote authentication
		keys, err = lm.AuthManager.DeriveKeys(password, user.KeySalt)
		if err != nil {
			return nil, fmt.Errorf("failed to derive keys: %w", err)
		}

		fmt.Print("Authenticating with remote server...")
		if err := lm.remoteAuth.AuthenticateWithDerivedKey(email, keys.RemoteAuthKey); err != nil {
			fmt.Printf(" [FAIL] Failed: %v\n", err)
			lm.logger.WithError(err).Debug().Msg("Remote authentication failed, trying local-only")
			remoteAuthSucceeded = false
		} else {
			fmt.Printf(" [OK] Success\n")
			remoteAuthSucceeded = true
			result.RemoteSuccess = true
			lm.logger.Info().Msg("Remote authentication successful")
		}
	}

	// 3. Try local authentication
	if keys == nil {
		// Derive keys for local authentication if not already done
		keys, err = lm.AuthManager.DeriveKeys(password, user.KeySalt)
		if err != nil {
			return nil, fmt.Errorf("failed to derive keys: %w", err)
		}
	}

	// Verify local password
	localKeys, localErr := lm.AuthManager.VerifyPassword(user.Username, password)
	if localErr != nil {
		// Local authentication failed
		if remoteAuthSucceeded {
			// SMART RECOVERY: Remote succeeded but local failed
			// This means password was changed on another device
			lm.logger.Info().Msg("Detected password change - remote auth succeeded but local failed")
			fmt.Println("[SYNC] Password change detected from another device")
			fmt.Println("[AUTH] Re-encrypting local data with new password...")

			if err := lm.handlePasswordChangeRecovery(password, keys); err != nil {
				return nil, fmt.Errorf("password change recovery failed: %w", err)
			}

			fmt.Println("[OK] Password change recovery completed")
			result.LocalSuccess = true
			result.RemoteSuccess = true // Remote auth succeeded, so mark it as successful
			result.Message = "Password updated and local data re-encrypted successfully"
		} else {
			// Both remote and local failed
			return nil, fmt.Errorf("invalid password")
		}
	} else {
		// Local authentication succeeded
		keys = localKeys // Use the verified local keys

		// Store local session key
		if err := lm.AuthManager.StoreSessionKey(keys.LocalKey); err != nil {
			return nil, fmt.Errorf("failed to unlock local storage: %w", err)
		}

		result.LocalSuccess = true
		fmt.Println("[OK] Local storage unlocked")
	}

	// 4. Handle sync status messaging
	if lm.config.Sync.Enabled && email != "" {
		if result.RemoteSuccess && result.LocalSuccess {
			result.Message = "Both local and remote authentication successful"
			fmt.Println("[OK] Remote session active")
		} else if result.LocalSuccess && !result.RemoteSuccess {
			result.Message = "Local storage unlocked, but remote authentication failed (offline mode)"
		}
	} else {
		result.Message = "Local storage unlocked (sync not configured)"
	}

	lm.logger.WithFields(map[string]interface{}{
		"local_success":  result.LocalSuccess,
		"remote_success": result.RemoteSuccess,
		"username":       user.Username,
		"email":          email,
	}).Info().Msg("Smart login completed")

	return result, nil
}

// handlePasswordChangeRecovery handles automatic password change recovery
func (lm *LoginManager) handlePasswordChangeRecovery(newPassword string, newKeys *auth.KeyDerivationResult) error {
	lm.logger.Info().Msg("Starting automatic password change recovery")

	// Get current user
	user, err := lm.AuthManager.GetUser()
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	// We need to get the old session key to re-encrypt data
	// Try to load the existing session (encrypted with old password)
	oldKey, err := lm.AuthManager.LoadSessionKey()
	if err != nil {
		lm.logger.Debug().Msg("Could not load old session key, attempting alternative recovery")
		// Alternative: try to get old key from storage directly
		// This might fail, but we'll try re-encryption anyway
		oldKey = nil
	}

	// Re-encrypt stored data with new password
	if oldKey != nil {
		err = lm.AuthManager.ReencryptDataForPasswordChange(user.Username, newPassword, oldKey, newKeys.EncryptionKey)
	} else {
		// Try re-encryption without old key (may skip some records)
		lm.logger.Warn().Msg("Attempting re-encryption without old session key")
		err = lm.AuthManager.ReencryptDataForPasswordChange(user.Username, newPassword, []byte{}, newKeys.EncryptionKey)
	}

	if err != nil {
		return fmt.Errorf("failed to re-encrypt local data: %w", err)
	}

	// Update authentication state atomically
	if err := lm.AuthManager.UpdatePasswordStateAtomic(newPassword); err != nil {
		return fmt.Errorf("failed to update auth state: %w", err)
	}

	// Store new session key to keep storage unlocked
	if err := lm.AuthManager.StoreSessionKey(newKeys.LocalKey); err != nil {
		return fmt.Errorf("failed to store new session key: %w", err)
	}

	// Re-authenticate and store credentials with new session key
	// This fixes the token encryption key mismatch issue
	if lm.config.Sync.Enabled && lm.config.Sync.Email != "" {
		lm.logger.Debug().Msg("Re-storing remote credentials with new session key")
		if err := lm.remoteAuth.AuthenticateWithDerivedKey(lm.config.Sync.Email, newKeys.RemoteAuthKey); err != nil {
			lm.logger.WithError(err).Warn().Msg("Failed to re-store remote credentials after recovery")
			// Don't fail the entire recovery for this, but log it
		} else {
			lm.logger.Info().Msg("Remote credentials re-stored successfully with new session key")
		}
	}

	lm.logger.Info().Msg("Password change recovery completed successfully")
	return nil
}

// SetupSync configures remote sync for existing local user
func (lm *LoginManager) SetupSync(email, password string) error {
	// 1. Check if local user exists and is unlocked
	if !lm.AuthManager.UserExists() {
		return fmt.Errorf("not initialized - run 'ccr init' first")
	}

	if !lm.AuthManager.IsSessionActive() {
		return fmt.Errorf("not logged in - run 'ccr login' first")
	}

	// Get user info
	user, err := lm.AuthManager.GetUser()
	if err != nil {
		return fmt.Errorf("failed to get user info: %w", err)
	}

	// 2. Verify password and get derived keys
	keys, err := lm.AuthManager.VerifyPassword(user.Username, password)
	if err != nil {
		return fmt.Errorf("invalid password")
	}

	// 3. Validate email
	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return fmt.Errorf("invalid email format")
	}

	fmt.Printf("Setting up remote sync for %s...\n", email)
	fmt.Printf("Server: %s\n", lm.config.GetSyncServerURL())

	// 4. Register remote account
	fmt.Print("Creating remote account...")
	// 4. Register account remotely
	response, err := lm.remoteAuth.RegisterWithDerivedKey(email, keys.RemoteAuthKey)
	if err != nil {
		fmt.Printf(" [FAIL] Failed\n")
		return fmt.Errorf("failed to register remote account: %w", err)
	}
	fmt.Printf(" [OK] Success\n")

	// 5. Authenticate with remote
	fmt.Print("Authenticating with remote...")
	if err := lm.remoteAuth.AuthenticateWithDerivedKey(email, keys.RemoteAuthKey); err != nil {
		fmt.Printf(" [FAIL] Failed\n")
		return fmt.Errorf("failed to authenticate with remote: %w", err)
	}
	fmt.Printf(" [OK] Success\n")

	// 6. Update config
	lm.config.Sync.Email = email
	lm.config.Sync.Enabled = true

	// 7. Save configuration
	if err := lm.saveConfig(); err != nil {
		lm.logger.WithError(err).Warn().Msg("Failed to save configuration")
		fmt.Printf("[WARN] Warning: Failed to save configuration: %v\n", err)
	}

	fmt.Printf("\n[OK] Sync setup complete!\n")
	fmt.Printf("Email: %s\n", email)
	fmt.Printf("User ID: %s\n", response.UserID)
	fmt.Printf("Device ID: %s\n", response.DeviceID)

	return nil
}

// RegisterRemoteSync registers with remote server using stored email and verifying password
func (lm *LoginManager) RegisterRemoteSync(inputEmail, password string) (*sync.RegisterResponse, error) {
	// 1. Check if local user exists and is unlocked
	if !lm.AuthManager.UserExists() {
		return nil, fmt.Errorf("not initialized - run 'ccr init' first")
	}

	if !lm.AuthManager.IsSessionActive() {
		return nil, fmt.Errorf("not logged in - please run 'ccr unlock' first")
	}

	// 2. Check if sync already enabled
	if lm.config.Sync.Enabled {
		return nil, fmt.Errorf("sync already enabled for %s", lm.config.Sync.Email)
	}

	// 3. Get user info
	user, err := lm.AuthManager.GetUser()
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// 4. Verify password and get derived keys
	keys, err := lm.AuthManager.VerifyPassword(user.Username, password)
	if err != nil {
		return nil, fmt.Errorf("password doesn't match local credentials")
	}

	// 5. Validate email
	if !strings.Contains(inputEmail, "@") || !strings.Contains(inputEmail, ".") {
		return nil, fmt.Errorf("invalid email format")
	}

	lm.logger.Info().
		Str("email", inputEmail).
		Msg("Starting remote sync registration")

	// 6. Try to register remote account
	response, err := lm.remoteAuth.RegisterWithDerivedKey(inputEmail, keys.RemoteAuthKey)
	if err != nil {
		// Check if it's a "user already exists" error
		if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "Conflict") {
			// User already has an account, offer to login instead
			fmt.Printf("\n[WARN] An account with email %s already exists.\n", inputEmail)
			fmt.Print("Would you like to login to the existing account instead? [Y/n]: ")

			var loginChoice string
			fmt.Scanln(&loginChoice)

			if loginChoice != "" && strings.ToLower(loginChoice) != "y" && strings.ToLower(loginChoice) != "yes" {
				return nil, fmt.Errorf("sync registration cancelled - account already exists")
			}

			// Try to authenticate with existing account
			fmt.Print("Authenticating with existing account...")
			if err := lm.remoteAuth.AuthenticateWithDerivedKey(inputEmail, keys.RemoteAuthKey); err != nil {
				fmt.Printf(" [FAIL] Failed\n")
				return nil, fmt.Errorf("failed to authenticate with existing account - please verify your credentials: %w", err)
			}
			fmt.Printf(" [OK] Success\n")

			// Create a mock response for existing account (we don't have the actual registration response)
			response = &sync.RegisterResponse{
				UserID:   "existing", // We don't know the actual user ID
				DeviceID: "existing", // We don't know the actual device ID
				Email:    inputEmail,
			}
		} else {
			return nil, fmt.Errorf("failed to register remote account: %w", err)
		}
	} else {
		// 7. New account created, authenticate with remote
		if err := lm.remoteAuth.AuthenticateWithDerivedKey(inputEmail, keys.RemoteAuthKey); err != nil {
			return nil, fmt.Errorf("failed to authenticate with remote: %w", err)
		}
	}

	// 8. Update config
	lm.config.Sync.Email = inputEmail
	lm.config.Sync.Enabled = true

	// 9. Save configuration
	if err := lm.saveConfig(); err != nil {
		lm.logger.WithError(err).Warn().Msg("Failed to save configuration")
		return nil, fmt.Errorf("failed to save configuration: %w", err)
	}

	// 10. Setup background sync daemon
	daemonManager := daemon.NewManager(lm.config)
	if err := daemonManager.SetupBackgroundSync(); err != nil {
		lm.logger.WithError(err).Warn().Msg("Failed to setup background sync during registration")
		// Don't return error, just log warning
	}
	daemonManager.Close()

	lm.logger.WithFields(map[string]interface{}{
		"email":     inputEmail,
		"user_id":   response.UserID,
		"device_id": response.DeviceID,
	}).Info().Msg("Remote sync registration completed successfully")

	return response, nil
}

// Logout clears both local and remote sessions
func (lm *LoginManager) Logout() error {
	var errors []string

	// Clear local session
	if err := lm.AuthManager.LockSession(); err != nil {
		errors = append(errors, fmt.Sprintf("failed to lock local session: %v", err))
	}

	// Clear remote credentials
	if err := lm.remoteAuth.Logout(); err != nil {
		errors = append(errors, fmt.Sprintf("failed to logout remote: %v", err))
	}

	if len(errors) > 0 {
		return fmt.Errorf("logout errors: %v", errors)
	}

	fmt.Println("[OK] Logged out successfully")
	return nil
}

// IsLoggedIn checks authentication status
func (lm *LoginManager) IsLoggedIn() (localOK, remoteOK bool) {
	localOK = lm.AuthManager.IsSessionActive()
	remoteOK = lm.remoteAuth.IsServerAuthenticated()
	return localOK, remoteOK
}

// GetAuthStatus returns detailed authentication status
func (lm *LoginManager) GetAuthStatus() map[string]interface{} {
	localOK, remoteOK := lm.IsLoggedIn()

	status := map[string]interface{}{
		"local_authenticated":  localOK,
		"remote_authenticated": remoteOK,
		"email":                lm.config.Sync.Email,
		"server":               lm.config.GetSyncServerURL(),
		"sync_enabled":         lm.config.Sync.Enabled,
	}

	if localOK {
		if user, err := lm.AuthManager.GetUser(); err == nil {
			status["username"] = user.Username
		}
		if remaining, _ := lm.AuthManager.GetSessionTimeRemaining(); remaining > 0 {
			status["local_session_remaining"] = remaining.String()
		}
	}

	if remoteOK {
		if expiry, err := lm.remoteAuth.GetTokenExpiryTime(); err == nil {
			status["remote_token_expires"] = expiry
		}
	}

	return status
}

// ChangePassword changes both local and remote passwords
func (lm *LoginManager) ChangePassword(currentPassword, newPassword string) error {
	lm.logger.Info().Msg("Starting password change process")

	// 1. Validate current password
	user, err := lm.AuthManager.GetUser()
	if err != nil {
		return fmt.Errorf("failed to get user info: %w", err)
	}

	// Verify current password and get current keys
	currentKeys, err := lm.AuthManager.VerifyPassword(user.Username, currentPassword)
	if err != nil {
		return fmt.Errorf("invalid current password")
	}

	// 2. Ensure storage is unlocked for sync operations
	// Use the current password to unlock storage if needed
	if !lm.AuthManager.IsSessionActive() {
		lm.logger.Info().Msg("Storage is locked, unlocking with current password")
		if err := lm.AuthManager.StoreSessionKey(currentKeys.LocalKey); err != nil {
			return fmt.Errorf("failed to unlock storage with current password: %w", err)
		}
		lm.logger.Info().Msg("Storage unlocked successfully")
	}

	// 3. Derive new keys
	// Use same salt for consistency
	newKeys, err := lm.AuthManager.DeriveKeys(newPassword, currentKeys.Salt)
	if err != nil {
		return fmt.Errorf("failed to derive new keys: %w", err)
	}

	// 4. If sync is enabled, ensure we're in sync before changing
	if lm.config.Sync.Enabled && lm.config.Sync.Email != "" {
		lm.logger.Info().Msg("Checking sync status before password change")

		// Phase 2: Perfect Sync integrity check
		fmt.Print("Verifying data integrity...")
		integrityResponse, err := lm.syncService.VerifyIntegrity()
		if err != nil {
			fmt.Printf(" [FAIL] Failed\n")
			return fmt.Errorf("integrity verification failed: %w", err)
		}

		if integrityResponse.IntegrityStatus != "perfect" {
			fmt.Printf(" [WARN] Differences found\n")
			fmt.Print("Synchronizing data...")

			if err := lm.syncService.SyncNow(); err != nil {
				fmt.Printf(" [FAIL] Failed\n")
				return fmt.Errorf("failed to synchronize before password change: %w", err)
			}
			fmt.Printf(" [OK] Success\n")
		} else {
			fmt.Printf(" [OK] Perfect\n")
		}

		// Change remote password FIRST (this acquires the password change lock)
		lm.logger.Info().Msg("Changing remote password and acquiring lock")
		fmt.Print("Updating remote password...")

		if err := lm.remoteAuth.ChangePassword(currentKeys.RemoteAuthKey, newKeys.RemoteAuthKey); err != nil {
			fmt.Printf(" [FAIL] Failed\n")
			lm.logger.WithError(err).Error().Msg("Failed to change remote password")
			return fmt.Errorf("failed to change remote password: %w", err)
		}
		fmt.Printf(" [OK] Success\n")

		// Clear any existing credentials to ensure clean state
		lm.logger.Debug().Msg("Clearing existing credentials before re-authentication")
		if err := lm.remoteAuth.Logout(); err != nil {
			lm.logger.WithError(err).Debug().Msg("Failed to clear credentials (may not exist)")
		}

		// Re-authenticate immediately with new password to get fresh tokens
		lm.logger.Info().Msg("Re-authenticating with new password to get fresh tokens")
		if err := lm.remoteAuth.AuthenticateWithDerivedKey(lm.config.Sync.Email, newKeys.RemoteAuthKey); err != nil {
			return fmt.Errorf("failed to re-authenticate after password change: %w", err)
		}
		lm.logger.Info().Msg("Re-authentication successful, fresh tokens obtained")

		// Phase 2: Batch record re-encryption
		fmt.Print("Re-encrypting records with new key...")
		stagingPath, err := lm.syncService.BatchReencryptRecords(newKeys.EncryptionKey)
		if err != nil {
			fmt.Printf(" [FAIL] Failed\n")
			return fmt.Errorf("failed to re-encrypt records: %w", err)
		}
		defer func() {
			// Cleanup staging area after password change (success or failure)
			if cleanupErr := lm.syncService.CleanupStagingArea(stagingPath); cleanupErr != nil {
				lm.logger.Warn().Err(cleanupErr).Msg("Failed to cleanup staging area")
			}
		}()
		fmt.Printf(" [OK] Success\n")

		fmt.Print("Uploading re-encrypted records...")
		if err := lm.syncService.BatchUpdateRemoteRecords(stagingPath); err != nil {
			fmt.Printf(" [FAIL] Failed\n")
			return fmt.Errorf("failed to update remote records: %w", err)
		}
		fmt.Printf(" [OK] Success\n")

		// Credentials already updated after password change above
	}

	// 5. Change local password
	lm.logger.Info().Msg("Changing local password")
	if err := lm.AuthManager.ChangePassword(currentPassword, newPassword); err != nil {
		return fmt.Errorf("failed to change local password: %w", err)
	}
	fmt.Println("[OK] Local password changed")

	// 7. Update session with new key to keep storage unlocked
	lm.logger.Info().Msg("Updating session with new key")
	if err := lm.AuthManager.StoreSessionKey(newKeys.LocalKey); err != nil {
		lm.logger.WithError(err).Error().Msg("Failed to update session key - storage will be locked")
		fmt.Println("[WARN] Warning: Session update failed. You may need to run 'ccr unlock' to access your data.")
		return fmt.Errorf("password changed but session update failed: %w", err)
	}

	lm.logger.Info().Msg("Session renewed with new key - storage remains unlocked")

	// 8. Re-store remote credentials with new session key (final step)
	// This ensures remote authentication works immediately after password change
	if lm.config.Sync.Enabled && lm.config.Sync.Email != "" {
		lm.logger.Debug().Msg("Final step: Re-storing remote credentials with new session key")
		if err := lm.remoteAuth.AuthenticateWithDerivedKey(lm.config.Sync.Email, newKeys.RemoteAuthKey); err != nil {
			lm.logger.WithError(err).Warn().Msg("Failed to re-store remote credentials after password change - remote sync may require re-authentication")
			fmt.Println("[WARN] Warning: Remote authentication may require 'ccr login' to reactivate sync")
		} else {
			lm.logger.Info().Msg("Remote credentials successfully updated with new session key")
		}
	}

	fmt.Println("\n[OK] Password changed successfully!")
	if lm.config.Sync.Enabled {
		fmt.Println("Please use the new password on all your devices.")
	}

	lm.logger.Info().Msg("Password change completed successfully")
	return nil
}

// Close cleans up resources
func (lm *LoginManager) Close() {
	if lm.AuthManager != nil {
		lm.AuthManager.Close()
	}
}

// saveConfig saves the current configuration to disk
func (lm *LoginManager) saveConfig() error {
	// Determine config path
	configPath := ""
	if homeDir, err := os.UserHomeDir(); err == nil {
		configPath = filepath.Join(homeDir, ".config", "commandchronicles", "config.toml")
	}

	if configPath == "" {
		return fmt.Errorf("could not determine config file path")
	}

	return lm.config.Save(configPath)
}

// InitExistingUser initializes CommandChronicles for an existing user on a new device
func (lm *LoginManager) InitExistingUser(email, password string) error {
	lm.logger.Info().
		Str("email", email).
		Msg("Starting existing user initialization on new device")

	// 1. Check if local user already exists
	if lm.AuthManager.UserExists() {
		return fmt.Errorf("CommandChronicles is already initialized on this device")
	}

	// 2. Create local username from email (use part before @) to match registration
	username := strings.Split(email, "@")[0]
	if username == "" {
		username = "user"
	}

	// 3. Generate deterministic salt from username (same as registration)
	salt := sha256.Sum256([]byte("commandchronicles-salt-v1:" + username))

	// 4. Derive keys from password and salt
	keys, err := lm.AuthManager.DeriveKeys(password, salt[:])
	if err != nil {
		return fmt.Errorf("failed to derive keys: %w", err)
	}

	// 5. Create local user profile first (before remote auth)
	if lm.StatusCallback != nil {
		lm.StatusCallback("Creating local user profile...", false)
	}
	user, _, err := lm.AuthManager.InitUser(username, password)
	if err != nil {
		if lm.StatusCallback != nil {
			lm.StatusCallback("Creating local user profile... [FAIL] Failed", false)
		}
		return fmt.Errorf("failed to create local user: %w", err)
	}
	if lm.StatusCallback != nil {
		lm.StatusCallback("Creating local user profile... [OK] Success", true)
	}

	// 6. Create session with derived keys (needed for storing remote credentials)
	if err := lm.AuthManager.StoreSessionKey(keys.LocalKey); err != nil {
		return fmt.Errorf("failed to store session key: %w", err)
	}

	// 7. Set up sync configuration
	lm.config.Sync.Enabled = true
	lm.config.Sync.Email = email
	lm.config.Sync.BatchSize = 1000
	lm.config.Sync.MaxRetries = 3

	// 8. Save configuration
	var configPath string
	if homeDir, err := os.UserHomeDir(); err == nil {
		configPath = filepath.Join(homeDir, ".config", "commandchronicles", "config.toml")
	}
	if configPath == "" {
		return fmt.Errorf("could not determine config file path")
	}
	if err := lm.config.Save(configPath); err != nil {
		return fmt.Errorf("failed to save sync configuration: %w", err)
	}

	// 9. Now authenticate with remote server (session exists, can store credentials)
	if lm.StatusCallback != nil {
		lm.StatusCallback("Authenticating with server...", false)
	}
	if err := lm.remoteAuth.AuthenticateWithDerivedKey(email, keys.RemoteAuthKey); err != nil {
		if lm.StatusCallback != nil {
			lm.StatusCallback("Authenticating with server... [FAIL] Failed", false)
		}
		return fmt.Errorf("authentication failed: %w", err)
	}
	if lm.StatusCallback != nil {
		lm.StatusCallback("Authenticating with server... [OK] Success", true)
	}

	// 10. Get user info from server for logging
	userID, err := lm.remoteAuth.GetUserID()
	if err != nil {
		return fmt.Errorf("failed to get user ID: %w", err)
	}

	// 11. Create new storage instance and unlock it for sync
	if lm.StatusCallback != nil {
		lm.StatusCallback("Downloading your command history...", false)
	}

	// Load the session key we just created
	sessionKey, err := lm.AuthManager.LoadSessionKey()
	if err != nil {
		if lm.StatusCallback != nil {
			lm.StatusCallback("Downloading your command history... [FAIL] Failed", false)
		}
		return fmt.Errorf("failed to load session key: %w", err)
	}

	// Create new storage instance for sync
	syncStorage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
		Config:              lm.config,
		CreateIfMissing:     true,
		ValidatePermissions: true,
		EnableSecureDelete:  true,
	})
	if err != nil {
		if lm.StatusCallback != nil {
			lm.StatusCallback("Downloading your command history... [FAIL] Failed", false)
		}
		return fmt.Errorf("failed to create sync storage: %w", err)
	}
	defer syncStorage.Close()

	// Unlock storage with session key
	if err := syncStorage.UnlockWithKey(sessionKey); err != nil {
		if lm.StatusCallback != nil {
			lm.StatusCallback("Downloading your command history... [FAIL] Failed", false)
		}
		return fmt.Errorf("failed to unlock sync storage: %w", err)
	}

	// Create new sync service with unlocked storage
	syncService := sync.NewSyncService(lm.config, syncStorage, lm.AuthManager)

	// Initialize and perform initial sync
	if err := syncService.Initialize(); err != nil {
		if lm.StatusCallback != nil {
			lm.StatusCallback("Downloading your command history... [FAIL] Failed", false)
		}
		return fmt.Errorf("failed to initialize sync: %w", err)
	}

	// Perform initial sync to download existing records
	if err := syncService.PerformSync(); err != nil {
		if lm.StatusCallback != nil {
			lm.StatusCallback("Downloading your command history... [WARN] Warning", false)
		}
		lm.logger.WithError(err).Warn().Msg("Initial sync failed, but setup completed")
		if lm.StatusCallback != nil {
			lm.StatusCallback("Note: Sync failed but account setup is complete. Try 'ccr sync now' later.", false)
		}
	} else {
		if lm.StatusCallback != nil {
			lm.StatusCallback("Downloading your command history... [OK] Success", true)
		}
	}

	// 12. Success message
	lm.logger.WithFields(map[string]interface{}{
		"username": user.Username,
		"email":    email,
		"user_id":  userID,
	}).Info().Msg("Existing user initialization completed successfully")

	return nil
}
