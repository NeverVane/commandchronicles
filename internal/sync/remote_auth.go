package sync

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/NeverVane/commandchronicles-cli/internal/auth"
	"github.com/NeverVane/commandchronicles-cli/internal/config"
	"github.com/NeverVane/commandchronicles-cli/internal/logger"
	"github.com/NeverVane/commandchronicles-cli/pkg/crypto"
)

type RemoteAuthenticator struct {
	config     *config.Config
	logger     *logger.Logger
	httpClient *http.Client
	encryptor  *crypto.Encryptor
	deviceMgr  *DeviceManager
	localAuth  *auth.AuthManager
}

type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
	UserID       string `json:"user_id"`
	DeviceID     string `json:"device_id"`
}

type StoredCredentials struct {
	AccessToken  []byte `json:"access_token"`  // Encrypted access token
	RefreshToken []byte `json:"refresh_token"` // Encrypted refresh token
	ExpiresAt    int64  `json:"expires_at"`    // Access token expiry
	UserID       string `json:"user_id"`
	DeviceID     string `json:"device_id"`
	Version      int    `json:"version"` // For future migrations
}

type TokenValidationResponse struct {
	Valid     bool   `json:"valid"`
	Message   string `json:"message"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

func NewRemoteAuthenticator(cfg *config.Config, localAuth *auth.AuthManager) *RemoteAuthenticator {
	return &RemoteAuthenticator{
		config: cfg,
		logger: logger.GetLogger().WithComponent("remote-auth"),
		httpClient: &http.Client{
			Timeout: cfg.GetSyncTimeout(),
		},
		encryptor: crypto.NewEncryptor(),
		deviceMgr: NewDeviceManager(cfg),
		localAuth: localAuth,
	}
}

func (ra *RemoteAuthenticator) Authenticate(email, password string) error {
	// Get device information
	deviceInfo, err := ra.deviceMgr.GetDeviceInfo()
	if err != nil {
		return fmt.Errorf("failed to get device info: %w", err)
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	loginReq := LoginRequest{
		Email:    email,
		Password: password,
		Device: DeviceRegistration{
			DeviceID:   deviceInfo.DeviceID,
			DeviceName: hostname,
			Hostname:   hostname,
			Platform:   runtime.GOOS,
			UserAgent:  "CommandChronicles/1.0.0",
		},
	}

	reqBody, err := json.Marshal(loginReq)
	if err != nil {
		return fmt.Errorf("failed to marshal login request: %w", err)
	}

	resp, err := ra.httpClient.Post(
		ra.config.GetSyncServerURL()+"/api/v1/auth/login",
		"application/json",
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication failed: status %d", resp.StatusCode)
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("failed to decode auth response: %w", err)
	}

	// Store encrypted credentials
	if err := ra.storeCredentials(&authResp); err != nil {
		return fmt.Errorf("failed to store credentials: %w", err)
	}

	ra.logger.Info().
		Str("user_id", authResp.UserID).
		Str("device_id", authResp.DeviceID).
		Msg("Authentication successful with device registration")
	return nil
}

func (ra *RemoteAuthenticator) GetValidToken() (string, error) {
	creds, err := ra.loadCredentials()
	if err != nil {
		return "", fmt.Errorf("failed to load credentials: %w", err)
	}

	// Check if access token is expired (with 60 second buffer)
	if time.Now().Unix() > (creds.ExpiresAt - 60) {
		// Token expired - attempt refresh
		ra.logger.Debug().Msg("Access token expired, attempting refresh")

		if err := ra.RefreshToken(); err != nil {
			ra.logger.Warn().Err(err).Msg("Token refresh failed")
			return "", fmt.Errorf("token refresh failed: %w", err)
		}

		// Reload credentials after refresh
		creds, err = ra.loadCredentials()
		if err != nil {
			return "", fmt.Errorf("failed to reload credentials after refresh: %w", err)
		}

		ra.logger.Info().Msg("Token refreshed successfully")
	}

	return string(creds.AccessToken), nil
}

// IsAuthenticated checks if the user is authenticated with valid tokens
func (ra *RemoteAuthenticator) IsAuthenticated() bool {
	_, err := ra.GetValidToken()
	return err == nil
}

// IsServerAuthenticated validates the token against the server
func (ra *RemoteAuthenticator) IsServerAuthenticated() bool {
	err := ra.ValidateTokenWithServer()
	if err != nil {
		ra.logger.Debug().Err(err).Msg("IsServerAuthenticated failed")
		return false
	}
	ra.logger.Debug().Msg("IsServerAuthenticated succeeded")
	return true
}

// ValidateTokenWithServer calls the server's token validation endpoint
func (ra *RemoteAuthenticator) ValidateTokenWithServer() error {
	ra.logger.Debug().Msg("Starting server token validation")

	// Get current token without refresh to avoid recursion
	creds, err := ra.loadCredentials()
	if err != nil {
		ra.logger.Debug().Err(err).Msg("Failed to load credentials for validation")
		return fmt.Errorf("failed to load credentials: %w", err)
	}

	ra.logger.Debug().
		Int64("expires_at", creds.ExpiresAt).
		Int64("current_time", time.Now().Unix()).
		Str("user_id", creds.UserID).
		Str("device_id", creds.DeviceID).
		Msg("Loaded credentials for validation")

	// Check if token is expired locally first
	if time.Now().Unix() > creds.ExpiresAt {
		ra.logger.Debug().Msg("Token expired locally, validation failed")
		return fmt.Errorf("token expired locally")
	}

	// Make validation request to server
	req, err := http.NewRequest("GET", ra.config.GetSyncServerURL()+"/api/v1/auth/validate", nil)
	if err != nil {
		return fmt.Errorf("failed to create validation request: %w", err)
	}

	// Add authorization header
	req.Header.Set("Authorization", "Bearer "+string(creds.AccessToken))
	req.Header.Set("Content-Type", "application/json")

	// Make the request
	ra.logger.Debug().Str("url", req.URL.String()).Msg("Making token validation request")
	resp, err := ra.httpClient.Do(req)
	if err != nil {
		ra.logger.Debug().Err(err).Msg("Token validation HTTP request failed")
		return fmt.Errorf("validation request failed: %w", err)
	}
	defer resp.Body.Close()

	ra.logger.Debug().Int("status_code", resp.StatusCode).Msg("Received validation response")

	// Handle response
	if resp.StatusCode == 200 {
		// Token is valid
		ra.logger.Debug().Msg("Token validated successfully with server")
		return nil
	}

	// Parse error response
	var validationResp TokenValidationResponse
	if err := json.NewDecoder(resp.Body).Decode(&validationResp); err != nil {
		ra.logger.Debug().
			Int("status_code", resp.StatusCode).
			Err(err).
			Msg("Failed to parse validation error response")
		return fmt.Errorf("token validation failed with status %d", resp.StatusCode)
	}

	ra.logger.Debug().
		Int("status_code", resp.StatusCode).
		Str("error", validationResp.Error).
		Str("message", validationResp.Message).
		Bool("valid", validationResp.Valid).
		Msg("Token validation failed - parsed response")

	// Check for password change error specifically
	if validationResp.Error == "password_changed" {
		ra.logger.Info().Msg("Token invalidated due to password change on another device")
		return fmt.Errorf("password changed on another device")
	}

	// Other validation failures
	ra.logger.Debug().
		Str("error", validationResp.Error).
		Str("message", validationResp.Message).
		Msg("Token validation failed")

	return fmt.Errorf("token validation failed: %s", validationResp.Message)
}

func (ra *RemoteAuthenticator) GetUserID() (string, error) {
	creds, err := ra.loadCredentials()
	if err != nil {
		return "", err
	}
	return creds.UserID, nil
}

func (ra *RemoteAuthenticator) GetDeviceID() (string, error) {
	creds, err := ra.loadCredentials()
	if err != nil {
		return "", err
	}
	return creds.DeviceID, nil
}

// GetStoredEmail retrieves the email address from stored credentials or config
func (ra *RemoteAuthenticator) GetStoredEmail() (string, error) {
	// Try to get email from config first
	if ra.config.Sync.Email != "" {
		return ra.config.Sync.Email, nil
	}

	// If not in config, we'll need to prompt the user
	// This could be enhanced to store email in credentials in the future
	return "", fmt.Errorf("email not found in stored credentials - user input required")
}

func (ra *RemoteAuthenticator) storeCredentials(auth *AuthResponse) error {
	// Ensure local authentication is active
	if !ra.localAuth.IsSessionActive() {
		return fmt.Errorf("local authentication required - please unlock storage first")
	}

	// Get session key for encryption
	sessionKey, err := ra.localAuth.LoadSessionKey()
	if err != nil {
		return fmt.Errorf("failed to load session key: %w", err)
	}

	// Encrypt the access token with session key (use first 32 bytes only)
	encryptedAccessToken, err := ra.encryptor.EncryptBytes([]byte(auth.AccessToken), sessionKey[:32])
	if err != nil {
		return fmt.Errorf("failed to encrypt access token: %w", err)
	}

	// Encrypt the refresh token with session key
	encryptedRefreshToken, err := ra.encryptor.EncryptBytes([]byte(auth.RefreshToken), sessionKey[:32])
	if err != nil {
		return fmt.Errorf("failed to encrypt refresh token: %w", err)
	}

	creds := StoredCredentials{
		AccessToken:  encryptedAccessToken,
		RefreshToken: encryptedRefreshToken,
		ExpiresAt:    auth.ExpiresAt,
		UserID:       auth.UserID,
		DeviceID:     auth.DeviceID,
		Version:      1,
	}

	credsPath := ra.getCredentialsPath()
	if err := os.MkdirAll(filepath.Dir(credsPath), 0700); err != nil {
		return err
	}

	credsData, err := json.Marshal(creds)
	if err != nil {
		return err
	}

	return os.WriteFile(credsPath, credsData, 0600)
}

func (ra *RemoteAuthenticator) loadCredentials() (*StoredCredentials, error) {
	// Ensure local authentication is active
	if !ra.localAuth.IsSessionActive() {
		return nil, fmt.Errorf("local authentication required - please unlock storage first")
	}

	credsPath := ra.getCredentialsPath()

	data, err := os.ReadFile(credsPath)
	if err != nil {
		return nil, err
	}

	var creds StoredCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, err
	}

	// Get session key for decryption
	sessionKey, err := ra.localAuth.LoadSessionKey()
	if err != nil {
		return nil, fmt.Errorf("failed to load session key: %w", err)
	}

	// Decrypt the access token (use first 32 bytes of session key)
	decryptedAccessToken, err := ra.encryptor.DecryptBytes(creds.AccessToken, sessionKey[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt access token: %w", err)
	}

	// Decrypt the refresh token
	decryptedRefreshToken, err := ra.encryptor.DecryptBytes(creds.RefreshToken, sessionKey[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt refresh token: %w", err)
	}

	// Return credentials with decrypted tokens
	creds.AccessToken = decryptedAccessToken
	creds.RefreshToken = decryptedRefreshToken
	return &creds, nil
}

func (ra *RemoteAuthenticator) getCredentialsPath() string {
	configDir := filepath.Dir(ra.config.Database.Path)
	return filepath.Join(configDir, "sync_credentials.json")
}

func (ra *RemoteAuthenticator) Logout() error {
	credsPath := ra.getCredentialsPath()
	if err := os.Remove(credsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	ra.logger.Info().Msg("Logged out successfully")
	return nil
}

func (ra *RemoteAuthenticator) TestConnection() error {
	if !ra.config.Sync.Enabled {
		return fmt.Errorf("sync is not enabled")
	}

	// Use hardcoded server URL instead of config
	serverURL := ra.config.GetSyncServerURL()
	req, err := http.NewRequest("GET", serverURL+"/api/v1/health", nil)
	if err != nil {
		return err
	}

	// Test basic connectivity first (health endpoint doesn't require auth)
	resp, err := ra.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server health check failed: status %d", resp.StatusCode)
	}

	return nil
}

func (ra *RemoteAuthenticator) RefreshToken() error {
	// Load current credentials to get refresh token
	creds, err := ra.loadCredentials()
	if err != nil {
		return fmt.Errorf("failed to load credentials for refresh: %w", err)
	}

	// Prepare refresh request
	refreshReq := struct {
		RefreshToken string `json:"refresh_token"`
	}{
		RefreshToken: string(creds.RefreshToken),
	}

	reqBody, err := json.Marshal(refreshReq)
	if err != nil {
		return fmt.Errorf("failed to marshal refresh request: %w", err)
	}

	// Make refresh request to server
	resp, err := ra.httpClient.Post(
		ra.config.GetSyncServerURL()+"/api/v1/auth/refresh",
		"application/json",
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		return fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle non-success responses
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			// Refresh token expired or invalid - clear credentials
			ra.Logout()
			return fmt.Errorf("refresh token expired - please re-authenticate")
		}
		return fmt.Errorf("token refresh failed: status %d", resp.StatusCode)
	}

	// Parse response with new tokens
	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("failed to decode refresh response: %w", err)
	}

	// Store new tokens
	if err := ra.storeCredentials(&authResp); err != nil {
		return fmt.Errorf("failed to store refreshed credentials: %w", err)
	}

	ra.logger.Info().Msg("Token refreshed successfully")
	return nil
}

// AuthenticateWithDerivedKey authenticates using pre-derived remote auth key (for existing users)
func (ra *RemoteAuthenticator) AuthenticateWithDerivedKey(email string, remoteAuthKey []byte) error {
	// Get device information
	deviceInfo, err := ra.deviceMgr.GetDeviceInfo()
	if err != nil {
		return fmt.Errorf("failed to get device info: %w", err)
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	// Convert remote auth key to hex format (as expected by server)
	passwordHex := fmt.Sprintf("%x", remoteAuthKey)

	loginReq := LoginRequest{
		Email:    email,
		Password: passwordHex,
		Device: DeviceRegistration{
			DeviceID:   deviceInfo.DeviceID,
			DeviceName: hostname,
			Hostname:   hostname,
			Platform:   runtime.GOOS,
			UserAgent:  "CommandChronicles/1.0.0",
		},
	}

	reqBody, err := json.Marshal(loginReq)
	if err != nil {
		return fmt.Errorf("failed to marshal login request: %w", err)
	}

	resp, err := ra.httpClient.Post(
		ra.config.GetSyncServerURL()+"/api/v1/auth/login",
		"application/json",
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication failed: status %d", resp.StatusCode)
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("failed to decode auth response: %w", err)
	}

	// Store encrypted credentials
	if err := ra.storeCredentials(&authResp); err != nil {
		return fmt.Errorf("failed to store credentials: %w", err)
	}

	ra.logger.Info().
		Str("user_id", authResp.UserID).
		Str("device_id", authResp.DeviceID).
		Msg("Authentication successful with derived key")
	return nil
}

func (ra *RemoteAuthenticator) GetTokenExpiryTime() (time.Time, error) {
	creds, err := ra.loadCredentials()
	if err != nil {
		return time.Time{}, err
	}

	return time.Unix(creds.ExpiresAt, 0), nil
}

// RegisterWithDerivedKey registers a new account using derived key subset
func (ra *RemoteAuthenticator) RegisterWithDerivedKey(email string, remoteKey []byte) (*RegisterResponse, error) {
	// Convert 32-byte derived key to hex string for transmission
	remotePassword := fmt.Sprintf("%x", remoteKey)

	// Get device information for registration
	deviceInfo, err := ra.deviceMgr.GetDeviceInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get device info: %w", err)
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	device := DeviceRegistration{
		DeviceID:   deviceInfo.DeviceID,
		DeviceName: hostname,
		Hostname:   hostname,
		Platform:   deviceInfo.Platform,
		UserAgent:  deviceInfo.UserAgent,
	}

	ra.logger.Debug().
		Str("email", email).
		Int("remote_key_length", len(remoteKey)).
		Msg("Registering with derived key")

	// Use SyncClient to register
	client := NewSyncClient(ra.config, ra)
	return client.Register(email, remotePassword, remotePassword, device)
}

// AuthenticateWithDerivedKey authenticates using derived key subset

// ChangePassword changes the remote password
func (ra *RemoteAuthenticator) ChangePassword(currentRemoteKey, newRemoteKey []byte) error {
	// Convert keys to hex
	currentHex := fmt.Sprintf("%x", currentRemoteKey)
	newHex := fmt.Sprintf("%x", newRemoteKey)

	// Prepare request
	req := struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
	}{
		CurrentPassword: currentHex,
		NewPassword:     newHex,
		ConfirmPassword: newHex,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal password change request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequest("PUT",
		ra.config.GetSyncServerURL()+"/api/v1/user/password",
		bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers
	httpReq.Header.Set("Content-Type", "application/json")
	token, err := ra.GetValidToken()
	if err != nil {
		return fmt.Errorf("failed to get auth token: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)

	// Execute request
	resp, err := ra.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("password change request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response
	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error   string `json:"error"`
			Message string `json:"message"`
			Code    string `json:"code"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil {
			return fmt.Errorf("password change failed: %s - %s", errResp.Code, errResp.Message)
		}
		return fmt.Errorf("password change failed: status %d", resp.StatusCode)
	}

	ra.logger.Info().Msg("Remote password changed successfully")
	return nil
}

// SubscriptionCancelResponse represents the API response for subscription cancellation
type SubscriptionCancelResponse struct {
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	CancelledAt   string `json:"cancelled_at"`
	EffectiveDate string `json:"effective_date"`
	AccessInfo    string `json:"access_info"`
}

// CancelSubscription cancels the user's premium subscription
func (ra *RemoteAuthenticator) CancelSubscription() (*SubscriptionCancelResponse, error) {
	ra.logger.Info().Msg("Initiating subscription cancellation")

	// Get valid token for authentication
	token, err := ra.GetValidToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get valid token: %w", err)
	}

	// Create DELETE request
	req, err := http.NewRequest("DELETE",
		ra.config.GetSyncServerURL()+"/api/v1/subscription/cancel",
		nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cancellation request: %w", err)
	}

	// Add authentication header
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	ra.logger.Debug().Msg("Making subscription cancellation request")

	// Execute request
	resp, err := ra.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute cancellation request: %w", err)
	}
	defer resp.Body.Close()

	ra.logger.Debug().Int("status_code", resp.StatusCode).Msg("Received cancellation response")

	// Handle different response codes
	switch resp.StatusCode {
	case http.StatusOK:
		var cancelResp SubscriptionCancelResponse
		if err := json.NewDecoder(resp.Body).Decode(&cancelResp); err != nil {
			return nil, fmt.Errorf("failed to decode success response: %w", err)
		}
		ra.logger.Info().Msg("Subscription cancelled successfully")
		return &cancelResp, nil

	case http.StatusUnauthorized:
		return nil, fmt.Errorf("authentication failed - please login again")

	case http.StatusForbidden:
		return nil, fmt.Errorf("cannot cancel Community subscription - you're already on the free tier")

	case http.StatusConflict:
		return nil, fmt.Errorf("subscription already cancelled")

	case http.StatusNotFound:
		return nil, fmt.Errorf("no subscription found")

	default:
		// Try to decode error response
		var errResp struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil {
			return nil, fmt.Errorf("cancellation failed: %s", errResp.Message)
		}
		return nil, fmt.Errorf("cancellation failed with status %d", resp.StatusCode)
	}
}
