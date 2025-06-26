package sync

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
	
	"github.com/NeverVane/commandchronicles-cli/internal/config"
	"github.com/NeverVane/commandchronicles-cli/internal/logger"
)

type TokenManager struct {
	config       *config.Config
	logger       *logger.Logger
	tokenPath    string
	currentToken *JWTToken
}

type JWTToken struct {
	AccessToken string `json:"access_token"`
	ExpiresAt   int64  `json:"expires_at"`
	UserID      string `json:"user_id"`
	DeviceID    string `json:"device_id"`
	IssuedAt    int64  `json:"issued_at"`
	TokenType   string `json:"token_type"`
}

func NewTokenManager(cfg *config.Config) *TokenManager {
	configDir := filepath.Dir(cfg.Database.Path)
	tokenPath := filepath.Join(configDir, "jwt_token.json")
	
	return &TokenManager{
		config:    cfg,
		logger:    logger.GetLogger().WithComponent("token"),
		tokenPath: tokenPath,
	}
}

func (tm *TokenManager) LoadToken() error {
	data, err := os.ReadFile(tm.tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No token file exists
		}
		return fmt.Errorf("failed to read token file: %w", err)
	}
	
	var token JWTToken
	if err := json.Unmarshal(data, &token); err != nil {
		return fmt.Errorf("failed to parse token file: %w", err)
	}
	
	tm.currentToken = &token
	return nil
}

func (tm *TokenManager) SaveToken(token *JWTToken) error {
	tm.currentToken = token
	
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}
	
	if err := os.MkdirAll(filepath.Dir(tm.tokenPath), 0700); err != nil {
		return fmt.Errorf("failed to create token directory: %w", err)
	}
	
	if err := os.WriteFile(tm.tokenPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}
	
	tm.logger.Debug().Msg("Token saved successfully")
	return nil
}

func (tm *TokenManager) IsTokenValid() bool {
	if tm.currentToken == nil {
		return false
	}
	
	// Add 60 second buffer for token expiration
	return time.Now().Unix() < (tm.currentToken.ExpiresAt - 60)
}

func (tm *TokenManager) GetValidToken() (string, error) {
	if err := tm.LoadToken(); err != nil {
		return "", err
	}
	
	if !tm.IsTokenValid() {
		return "", fmt.Errorf("token expired or invalid")
	}
	
	return tm.currentToken.AccessToken, nil
}

func (tm *TokenManager) ClearToken() error {
	tm.currentToken = nil
	
	if err := os.Remove(tm.tokenPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove token file: %w", err)
	}
	
	tm.logger.Debug().Msg("Token cleared successfully")
	return nil
}

func (tm *TokenManager) GetUserID() string {
	if tm.currentToken == nil {
		return ""
	}
	return tm.currentToken.UserID
}

func (tm *TokenManager) GetDeviceID() string {
	if tm.currentToken == nil {
		return ""
	}
	return tm.currentToken.DeviceID
}

func (tm *TokenManager) GetTokenInfo() (*JWTToken, error) {
	if err := tm.LoadToken(); err != nil {
		return nil, err
	}
	
	if tm.currentToken == nil {
		return nil, fmt.Errorf("no token available")
	}
	
	return tm.currentToken, nil
}

func (tm *TokenManager) GetTimeUntilExpiry() (time.Duration, error) {
	if tm.currentToken == nil {
		return 0, fmt.Errorf("no token loaded")
	}
	
	expiryTime := time.Unix(tm.currentToken.ExpiresAt, 0)
	return time.Until(expiryTime), nil
}

func (tm *TokenManager) IsExpiringSoon(threshold time.Duration) bool {
	if tm.currentToken == nil {
		return true
	}
	
	timeUntilExpiry, err := tm.GetTimeUntilExpiry()
	if err != nil {
		return true
	}
	
	return timeUntilExpiry < threshold
}

func (tm *TokenManager) ValidateTokenStructure() error {
	if tm.currentToken == nil {
		return fmt.Errorf("no token to validate")
	}
	
	if tm.currentToken.AccessToken == "" {
		return fmt.Errorf("access token is empty")
	}
	
	if tm.currentToken.ExpiresAt == 0 {
		return fmt.Errorf("expiration time is not set")
	}
	
	if tm.currentToken.UserID == "" {
		return fmt.Errorf("user ID is empty")
	}
	
	if tm.currentToken.DeviceID == "" {
		return fmt.Errorf("device ID is empty")
	}
	
	return nil
}

func (tm *TokenManager) CreateTokenFromAuth(auth *AuthResponse) *JWTToken {
	return &JWTToken{
		AccessToken: auth.AccessToken,
		ExpiresAt:   auth.ExpiresAt,
		UserID:      auth.UserID,
		DeviceID:    auth.DeviceID,
		IssuedAt:    time.Now().Unix(),
		TokenType:   "Bearer",
	}
}

func (tm *TokenManager) GetTokenAge() (time.Duration, error) {
	if tm.currentToken == nil {
		return 0, fmt.Errorf("no token loaded")
	}
	
	issuedTime := time.Unix(tm.currentToken.IssuedAt, 0)
	return time.Since(issuedTime), nil
}