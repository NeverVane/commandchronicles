package sync

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/NeverVane/commandchronicles/internal/config"
	"github.com/NeverVane/commandchronicles/internal/logger"
	securestorage "github.com/NeverVane/commandchronicles/pkg/storage"
	"github.com/google/uuid"
)

// RulesManager handles sync rule creation, storage, and management
type RulesManager struct {
	storage            *securestorage.SecureStorage
	config             *config.Config
	logger             *logger.Logger
	deviceAliasManager *DeviceAliasManager
}

// SyncRule represents a sync rule configuration
type SyncRule struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Description  string          `json:"description,omitempty"`
	Action       string          `json:"action"`        // "allow" or "deny"
	TargetDevice string          `json:"target_device"` // Device ID (not alias)
	Conditions   []RuleCondition `json:"conditions,omitempty"`
	Active       bool            `json:"active"`
	CreatedAt    int64           `json:"created_at"`
	UpdatedAt    int64           `json:"updated_at"`
}

// RuleCondition represents conditions for rule application (for future phases)
type RuleCondition struct {
	Type     string `json:"type"`     // "tag", "working_dir", "command_pattern"
	Operator string `json:"operator"` // "equals", "contains", "starts_with", "regex"
	Value    string `json:"value"`
	Negate   bool   `json:"negate,omitempty"`
}

// RuleSummary provides an overview of rules
type RuleSummary struct {
	TotalRules  int `json:"total_rules"`
	ActiveRules int `json:"active_rules"`
	AllowRules  int `json:"allow_rules"`
	DenyRules   int `json:"deny_rules"`
}

// NewRulesManager creates a new rules manager
func NewRulesManager(storage *securestorage.SecureStorage, cfg *config.Config, deviceAliasManager *DeviceAliasManager) *RulesManager {
	return &RulesManager{
		storage:            storage,
		config:             cfg,
		logger:             logger.GetLogger().WithComponent("rules-manager"),
		deviceAliasManager: deviceAliasManager,
	}
}

// CreateRule creates a new sync rule
func (rm *RulesManager) CreateRule(rule *SyncRule) error {
	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}

	// Validate rule
	if err := rm.validateRule(rule); err != nil {
		return fmt.Errorf("rule validation failed: %w", err)
	}

	// Generate ID and timestamps if not set
	if rule.ID == "" {
		rule.ID = uuid.New().String()
	}
	now := time.Now().UnixMilli()
	rule.CreatedAt = now
	rule.UpdatedAt = now

	// Serialize rule to JSON
	ruleData, err := json.Marshal(rule)
	if err != nil {
		return fmt.Errorf("failed to serialize rule: %w", err)
	}

	// Store in database
	query := `INSERT INTO sync_rules (id, rule_data, active, created_at) VALUES (?, ?, ?, ?)`
	_, err = rm.storage.GetDatabase().GetDB().Exec(query, rule.ID, string(ruleData), rule.Active, rule.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to store rule: %w", err)
	}

	rm.logger.Info().Str("rule_id", rule.ID).Str("action", rule.Action).Str("target", rule.TargetDevice).Msg("Rule created")

	// Trigger re-evaluation of existing commands
	if err := rm.triggerReEvaluation(); err != nil {
		rm.logger.Warn().Err(err).Msg("Failed to trigger re-evaluation after rule creation")
	}

	return nil
}

// ListRules returns all sync rules
func (rm *RulesManager) ListRules() ([]SyncRule, error) {
	query := `SELECT rule_data FROM sync_rules ORDER BY created_at DESC`

	rows, err := rm.storage.GetDatabase().GetDB().Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query rules: %w", err)
	}
	defer rows.Close()

	var rules []SyncRule
	for rows.Next() {
		var ruleData string
		if err := rows.Scan(&ruleData); err != nil {
			return nil, fmt.Errorf("failed to scan rule data: %w", err)
		}

		var rule SyncRule
		if err := json.Unmarshal([]byte(ruleData), &rule); err != nil {
			rm.logger.Warn().Str("rule_data", ruleData).Msg("Failed to unmarshal rule, skipping")
			continue
		}

		rules = append(rules, rule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rules: %w", err)
	}

	return rules, nil
}

// GetRule returns a specific rule by ID
func (rm *RulesManager) GetRule(ruleID string) (*SyncRule, error) {
	if ruleID == "" {
		return nil, fmt.Errorf("rule ID cannot be empty")
	}

	// First try exact match
	query := `SELECT rule_data FROM sync_rules WHERE id = ?`
	var ruleData string
	err := rm.storage.GetDatabase().GetDB().QueryRow(query, ruleID).Scan(&ruleData)
	if err == nil {
		var rule SyncRule
		if err := json.Unmarshal([]byte(ruleData), &rule); err != nil {
			return nil, fmt.Errorf("failed to unmarshal rule: %w", err)
		}
		return &rule, nil
	}

	// If no exact match and ID is at least 8 characters, try prefix match
	if len(ruleID) >= 8 {
		findQuery := `SELECT id, rule_data FROM sync_rules WHERE id LIKE ?`
		rows, err := rm.storage.GetDatabase().GetDB().Query(findQuery, ruleID+"%")
		if err != nil {
			return nil, fmt.Errorf("failed to search for rules: %w", err)
		}
		defer rows.Close()

		var matches []struct {
			ID   string
			Data string
		}
		for rows.Next() {
			var match struct {
				ID   string
				Data string
			}
			if err := rows.Scan(&match.ID, &match.Data); err != nil {
				continue
			}
			matches = append(matches, match)
		}

		if len(matches) == 0 {
			return nil, fmt.Errorf("rule not found: %s", ruleID)
		}

		if len(matches) > 1 {
			var matchingIDs []string
			for _, match := range matches {
				matchingIDs = append(matchingIDs, match.ID)
			}
			return nil, fmt.Errorf("ambiguous rule ID %s matches multiple rules: %v", ruleID, matchingIDs)
		}

		var rule SyncRule
		if err := json.Unmarshal([]byte(matches[0].Data), &rule); err != nil {
			return nil, fmt.Errorf("failed to unmarshal rule: %w", err)
		}
		return &rule, nil
	}

	return nil, fmt.Errorf("rule not found: %s", ruleID)
}

// UpdateRule updates an existing rule
func (rm *RulesManager) UpdateRule(rule *SyncRule) error {
	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}

	if rule.ID == "" {
		return fmt.Errorf("rule ID cannot be empty")
	}

	// Validate rule
	if err := rm.validateRule(rule); err != nil {
		return fmt.Errorf("rule validation failed: %w", err)
	}

	// Update timestamp
	rule.UpdatedAt = time.Now().UnixMilli()

	// Serialize rule to JSON
	ruleData, err := json.Marshal(rule)
	if err != nil {
		return fmt.Errorf("failed to serialize rule: %w", err)
	}

	// Update in database
	query := `UPDATE sync_rules SET rule_data = ?, active = ? WHERE id = ?`
	result, err := rm.storage.GetDatabase().GetDB().Exec(query, string(ruleData), rule.Active, rule.ID)
	if err != nil {
		return fmt.Errorf("failed to update rule: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("rule not found: %s", rule.ID)
	}

	rm.logger.Info().Str("rule_id", rule.ID).Msg("Rule updated")
	return nil
}

// DeleteRule deletes a rule by ID
func (rm *RulesManager) DeleteRule(ruleID string) error {
	if ruleID == "" {
		return fmt.Errorf("rule ID cannot be empty")
	}

	// First try exact match
	query := `DELETE FROM sync_rules WHERE id = ?`
	result, err := rm.storage.GetDatabase().GetDB().Exec(query, ruleID)
	if err != nil {
		return fmt.Errorf("failed to delete rule: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	// If exact match worked, we're done
	if rowsAffected > 0 {
		rm.logger.Info().Str("rule_id", ruleID).Msg("Rule deleted")

		// Trigger re-evaluation of existing commands
		if err := rm.triggerReEvaluation(); err != nil {
			rm.logger.Warn().Err(err).Msg("Failed to trigger re-evaluation after rule deletion")
		}

		return nil
	}

	// If no exact match and ID is at least 8 characters, try prefix match
	if len(ruleID) >= 8 {
		// Find rules matching the prefix
		findQuery := `SELECT id FROM sync_rules WHERE id LIKE ?`
		rows, err := rm.storage.GetDatabase().GetDB().Query(findQuery, ruleID+"%")
		if err != nil {
			return fmt.Errorf("failed to search for rules: %w", err)
		}
		defer rows.Close()

		var matchingIDs []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				continue
			}
			matchingIDs = append(matchingIDs, id)
		}

		if len(matchingIDs) == 0 {
			return fmt.Errorf("rule not found: %s", ruleID)
		}

		if len(matchingIDs) > 1 {
			return fmt.Errorf("ambiguous rule ID %s matches multiple rules: %v", ruleID, matchingIDs)
		}

		// Delete the matching rule
		fullID := matchingIDs[0]
		deleteQuery := `DELETE FROM sync_rules WHERE id = ?`
		_, err = rm.storage.GetDatabase().GetDB().Exec(deleteQuery, fullID)
		if err != nil {
			return fmt.Errorf("failed to delete rule: %w", err)
		}

		rm.logger.Info().Str("rule_id", fullID).Str("partial_id", ruleID).Msg("Rule deleted")

		// Trigger re-evaluation of existing commands
		if err := rm.triggerReEvaluation(); err != nil {
			rm.logger.Warn().Err(err).Msg("Failed to trigger re-evaluation after rule deletion")
		}

		return nil
	}

	return fmt.Errorf("rule not found: %s", ruleID)
}

// ToggleRule enables or disables a rule
func (rm *RulesManager) ToggleRule(ruleID string, active bool) error {
	if ruleID == "" {
		return fmt.Errorf("rule ID cannot be empty")
	}

	// Get current rule
	rule, err := rm.GetRule(ruleID)
	if err != nil {
		return fmt.Errorf("failed to get rule: %w", err)
	}

	// Update active state
	rule.Active = active
	rule.UpdatedAt = time.Now().UnixMilli()

	// Serialize and update
	ruleData, err := json.Marshal(rule)
	if err != nil {
		return fmt.Errorf("failed to serialize rule: %w", err)
	}

	query := `UPDATE sync_rules SET rule_data = ?, active = ? WHERE id = ?`
	_, err = rm.storage.GetDatabase().GetDB().Exec(query, string(ruleData), active, ruleID)
	if err != nil {
		return fmt.Errorf("failed to toggle rule: %w", err)
	}

	rm.logger.Info().Str("rule_id", ruleID).Bool("active", active).Msg("Rule toggled")

	// Trigger re-evaluation of existing commands
	if err := rm.triggerReEvaluation(); err != nil {
		rm.logger.Warn().Err(err).Msg("Failed to trigger re-evaluation after rule toggle")
	}

	return nil
}

// CreateAllowRule creates a simple allow rule for a device
func (rm *RulesManager) CreateAllowRule(deviceAliasOrID string) error {
	// Resolve device alias to ID
	deviceID, err := rm.deviceAliasManager.ResolveAlias(deviceAliasOrID)
	if err != nil {
		return fmt.Errorf("failed to resolve device: %w", err)
	}

	// Get device alias for naming (if exists)
	alias, _ := rm.deviceAliasManager.GetDeviceAlias(deviceID)
	displayName := deviceAliasOrID
	if alias != "" {
		displayName = alias
	}

	rule := &SyncRule{
		Name:         fmt.Sprintf("Allow sync to %s", displayName),
		Description:  fmt.Sprintf("Allow all commands to sync to device %s", displayName),
		Action:       "allow",
		TargetDevice: deviceID,
		Active:       true,
	}

	return rm.CreateRule(rule)
}

// CreateDenyRule creates a simple deny rule for a device
func (rm *RulesManager) CreateDenyRule(deviceAliasOrID string) error {
	// Resolve device alias to ID
	deviceID, err := rm.deviceAliasManager.ResolveAlias(deviceAliasOrID)
	if err != nil {
		return fmt.Errorf("failed to resolve device: %w", err)
	}

	// Get device alias for naming (if exists)
	alias, _ := rm.deviceAliasManager.GetDeviceAlias(deviceID)
	displayName := deviceAliasOrID
	if alias != "" {
		displayName = alias
	}

	rule := &SyncRule{
		Name:         fmt.Sprintf("Deny sync to %s", displayName),
		Description:  fmt.Sprintf("Prevent commands from syncing to device %s", displayName),
		Action:       "deny",
		TargetDevice: deviceID,
		Active:       true,
	}

	return rm.CreateRule(rule)
}

// CreateConditionalAllowRule creates an allow rule with specific conditions
func (rm *RulesManager) CreateConditionalAllowRule(deviceAliasOrID string, conditions []RuleCondition) error {
	// Resolve device alias to ID
	deviceID, err := rm.deviceAliasManager.ResolveAlias(deviceAliasOrID)
	if err != nil {
		return fmt.Errorf("failed to resolve device: %w", err)
	}

	// Get device alias for naming (if exists)
	alias, _ := rm.deviceAliasManager.GetDeviceAlias(deviceID)
	displayName := deviceAliasOrID
	if alias != "" {
		displayName = alias
	}

	// Generate condition description
	conditionDesc := rm.generateConditionDescription(conditions)
	ruleName := fmt.Sprintf("Allow %s to %s", conditionDesc, displayName)
	ruleDesc := fmt.Sprintf("Allow commands matching %s to sync to device %s", conditionDesc, displayName)

	rule := &SyncRule{
		Name:         ruleName,
		Description:  ruleDesc,
		Action:       "allow",
		TargetDevice: deviceID,
		Conditions:   conditions,
		Active:       true,
	}

	return rm.CreateRule(rule)
}

// CreateConditionalDenyRule creates a deny rule with specific conditions
func (rm *RulesManager) CreateConditionalDenyRule(deviceAliasOrID string, conditions []RuleCondition) error {
	// Resolve device alias to ID
	deviceID, err := rm.deviceAliasManager.ResolveAlias(deviceAliasOrID)
	if err != nil {
		return fmt.Errorf("failed to resolve device: %w", err)
	}

	// Get device alias for naming (if exists)
	alias, _ := rm.deviceAliasManager.GetDeviceAlias(deviceID)
	displayName := deviceAliasOrID
	if alias != "" {
		displayName = alias
	}

	// Generate condition description
	conditionDesc := rm.generateConditionDescription(conditions)
	ruleName := fmt.Sprintf("Deny %s to %s", conditionDesc, displayName)
	ruleDesc := fmt.Sprintf("Prevent commands matching %s from syncing to device %s", conditionDesc, displayName)

	rule := &SyncRule{
		Name:         ruleName,
		Description:  ruleDesc,
		Action:       "deny",
		TargetDevice: deviceID,
		Conditions:   conditions,
		Active:       true,
	}

	return rm.CreateRule(rule)
}

// CreateTagRule creates a rule based on command tags
func (rm *RulesManager) CreateTagRule(deviceAliasOrID, tag string, allow bool) error {
	conditions := []RuleCondition{
		{
			Type:     "tag",
			Operator: "equals",
			Value:    tag,
		},
	}

	if allow {
		return rm.CreateConditionalAllowRule(deviceAliasOrID, conditions)
	}
	return rm.CreateConditionalDenyRule(deviceAliasOrID, conditions)
}

// CreateDirectoryRule creates a rule based on working directory
func (rm *RulesManager) CreateDirectoryRule(deviceAliasOrID, directory string, allow bool) error {
	conditions := []RuleCondition{
		{
			Type:     "working_dir",
			Operator: "starts_with",
			Value:    directory,
		},
	}

	if allow {
		return rm.CreateConditionalAllowRule(deviceAliasOrID, conditions)
	}
	return rm.CreateConditionalDenyRule(deviceAliasOrID, conditions)
}

// CreatePatternRule creates a rule based on command pattern
func (rm *RulesManager) CreatePatternRule(deviceAliasOrID, pattern string, allow bool) error {
	conditions := []RuleCondition{
		{
			Type:     "command_pattern",
			Operator: "starts_with",
			Value:    pattern,
		},
	}

	if allow {
		return rm.CreateConditionalAllowRule(deviceAliasOrID, conditions)
	}
	return rm.CreateConditionalDenyRule(deviceAliasOrID, conditions)
}

// CreateTimeRule creates a rule based on time constraints
func (rm *RulesManager) CreateTimeRule(deviceAliasOrID, timeCondition string, allow bool) error {
	conditions := []RuleCondition{
		{
			Type:     "time",
			Operator: "during",
			Value:    timeCondition,
		},
	}

	if allow {
		return rm.CreateConditionalAllowRule(deviceAliasOrID, conditions)
	}
	return rm.CreateConditionalDenyRule(deviceAliasOrID, conditions)
}

// generateConditionDescription creates a human-readable description of conditions
func (rm *RulesManager) generateConditionDescription(conditions []RuleCondition) string {
	if len(conditions) == 0 {
		return "all commands"
	}

	var parts []string
	for _, condition := range conditions {
		var desc string
		switch condition.Type {
		case "tag":
			desc = fmt.Sprintf("tag:%s", condition.Value)
		case "working_dir":
			desc = fmt.Sprintf("dir:%s", condition.Value)
		case "command_pattern":
			desc = fmt.Sprintf("cmd:%s", condition.Value)
		case "time":
			desc = fmt.Sprintf("time:%s", condition.Value)
		default:
			desc = fmt.Sprintf("%s:%s", condition.Type, condition.Value)
		}

		if condition.Negate {
			desc = "!" + desc
		}

		parts = append(parts, desc)
	}

	return strings.Join(parts, " AND ")
}

// GetRulesSummary returns a summary of all rules
func (rm *RulesManager) GetRulesSummary() (*RuleSummary, error) {
	rules, err := rm.ListRules()
	if err != nil {
		return nil, fmt.Errorf("failed to get rules: %w", err)
	}

	summary := &RuleSummary{
		TotalRules: len(rules),
	}

	for _, rule := range rules {
		if rule.Active {
			summary.ActiveRules++
		}

		switch rule.Action {
		case "allow":
			summary.AllowRules++
		case "deny":
			summary.DenyRules++
		}
	}

	return summary, nil
}

// GetActiveRules returns only active rules
func (rm *RulesManager) GetActiveRules() ([]SyncRule, error) {
	query := `SELECT rule_data FROM sync_rules WHERE active = true ORDER BY created_at DESC`

	rows, err := rm.storage.GetDatabase().GetDB().Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query active rules: %w", err)
	}
	defer rows.Close()

	var rules []SyncRule
	for rows.Next() {
		var ruleData string
		if err := rows.Scan(&ruleData); err != nil {
			return nil, fmt.Errorf("failed to scan rule data: %w", err)
		}

		var rule SyncRule
		if err := json.Unmarshal([]byte(ruleData), &rule); err != nil {
			rm.logger.Warn().Str("rule_data", ruleData).Msg("Failed to unmarshal rule, skipping")
			continue
		}

		rules = append(rules, rule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rules: %w", err)
	}

	return rules, nil
}

// validateRule validates a rule's fields
func (rm *RulesManager) validateRule(rule *SyncRule) error {
	if rule.Name == "" {
		return fmt.Errorf("rule name cannot be empty")
	}

	if len(rule.Name) > 100 {
		return fmt.Errorf("rule name cannot exceed 100 characters")
	}

	if len(rule.Description) > 500 {
		return fmt.Errorf("rule description cannot exceed 500 characters")
	}

	if rule.Action != "allow" && rule.Action != "deny" {
		return fmt.Errorf("rule action must be 'allow' or 'deny', got: %s", rule.Action)
	}

	if rule.TargetDevice == "" {
		return fmt.Errorf("target device cannot be empty")
	}

	// Validate target device exists
	if !strings.HasPrefix(rule.TargetDevice, "ccr_") {
		return fmt.Errorf("target device must be a valid device ID (starts with 'ccr_')")
	}

	return nil
}

// GetRulesForDevice returns all rules that apply to a specific device
func (rm *RulesManager) GetRulesForDevice(deviceID string) ([]SyncRule, error) {
	if deviceID == "" {
		return nil, fmt.Errorf("device ID cannot be empty")
	}

	query := `SELECT rule_data FROM sync_rules WHERE active = true ORDER BY created_at ASC`

	rows, err := rm.storage.GetDatabase().GetDB().Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query rules: %w", err)
	}
	defer rows.Close()

	var deviceRules []SyncRule
	for rows.Next() {
		var ruleData string
		if err := rows.Scan(&ruleData); err != nil {
			return nil, fmt.Errorf("failed to scan rule data: %w", err)
		}

		var rule SyncRule
		if err := json.Unmarshal([]byte(ruleData), &rule); err != nil {
			rm.logger.Warn().Str("rule_data", ruleData).Msg("Failed to unmarshal rule, skipping")
			continue
		}

		// Check if rule applies to this device
		if rule.TargetDevice == deviceID {
			deviceRules = append(deviceRules, rule)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rules: %w", err)
	}

	return deviceRules, nil
}

// HasRules returns true if any rules exist in the system
func (rm *RulesManager) HasRules() (bool, error) {
	query := `SELECT COUNT(*) FROM sync_rules WHERE active = true`
	var count int
	err := rm.storage.GetDatabase().GetDB().QueryRow(query).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to count rules: %w", err)
	}

	return count > 0, nil
}

// triggerReEvaluation marks all synced commands for re-sync so they get re-uploaded with new target_devices
func (rm *RulesManager) triggerReEvaluation() error {
	rm.logger.Debug().Msg("Triggering re-evaluation of existing commands due to rule change")

	// Count all commands before marking them for re-evaluation
	countQuery := `SELECT COUNT(*) FROM history`
	var totalCount int64
	if err := rm.storage.GetDatabase().GetDB().QueryRow(countQuery).Scan(&totalCount); err != nil {
		rm.logger.Error().Err(err).Msg("Failed to count commands")
		return err
	}

	if totalCount == 0 {
		rm.logger.Debug().Msg("No commands found to re-evaluate")
		return nil
	}

	// Mark all commands for re-sync so they get re-uploaded with new target_devices
	// This includes both synced (sync_status = 1) and unsynced (sync_status = 0) commands
	updateQuery := `UPDATE history SET sync_status = 0, last_synced = NULL WHERE sync_status = 1 OR sync_status = 0 OR sync_status IS NULL`
	result, err := rm.storage.GetDatabase().GetDB().Exec(updateQuery)
	if err != nil {
		rm.logger.Error().Err(err).Msg("Failed to mark commands for re-sync")
		return fmt.Errorf("failed to mark commands for re-sync: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		rm.logger.Error().Err(err).Msg("Failed to get rows affected")
		rowsAffected = totalCount // Fallback to count
	}

	rm.logger.Info().
		Int64("commands_marked", rowsAffected).
		Msg("Marked all existing commands for rule re-evaluation - they will be re-uploaded with new target_devices on next sync")

	return nil
}

// ForceReEvaluation forces re-evaluation of all commands for testing purposes
func (rm *RulesManager) ForceReEvaluation() error {
	rm.logger.Info().Msg("Forcing re-evaluation of all commands for testing")
	return rm.triggerReEvaluation()
}
