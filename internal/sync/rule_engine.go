package sync

import (
	"fmt"
	"strings"

	"github.com/NeverVane/commandchronicles/internal/logger"
	"github.com/NeverVane/commandchronicles/internal/storage"
)

// RuleEngine handles rule evaluation and target device determination
type RuleEngine struct {
	rulesManager       *RulesManager
	deviceAliasManager *DeviceAliasManager
	logger             *logger.Logger
}

// RuleEvaluationResult contains the result of rule evaluation
type RuleEvaluationResult struct {
	TargetDevices []string `json:"target_devices"`
	RulesApplied  []string `json:"rules_applied"`
	DefaultUsed   bool     `json:"default_used"`
	Explanation   string   `json:"explanation,omitempty"`
}

// NewRuleEngine creates a new rule engine
func NewRuleEngine(rulesManager *RulesManager, deviceAliasManager *DeviceAliasManager) *RuleEngine {
	return &RuleEngine{
		rulesManager:       rulesManager,
		deviceAliasManager: deviceAliasManager,
		logger:             logger.GetLogger().WithComponent("rule-engine"),
	}
}

// EvaluateRules evaluates all applicable rules for a command and returns target devices
func (re *RuleEngine) EvaluateRules(record *storage.CommandRecord) (*RuleEvaluationResult, error) {
	if record == nil {
		return nil, fmt.Errorf("command record cannot be nil")
	}

	// Check if any rules exist in the system
	hasRules, err := re.rulesManager.HasRules()
	if err != nil {
		return nil, fmt.Errorf("failed to check for rules: %w", err)
	}

	// If no rules exist, use default behavior (sync to all devices)
	if !hasRules {
		return re.getDefaultTargets()
	}

	// Get all active rules
	activeRules, err := re.rulesManager.GetActiveRules()
	if err != nil {
		return nil, fmt.Errorf("failed to get active rules: %w", err)
	}

	// If no active rules, use default behavior
	if len(activeRules) == 0 {
		return re.getDefaultTargets()
	}

	// Start with all available devices
	allDevices, err := re.getAllActiveDevices()
	if err != nil {
		return nil, fmt.Errorf("failed to get all devices: %w", err)
	}

	// Apply rules to determine final target list
	result := &RuleEvaluationResult{
		TargetDevices: make([]string, 0),
		RulesApplied:  make([]string, 0),
		DefaultUsed:   false,
	}

	// Evaluate rules and build target device list
	targetDevices := make(map[string]bool)
	explanations := make([]string, 0)

	// First, assume all devices are targets (default allow)
	for _, device := range allDevices {
		targetDevices[device] = true
	}

	// Apply each rule in order (oldest first for consistent behavior)
	for _, rule := range activeRules {
		// Check if rule conditions match (for now, just apply to all commands)
		if re.evaluateConditions(record, rule.Conditions) {
			result.RulesApplied = append(result.RulesApplied, rule.ID)

			switch rule.Action {
			case "allow":
				// Allow rule: ensure this device is in the target list
				targetDevices[rule.TargetDevice] = true
				explanations = append(explanations, fmt.Sprintf("Allow rule for device %s", rule.TargetDevice))

			case "deny":
				// Deny rule: remove this device from the target list
				delete(targetDevices, rule.TargetDevice)
				explanations = append(explanations, fmt.Sprintf("Deny rule for device %s", rule.TargetDevice))
			}
		}
	}

	// Convert map to slice
	for deviceID := range targetDevices {
		result.TargetDevices = append(result.TargetDevices, deviceID)
	}

	// Generate explanation
	if len(explanations) > 0 {
		result.Explanation = strings.Join(explanations, "; ")
	} else {
		result.Explanation = "No applicable rules, using default behavior"
	}

	re.logger.Debug().
		Int("rules_applied", len(result.RulesApplied)).
		Int("target_devices", len(result.TargetDevices)).
		Str("explanation", result.Explanation).
		Msg("Rule evaluation completed")

	return result, nil
}

// GetDefaultTargets returns the default sync behavior (all active devices)
func (re *RuleEngine) GetDefaultTargets() (*RuleEvaluationResult, error) {
	return re.getDefaultTargets()
}

// getDefaultTargets implements the default sync behavior
func (re *RuleEngine) getDefaultTargets() (*RuleEvaluationResult, error) {
	allDevices, err := re.getAllActiveDevices()
	if err != nil {
		return nil, fmt.Errorf("failed to get all devices for default targets: %w", err)
	}

	result := &RuleEvaluationResult{
		TargetDevices: allDevices,
		RulesApplied:  []string{},
		DefaultUsed:   true,
		Explanation:   "No rules configured, syncing to all devices",
	}

	re.logger.Debug().
		Int("target_devices", len(result.TargetDevices)).
		Msg("Using default sync targets (all devices)")

	return result, nil
}

// getAllActiveDevices returns all active device IDs
func (re *RuleEngine) getAllActiveDevices() ([]string, error) {
	devices, err := re.deviceAliasManager.GetDevices()
	if err != nil {
		return nil, fmt.Errorf("failed to get devices: %w", err)
	}

	var activeDevices []string
	for _, device := range devices {
		if device.IsActive {
			activeDevices = append(activeDevices, device.DeviceID)
		}
	}

	return activeDevices, nil
}

// evaluateConditions checks if rule conditions match the command record
func (re *RuleEngine) evaluateConditions(record *storage.CommandRecord, conditions []RuleCondition) bool {
	// If no conditions, rule applies to all commands
	if len(conditions) == 0 {
		return true
	}

	// All conditions must match for the rule to apply
	for _, condition := range conditions {
		match := false

		switch condition.Type {
		case "tag":
			match = re.evaluateTagCondition(record, condition)
		case "working_dir":
			match = re.evaluateDirectoryCondition(record, condition)
		case "command_pattern":
			match = re.evaluatePatternCondition(record, condition)
		default:
			re.logger.Warn().Str("type", condition.Type).Msg("Unknown condition type")
			continue
		}

		// Apply negation if specified
		if condition.Negate {
			match = !match
		}

		// If any condition fails, the rule doesn't apply
		if !match {
			return false
		}
	}

	return true
}

// evaluateTagCondition checks if the command has specific tags
func (re *RuleEngine) evaluateTagCondition(record *storage.CommandRecord, condition RuleCondition) bool {
	if len(record.Tags) == 0 {
		return false
	}

	switch condition.Operator {
	case "equals":
		for _, tag := range record.Tags {
			if tag == condition.Value {
				return true
			}
		}
		return false

	case "contains":
		for _, tag := range record.Tags {
			if strings.Contains(tag, condition.Value) {
				return true
			}
		}
		return false

	case "starts_with":
		for _, tag := range record.Tags {
			if strings.HasPrefix(tag, condition.Value) {
				return true
			}
		}
		return false

	default:
		re.logger.Warn().Str("operator", condition.Operator).Msg("Unknown tag condition operator")
		return false
	}
}

// evaluateDirectoryCondition checks if the command was run in a specific directory
func (re *RuleEngine) evaluateDirectoryCondition(record *storage.CommandRecord, condition RuleCondition) bool {
	if record.WorkingDir == "" {
		return false
	}

	switch condition.Operator {
	case "equals":
		return record.WorkingDir == condition.Value

	case "contains":
		return strings.Contains(record.WorkingDir, condition.Value)

	case "starts_with":
		return strings.HasPrefix(record.WorkingDir, condition.Value)

	default:
		re.logger.Warn().Str("operator", condition.Operator).Msg("Unknown directory condition operator")
		return false
	}
}

// evaluatePatternCondition checks if the command matches a specific pattern
func (re *RuleEngine) evaluatePatternCondition(record *storage.CommandRecord, condition RuleCondition) bool {
	if record.Command == "" {
		return false
	}

	switch condition.Operator {
	case "equals":
		return record.Command == condition.Value

	case "contains":
		return strings.Contains(record.Command, condition.Value)

	case "starts_with":
		return strings.HasPrefix(record.Command, condition.Value)

	default:
		re.logger.Warn().Str("operator", condition.Operator).Msg("Unknown pattern condition operator")
		return false
	}
}

// SimulateRuleEvaluation simulates rule evaluation for a given command string
func (re *RuleEngine) SimulateRuleEvaluation(command, workingDir string, tags []string) (*RuleEvaluationResult, error) {
	// Create a mock command record for simulation
	mockRecord := &storage.CommandRecord{
		Command:    command,
		WorkingDir: workingDir,
		Tags:       tags,
		// Add other required fields with defaults
		ExitCode:  0,
		Duration:  0,
		Timestamp: 0,
		SessionID: "sim",
		Hostname:  "localhost",
		Version:   1,
		CreatedAt: 0,
	}

	return re.EvaluateRules(mockRecord)
}

// GetTargetDevicesForCurrentDevice returns devices that the current device should sync to
func (re *RuleEngine) GetTargetDevicesForCurrentDevice() ([]string, error) {
	// For a real implementation, this would create a mock record representing
	// a command from the current device and evaluate rules
	// For now, return all active devices as default
	return re.getAllActiveDevices()
}

// ValidateRuleLogic checks for potential rule conflicts or issues
func (re *RuleEngine) ValidateRuleLogic() ([]string, error) {
	activeRules, err := re.rulesManager.GetActiveRules()
	if err != nil {
		return nil, fmt.Errorf("failed to get active rules: %w", err)
	}

	var warnings []string

	// Check for conflicting rules for the same device
	deviceRules := make(map[string][]SyncRule)
	for _, rule := range activeRules {
		deviceRules[rule.TargetDevice] = append(deviceRules[rule.TargetDevice], rule)
	}

	for deviceID, rules := range deviceRules {
		if len(rules) > 1 {
			// Check for allow/deny conflicts
			hasAllow := false
			hasDeny := false
			for _, rule := range rules {
				if rule.Action == "allow" {
					hasAllow = true
				}
				if rule.Action == "deny" {
					hasDeny = true
				}
			}

			if hasAllow && hasDeny {
				warnings = append(warnings, fmt.Sprintf("Device %s has both allow and deny rules", deviceID))
			}
		}
	}

	return warnings, nil
}

// GetEvaluationDiagnostics returns detailed diagnostic information about rule evaluation
func (re *RuleEngine) GetEvaluationDiagnostics() (map[string]interface{}, error) {
	diagnostics := make(map[string]interface{})

	// Get rule counts
	hasRules, err := re.rulesManager.HasRules()
	if err != nil {
		return nil, fmt.Errorf("failed to check for rules: %w", err)
	}
	diagnostics["has_rules"] = hasRules

	if hasRules {
		summary, err := re.rulesManager.GetRulesSummary()
		if err != nil {
			return nil, fmt.Errorf("failed to get rules summary: %w", err)
		}
		diagnostics["rules_summary"] = summary
	}

	// Get device counts
	devices, err := re.deviceAliasManager.GetDevices()
	if err != nil {
		return nil, fmt.Errorf("failed to get devices: %w", err)
	}

	activeDevices := 0
	for _, device := range devices {
		if device.IsActive {
			activeDevices++
		}
	}

	diagnostics["total_devices"] = len(devices)
	diagnostics["active_devices"] = activeDevices

	// Validate rule logic
	warnings, err := re.ValidateRuleLogic()
	if err != nil {
		return nil, fmt.Errorf("failed to validate rule logic: %w", err)
	}
	diagnostics["rule_warnings"] = warnings

	return diagnostics, nil
}

// TestRuleEvaluationForAllDevices tests rule evaluation against all known devices
func (re *RuleEngine) TestRuleEvaluationForAllDevices(command string) (map[string]*RuleEvaluationResult, error) {
	devices, err := re.deviceAliasManager.GetDevices()
	if err != nil {
		return nil, fmt.Errorf("failed to get devices: %w", err)
	}

	results := make(map[string]*RuleEvaluationResult)

	for _, device := range devices {
		if device.IsActive {
			// Create mock record for this device
			mockRecord := &storage.CommandRecord{
				Command:    command,
				WorkingDir: "",
				Tags:       []string{},
				ExitCode:   0,
				Duration:   0,
				Timestamp:  0,
				SessionID:  "eval",
				Hostname:   device.Hostname,
				DeviceID:   device.DeviceID,
				Version:    1,
				CreatedAt:  0,
			}

			result, err := re.EvaluateRules(mockRecord)
			if err != nil {
				re.logger.Warn().Err(err).Str("device_id", device.DeviceID).Msg("Failed to evaluate rules for device")
				continue
			}

			displayName := device.DeviceID
			if device.Alias != "" {
				displayName = device.Alias
			}
			results[displayName] = result
		}
	}

	return results, nil
}

// GetRuleEvaluationStats returns statistics about rule evaluation efficiency
func (re *RuleEngine) GetRuleEvaluationStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Get active rules
	activeRules, err := re.rulesManager.GetActiveRules()
	if err != nil {
		return nil, fmt.Errorf("failed to get active rules: %w", err)
	}

	// Analyze rule distribution
	actionCounts := make(map[string]int)
	deviceCounts := make(map[string]int)
	conditionCounts := make(map[string]int)

	for _, rule := range activeRules {
		actionCounts[rule.Action]++
		deviceCounts[rule.TargetDevice]++

		for _, condition := range rule.Conditions {
			conditionCounts[condition.Type]++
		}
	}

	stats["action_distribution"] = actionCounts
	stats["rules_per_device"] = deviceCounts
	stats["condition_types"] = conditionCounts
	stats["total_active_rules"] = len(activeRules)

	// Calculate potential target devices
	allDevices, err := re.getAllActiveDevices()
	if err != nil {
		return nil, fmt.Errorf("failed to get all devices: %w", err)
	}
	stats["potential_targets"] = len(allDevices)

	return stats, nil
}
