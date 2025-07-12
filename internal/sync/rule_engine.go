package sync

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

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

// BatchEvaluationConfig configures batch processing parameters
type BatchEvaluationConfig struct {
	BatchSize   int
	WorkerCount int
	MaxMemoryMB int
}

// RuleConflict represents a conflict between rules
type RuleConflict struct {
	ConflictingRules []SyncRule `json:"conflicting_rules"`
	ConflictType     string     `json:"conflict_type"`
	DeviceID         string     `json:"device_id"`
	Description      string     `json:"description"`
}

// BatchEvaluationResult contains results of batch re-evaluation
type BatchEvaluationResult struct {
	ProcessedCommands int           `json:"processed_commands"`
	UpdatedCommands   int           `json:"updated_commands"`
	Duration          time.Duration `json:"duration"`
	MemoryUsedMB      int           `json:"memory_used_mb"`
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
	result := &RuleEvaluationResult{
		TargetDevices: []string{},
		RulesApplied:  []string{},
		DefaultUsed:   true,
		Explanation:   "No rules configured, using default behavior (empty target_devices)",
	}

	re.logger.Debug().
		Int("target_devices", len(result.TargetDevices)).
		Msg("Using default sync targets (empty - sync to all devices)")

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
		case "time":
			match = re.evaluateTimeCondition(record, condition)
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

// evaluateTimeCondition checks if the command was executed during a specific time period
func (re *RuleEngine) evaluateTimeCondition(record *storage.CommandRecord, condition RuleCondition) bool {
	if record.Timestamp == 0 {
		return false
	}

	// Convert timestamp to time
	commandTime := time.Unix(record.Timestamp/1000, 0)

	switch condition.Operator {
	case "during":
		return re.isTimeDuringPeriod(commandTime, condition.Value)
	case "after":
		return re.isTimeAfter(commandTime, condition.Value)
	case "before":
		return re.isTimeBefore(commandTime, condition.Value)
	default:
		re.logger.Warn().Str("operator", condition.Operator).Msg("Unknown time condition operator")
		return false
	}
}

// isTimeDuringPeriod checks if time falls within a period (e.g., "09:00-17:00")
func (re *RuleEngine) isTimeDuringPeriod(t time.Time, period string) bool {
	parts := strings.Split(period, "-")
	if len(parts) != 2 {
		re.logger.Warn().Str("period", period).Msg("Invalid time period format, expected HH:MM-HH:MM")
		return false
	}

	startTime, err := time.Parse("15:04", strings.TrimSpace(parts[0]))
	if err != nil {
		re.logger.Warn().Str("start_time", parts[0]).Msg("Invalid start time format")
		return false
	}

	endTime, err := time.Parse("15:04", strings.TrimSpace(parts[1]))
	if err != nil {
		re.logger.Warn().Str("end_time", parts[1]).Msg("Invalid end time format")
		return false
	}

	// Get hour and minute from command time
	commandHour := t.Hour()
	commandMinute := t.Minute()
	startHour := startTime.Hour()
	startMinute := startTime.Minute()
	endHour := endTime.Hour()
	endMinute := endTime.Minute()

	// Convert to minutes for easier comparison
	commandMinutes := commandHour*60 + commandMinute
	startMinutes := startHour*60 + startMinute
	endMinutes := endHour*60 + endMinute

	// Handle overnight periods (e.g., "22:00-06:00")
	if endMinutes < startMinutes {
		return commandMinutes >= startMinutes || commandMinutes <= endMinutes
	}

	return commandMinutes >= startMinutes && commandMinutes <= endMinutes
}

// isTimeAfter checks if time is after a specific time (e.g., "18:00")
func (re *RuleEngine) isTimeAfter(t time.Time, timeStr string) bool {
	targetTime, err := time.Parse("15:04", strings.TrimSpace(timeStr))
	if err != nil {
		re.logger.Warn().Str("time", timeStr).Msg("Invalid time format")
		return false
	}

	commandMinutes := t.Hour()*60 + t.Minute()
	targetMinutes := targetTime.Hour()*60 + targetTime.Minute()

	return commandMinutes >= targetMinutes
}

// isTimeBefore checks if time is before a specific time (e.g., "09:00")
func (re *RuleEngine) isTimeBefore(t time.Time, timeStr string) bool {
	targetTime, err := time.Parse("15:04", strings.TrimSpace(timeStr))
	if err != nil {
		re.logger.Warn().Str("time", timeStr).Msg("Invalid time format")
		return false
	}

	commandMinutes := t.Hour()*60 + t.Minute()
	targetMinutes := targetTime.Hour()*60 + targetTime.Minute()

	return commandMinutes <= targetMinutes
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

// ReEvaluateAllUnsyncedCommands re-evaluates rules for all unsynced commands with parallel processing
func (re *RuleEngine) ReEvaluateAllUnsyncedCommands() (*BatchEvaluationResult, error) {
	// Get default configuration
	config := &BatchEvaluationConfig{
		BatchSize:   1000,
		WorkerCount: runtime.NumCPU(),
		MaxMemoryMB: 500,
	}

	return re.ReEvaluateAllUnsyncedCommandsWithConfig(config)
}

// ReEvaluateAllUnsyncedCommandsWithConfig re-evaluates rules with custom configuration
func (re *RuleEngine) ReEvaluateAllUnsyncedCommandsWithConfig(config *BatchEvaluationConfig) (*BatchEvaluationResult, error) {
	start := time.Now()
	result := &BatchEvaluationResult{}

	re.logger.Info().
		Int("workers", config.WorkerCount).
		Int("batch_size", config.BatchSize).
		Msg("Starting batch rule re-evaluation")

	// Get storage interface (we'll need to add this method to access unsynced records)
	// For now, simulate the streaming approach

	// Create worker pool
	jobs := make(chan []*storage.CommandRecord, config.WorkerCount*2)
	results := make(chan batchResult, config.WorkerCount*2)

	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < config.WorkerCount; i++ {
		wg.Add(1)
		go re.evaluationWorker(jobs, results, &wg)
	}

	// Start result collector
	resultsChan := make(chan *BatchEvaluationResult, 1)
	go re.collectResults(results, result, resultsChan)

	// Stream batches of commands
	go func() {
		defer close(jobs)

		// This would be replaced with actual streaming from storage
		// For now, we'll simulate the batching approach
		offset := 0
		for {
			batch, err := re.getUnsyncedCommandsBatch(offset, config.BatchSize)
			if err != nil {
				re.logger.Error().Err(err).Msg("Failed to get commands batch")
				break
			}

			if len(batch) == 0 {
				break
			}

			jobs <- batch
			offset += len(batch)
		}
	}()

	// Wait for workers to complete
	wg.Wait()
	close(results)

	// Wait for result collection
	finalResult := <-resultsChan
	finalResult.Duration = time.Since(start)

	re.logger.Info().
		Int("processed", finalResult.ProcessedCommands).
		Int("updated", finalResult.UpdatedCommands).
		Dur("duration", finalResult.Duration).
		Msg("Batch rule re-evaluation completed")

	return finalResult, nil
}

// evaluationWorker processes batches of commands in parallel
func (re *RuleEngine) evaluationWorker(jobs <-chan []*storage.CommandRecord, results chan<- batchResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for batch := range jobs {
		batchRes := batchResult{
			processed: len(batch),
			updated:   0,
		}

		for _, record := range batch {
			// Evaluate rules for this record
			_, err := re.EvaluateRules(record)
			if err != nil {
				re.logger.Warn().Err(err).Int64("record_id", record.ID).Msg("Failed to evaluate rules for record")
				continue
			}

			// Check if routing changed (this would require comparing with stored routing)
			// For now, we'll assume all records need updating
			batchRes.updated++

			// Here we would update the database with new routing metadata
			// This would be implemented with a batch update operation
		}

		results <- batchRes
	}
}

// batchResult represents the result of processing a batch
type batchResult struct {
	processed int
	updated   int
}

// collectResults aggregates results from all workers
func (re *RuleEngine) collectResults(results <-chan batchResult, final *BatchEvaluationResult, done chan<- *BatchEvaluationResult) {
	for result := range results {
		final.ProcessedCommands += result.processed
		final.UpdatedCommands += result.updated
	}
	done <- final
}

// getUnsyncedCommandsBatch gets a batch of unsynced commands (placeholder)
func (re *RuleEngine) getUnsyncedCommandsBatch(offset, limit int) ([]*storage.CommandRecord, error) {
	// This would be implemented to actually fetch from storage
	// For now, return empty to simulate end of data
	return []*storage.CommandRecord{}, nil
}

// DetectRuleConflicts analyzes all rules and detects conflicts
func (re *RuleEngine) DetectRuleConflicts() ([]RuleConflict, error) {
	activeRules, err := re.rulesManager.GetActiveRules()
	if err != nil {
		return nil, fmt.Errorf("failed to get active rules: %w", err)
	}

	var conflicts []RuleConflict

	// Group rules by device
	deviceRules := make(map[string][]SyncRule)
	for _, rule := range activeRules {
		deviceRules[rule.TargetDevice] = append(deviceRules[rule.TargetDevice], rule)
	}

	// Check for conflicts within each device
	for deviceID, rules := range deviceRules {
		deviceConflicts := re.detectDeviceConflicts(deviceID, rules)
		conflicts = append(conflicts, deviceConflicts...)
	}

	return conflicts, nil
}

// detectDeviceConflicts finds conflicts for rules targeting the same device
func (re *RuleEngine) detectDeviceConflicts(deviceID string, rules []SyncRule) []RuleConflict {
	var conflicts []RuleConflict

	// Check for allow/deny conflicts with overlapping conditions
	for i := 0; i < len(rules); i++ {
		for j := i + 1; j < len(rules); j++ {
			if conflict := re.checkRulePairConflict(deviceID, rules[i], rules[j]); conflict != nil {
				conflicts = append(conflicts, *conflict)
			}
		}
	}

	return conflicts
}

// checkRulePairConflict checks if two rules conflict with each other
func (re *RuleEngine) checkRulePairConflict(deviceID string, rule1, rule2 SyncRule) *RuleConflict {
	// If same action, no conflict
	if rule1.Action == rule2.Action {
		return nil
	}

	// Check if conditions overlap
	if re.conditionsOverlap(rule1.Conditions, rule2.Conditions) {
		return &RuleConflict{
			ConflictingRules: []SyncRule{rule1, rule2},
			ConflictType:     "allow_deny_overlap",
			DeviceID:         deviceID,
			Description:      fmt.Sprintf("Rule '%s' (%s) conflicts with rule '%s' (%s) - overlapping conditions", rule1.Name, rule1.Action, rule2.Name, rule2.Action),
		}
	}

	return nil
}

// conditionsOverlap checks if two sets of conditions overlap
func (re *RuleEngine) conditionsOverlap(conditions1, conditions2 []RuleCondition) bool {
	// If either has no conditions, they apply to all commands (overlap)
	if len(conditions1) == 0 || len(conditions2) == 0 {
		return true
	}

	// Check for exact condition matches
	for _, c1 := range conditions1 {
		for _, c2 := range conditions2 {
			if c1.Type == c2.Type && c1.Operator == c2.Operator && c1.Value == c2.Value {
				return true
			}
		}
	}

	return false
}

// ResolveConflict resolves a conflict by deleting the older conflicting rule
func (re *RuleEngine) ResolveConflict(conflict RuleConflict, keepRuleID string) error {
	if len(conflict.ConflictingRules) != 2 {
		return fmt.Errorf("can only resolve conflicts between exactly 2 rules")
	}

	var ruleToDelete string
	for _, rule := range conflict.ConflictingRules {
		if rule.ID != keepRuleID {
			ruleToDelete = rule.ID
			break
		}
	}

	if ruleToDelete == "" {
		return fmt.Errorf("rule to keep not found in conflict")
	}

	// Delete the conflicting rule
	if err := re.rulesManager.DeleteRule(ruleToDelete); err != nil {
		return fmt.Errorf("failed to delete conflicting rule: %w", err)
	}

	re.logger.Info().
		Str("deleted_rule", ruleToDelete).
		Str("kept_rule", keepRuleID).
		Msg("Resolved rule conflict by deleting older rule")

	return nil
}

// AutoResolveConflicts automatically resolves conflicts by keeping newer rules
func (re *RuleEngine) AutoResolveConflicts() (int, error) {
	conflicts, err := re.DetectRuleConflicts()
	if err != nil {
		return 0, fmt.Errorf("failed to detect conflicts: %w", err)
	}

	resolved := 0
	for _, conflict := range conflicts {
		if len(conflict.ConflictingRules) == 2 {
			// Keep the newer rule (higher created_at timestamp)
			rule1 := conflict.ConflictingRules[0]
			rule2 := conflict.ConflictingRules[1]

			var keepRule string
			if rule1.CreatedAt > rule2.CreatedAt {
				keepRule = rule1.ID
			} else {
				keepRule = rule2.ID
			}

			if err := re.ResolveConflict(conflict, keepRule); err != nil {
				re.logger.Warn().Err(err).Msg("Failed to auto-resolve conflict")
				continue
			}

			resolved++
		}
	}

	return resolved, nil
}
