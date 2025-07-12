# Sync Rules System Implementation Plan

## Overview
This document outlines the implementation plan for the CommandChronicles sync rules system, allowing users to control which commands are synced to which devices with human-readable device aliases.

## Database Schema

### New Tables

```sql
-- Device list (populated during sync)
CREATE TABLE devices (
    device_id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    platform TEXT NOT NULL,
    last_seen INTEGER NOT NULL,
    is_active BOOLEAN DEFAULT true,
    updated_at INTEGER NOT NULL
);

-- Device aliases (local to each device)
CREATE TABLE device_aliases (
    device_id TEXT PRIMARY KEY,
    alias TEXT UNIQUE NOT NULL,
    is_enabled BOOLEAN DEFAULT true,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(device_id)
);

-- Sync rules (stored as JSON)
CREATE TABLE sync_rules (
    id TEXT PRIMARY KEY,
    rule_data TEXT NOT NULL,  -- JSON rule definition
    active BOOLEAN DEFAULT true,
    created_at INTEGER NOT NULL
);

-- Indexes
CREATE INDEX idx_devices_active ON devices(is_active);
CREATE INDEX idx_device_aliases_enabled ON device_aliases(is_enabled);
CREATE INDEX idx_sync_rules_active ON sync_rules(active);
```

### Schema Integration
Add migration to `internal/storage/migrations.go`:
```go
3: []string{
    `CREATE TABLE devices (...)`,
    `CREATE TABLE device_aliases (...)`,
    `CREATE TABLE sync_rules (...)`,
    `CREATE INDEX idx_devices_active ON devices(is_active)`,
    `CREATE INDEX idx_device_aliases_enabled ON device_aliases(is_enabled)`,
    `CREATE INDEX idx_sync_rules_active ON sync_rules(active)`,
},
```

## Phase 1: Device Management (Week 1)

### Goal
Integrate device list updates with existing sync process and implement device alias management.

### Files to Create

#### `internal/sync/device_manager.go`
```go
package sync

import (
    "database/sql"
    "time"
    "github.com/NeverVane/commandchronicles/internal/config"
    "github.com/NeverVane/commandchronicles/internal/logger"
    securestorage "github.com/NeverVane/commandchronicles/pkg/storage"
)

type DeviceManager struct {
    storage *securestorage.SecureStorage
    config  *config.Config
    logger  *logger.Logger
}

type Device struct {
    DeviceID   string `json:"device_id"`
    Hostname   string `json:"hostname"`
    Platform   string `json:"platform"`
    LastSeen   int64  `json:"last_seen"`
    IsActive   bool   `json:"is_active"`
    Alias      string `json:"alias,omitempty"`
    IsEnabled  bool   `json:"is_enabled"`
    IsCurrent  bool   `json:"is_current"`
}

func NewDeviceManager(storage *securestorage.SecureStorage, cfg *config.Config) *DeviceManager
func (dm *DeviceManager) UpdateDevicesList(devices []ServerDevice) error
func (dm *DeviceManager) GetDevices() ([]Device, error)
func (dm *DeviceManager) SetDeviceAlias(deviceID, alias string) error
func (dm *DeviceManager) RemoveDeviceAlias(deviceID string) error
func (dm *DeviceManager) ResolveAlias(aliasOrID string) (string, error)
func (dm *DeviceManager) DeactivateDevice(deviceID string) error
func (dm *DeviceManager) ReactivateDevice(deviceID string) error
func (dm *DeviceManager) GetCurrentDeviceID() (string, error)
```

### Files to Modify

#### `internal/sync/service.go`
Add device list update integration:
```go
// Add to SyncService struct
type SyncService struct {
    // ... existing fields
    deviceManager *DeviceManager
}

// Modify PerformSync method
func (s *SyncService) PerformSync() error {
    // ... existing sync logic

    // Update device list during sync
    if err := s.updateDevicesList(); err != nil {
        s.logger.Warn().Err(err).Msg("Failed to update devices list during sync")
    }

    // ... rest of existing sync logic
}

// Add new method
func (s *SyncService) updateDevicesList() error {
    // Get devices from sync response or separate call
    devices, err := s.client.GetDevices()
    if err != nil {
        return fmt.Errorf("failed to fetch devices: %w", err)
    }

    return s.deviceManager.UpdateDevicesList(devices)
}
```

#### `internal/sync/client.go`
Add device list fetching:
```go
type ServerDevice struct {
    DeviceID  string `json:"device_id"`
    Hostname  string `json:"hostname"`
    Platform  string `json:"platform"`
    LastSeen  string `json:"last_seen"`
    IsActive  bool   `json:"is_active"`
}

type DevicesResponse struct {
    Devices []ServerDevice `json:"devices"`
}

func (sc *SyncClient) GetDevices() ([]ServerDevice, error) {
    req, err := sc.newAuthenticatedRequest("GET", sc.apiURL("/devices"), nil)
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }

    resp, err := sc.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("request failed: %w", err)
    }

    var devicesResp DevicesResponse
    if err := sc.handleResponse(resp, &devicesResp); err != nil {
        return nil, err
    }

    return devicesResp.Devices, nil
}
```

#### `main.go`
Add device management commands:
```go
func devicesCmd(cfg *config.Config) *cobra.Command {
    cmd := &cobra.Command{
        Use:   "devices",
        Short: "Manage devices and aliases",
        Long:  "List devices and manage human-readable aliases for sync rules",
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
        RunE: func(cmd *cobra.Command, args []string) error {
            // Implementation
        },
    }
}

func devicesAliasCmd(cfg *config.Config) *cobra.Command {
    return &cobra.Command{
        Use:   "alias <device-id> <alias>",
        Short: "Set device alias",
        Args:  cobra.ExactArgs(2),
        RunE: func(cmd *cobra.Command, args []string) error {
            // Implementation
        },
    }
}

func devicesRemoveAliasCmd(cfg *config.Config) *cobra.Command {
    return &cobra.Command{
        Use:   "remove-alias <device-id>",
        Short: "Remove device alias",
        Args:  cobra.ExactArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
            // Implementation
        },
    }
}
```

### Server Communication

#### Device List Request
**Request:**
```
GET /api/v1/devices
Headers:
  Authorization: Bearer <token>
  Content-Type: application/json
```

**Expected Response:**
```json
{
  "devices": [
    {
      "device_id": "ccr_a1b2c3d4e5f6",
      "hostname": "work-laptop",
      "platform": "darwin",
      "last_seen": "2024-01-15T10:30:00Z",
      "is_active": true
    },
    {
      "device_id": "ccr_e5f6g7h8i9j0",
      "hostname": "home-desktop",
      "platform": "linux",
      "last_seen": "2024-01-14T22:15:00Z",
      "is_active": true
    }
  ]
}
```

### CLI Commands
```bash
ccr devices show                    # List devices with aliases
ccr devices alias <id> <name>       # Set device alias
ccr devices remove-alias <id>       # Remove device alias
```

## Phase 2: Basic Rules (Week 2)

### Goal
Implement basic allow/deny rules per device with local storage.

### Files to Create

#### `internal/sync/rules_manager.go`
```go
package sync

import (
    "encoding/json"
    "fmt"
    "time"
    "github.com/google/uuid"
    "github.com/NeverVane/commandchronicles/internal/config"
    "github.com/NeverVane/commandchronicles/internal/logger"
    securestorage "github.com/NeverVane/commandchronicles/pkg/storage"
)

type RulesManager struct {
    storage       *securestorage.SecureStorage
    config        *config.Config
    logger        *logger.Logger
    deviceManager *DeviceManager
}

type SyncRule struct {
    ID           string           `json:"id"`
    Name         string           `json:"name"`
    Action       string           `json:"action"`        // "allow" or "deny"
    TargetDevice string           `json:"target_device"` // Device ID (not alias)
    Conditions   []RuleCondition  `json:"conditions,omitempty"`
    Active       bool             `json:"active"`
    CreatedAt    int64            `json:"created_at"`
}

type RuleCondition struct {
    Type     string `json:"type"`     // "tag", "working_dir", "command_pattern"
    Operator string `json:"operator"` // "equals", "contains", "starts_with"
    Value    string `json:"value"`
    Negate   bool   `json:"negate,omitempty"`
}

func NewRulesManager(storage *securestorage.SecureStorage, cfg *config.Config, dm *DeviceManager) *RulesManager
func (rm *RulesManager) CreateRule(rule *SyncRule) error
func (rm *RulesManager) ListRules() ([]SyncRule, error)
func (rm *RulesManager) GetRule(ruleID string) (*SyncRule, error)
func (rm *RulesManager) UpdateRule(rule *SyncRule) error
func (rm *RulesManager) DeleteRule(ruleID string) error
func (rm *RulesManager) ToggleRule(ruleID string, active bool) error
func (rm *RulesManager) CreateAllowRule(deviceAlias string) error
func (rm *RulesManager) CreateDenyRule(deviceAlias string) error
```

### Files to Modify

#### `main.go`
Add rule management commands:
```go
func rulesCmd(cfg *config.Config) *cobra.Command {
    cmd := &cobra.Command{
        Use:   "rules",
        Short: "Manage sync rules",
        Long:  "Create and manage rules for controlling command synchronization",
    }

    cmd.AddCommand(rulesListCmd(cfg))
    cmd.AddCommand(rulesAllowCmd(cfg))
    cmd.AddCommand(rulesDenyCmd(cfg))
    cmd.AddCommand(rulesDeleteCmd(cfg))
    cmd.AddCommand(rulesEnableCmd(cfg))
    cmd.AddCommand(rulesDisableCmd(cfg))

    return cmd
}

func rulesListCmd(cfg *config.Config) *cobra.Command {
    return &cobra.Command{
        Use:   "list",
        Short: "List all sync rules",
        RunE: func(cmd *cobra.Command, args []string) error {
            // Implementation
        },
    }
}

func rulesAllowCmd(cfg *config.Config) *cobra.Command {
    return &cobra.Command{
        Use:   "allow <device>",
        Short: "Create allow rule for device",
        Args:  cobra.ExactArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
            // Implementation
        },
    }
}

func rulesDenyCmd(cfg *config.Config) *cobra.Command {
    return &cobra.Command{
        Use:   "deny <device>",
        Short: "Create deny rule for device",
        Args:  cobra.ExactArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
            // Implementation
        },
    }
}
```

### CLI Commands
```bash
ccr rules list                      # List all rules
ccr rules allow <device>            # Create allow rule
ccr rules deny <device>             # Create deny rule
ccr rules delete <rule-id>          # Delete rule
ccr rules enable <rule-id>          # Enable rule
ccr rules disable <rule-id>         # Disable rule
```

## Phase 3: Rule Evaluation & Sync Integration (Week 3)

### Goal
Integrate rule evaluation with existing sync process and send routing metadata to server.

### Files to Create

#### `internal/sync/rule_engine.go`
```go
package sync

import (
    "fmt"
    "strings"
    "github.com/NeverVane/commandchronicles/internal/logger"
    "github.com/NeverVane/commandchronicles/internal/storage"
)

type RuleEngine struct {
    rulesManager  *RulesManager
    deviceManager *DeviceManager
    logger        *logger.Logger
}

type RuleEvaluationResult struct {
    TargetDevices []string `json:"target_devices"`
    RulesApplied  []string `json:"rules_applied"`
    DefaultUsed   bool     `json:"default_used"`
}

func NewRuleEngine(rm *RulesManager, dm *DeviceManager) *RuleEngine
func (re *RuleEngine) EvaluateRules(record *storage.CommandRecord) (*RuleEvaluationResult, error)
func (re *RuleEngine) GetDefaultTargets() ([]string, error)
func (re *RuleEngine) evaluateConditions(record *storage.CommandRecord, conditions []RuleCondition) bool
```

### Files to Modify

#### `internal/sync/service.go`
Integrate rule evaluation:
```go
// Add to SyncService struct
type SyncService struct {
    // ... existing fields
    ruleEngine *RuleEngine
}

// Modify UploadNewRecords method
func (s *SyncService) UploadNewRecords() error {
    records, err := s.getRecordsForSync()
    if err != nil {
        return fmt.Errorf("failed to get records for sync: %w", err)
    }

    var syncRecords []SyncRecord
    for _, record := range records {
        // Evaluate rules for this record
        evaluation, err := s.ruleEngine.EvaluateRules(record)
        if err != nil {
            s.logger.Warn().Err(err).Msg("Failed to evaluate rules, using default")
            evaluation = &RuleEvaluationResult{
                TargetDevices: s.getDefaultTargets(),
                DefaultUsed:   true,
            }
        }

        // Create sync record with routing metadata
        syncRecord := SyncRecord{
            RecordHash:       record.RecordHash,
            EncryptedPayload: encryptedPayload,
            TimestampMs:      record.Timestamp,
            Hostname:         record.Hostname,
            SessionID:        record.SessionID,
            TargetDevices:    evaluation.TargetDevices,
        }

        syncRecords = append(syncRecords, syncRecord)
    }

    // Upload with routing metadata
    return s.uploadRecords(syncRecords)
}
```

#### `internal/sync/client.go`
Add routing metadata to sync requests:
```go
type SyncRecord struct {
    RecordHash       string   `json:"record_hash"`
    EncryptedPayload []byte   `json:"encrypted_payload"`
    TimestampMs      int64    `json:"timestamp_ms"`
    Hostname         string   `json:"hostname"`
    SessionID        string   `json:"session_id"`
    TargetDevices    []string `json:"target_devices,omitempty"` // New field
}
```

### Server Communication

#### Sync Upload with Routing Metadata
**Request:**
```
POST /api/v1/sync/upload
Headers:
  Authorization: Bearer <token>
  Content-Type: application/json

Body:
{
  "device_id": "ccr_a1b2c3d4e5f6",
  "records": [
    {
      "record_hash": "sha256_hash_here",
      "encrypted_payload": "base64_encrypted_data",
      "timestamp_ms": 1705312200000,
      "hostname": "work-laptop",
      "session_id": "session_uuid",
      "target_devices": ["ccr_e5f6g7h8i9j0", "ccr_k1l2m3n4o5p6"]
    }
  ],
  "metadata": {
    "client_version": "2.0.0",
    "last_sync_time": 1705312100000,
    "total_record_count": 1
  }
}
```

**Expected Response:**
```json
{
  "success": true,
  "processed_count": 1,
  "duplicate_count": 0,
  "error_count": 0,
  "sync_session_id": "sync_session_uuid"
}
```

## Phase 4: Conditional Rules (Week 4)

### Goal
Add tag-based, directory-based, and command pattern rules.

### Files to Modify

#### `internal/sync/rules_manager.go`
Add conditional rule creation:
```go
func (rm *RulesManager) CreateConditionalAllowRule(deviceAlias string, conditions []RuleCondition) error
func (rm *RulesManager) CreateConditionalDenyRule(deviceAlias string, conditions []RuleCondition) error
func (rm *RulesManager) CreateTagRule(deviceAlias, tag string, allow bool) error
func (rm *RulesManager) CreateDirectoryRule(deviceAlias, directory string, allow bool) error
func (rm *RulesManager) CreatePatternRule(deviceAlias, pattern string, allow bool) error
```

#### `internal/sync/rule_engine.go`
Enhance condition evaluation:
```go
func (re *RuleEngine) evaluateConditions(record *storage.CommandRecord, conditions []RuleCondition) bool {
    for _, condition := range conditions {
        match := false

        switch condition.Type {
        case "tag":
            match = re.evaluateTagCondition(record, condition)
        case "working_dir":
            match = re.evaluateDirectoryCondition(record, condition)
        case "command_pattern":
            match = re.evaluatePatternCondition(record, condition)
        }

        if condition.Negate {
            match = !match
        }

        if !match {
            return false // All conditions must match
        }
    }

    return true
}

func (re *RuleEngine) evaluateTagCondition(record *storage.CommandRecord, condition RuleCondition) bool
func (re *RuleEngine) evaluateDirectoryCondition(record *storage.CommandRecord, condition RuleCondition) bool
func (re *RuleEngine) evaluatePatternCondition(record *storage.CommandRecord, condition RuleCondition) bool
```

#### `main.go`
Add conditional rule commands:
```go
func rulesAllowCmd(cfg *config.Config) *cobra.Command {
    cmd := &cobra.Command{
        Use:   "allow <device>",
        Short: "Create allow rule for device",
        Args:  cobra.ExactArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
            // Implementation with flag parsing
        },
    }

    cmd.Flags().String("tag", "", "Allow commands with specific tag")
    cmd.Flags().String("dir", "", "Allow commands from specific directory")
    cmd.Flags().String("pattern", "", "Allow commands matching pattern")

    return cmd
}

func rulesDenyCmd(cfg *config.Config) *cobra.Command {
    cmd := &cobra.Command{
        Use:   "deny <device>",
        Short: "Create deny rule for device",
        Args:  cobra.ExactArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
            // Implementation with flag parsing
        },
    }

    cmd.Flags().String("tag", "", "Deny commands with specific tag")
    cmd.Flags().String("dir", "", "Deny commands from specific directory")
    cmd.Flags().String("pattern", "", "Deny commands matching pattern")

    return cmd
}
```

### CLI Commands
```bash
ccr rules allow <device> --tag docker          # Allow docker commands
ccr rules deny <device> --dir /work            # Deny commands from /work
ccr rules allow <device> --pattern "git*"      # Allow git commands
ccr rules deny <device> --tag sensitive        # Deny sensitive commands
```

## Phase 5: Rule Testing & Management (Week 5)

### Goal
Provide tools for testing rules and detecting conflicts.

### Files to Create

#### `internal/sync/rule_tester.go`
```go
package sync

import (
    "fmt"
    "github.com/NeverVane/commandchronicles/internal/cache"
    "github.com/NeverVane/commandchronicles/internal/storage"
    "github.com/NeverVane/commandchronicles/internal/logger"
)

type RuleTester struct {
    ruleEngine *RuleEngine
    cache      *cache.Cache
    logger     *logger.Logger
}

type TestResult struct {
    Command       string   `json:"command"`
    TargetDevices []string `json:"target_devices"`
    RulesApplied  []string `json:"rules_applied"`
    WorkingDir    string   `json:"working_dir"`
    Tags          []string `json:"tags"`
}

type RuleConflict struct {
    DeviceID     string   `json:"device_id"`
    DeviceAlias  string   `json:"device_alias"`
    ConflictType string   `json:"conflict_type"`
    Rules        []string `json:"rules"`
    Description  string   `json:"description"`
}

func NewRuleTester(re *RuleEngine, cache *cache.Cache) *RuleTester
func (rt *RuleTester) TestRulesAgainstHistory(limit int) ([]TestResult, error)
func (rt *RuleTester) SimulateCommand(command, workingDir string, tags []string) (*TestResult, error)
func (rt *RuleTester) DetectConflicts() ([]RuleConflict, error)
func (rt *RuleTester) GetRulesSummary() (*RulesSummary, error)
```

### Files to Modify

#### `main.go`
Add testing commands:
```go
func rulesTestCmd(cfg *config.Config) *cobra.Command {
    cmd := &cobra.Command{
        Use:   "test",
        Short: "Test rules against recent commands",
        RunE: func(cmd *cobra.Command, args []string) error {
            // Implementation
        },
    }

    cmd.Flags().Int("limit", 10, "Number of recent commands to test")

    return cmd
}

func rulesSimulateCmd(cfg *config.Config) *cobra.Command {
    return &cobra.Command{
        Use:   "simulate <command>",
        Short: "Simulate rule evaluation for a command",
        Args:  cobra.ExactArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
            // Implementation
        },
    }
}

func rulesConflictsCmd(cfg *config.Config) *cobra.Command {
    return &cobra.Command{
        Use:   "conflicts",
        Short: "Show rule conflicts",
        RunE: func(cmd *cobra.Command, args []string) error {
            // Implementation
        },
    }
}

func rulesStatusCmd(cfg *config.Config) *cobra.Command {
    return &cobra.Command{
        Use:   "status",
        Short: "Show rules summary",
        RunE: func(cmd *cobra.Command, args []string) error {
            // Implementation
        },
    }
}
```

### CLI Commands
```bash
ccr rules test                          # Test rules against recent commands
ccr rules test --limit 20               # Test against 20 recent commands
ccr rules simulate "docker ps"          # Simulate command sync
ccr rules conflicts                     # Show rule conflicts
ccr rules status                        # Show rules summary
```

## Final CLI Command Structure

```bash
# Device Management
ccr devices show                        # List devices and aliases
ccr devices alias <id> <name>           # Set device alias
ccr devices remove-alias <id>           # Remove device alias

# Basic Rule Management
ccr rules                               # List rules (default)
ccr rules list                          # List rules
ccr rules allow <device>                # Create allow rule
ccr rules deny <device>                 # Create deny rule
ccr rules delete <rule-id>              # Delete rule
ccr rules enable <rule-id>              # Enable rule
ccr rules disable <rule-id>             # Disable rule

# Conditional Rules
ccr rules allow <device> --tag <tag>            # Tag-based allow
ccr rules deny <device> --dir <directory>       # Directory-based deny
ccr rules allow <device> --pattern <pattern>    # Pattern-based allow

# Rule Testing
ccr rules test                          # Test rules against history
ccr rules test --limit 20               # Test against specific number
ccr rules simulate <command>            # Simulate command evaluation
ccr rules conflicts                     # Show rule conflicts
ccr rules status                        # Show rules summary
```

## Server API Requirements

### Device Management
- `GET /api/v1/devices` - List user devices
- No additional device alias endpoints needed (local only)
- Add device sync job to 'ccr sync now' and to existing daemon

### Sync with Routing
- `POST /api/v1/sync/upload` - Upload with target_devices array
- Existing sync endpoints remain unchanged

### Server Logic Requirements
- Route commands to specified target devices
- Validate requesting device has authority to set targets
- Handle missing target devices gracefully
- Log routing decisions for debugging

## Implementation Notes

### Error Handling
- Follow existing error patterns in the codebase
- Use `fmt.Errorf` with wrapping for context
- Log warnings for non-critical failures
- Graceful degradation when rules evaluation fails

### Logging
- Use existing logger component with appropriate levels
- Add component-specific loggers: "device-manager", "rules-manager", "rule-engine"
- Log rule evaluation decisions for debugging

### Testing
- Unit tests for rule evaluation logic
- Integration tests for sync with routing metadata
- CLI command tests following existing patterns

### Performance
- Cache device list locally
- Cache rule evaluation results where appropriate
- Batch database operations
- Use existing database connection patterns

### Security
- Validate all user inputs
- Sanitize device aliases
- Prevent SQL injection in rule storage
- Follow existing authentication patterns

## Migration Strategy

### Database Migration
- Add new tables in migration version 3
- Populate devices table during first sync after upgrade
- Handle schema upgrades gracefully

### Backward Compatibility
- Default behavior: sync to all devices (existing behavior)
- Rules are opt-in - no rules means legacy behavior
- Existing sync continues to work without modification

### Rollback Plan
- Rules can be disabled without affecting sync
- Device aliases are cosmetic only
- Core sync functionality remains unchanged

This implementation plan provides a comprehensive roadmap for implementing the sync rules system while maintaining compatibility with existing CommandChronicles functionality.
