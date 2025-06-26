package stats

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/NeverVane/commandchronicles-cli/internal/auth"
	"github.com/NeverVane/commandchronicles-cli/internal/config"
	"github.com/NeverVane/commandchronicles-cli/internal/logger"
	"github.com/NeverVane/commandchronicles-cli/internal/storage"
	securestorage "github.com/NeverVane/commandchronicles-cli/pkg/storage"
)

// CommandStats represents statistics for a specific command
type CommandStats struct {
	Command     string    `json:"command"`
	Count       int       `json:"count"`
	SuccessRate float64   `json:"success_rate"`
	SuccessfulRuns int    `json:"successful_runs"`
	FailedRuns  int       `json:"failed_runs"`
	AvgDuration int64     `json:"avg_duration_ms"`
	MinDuration int64     `json:"min_duration_ms"`
	MaxDuration int64     `json:"max_duration_ms"`
	LastUsed    time.Time `json:"last_used"`
	FirstUsed   time.Time `json:"first_used"`
}

// DirectoryStats represents statistics for commands run in specific directories
type DirectoryStats struct {
	Directory   string    `json:"directory"`
	Count       int       `json:"count"`
	LastUsed    time.Time `json:"last_used"`
	FirstUsed   time.Time `json:"first_used"`
	UniqueCommands int    `json:"unique_commands"`
	SuccessRate float64   `json:"success_rate"`
}

// TimeStats represents usage patterns by time periods
type TimeStats struct {
	Hour        int `json:"hour"`
	Count       int `json:"count"`
	SuccessRate float64 `json:"success_rate"`
}

// DayStats represents usage patterns by day of week
type DayStats struct {
	Weekday     int `json:"weekday"` // 0=Sunday, 1=Monday, etc.
	DayName     string `json:"day_name"`
	Count       int `json:"count"`
	SuccessRate float64 `json:"success_rate"`
}

// SessionStats represents statistics for shell sessions
type SessionStats struct {
	SessionID   string `json:"session_id"`
	CommandCount int   `json:"command_count"`
	Duration    int64  `json:"duration_ms"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	SuccessRate float64   `json:"success_rate"`
}

// OverallStats represents comprehensive statistics
type OverallStats struct {
	TotalCommands     int     `json:"total_commands"`
	UniqueCommands    int     `json:"unique_commands"`
	TotalDirectories  int     `json:"total_directories"`
	TotalSessions     int     `json:"total_sessions"`
	OverallSuccessRate float64 `json:"overall_success_rate"`
	TotalDuration     int64   `json:"total_duration_ms"`
	AvgDuration       int64   `json:"avg_duration_ms"`
	EarliestCommand   time.Time `json:"earliest_command"`
	LatestCommand     time.Time `json:"latest_command"`
	TimeSpan          int64   `json:"time_span_ms"`
}

// StatsPeriod defines time periods for filtering statistics
type StatsPeriod string

const (
	PeriodAll   StatsPeriod = "all"
	PeriodDay   StatsPeriod = "1d"
	PeriodWeek  StatsPeriod = "1w"
	PeriodMonth StatsPeriod = "1m"
	PeriodYear  StatsPeriod = "1y"
)

// StatsOptions provides configuration for statistics generation
type StatsOptions struct {
	Period        StatsPeriod `json:"period"`
	TopN          int         `json:"top_n"`
	MinOccurrences int        `json:"min_occurrences"`
	IncludeGitInfo bool       `json:"include_git_info"`
	SessionFilter string     `json:"session_filter"`
	HostnameFilter string    `json:"hostname_filter"`
	DirectoryFilter string   `json:"directory_filter"`
	CommandFilter string     `json:"command_filter"`
}

// StatsResult contains all generated statistics
type StatsResult struct {
	Overall       *OverallStats      `json:"overall"`
	TopCommands   []*CommandStats    `json:"top_commands"`
	TopDirectories []*DirectoryStats `json:"top_directories"`
	HourlyPattern []*TimeStats       `json:"hourly_pattern"`
	DailyPattern  []*DayStats        `json:"daily_pattern"`
	Sessions      []*SessionStats    `json:"sessions"`
	GeneratedAt   time.Time          `json:"generated_at"`
	Period        StatsPeriod        `json:"period"`
	RecordsAnalyzed int              `json:"records_analyzed"`
}

// StatsEngine provides statistical analysis of command history
type StatsEngine struct {
	storage *securestorage.SecureStorage
	authMgr *auth.AuthManager
	config  *config.Config
	logger  *logger.Logger
	mu      sync.RWMutex
}

// NewStatsEngine creates a new statistics engine
func NewStatsEngine(cfg *config.Config, storage *securestorage.SecureStorage, authMgr *auth.AuthManager) *StatsEngine {
	return &StatsEngine{
		storage: storage,
		authMgr: authMgr,
		config:  cfg,
		logger:  logger.GetLogger().WithComponent("stats"),
	}
}

// GenerateStats generates comprehensive statistics from the command history
func (se *StatsEngine) GenerateStats(opts *StatsOptions) (*StatsResult, error) {
	se.mu.RLock()
	defer se.mu.RUnlock()

	if opts == nil {
		opts = &StatsOptions{
			Period: PeriodAll,
			TopN:   10,
			MinOccurrences: 1,
		}
	}

	se.logger.Info().
		Str("period", string(opts.Period)).
		Int("top_n", opts.TopN).
		Msg("Generating command statistics")

	// Check if session is active
	if !se.authMgr.IsSessionActive() {
		return nil, fmt.Errorf("no active session - please unlock first")
	}



	// Calculate time filter based on period
	var sinceTime *time.Time
	if opts.Period != PeriodAll {
		since := se.calculateSinceTime(opts.Period)
		sinceTime = &since
	}

	// Create query options for filtering
	queryOpts := &securestorage.QueryOptions{
		Since:      sinceTime,
		SessionID:  opts.SessionFilter,
		Hostname:   opts.HostnameFilter,
		WorkingDir: opts.DirectoryFilter,
		Command:    opts.CommandFilter,
		OrderBy:    "timestamp",
		Ascending:  true,
	}

	// Retrieve all matching records
	result, err := se.storage.Retrieve(queryOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve records: %w", err)
	}

	se.logger.Info().
		Int("records", len(result.Records)).
		Msg("Retrieved records for analysis")

	// Generate statistics from records
	stats := se.analyzeRecords(result.Records, opts)
	stats.GeneratedAt = time.Now()
	stats.Period = opts.Period
	stats.RecordsAnalyzed = len(result.Records)

	se.logger.Info().
		Int("total_commands", stats.Overall.TotalCommands).
		Int("unique_commands", stats.Overall.UniqueCommands).
		Float64("success_rate", stats.Overall.OverallSuccessRate).
		Msg("Statistics generation completed")

	return stats, nil
}

// analyzeRecords performs the actual statistical analysis
func (se *StatsEngine) analyzeRecords(records []*storage.CommandRecord, opts *StatsOptions) *StatsResult {
	// Set default options if nil
	if opts == nil {
		opts = &StatsOptions{
			Period: PeriodAll,
			TopN:   10,
			MinOccurrences: 1,
		}
	}

	commandMap := make(map[string]*CommandStats)
	directoryMap := make(map[string]*DirectoryStats)
	hourlyMap := make(map[int]*TimeStats)
	dailyMap := make(map[int]*DayStats)
	sessionMap := make(map[string]*SessionStats)

	overall := &OverallStats{}
	
	// Initialize time pattern maps
	for i := 0; i < 24; i++ {
		hourlyMap[i] = &TimeStats{Hour: i}
	}
	
	dayNames := []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}
	for i := 0; i < 7; i++ {
		dailyMap[i] = &DayStats{Weekday: i, DayName: dayNames[i]}
	}

	// Track overall statistics
	var totalDuration int64
	var successfulCommands int
	var earliestTime, latestTime time.Time

	for i, record := range records {
		timestamp := time.UnixMilli(record.Timestamp)
		
		// Track earliest and latest commands
		if i == 0 || timestamp.Before(earliestTime) {
			earliestTime = timestamp
		}
		if i == 0 || timestamp.After(latestTime) {
			latestTime = timestamp
		}

		// Extract base command (first word)
		cmd := se.extractBaseCommand(record.Command)
		if cmd == "" {
			continue
		}

		// Update command statistics
		se.updateCommandStats(commandMap, cmd, record, timestamp)

		// Update directory statistics
		se.updateDirectoryStats(directoryMap, record.WorkingDir, record, timestamp)

		// Update time pattern statistics
		se.updateTimeStats(hourlyMap, dailyMap, record, timestamp)

		// Update session statistics
		se.updateSessionStats(sessionMap, record, timestamp)

		// Update overall counters
		totalDuration += record.Duration
		if record.ExitCode == 0 {
			successfulCommands++
		}
	}

	// Calculate overall statistics
	overall.TotalCommands = len(records)
	overall.UniqueCommands = len(commandMap)
	overall.TotalDirectories = len(directoryMap)
	overall.TotalSessions = len(sessionMap)
	overall.TotalDuration = totalDuration
	overall.EarliestCommand = earliestTime
	overall.LatestCommand = latestTime
	overall.TimeSpan = latestTime.Sub(earliestTime).Milliseconds()

	if len(records) > 0 {
		overall.OverallSuccessRate = float64(successfulCommands) / float64(len(records)) * 100.0
		overall.AvgDuration = totalDuration / int64(len(records))
	}

	// Sort and filter results
	topCommands := se.sortCommandStats(commandMap, opts)
	topDirectories := se.sortDirectoryStats(directoryMap, opts)
	hourlyPattern := se.convertHourlyStats(hourlyMap)
	dailyPattern := se.convertDailyStats(dailyMap)
	sessions := se.sortSessionStats(sessionMap, opts)

	return &StatsResult{
		Overall:        overall,
		TopCommands:    topCommands,
		TopDirectories: topDirectories,
		HourlyPattern:  hourlyPattern,
		DailyPattern:   dailyPattern,
		Sessions:       sessions,
	}
}

// extractBaseCommand extracts the base command from a full command line
func (se *StatsEngine) extractBaseCommand(command string) string {
	parts := strings.Fields(strings.TrimSpace(command))
	if len(parts) == 0 {
		return ""
	}
	
	baseCmd := parts[0]
	
	// Handle common patterns
	if strings.HasPrefix(baseCmd, "sudo") && len(parts) > 1 {
		return parts[1] // Return the actual command after sudo
	}
	
	// Remove path components for commands with full paths
	if strings.Contains(baseCmd, "/") {
		pathParts := strings.Split(baseCmd, "/")
		return pathParts[len(pathParts)-1]
	}
	
	return baseCmd
}

// updateCommandStats updates statistics for a specific command
func (se *StatsEngine) updateCommandStats(commandMap map[string]*CommandStats, cmd string, record *storage.CommandRecord, timestamp time.Time) {
	stats, exists := commandMap[cmd]
	if !exists {
		stats = &CommandStats{
			Command:     cmd,
			FirstUsed:   timestamp,
			MinDuration: record.Duration,
			MaxDuration: record.Duration,
		}
		commandMap[cmd] = stats
	}

	stats.Count++
	stats.AvgDuration = (stats.AvgDuration*int64(stats.Count-1) + record.Duration) / int64(stats.Count)
	
	if record.Duration < stats.MinDuration {
		stats.MinDuration = record.Duration
	}
	if record.Duration > stats.MaxDuration {
		stats.MaxDuration = record.Duration
	}
	
	if timestamp.After(stats.LastUsed) {
		stats.LastUsed = timestamp
	}
	if timestamp.Before(stats.FirstUsed) {
		stats.FirstUsed = timestamp
	}

	if record.ExitCode == 0 {
		stats.SuccessfulRuns++
	} else {
		stats.FailedRuns++
	}
	
	stats.SuccessRate = float64(stats.SuccessfulRuns) / float64(stats.Count) * 100.0
}

// updateDirectoryStats updates statistics for directory usage
func (se *StatsEngine) updateDirectoryStats(directoryMap map[string]*DirectoryStats, workingDir string, record *storage.CommandRecord, timestamp time.Time) {
	stats, exists := directoryMap[workingDir]
	if !exists {
		stats = &DirectoryStats{
			Directory: workingDir,
			FirstUsed: timestamp,
		}
		directoryMap[workingDir] = stats
	}

	stats.Count++
	if timestamp.After(stats.LastUsed) {
		stats.LastUsed = timestamp
	}
	if timestamp.Before(stats.FirstUsed) {
		stats.FirstUsed = timestamp
	}

	// Calculate success rate
	successCount := 0
	for _, otherRecord := range []*storage.CommandRecord{record} {
		if otherRecord.WorkingDir == workingDir && otherRecord.ExitCode == 0 {
			successCount++
		}
	}
	// Note: This is simplified - in a real implementation, we'd track this properly
	if record.ExitCode == 0 {
		stats.SuccessRate = (stats.SuccessRate*float64(stats.Count-1) + 100.0) / float64(stats.Count)
	} else {
		stats.SuccessRate = (stats.SuccessRate*float64(stats.Count-1) + 0.0) / float64(stats.Count)
	}
}

// updateTimeStats updates time-based usage patterns
func (se *StatsEngine) updateTimeStats(hourlyMap map[int]*TimeStats, dailyMap map[int]*DayStats, record *storage.CommandRecord, timestamp time.Time) {
	hour := timestamp.Hour()
	weekday := int(timestamp.Weekday())

	// Update hourly stats
	hourlyMap[hour].Count++
	if record.ExitCode == 0 {
		oldRate := hourlyMap[hour].SuccessRate
		oldCount := hourlyMap[hour].Count - 1
		hourlyMap[hour].SuccessRate = (oldRate*float64(oldCount) + 100.0) / float64(hourlyMap[hour].Count)
	} else {
		oldRate := hourlyMap[hour].SuccessRate
		oldCount := hourlyMap[hour].Count - 1
		hourlyMap[hour].SuccessRate = (oldRate*float64(oldCount) + 0.0) / float64(hourlyMap[hour].Count)
	}

	// Update daily stats
	dailyMap[weekday].Count++
	if record.ExitCode == 0 {
		oldRate := dailyMap[weekday].SuccessRate
		oldCount := dailyMap[weekday].Count - 1
		dailyMap[weekday].SuccessRate = (oldRate*float64(oldCount) + 100.0) / float64(dailyMap[weekday].Count)
	} else {
		oldRate := dailyMap[weekday].SuccessRate
		oldCount := dailyMap[weekday].Count - 1
		dailyMap[weekday].SuccessRate = (oldRate*float64(oldCount) + 0.0) / float64(dailyMap[weekday].Count)
	}
}

// updateSessionStats updates statistics for shell sessions
func (se *StatsEngine) updateSessionStats(sessionMap map[string]*SessionStats, record *storage.CommandRecord, timestamp time.Time) {
	stats, exists := sessionMap[record.SessionID]
	if !exists {
		stats = &SessionStats{
			SessionID: record.SessionID,
			StartTime: timestamp,
			EndTime:   timestamp,
		}
		sessionMap[record.SessionID] = stats
	}

	stats.CommandCount++
	if timestamp.Before(stats.StartTime) {
		stats.StartTime = timestamp
	}
	if timestamp.After(stats.EndTime) {
		stats.EndTime = timestamp
	}
	stats.Duration = stats.EndTime.Sub(stats.StartTime).Milliseconds()

	// Update success rate
	if record.ExitCode == 0 {
		oldRate := stats.SuccessRate
		oldCount := stats.CommandCount - 1
		stats.SuccessRate = (oldRate*float64(oldCount) + 100.0) / float64(stats.CommandCount)
	} else {
		oldRate := stats.SuccessRate
		oldCount := stats.CommandCount - 1
		stats.SuccessRate = (oldRate*float64(oldCount) + 0.0) / float64(stats.CommandCount)
	}
}

// sortCommandStats sorts and filters command statistics
func (se *StatsEngine) sortCommandStats(commandMap map[string]*CommandStats, opts *StatsOptions) []*CommandStats {
	if opts == nil {
		opts = &StatsOptions{MinOccurrences: 1, TopN: 10}
	}

	stats := make([]*CommandStats, 0, len(commandMap))
	for _, stat := range commandMap {
		if stat.Count >= opts.MinOccurrences {
			stats = append(stats, stat)
		}
	}

	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Count > stats[j].Count
	})

	if opts.TopN > 0 && len(stats) > opts.TopN {
		stats = stats[:opts.TopN]
	}

	return stats
}

// sortDirectoryStats sorts and filters directory statistics
func (se *StatsEngine) sortDirectoryStats(directoryMap map[string]*DirectoryStats, opts *StatsOptions) []*DirectoryStats {
	if opts == nil {
		opts = &StatsOptions{MinOccurrences: 1, TopN: 10}
	}

	stats := make([]*DirectoryStats, 0, len(directoryMap))
	for _, stat := range directoryMap {
		if stat.Count >= opts.MinOccurrences {
			stats = append(stats, stat)
		}
	}

	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Count > stats[j].Count
	})

	if opts.TopN > 0 && len(stats) > opts.TopN {
		stats = stats[:opts.TopN]
	}

	return stats
}

// convertHourlyStats converts map to sorted slice
func (se *StatsEngine) convertHourlyStats(hourlyMap map[int]*TimeStats) []*TimeStats {
	stats := make([]*TimeStats, 24)
	for i := 0; i < 24; i++ {
		stats[i] = hourlyMap[i]
	}
	return stats
}

// convertDailyStats converts map to sorted slice
func (se *StatsEngine) convertDailyStats(dailyMap map[int]*DayStats) []*DayStats {
	stats := make([]*DayStats, 7)
	for i := 0; i < 7; i++ {
		stats[i] = dailyMap[i]
	}
	return stats
}

// sortSessionStats sorts session statistics by duration
func (se *StatsEngine) sortSessionStats(sessionMap map[string]*SessionStats, opts *StatsOptions) []*SessionStats {
	if opts == nil {
		opts = &StatsOptions{TopN: 10}
	}

	stats := make([]*SessionStats, 0, len(sessionMap))
	for _, stat := range sessionMap {
		stats = append(stats, stat)
	}

	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Duration > stats[j].Duration
	})

	if opts.TopN > 0 && len(stats) > opts.TopN {
		stats = stats[:opts.TopN]
	}

	return stats
}

// calculateSinceTime calculates the start time based on the period
func (se *StatsEngine) calculateSinceTime(period StatsPeriod) time.Time {
	now := time.Now()
	switch period {
	case PeriodDay:
		return now.AddDate(0, 0, -1)
	case PeriodWeek:
		return now.AddDate(0, 0, -7)
	case PeriodMonth:
		return now.AddDate(0, -1, 0)
	case PeriodYear:
		return now.AddDate(-1, 0, 0)
	default:
		return time.Time{} // Beginning of time
	}
}

// GetQuickStats returns basic statistics without detailed breakdowns
func (se *StatsEngine) GetQuickStats() (*OverallStats, error) {
	opts := &StatsOptions{
		Period: PeriodAll,
		TopN:   0, // Don't need detailed breakdowns
	}

	result, err := se.GenerateStats(opts)
	if err != nil {
		return nil, err
	}

	return result.Overall, nil
}

// GetTopCommands returns the most frequently used commands
func (se *StatsEngine) GetTopCommands(limit int, period StatsPeriod) ([]*CommandStats, error) {
	opts := &StatsOptions{
		Period: period,
		TopN:   limit,
		MinOccurrences: 1,
	}

	result, err := se.GenerateStats(opts)
	if err != nil {
		return nil, err
	}

	return result.TopCommands, nil
}