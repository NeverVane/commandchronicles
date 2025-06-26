package stats

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeverVane/commandchronicles-cli/internal/storage"
)

// Helper function to create test command records
func createTestRecord(command string, exitCode int, duration int64, workingDir string, timestamp time.Time, sessionID string) *storage.CommandRecord {
	return &storage.CommandRecord{
		Command:    command,
		ExitCode:   exitCode,
		Duration:   duration,
		WorkingDir: workingDir,
		Timestamp:  timestamp.UnixMilli(),
		SessionID:  sessionID,
		Hostname:   "test-host",
		User:       "testuser",
		Shell:      "bash",
		Version:    1,
		CreatedAt:  timestamp.UnixMilli(),
	}
}

func TestStatsEngine_ExtractBaseCommand(t *testing.T) {
	engine := &StatsEngine{}

	tests := []struct {
		command  string
		expected string
	}{
		{"git status", "git"},
		{"sudo apt install package", "apt"},
		{"ls -la", "ls"},
		{"/usr/bin/python3 script.py", "python3"},
		{"./local-script.sh", "local-script.sh"},
		{"", ""},
		{"   ", ""},
		{"single", "single"},
		{"sudo su -", "su"},
		{"/bin/bash -c 'echo hello'", "bash"},
	}

	for _, test := range tests {
		t.Run(test.command, func(t *testing.T) {
			result := engine.extractBaseCommand(test.command)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestStatsEngine_CalculateSinceTime(t *testing.T) {
	engine := &StatsEngine{}
	now := time.Now()

	tests := []struct {
		period   StatsPeriod
		expected time.Duration
	}{
		{PeriodDay, 24 * time.Hour},
		{PeriodWeek, 7 * 24 * time.Hour},
		{PeriodMonth, 30 * 24 * time.Hour}, // Approximate
		{PeriodYear, 365 * 24 * time.Hour}, // Approximate
	}

	for _, test := range tests {
		t.Run(string(test.period), func(t *testing.T) {
			result := engine.calculateSinceTime(test.period)
			
			if test.period == PeriodAll {
				assert.True(t, result.IsZero())
			} else {
				diff := now.Sub(result)
				// Allow for larger tolerance for month and year calculations due to varying month lengths
				tolerance := 3600.0 // 1 hour for day/week
				if test.period == PeriodMonth {
					tolerance = 86400.0 * 2 // 2 days tolerance for month
				} else if test.period == PeriodYear {
					tolerance = 86400.0 * 7 // 1 week tolerance for year
				}
				assert.InDelta(t, test.expected.Seconds(), diff.Seconds(), tolerance)
			}
		})
	}
}

func TestStatsEngine_AnalyzeRecords_EmptyDataset(t *testing.T) {
	engine := &StatsEngine{}
	records := []*storage.CommandRecord{}
	opts := &StatsOptions{
		Period: PeriodAll,
		TopN:   10,
	}

	result := engine.analyzeRecords(records, opts)

	assert.Equal(t, 0, result.Overall.TotalCommands)
	assert.Equal(t, 0, result.Overall.UniqueCommands)
	assert.Equal(t, 0.0, result.Overall.OverallSuccessRate)
	assert.Len(t, result.TopCommands, 0)
	assert.Len(t, result.TopDirectories, 0)
	assert.Len(t, result.HourlyPattern, 24)
	assert.Len(t, result.DailyPattern, 7)
}

func TestStatsEngine_AnalyzeRecords_CommandStats(t *testing.T) {
	engine := &StatsEngine{}
	now := time.Now()
	
	records := []*storage.CommandRecord{
		createTestRecord("git status", 0, 100, "/project", now, "session1"),
		createTestRecord("git status", 0, 150, "/project", now.Add(1*time.Minute), "session1"),
		createTestRecord("git status", 1, 200, "/project", now.Add(2*time.Minute), "session1"),
		createTestRecord("ls -la", 0, 50, "/project", now.Add(3*time.Minute), "session1"),
	}

	opts := &StatsOptions{
		Period: PeriodAll,
		TopN:   10,
	}

	result := engine.analyzeRecords(records, opts)

	// Verify overall stats
	assert.Equal(t, 4, result.Overall.TotalCommands)
	assert.Equal(t, 2, result.Overall.UniqueCommands) // git, ls
	assert.Equal(t, 75.0, result.Overall.OverallSuccessRate) // 3 successful out of 4

	// Find git command stats
	var gitStats *CommandStats
	for _, cmd := range result.TopCommands {
		if cmd.Command == "git" {
			gitStats = cmd
			break
		}
	}

	require.NotNil(t, gitStats)
	assert.Equal(t, 3, gitStats.Count)
	assert.Equal(t, 2, gitStats.SuccessfulRuns)
	assert.Equal(t, 1, gitStats.FailedRuns)
	assert.InDelta(t, 66.67, gitStats.SuccessRate, 0.1)
	assert.Equal(t, int64(150), gitStats.AvgDuration) // (100+150+200)/3
	assert.Equal(t, int64(100), gitStats.MinDuration)
	assert.Equal(t, int64(200), gitStats.MaxDuration)
}

func TestStatsEngine_AnalyzeRecords_TimePatterns(t *testing.T) {
	engine := &StatsEngine{}
	
	// Create records at specific known dates and times
	// Using a known Monday and Tuesday for reliable testing
	monday9AM := time.Date(2024, 2, 5, 9, 0, 0, 0, time.UTC)   // Monday Feb 5, 2024 at 9 AM
	tuesday3PM := time.Date(2024, 2, 6, 15, 0, 0, 0, time.UTC) // Tuesday Feb 6, 2024 at 3 PM
	
	// Verify our test dates are correct weekdays
	require.Equal(t, time.Monday, monday9AM.Weekday(), "Test date should be Monday")
	require.Equal(t, time.Tuesday, tuesday3PM.Weekday(), "Test date should be Tuesday")
	
	records := []*storage.CommandRecord{
		createTestRecord("ls", 0, 50, "/home", monday9AM, "session1"),
		createTestRecord("pwd", 0, 25, "/home", monday9AM.Add(1*time.Minute), "session1"),
		createTestRecord("git status", 1, 100, "/project", tuesday3PM, "session2"),
	}

	opts := &StatsOptions{
		Period: PeriodAll,
		TopN:   10,
	}

	result := engine.analyzeRecords(records, opts)

	// Check hourly pattern (adjusted for timezone conversion UTC -> local)
	assert.Equal(t, 2, result.HourlyPattern[10].Count)  // 9 AM UTC -> 10 AM local
	assert.Equal(t, 1, result.HourlyPattern[16].Count) // 3 PM UTC -> 4 PM local  
	assert.Equal(t, 0, result.HourlyPattern[12].Count) // Noon (no commands)

	// Check daily pattern - Note: Go's time.Weekday() uses Sunday=0, Monday=1, Tuesday=2
	assert.Equal(t, 2, result.DailyPattern[1].Count) // Monday (2 commands)
	assert.Equal(t, 1, result.DailyPattern[2].Count) // Tuesday (1 command)
	assert.Equal(t, 0, result.DailyPattern[0].Count) // Sunday (no commands)
}



func TestStatsEngine_AnalyzeRecords_FilterByMinOccurrences(t *testing.T) {
	engine := &StatsEngine{}
	now := time.Now()
	
	records := []*storage.CommandRecord{
		createTestRecord("git status", 0, 100, "/project", now, "session1"),
		createTestRecord("git status", 0, 100, "/project", now, "session1"),
		createTestRecord("git status", 0, 100, "/project", now, "session1"),
		createTestRecord("ls -la", 0, 50, "/project", now, "session1"),
		createTestRecord("pwd", 0, 25, "/home", now, "session2"),
	}

	opts := &StatsOptions{
		Period:         PeriodAll,
		TopN:           10,
		MinOccurrences: 2, // Only commands with 2+ occurrences
	}

	result := engine.analyzeRecords(records, opts)

	// Only git should be included (3 occurrences >= 2)
	assert.Len(t, result.TopCommands, 1)
	assert.Equal(t, "git", result.TopCommands[0].Command)
	assert.Equal(t, 3, result.TopCommands[0].Count)
}

func TestStatsEngine_AnalyzeRecords_TopNLimit(t *testing.T) {
	engine := &StatsEngine{}
	now := time.Now()
	
	records := []*storage.CommandRecord{
		createTestRecord("git status", 0, 100, "/project", now, "session1"),
		createTestRecord("git status", 0, 100, "/project", now, "session1"),
		createTestRecord("ls -la", 0, 50, "/project", now, "session1"),
		createTestRecord("pwd", 0, 25, "/home", now, "session2"),
		createTestRecord("cd /tmp", 0, 10, "/tmp", now, "session3"),
	}

	opts := &StatsOptions{
		Period: PeriodAll,
		TopN:   2, // Limit to top 2 commands
	}

	result := engine.analyzeRecords(records, opts)

	// Should only return top 2 commands
	assert.Len(t, result.TopCommands, 2)
	assert.Equal(t, "git", result.TopCommands[0].Command) // Most frequent (2)
	// Second should be one of the single-occurrence commands
	assert.Equal(t, 1, result.TopCommands[1].Count)
}

func TestStatsEngine_UpdateSessionStats(t *testing.T) {
	engine := &StatsEngine{}
	sessionMap := make(map[string]*SessionStats)
	
	baseTime := time.Now()
	record1 := createTestRecord("ls", 0, 50, "/home", baseTime, "session1")
	record2 := createTestRecord("pwd", 1, 25, "/home", baseTime.Add(1*time.Minute), "session1")
	record3 := createTestRecord("cd", 0, 10, "/tmp", baseTime.Add(2*time.Minute), "session1")

	// Process records
	engine.updateSessionStats(sessionMap, record1, baseTime)
	engine.updateSessionStats(sessionMap, record2, baseTime.Add(1*time.Minute))
	engine.updateSessionStats(sessionMap, record3, baseTime.Add(2*time.Minute))

	stats := sessionMap["session1"]
	require.NotNil(t, stats)
	
	assert.Equal(t, 3, stats.CommandCount)
	assert.Equal(t, baseTime, stats.StartTime)
	assert.Equal(t, baseTime.Add(2*time.Minute), stats.EndTime)
	assert.Equal(t, int64(120000), stats.Duration) // 2 minutes in milliseconds
	assert.InDelta(t, 66.67, stats.SuccessRate, 0.1) // 2 success out of 3
}

func TestStatsEngine_UpdateCommandStats(t *testing.T) {
	engine := &StatsEngine{}
	commandMap := make(map[string]*CommandStats)
	
	baseTime := time.Now()
	record1 := createTestRecord("git status", 0, 100, "/project", baseTime, "session1")
	record2 := createTestRecord("git status", 1, 200, "/project", baseTime.Add(1*time.Minute), "session1")

	// Process records
	engine.updateCommandStats(commandMap, "git", record1, baseTime)
	engine.updateCommandStats(commandMap, "git", record2, baseTime.Add(1*time.Minute))

	stats := commandMap["git"]
	require.NotNil(t, stats)
	
	assert.Equal(t, 2, stats.Count)
	assert.Equal(t, 1, stats.SuccessfulRuns)
	assert.Equal(t, 1, stats.FailedRuns)
	assert.Equal(t, 50.0, stats.SuccessRate)
	assert.Equal(t, int64(150), stats.AvgDuration) // (100+200)/2
	assert.Equal(t, int64(100), stats.MinDuration)
	assert.Equal(t, int64(200), stats.MaxDuration)
	assert.Equal(t, baseTime, stats.FirstUsed)
	assert.Equal(t, baseTime.Add(1*time.Minute), stats.LastUsed)
}

func TestStatsEngine_DirectoryStatsCalculation(t *testing.T) {
	engine := &StatsEngine{}
	now := time.Now()
	
	records := []*storage.CommandRecord{
		createTestRecord("ls", 0, 50, "/project", now, "session1"),
		createTestRecord("git status", 0, 100, "/project", now.Add(1*time.Minute), "session1"),
		createTestRecord("pwd", 1, 25, "/project", now.Add(2*time.Minute), "session1"),
		createTestRecord("cd", 0, 10, "/home", now.Add(3*time.Minute), "session2"),
	}

	opts := &StatsOptions{
		Period: PeriodAll,
		TopN:   10,
	}

	result := engine.analyzeRecords(records, opts)

	// Find project directory stats
	var projectStats *DirectoryStats
	for _, dir := range result.TopDirectories {
		if dir.Directory == "/project" {
			projectStats = dir
			break
		}
	}

	require.NotNil(t, projectStats)
	assert.Equal(t, 3, projectStats.Count)
	assert.Equal(t, "/project", projectStats.Directory)
	
	// Find home directory stats
	var homeStats *DirectoryStats
	for _, dir := range result.TopDirectories {
		if dir.Directory == "/home" {
			homeStats = dir
			break
		}
	}

	require.NotNil(t, homeStats)
	assert.Equal(t, 1, homeStats.Count)
	assert.Equal(t, "/home", homeStats.Directory)
}

func TestStatsOptions_DefaultValues(t *testing.T) {
	// Test that nil options get proper defaults in analysis
	engine := &StatsEngine{}
	
	records := []*storage.CommandRecord{
		createTestRecord("git status", 0, 100, "/project", time.Now(), "session1"),
	}

	result := engine.analyzeRecords(records, nil)
	
	// Should not crash and should return reasonable results
	assert.Equal(t, 1, result.Overall.TotalCommands)
	assert.Equal(t, 1, result.Overall.UniqueCommands)
	assert.Len(t, result.HourlyPattern, 24)
	assert.Len(t, result.DailyPattern, 7)
}

func TestStatsEngine_SortingBehavior(t *testing.T) {
	engine := &StatsEngine{}
	now := time.Now()
	
	// Create records with different frequencies
	records := []*storage.CommandRecord{
		// git appears 3 times
		createTestRecord("git status", 0, 100, "/project", now, "session1"),
		createTestRecord("git push", 0, 200, "/project", now.Add(1*time.Minute), "session1"),
		createTestRecord("git pull", 0, 150, "/project", now.Add(2*time.Minute), "session1"),
		// ls appears 2 times  
		createTestRecord("ls -la", 0, 50, "/project", now.Add(3*time.Minute), "session1"),
		createTestRecord("ls", 0, 30, "/home", now.Add(4*time.Minute), "session2"),
		// pwd appears 1 time
		createTestRecord("pwd", 0, 25, "/home", now.Add(5*time.Minute), "session2"),
	}

	opts := &StatsOptions{
		Period: PeriodAll,
		TopN:   10,
	}

	result := engine.analyzeRecords(records, opts)

	// Commands should be sorted by frequency (descending)
	require.Len(t, result.TopCommands, 3)
	assert.Equal(t, "git", result.TopCommands[0].Command) // 3 occurrences
	assert.Equal(t, 3, result.TopCommands[0].Count)
	assert.Equal(t, "ls", result.TopCommands[1].Command)  // 2 occurrences
	assert.Equal(t, 2, result.TopCommands[1].Count)
	assert.Equal(t, "pwd", result.TopCommands[2].Command) // 1 occurrence
	assert.Equal(t, 1, result.TopCommands[2].Count)
}