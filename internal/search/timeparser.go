package search

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// TimeFilter represents parsed time constraints from a search query
type TimeFilter struct {
	Since         *time.Time
	Until         *time.Time
	OriginalQuery string // Query with time expressions removed
	HasTimeFilter bool
}

// TimeParser handles parsing of time expressions from search queries
type TimeParser struct {
	patterns []*timePattern
}

type timePattern struct {
	regex   *regexp.Regexp
	handler func(matches []string) (since, until *time.Time)
}

// NewTimeParser creates a new time expression parser
func NewTimeParser() *TimeParser {
	parser := &TimeParser{}
	parser.initializePatterns()
	return parser
}

// initializePatterns sets up all supported time expression patterns
func (tp *TimeParser) initializePatterns() {
	tp.patterns = []*timePattern{
		// Range patterns: "1h-30m", "2d-1d" - MUST come first to avoid basic pattern matching
		{
			regex: regexp.MustCompile(`^(\d+)([hmdw])-(\d+)([hmdw])\s*(.*)$`),
			handler: func(matches []string) (since, until *time.Time) {
				sinceDuration := tp.parseDuration(matches[1], matches[2])
				untilDuration := tp.parseDuration(matches[3], matches[4])
				
				// Validate that since > until (first time is further back)
				if sinceDuration > 0 && untilDuration > 0 && sinceDuration > untilDuration {
					sinceTime := time.Now().Add(-sinceDuration)
					untilTime := time.Now().Add(-untilDuration)
					return &sinceTime, &untilTime
				}
				return nil, nil
			},
		},
		
		// "since" patterns: "since 1h", "since 2d"
		{
			regex: regexp.MustCompile(`^since\s+(\d+)([hmdw])\s*(.*)$`),
			handler: func(matches []string) (since, until *time.Time) {
				duration := tp.parseDuration(matches[1], matches[2])
				if duration > 0 {
					sinceTime := time.Now().Add(-duration)
					return &sinceTime, nil
				}
				return nil, nil
			},
		},
		
		// "last" patterns: "last 1h", "last 2d"
		{
			regex: regexp.MustCompile(`^last\s+(\d+)([hmdw])\s*(.*)$`),
			handler: func(matches []string) (since, until *time.Time) {
				duration := tp.parseDuration(matches[1], matches[2])
				if duration > 0 {
					sinceTime := time.Now().Add(-duration)
					return &sinceTime, nil
				}
				return nil, nil
			},
		},
		
		// Natural language: "today"
		{
			regex: regexp.MustCompile(`^today\s*(.*)$`),
			handler: func(matches []string) (since, until *time.Time) {
				now := time.Now()
				startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
				return &startOfDay, nil
			},
		},
		
		// Natural language: "yesterday"
		{
			regex: regexp.MustCompile(`^yesterday\s*(.*)$`),
			handler: func(matches []string) (since, until *time.Time) {
				now := time.Now()
				yesterday := now.AddDate(0, 0, -1)
				startOfYesterday := time.Date(yesterday.Year(), yesterday.Month(), yesterday.Day(), 0, 0, 0, 0, yesterday.Location())
				endOfYesterday := time.Date(yesterday.Year(), yesterday.Month(), yesterday.Day(), 23, 59, 59, 999999999, yesterday.Location())
				return &startOfYesterday, &endOfYesterday
			},
		},
		
		// Natural language: "this week"
		{
			regex: regexp.MustCompile(`^this\s+week\s*(.*)$`),
			handler: func(matches []string) (since, until *time.Time) {
				now := time.Now()
				// Find start of current week (Monday)
				weekday := int(now.Weekday())
				if weekday == 0 { // Sunday
					weekday = 7
				}
				daysToSubtract := weekday - 1
				startOfWeek := now.AddDate(0, 0, -daysToSubtract)
				startOfWeek = time.Date(startOfWeek.Year(), startOfWeek.Month(), startOfWeek.Day(), 0, 0, 0, 0, startOfWeek.Location())
				return &startOfWeek, nil
			},
		},
		
		// Natural language: "last week"
		{
			regex: regexp.MustCompile(`^last\s+week\s*(.*)$`),
			handler: func(matches []string) (since, until *time.Time) {
				now := time.Now()
				// Find start of current week (Monday)
				weekday := int(now.Weekday())
				if weekday == 0 { // Sunday
					weekday = 7
				}
				daysToSubtract := weekday - 1 + 7 // Go back to start of last week
				startOfLastWeek := now.AddDate(0, 0, -daysToSubtract)
				startOfLastWeek = time.Date(startOfLastWeek.Year(), startOfLastWeek.Month(), startOfLastWeek.Day(), 0, 0, 0, 0, startOfLastWeek.Location())
				endOfLastWeek := startOfLastWeek.AddDate(0, 0, 6)
				endOfLastWeek = time.Date(endOfLastWeek.Year(), endOfLastWeek.Month(), endOfLastWeek.Day(), 23, 59, 59, 999999999, endOfLastWeek.Location())
				return &startOfLastWeek, &endOfLastWeek
			},
		},
		
		// Basic duration patterns: "1h", "2d", "30m", "1w" - MUST come last to avoid conflicts
		{
			regex: regexp.MustCompile(`^(\d+)([hmdw])\s*(.*)$`),
			handler: func(matches []string) (since, until *time.Time) {
				duration := tp.parseDuration(matches[1], matches[2])
				if duration > 0 {
					sinceTime := time.Now().Add(-duration)
					return &sinceTime, nil
				}
				return nil, nil
			},
		},
	}
}

// ParseTimeExpression parses time expressions from a search query
func (tp *TimeParser) ParseTimeExpression(query string) *TimeFilter {
	query = strings.TrimSpace(query)
	originalQuery := query
	
	for _, pattern := range tp.patterns {
		matches := pattern.regex.FindStringSubmatch(strings.ToLower(query))
		if len(matches) > 0 {
			since, until := pattern.handler(matches)
			
			// Extract remaining query (usually the last capture group)
			remainingQuery := ""
			if len(matches) > 0 {
				remainingQuery = strings.TrimSpace(matches[len(matches)-1])
			}
			
			return &TimeFilter{
				Since:         since,
				Until:         until,
				OriginalQuery: remainingQuery,
				HasTimeFilter: since != nil || until != nil,
			}
		}
	}
	
	// No time expression found
	return &TimeFilter{
		Since:         nil,
		Until:         nil,
		OriginalQuery: originalQuery,
		HasTimeFilter: false,
	}
}

// parseDuration converts number and unit to time.Duration
func (tp *TimeParser) parseDuration(numStr, unit string) time.Duration {
	num, err := strconv.Atoi(numStr)
	if err != nil || num <= 0 {
		return 0
	}
	
	switch unit {
	case "m":
		return time.Duration(num) * time.Minute
	case "h":
		return time.Duration(num) * time.Hour
	case "d":
		return time.Duration(num) * 24 * time.Hour
	case "w":
		return time.Duration(num) * 7 * 24 * time.Hour
	default:
		return 0
	}
}

// FormatTimeFilter returns a human-readable description of the time filter
func (tf *TimeFilter) FormatTimeFilter() string {
	if !tf.HasTimeFilter {
		return ""
	}
	
	now := time.Now()
	
	if tf.Since != nil && tf.Until == nil {
		duration := now.Sub(*tf.Since)
		return formatDuration(duration) + " ago"
	}
	
	if tf.Since == nil && tf.Until != nil {
		duration := now.Sub(*tf.Until)
		return "until " + formatDuration(duration) + " ago"
	}
	
	if tf.Since != nil && tf.Until != nil {
		sinceDuration := now.Sub(*tf.Since)
		untilDuration := now.Sub(*tf.Until)
		return formatDuration(sinceDuration) + " ago to " + formatDuration(untilDuration) + " ago"
	}
	
	return ""
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return "< 1min"
	}
	if d < time.Hour {
		minutes := int(d.Minutes())
		return strconv.Itoa(minutes) + "min"
	}
	if d < 24*time.Hour {
		hours := int(d.Hours())
		return strconv.Itoa(hours) + "h"
	}
	days := int(d.Hours() / 24)
	return strconv.Itoa(days) + "d"
}

// IsValidTimeExpression checks if a query contains a valid time expression
func (tp *TimeParser) IsValidTimeExpression(query string) bool {
	filter := tp.ParseTimeExpression(query)
	return filter.HasTimeFilter
}

// GetSupportedFormats returns a list of supported time expression formats
func (tp *TimeParser) GetSupportedFormats() []string {
	return []string{
		"1h, 2d, 30m, 1w - relative time",
		"since 1h, last 2d - explicit language",
		"today, yesterday - natural language",
		"this week, last week - week references",
		"1h-30m, 2d-1d - time ranges",
	}
}