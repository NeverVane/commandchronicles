package output

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/NeverVane/commandchronicles-cli/internal/config"
)

// ColorFormatter handles colored output based on configuration
type ColorFormatter struct {
	config  *config.OutputConfig
	enabled bool
	noColor bool
	isTTY   bool
	colors  map[string]string
}

// StatusType represents different types of CLI output status
type StatusType string

const (
	StatusSuccess StatusType = "success"
	StatusError   StatusType = "error"
	StatusWarning StatusType = "warning"
	StatusInfo    StatusType = "info"
	StatusTip     StatusType = "tip"
	StatusAuth    StatusType = "auth"
	StatusSetup   StatusType = "setup"
	StatusSync    StatusType = "sync"
	StatusStats   StatusType = "stats"
	StatusDone    StatusType = "done"
)

// ANSI color codes
const (
	Reset = "\033[0m"
	Bold  = "\033[1m"
)

// NewColorFormatter creates a new color formatter with the given configuration
func NewColorFormatter(cfg *config.OutputConfig) *ColorFormatter {
	formatter := &ColorFormatter{
		config: cfg,
		isTTY:  isTerminal(),
		colors: make(map[string]string),
	}

	// Determine if colors should be enabled
	formatter.enabled = cfg.ColorsEnabled && (!cfg.AutoDetectTTY || formatter.isTTY)

	// Check for NO_COLOR environment variable (follows standard)
	if os.Getenv("NO_COLOR") != "" {
		formatter.enabled = false
	}

	formatter.loadColorScheme()
	return formatter
}

// SetNoColor disables color output (for --no-color flag)
func (cf *ColorFormatter) SetNoColor(noColor bool) {
	cf.noColor = noColor
	cf.enabled = cf.config.ColorsEnabled && !noColor && (!cf.config.AutoDetectTTY || cf.isTTY)
}

// loadColorScheme loads the appropriate color scheme
func (cf *ColorFormatter) loadColorScheme() {
	switch cf.config.ColorScheme {
	case "modern":
		cf.colors = getModernColors()
	case "conservative":
		cf.colors = getConservativeColors()
	case "custom":
		cf.colors = getCustomColors(cf.config.Colors)
	default:
		cf.colors = getModernColors()
	}
}

// Status indicator functions with colored ASCII replacements
func (cf *ColorFormatter) Success(message string) string {
	return cf.formatStatus("[OK]", message, StatusSuccess)
}

func (cf *ColorFormatter) Error(message string) string {
	return cf.formatStatus("[FAIL]", message, StatusError)
}

func (cf *ColorFormatter) Warning(message string) string {
	return cf.formatStatus("[WARN]", message, StatusWarning)
}

func (cf *ColorFormatter) Info(message string) string {
	return cf.formatStatus("[INFO]", message, StatusInfo)
}

func (cf *ColorFormatter) Tip(message string) string {
	return cf.formatStatus("[TIP]", message, StatusTip)
}

func (cf *ColorFormatter) Auth(message string) string {
	return cf.formatStatus("[AUTH]", message, StatusAuth)
}

func (cf *ColorFormatter) Setup(message string) string {
	return cf.formatStatus("[SETUP]", message, StatusSetup)
}

func (cf *ColorFormatter) Sync(message string) string {
	return cf.formatStatus("[SYNC]", message, StatusSync)
}

func (cf *ColorFormatter) Stats(message string) string {
	return cf.formatStatus("[STATS]", message, StatusStats)
}

func (cf *ColorFormatter) Done(message string) string {
	return cf.formatStatus("[DONE]", message, StatusDone)
}

// formatStatus formats a status message with colored indicator
func (cf *ColorFormatter) formatStatus(indicator, message string, statusType StatusType) string {
	if !cf.enabled {
		return indicator + " " + message
	}

	colorCode := cf.colors[string(statusType)]
	if colorCode == "" {
		return indicator + " " + message
	}

	return colorCode + indicator + Reset + " " + message
}

// Colorize applies color to text based on status type
func (cf *ColorFormatter) Colorize(text string, statusType StatusType) string {
	if !cf.enabled {
		return text
	}

	colorCode := cf.colors[string(statusType)]
	if colorCode == "" {
		return text
	}

	return colorCode + text + Reset
}

// Bold makes text bold (if colors are enabled)
func (cf *ColorFormatter) Bold(text string) string {
	if !cf.enabled {
		return text
	}
	return Bold + text + Reset
}

// Header creates a styled header
func (cf *ColorFormatter) Header(text string) string {
	if !cf.enabled {
		return text
	}
	return cf.Bold(text)
}

// Modern color scheme (bright colors)
func getModernColors() map[string]string {
	return map[string]string{
		"success": hexToAnsi("#00FF00"), // Bright Green
		"error":   hexToAnsi("#FF0000"), // Bright Red
		"warning": hexToAnsi("#FF8800"), // Orange
		"info":    hexToAnsi("#0088FF"), // Bright Blue
		"tip":     hexToAnsi("#00FFFF"), // Bright Cyan
		"auth":    hexToAnsi("#0088FF"), // Bright Blue
		"setup":   hexToAnsi("#FF00FF"), // Bright Magenta
		"sync":    hexToAnsi("#0088FF"), // Bright Blue
		"stats":   hexToAnsi("#00FFFF"), // Bright Cyan
		"done":    hexToAnsi("#00FF00"), // Bright Green
	}
}

// Conservative color scheme (subtle colors)
func getConservativeColors() map[string]string {
	return map[string]string{
		"success": "\033[32m", // Green
		"error":   "\033[31m", // Red
		"warning": "\033[33m", // Yellow
		"info":    "\033[34m", // Blue
		"tip":     "\033[36m", // Cyan
		"auth":    "\033[34m", // Blue
		"setup":   "\033[35m", // Magenta
		"sync":    "\033[34m", // Blue
		"stats":   "\033[36m", // Cyan
		"done":    "\033[32m", // Green
	}
}

// Custom color scheme from config
func getCustomColors(colors config.ColorConfig) map[string]string {
	return map[string]string{
		"success": hexToAnsi(colors.Success),
		"error":   hexToAnsi(colors.Error),
		"warning": hexToAnsi(colors.Warning),
		"info":    hexToAnsi(colors.Info),
		"tip":     hexToAnsi(colors.Tip),
		"auth":    hexToAnsi(colors.Auth),
		"setup":   hexToAnsi(colors.Setup),
		"sync":    hexToAnsi(colors.Sync),
		"stats":   hexToAnsi(colors.Stats),
		"done":    hexToAnsi(colors.Done),
	}
}

// hexToAnsi converts hex color to ANSI escape sequence
func hexToAnsi(hex string) string {
	if hex == "" {
		return ""
	}

	// Remove # if present
	hex = strings.TrimPrefix(hex, "#")

	// Handle short hex format (e.g., "fff" -> "ffffff")
	if len(hex) == 3 {
		hex = string(hex[0]) + string(hex[0]) + string(hex[1]) + string(hex[1]) + string(hex[2]) + string(hex[2])
	}

	if len(hex) != 6 {
		return "" // Invalid hex color
	}

	// Parse RGB components
	r, err1 := strconv.ParseInt(hex[0:2], 16, 64)
	g, err2 := strconv.ParseInt(hex[2:4], 16, 64)
	b, err3 := strconv.ParseInt(hex[4:6], 16, 64)

	if err1 != nil || err2 != nil || err3 != nil {
		return "" // Invalid hex color
	}

	// Convert to ANSI 24-bit color escape sequence
	return fmt.Sprintf("\033[38;2;%d;%d;%dm", r, g, b)
}

// isTerminal checks if stdout is a terminal
func isTerminal() bool {
	fileInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

// IsEnabled returns whether colors are currently enabled
func (cf *ColorFormatter) IsEnabled() bool {
	return cf.enabled
}

// GetVerbosity returns the current verbosity level
func (cf *ColorFormatter) GetVerbosity() string {
	return cf.config.Verbosity
}

// ShouldShowVerbose returns true if verbose output should be shown
func (cf *ColorFormatter) ShouldShowVerbose() bool {
	return cf.config.Verbosity == "verbose" || cf.config.Verbosity == "normal"
}

// ShouldShowMinimal returns true if only minimal output should be shown
func (cf *ColorFormatter) ShouldShowMinimal() bool {
	return cf.config.Verbosity == "minimal"
}

// FormatProgress creates a simple progress indicator
func (cf *ColorFormatter) FormatProgress(current, total int, message string) string {
	percent := float64(current) / float64(total) * 100
	if cf.enabled {
		return fmt.Sprintf("%s [%d/%d] (%.1f%%) %s",
			cf.Colorize(">>", StatusInfo), current, total, percent, message)
	}
	return fmt.Sprintf(">> [%d/%d] (%.1f%%) %s", current, total, percent, message)
}

// Section creates a section header with separator
func (cf *ColorFormatter) Section(title string) string {
	if cf.enabled {
		return cf.Bold(title) + "\n" + strings.Repeat("=", len(title))
	}
	return title + "\n" + strings.Repeat("=", len(title))
}
