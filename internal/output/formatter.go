package output

import (
	"fmt"
	"os"

	"github.com/NeverVane/commandchronicles-cli/internal/config"
)

// Formatter provides a high-level interface for CLI output formatting
type Formatter struct {
	colorFormatter *ColorFormatter
	verboseMode    bool
	quietMode      bool
}

// NewFormatter creates a new formatter instance from config
func NewFormatter(cfg *config.Config) *Formatter {
	return &Formatter{
		colorFormatter: NewColorFormatter(&cfg.Output),
		verboseMode:    false,
		quietMode:      false,
	}
}

// SetFlags configures the formatter based on command line flags
func (f *Formatter) SetFlags(verbose, quiet, noColor bool) {
	f.verboseMode = verbose
	f.quietMode = quiet
	f.colorFormatter.SetNoColor(noColor)
}

// Print functions that respect verbosity levels

// Success prints a success message (always shown unless quiet)
func (f *Formatter) Success(format string, args ...interface{}) {
	if !f.quietMode {
		message := fmt.Sprintf(format, args...)
		fmt.Println(f.colorFormatter.Success(message))
	}
}

// Error prints an error message (always shown)
func (f *Formatter) Error(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, f.colorFormatter.Error(message))
}

// Warning prints a warning message (always shown unless quiet)
func (f *Formatter) Warning(format string, args ...interface{}) {
	if !f.quietMode {
		message := fmt.Sprintf(format, args...)
		fmt.Println(f.colorFormatter.Warning(message))
	}
}

// Info prints an info message (shown in normal and verbose modes)
func (f *Formatter) Info(format string, args ...interface{}) {
	if !f.quietMode && (f.verboseMode || f.colorFormatter.ShouldShowVerbose()) {
		message := fmt.Sprintf(format, args...)
		fmt.Println(f.colorFormatter.Info(message))
	}
}

// Verbose prints a verbose message (only shown in verbose mode)
func (f *Formatter) Verbose(format string, args ...interface{}) {
	if f.verboseMode || f.colorFormatter.GetVerbosity() == "verbose" {
		message := fmt.Sprintf(format, args...)
		fmt.Println(f.colorFormatter.Info(message))
	}
}

// Tip prints a tip message (shown unless quiet)
func (f *Formatter) Tip(format string, args ...interface{}) {
	if !f.quietMode {
		message := fmt.Sprintf(format, args...)
		fmt.Println(f.colorFormatter.Tip(message))
	}
}

// Status-specific print functions

// Auth prints an authentication-related message
func (f *Formatter) Auth(format string, args ...interface{}) {
	if !f.quietMode {
		message := fmt.Sprintf(format, args...)
		fmt.Println(f.colorFormatter.Auth(message))
	}
}

// Setup prints a setup/configuration message
func (f *Formatter) Setup(format string, args ...interface{}) {
	if !f.quietMode {
		message := fmt.Sprintf(format, args...)
		fmt.Println(f.colorFormatter.Setup(message))
	}
}

// Sync prints a sync-related message
func (f *Formatter) Sync(format string, args ...interface{}) {
	if !f.quietMode {
		message := fmt.Sprintf(format, args...)
		fmt.Println(f.colorFormatter.Sync(message))
	}
}

// Stats prints a statistics message
func (f *Formatter) Stats(format string, args ...interface{}) {
	if !f.quietMode {
		message := fmt.Sprintf(format, args...)
		fmt.Println(f.colorFormatter.Stats(message))
	}
}

// Done prints a completion message
func (f *Formatter) Done(format string, args ...interface{}) {
	if !f.quietMode {
		message := fmt.Sprintf(format, args...)
		fmt.Println(f.colorFormatter.Done(message))
	}
}

// Utility functions

// Print prints a plain message without status indicators
func (f *Formatter) Print(format string, args ...interface{}) {
	if !f.quietMode {
		fmt.Printf(format, args...)
	}
}

// Println prints a plain message with newline
func (f *Formatter) Println(format string, args ...interface{}) {
	if !f.quietMode {
		fmt.Printf(format+"\n", args...)
	}
}

// Header prints a formatted section header
func (f *Formatter) Header(title string) {
	if !f.quietMode {
		fmt.Println(f.colorFormatter.Section(title))
		fmt.Println()
	}
}

// Progress prints a progress indicator
func (f *Formatter) Progress(current, total int, message string) {
	if !f.quietMode && (f.verboseMode || f.colorFormatter.ShouldShowVerbose()) {
		fmt.Print("\r" + f.colorFormatter.FormatProgress(current, total, message))
		if current == total {
			fmt.Println() // New line when complete
		}
	}
}

// Separator prints a visual separator
func (f *Formatter) Separator() {
	if !f.quietMode {
		fmt.Println()
	}
}

// Bold formats text as bold
func (f *Formatter) Bold(text string) string {
	return f.colorFormatter.Bold(text)
}

// Colorize applies color to text
func (f *Formatter) Colorize(text string, statusType StatusType) string {
	return f.colorFormatter.Colorize(text, statusType)
}

// IsColorsEnabled returns whether colors are enabled
func (f *Formatter) IsColorsEnabled() bool {
	return f.colorFormatter.IsEnabled()
}

// IsVerbose returns whether verbose mode is active
func (f *Formatter) IsVerbose() bool {
	return f.verboseMode || f.colorFormatter.GetVerbosity() == "verbose"
}

// IsQuiet returns whether quiet mode is active
func (f *Formatter) IsQuiet() bool {
	return f.quietMode
}

// Conditional output helpers

// IfVerbose executes a function only if in verbose mode
func (f *Formatter) IfVerbose(fn func()) {
	if f.IsVerbose() {
		fn()
	}
}

// IfNotQuiet executes a function only if not in quiet mode
func (f *Formatter) IfNotQuiet(fn func()) {
	if !f.quietMode {
		fn()
	}
}

// Quick status indicator functions (just the indicators, no text)

// SuccessIcon returns just the success indicator
func (f *Formatter) SuccessIcon() string {
	return f.colorFormatter.formatStatus("[OK]", "", StatusSuccess)[:len(f.colorFormatter.formatStatus("[OK]", "", StatusSuccess))-1]
}

// ErrorIcon returns just the error indicator
func (f *Formatter) ErrorIcon() string {
	return f.colorFormatter.formatStatus("[FAIL]", "", StatusError)[:len(f.colorFormatter.formatStatus("[FAIL]", "", StatusError))-1]
}

// WarningIcon returns just the warning indicator
func (f *Formatter) WarningIcon() string {
	return f.colorFormatter.formatStatus("[WARN]", "", StatusWarning)[:len(f.colorFormatter.formatStatus("[WARN]", "", StatusWarning))-1]
}

// Simple inline status for command results
func (f *Formatter) InlineSuccess() string {
	if f.colorFormatter.IsEnabled() {
		return f.colorFormatter.Colorize("[OK]", StatusSuccess)
	}
	return "[OK]"
}

func (f *Formatter) InlineFail() string {
	if f.colorFormatter.IsEnabled() {
		return f.colorFormatter.Colorize("[FAIL]", StatusError)
	}
	return "[FAIL]"
}
