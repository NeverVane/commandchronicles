package sync

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

// PasswordChangeUI handles user interactions for password change recovery
type PasswordChangeUI struct {
	reader *bufio.Reader
}

// NewPasswordChangeUI creates a new password change UI handler
func NewPasswordChangeUI() *PasswordChangeUI {
	return &PasswordChangeUI{
		reader: bufio.NewReader(os.Stdin),
	}
}

// PromptForPasswordChangeConfirmation asks user if they want to proceed with password change recovery
func (ui *PasswordChangeUI) PromptForPasswordChangeConfirmation() (bool, error) {
	fmt.Printf(`
[INFO] Password change detected on another device

Your CommandChronicles password was changed on another device.
This device needs to be updated to continue syncing.

[OK] All your local commands will be preserved
[AUTH] Local data will be re-encrypted with your new password
[SYNC] Commands will be synced with the server

Would you like to update this device now? [Y/n]: `)

	response, err := ui.reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("failed to read user response: %w", err)
	}

	response = strings.ToLower(strings.TrimSpace(response))
	return response != "n" && response != "no", nil
}

// PromptForNewPassword securely prompts the user for their new password
func (ui *PasswordChangeUI) PromptForNewPassword() (string, error) {
	fmt.Printf("\nPlease enter your new CommandChronicles password: ")

	password, err := ui.securePasswordInput()
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	if len(password) < 8 {
		return "", fmt.Errorf("password must be at least 8 characters")
	}

	if len(password) > 128 {
		return "", fmt.Errorf("password too long (max 128 characters)")
	}

	return password, nil
}

// PromptForEmail prompts the user for their email address
func (ui *PasswordChangeUI) PromptForEmail() (string, error) {
	fmt.Printf("Please enter your email address: ")

	email, err := ui.reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read email: %w", err)
	}

	email = strings.TrimSpace(email)
	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return "", fmt.Errorf("invalid email format")
	}

	return email, nil
}

// securePasswordInput reads password input without echoing to terminal
func (ui *PasswordChangeUI) securePasswordInput() (string, error) {
	// Get file descriptor for stdin
	fd := int(syscall.Stdin)

	// Check if we're running in a terminal
	if !term.IsTerminal(fd) {
		// If not in terminal (e.g., testing), fall back to regular input
		password, err := ui.reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(password), nil
	}

	// Read password without echo
	passwordBytes, err := term.ReadPassword(fd)
	if err != nil {
		return "", fmt.Errorf("failed to read password securely: %w", err)
	}

	fmt.Println() // Add newline after password input
	return string(passwordBytes), nil
}

// ShowRecoveryProgress displays progress indicators during recovery
func (ui *PasswordChangeUI) ShowRecoveryProgress(step string, message string) {
	timestamp := time.Now().Format("15:04:05")

	var emoji string
	switch step {
	case "auth":
		emoji = "[AUTH]"
	case "reencrypt":
		emoji = "[SYNC]"
	case "update":
		emoji = "[SETUP]"
	case "sync":
		emoji = "[SYNC]"
	case "success":
		emoji = "[OK]"
	case "error":
		emoji = "[FAIL]"
	default:
		emoji = "[INFO]"
	}

	fmt.Printf("[%s] %s %s\n", timestamp, emoji, message)
}

// ShowError displays an error message with formatting
func (ui *PasswordChangeUI) ShowError(err error) {
	fmt.Printf("\n[FAIL] Error: %s\n\n", err.Error())
}

// ShowSuccess displays a success message
func (ui *PasswordChangeUI) ShowSuccess(message string) {
	fmt.Printf("\n[OK] %s\n\n", message)
}

// ShowWarning displays a warning message
func (ui *PasswordChangeUI) ShowWarning(message string) {
	fmt.Printf("\n[WARN] Warning: %s\n\n", message)
}

// PromptRetry asks if user wants to retry after an error
func (ui *PasswordChangeUI) PromptRetry(err error, operation string) (bool, error) {
	ui.ShowError(err)

	fmt.Printf("Would you like to retry %s? [Y/n]: ", operation)

	response, err := ui.reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("failed to read retry response: %w", err)
	}

	response = strings.ToLower(strings.TrimSpace(response))
	return response != "n" && response != "no", nil
}

// ShowRecoverySteps shows what will happen during recovery
func (ui *PasswordChangeUI) ShowRecoverySteps() {
	fmt.Printf(`
Password Change Recovery Process:

1. [AUTH] Authenticate with server using new password
2. [SYNC] Re-encrypt local data with new password
3. [SETUP] Update local authentication state
4. [SYNC] Sync with server to merge any differences
5. [OK] Recovery complete

This process preserves all your local commands.
`)
}

// ConfirmDataPreservation explains data preservation to user
func (ui *PasswordChangeUI) ConfirmDataPreservation() (bool, error) {
	fmt.Printf(`
[INFO] Data Preservation Notice:

• All your local commands will be preserved during this process
• Local data will be re-encrypted with your new password
• Any commands added since the password change will be synced to server
• No command history will be lost

Do you want to continue? [Y/n]: `)

	response, err := ui.reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("failed to read confirmation: %w", err)
	}

	response = strings.ToLower(strings.TrimSpace(response))
	return response != "n" && response != "no", nil
}

// ShowRecoveryComplete displays completion message with summary
func (ui *PasswordChangeUI) ShowRecoveryComplete(stats RecoveryStats) {
	fmt.Printf(`
[OK] Password Change Recovery Complete!

Summary:
• Local commands preserved: %d
• Commands re-encrypted: %d
• Commands synced: %d
• Recovery time: %s

Your device is now up to date and ready to sync.

`, stats.CommandsPreserved, stats.CommandsReencrypted, stats.CommandsSynced, stats.Duration.String())
}

// RecoveryStats contains statistics about the recovery operation
type RecoveryStats struct {
	CommandsPreserved   int
	CommandsReencrypted int
	CommandsSynced      int
	Duration            time.Duration
	StartTime           time.Time
	EndTime             time.Time
}

// NewRecoveryStats creates a new recovery stats tracker
func NewRecoveryStats() *RecoveryStats {
	return &RecoveryStats{
		StartTime: time.Now(),
	}
}

// Complete marks the recovery as completed and calculates duration
func (rs *RecoveryStats) Complete() {
	rs.EndTime = time.Now()
	rs.Duration = rs.EndTime.Sub(rs.StartTime)
}

// ProgressBar represents a simple text-based progress bar
type ProgressBar struct {
	total   int
	current int
	width   int
	label   string
}

// NewProgressBar creates a new progress bar
func NewProgressBar(total int, label string) *ProgressBar {
	width := 40
	if isWindows() {
		width = 20 // Shorter on Windows for better compatibility
	}

	return &ProgressBar{
		total: total,
		width: width,
		label: label,
	}
}

// Update updates the progress bar
func (pb *ProgressBar) Update(current int) {
	pb.current = current
	pb.render()
}

// Finish completes the progress bar
func (pb *ProgressBar) Finish() {
	pb.current = pb.total
	pb.render()
	fmt.Println()
}

// render draws the progress bar
func (pb *ProgressBar) render() {
	percent := float64(pb.current) / float64(pb.total)
	filled := int(percent * float64(pb.width))

	bar := strings.Repeat("█", filled) + strings.Repeat("░", pb.width-filled)

	fmt.Printf("\r%s [%s] %d/%d (%.1f%%)",
		pb.label, bar, pb.current, pb.total, percent*100)
}

// isWindows checks if running on Windows
func isWindows() bool {
	return runtime.GOOS == "windows"
}

// ClearLine clears the current line in terminal
func (ui *PasswordChangeUI) ClearLine() {
	if !isWindows() {
		fmt.Print("\r\033[K")
	} else {
		fmt.Print("\r" + strings.Repeat(" ", 80) + "\r")
	}
}

// ShowThinkingIndicator shows a simple thinking animation
func (ui *PasswordChangeUI) ShowThinkingIndicator(message string, done <-chan bool) {
	chars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	if isWindows() {
		chars = []string{"|", "/", "-", "\\"}
	}

	i := 0
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			ui.ClearLine()
			return
		case <-ticker.C:
			fmt.Printf("\r%s %s", chars[i%len(chars)], message)
			i++
		}
	}
}
