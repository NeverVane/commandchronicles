package history

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/NeverVane/commandchronicles/internal/storage"
	secureStorage "github.com/NeverVane/commandchronicles/pkg/storage"
)

// ExportFormat represents the export format type
type ExportFormat string

const (
	FormatJSON    ExportFormat = "json"
	FormatBash    ExportFormat = "bash"
	FormatZsh     ExportFormat = "zsh"
	FormatCSV     ExportFormat = "csv"
	FormatPlain   ExportFormat = "plain"
)

// ExportResult contains the result of an export operation
type ExportResult struct {
	ExportedRecords int
	OutputFile      string
	Format          ExportFormat
	BytesWritten    int64
	ExportedAt      time.Time
}

// JSONExportRecord represents a command record in JSON export format
type JSONExportRecord struct {
	Command    string            `json:"command"`
	ExitCode   int               `json:"exit_code"`
	Duration   int64             `json:"duration_ms"`
	WorkingDir string            `json:"working_dir"`
	Timestamp  time.Time         `json:"timestamp"`
	SessionID  string            `json:"session_id"`
	Hostname   string            `json:"hostname"`
	User       string            `json:"user"`
	Shell      string            `json:"shell"`
	GitRoot    string            `json:"git_root,omitempty"`
	GitBranch  string            `json:"git_branch,omitempty"`
	GitCommit  string            `json:"git_commit,omitempty"`
	TTY        string            `json:"tty,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
}

// ExportHistory exports command history to the specified format
func ExportHistory(store *secureStorage.SecureStorage, format ExportFormat, outputPath string, opts *ExportOptions) (*ExportResult, error) {
	if opts == nil {
		opts = &ExportOptions{}
	}

	// Retrieve records from storage
	queryOpts := &secureStorage.QueryOptions{
		SessionID: opts.SessionID,
	}

	if opts.Since != nil {
		queryOpts.Since = opts.Since
	}
	if opts.Until != nil {
		queryOpts.Until = opts.Until
	}

	retrieveResult, err := store.Retrieve(queryOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve records: %w", err)
	}

	// Create output file or use stdout
	var writer io.Writer
	var file *os.File
	
	if outputPath == "" || outputPath == "-" {
		writer = os.Stdout
		outputPath = "stdout"
	} else {
		// Ensure output directory exists
		if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
			return nil, fmt.Errorf("failed to create output directory: %w", err)
		}

		file, err = os.Create(outputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %w", err)
		}
		defer file.Close()
		writer = file
	}

	var bytesWritten int64
	exportedAt := time.Now()

	switch format {
	case FormatJSON:
		bytesWritten, err = exportToJSON(writer, retrieveResult.Records)
	case FormatBash:
		bytesWritten, err = exportToBash(writer, retrieveResult.Records)
	case FormatZsh:
		bytesWritten, err = exportToZsh(writer, retrieveResult.Records)
	case FormatCSV:
		bytesWritten, err = exportToCSV(writer, retrieveResult.Records)
	case FormatPlain:
		bytesWritten, err = exportToPlain(writer, retrieveResult.Records)
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to export to %s format: %w", format, err)
	}

	result := &ExportResult{
		ExportedRecords: len(retrieveResult.Records),
		OutputFile:      outputPath,
		Format:          format,
		BytesWritten:    bytesWritten,
		ExportedAt:      exportedAt,
	}

	return result, nil
}

// exportToJSON exports records to JSON format
func exportToJSON(writer io.Writer, records []*storage.CommandRecord) (int64, error) {
	var jsonRecords []JSONExportRecord

	for _, record := range records {
		jsonRecord := JSONExportRecord{
			Command:     record.Command,
			ExitCode:    record.ExitCode,
			Duration:    record.Duration,
			WorkingDir:  record.WorkingDir,
			Timestamp:   time.UnixMilli(record.Timestamp),
			SessionID:   record.SessionID,
			Hostname:    record.Hostname,
			User:        record.User,
			Shell:       record.Shell,
			GitRoot:     record.GitRoot,
			GitBranch:   record.GitBranch,
			GitCommit:   record.GitCommit,
			TTY:         record.TTY,
			Environment: record.Environment,
		}
		jsonRecords = append(jsonRecords, jsonRecord)
	}

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	
	if err := encoder.Encode(jsonRecords); err != nil {
		return 0, err
	}

	// Estimate bytes written (JSON encoding doesn't return this directly)
	data, _ := json.MarshalIndent(jsonRecords, "", "  ")
	return int64(len(data)), nil
}

// exportToBash exports records to bash history format
func exportToBash(writer io.Writer, records []*storage.CommandRecord) (int64, error) {
	bufWriter := bufio.NewWriter(writer)
	defer bufWriter.Flush()

	var bytesWritten int64

	for _, record := range records {
		// Write timestamp line
		timestamp := time.UnixMilli(record.Timestamp).Unix()
		timestampLine := fmt.Sprintf("#%d\n", timestamp)
		n, err := bufWriter.WriteString(timestampLine)
		if err != nil {
			return bytesWritten, err
		}
		bytesWritten += int64(n)

		// Write command line
		commandLine := record.Command + "\n"
		n, err = bufWriter.WriteString(commandLine)
		if err != nil {
			return bytesWritten, err
		}
		bytesWritten += int64(n)
	}

	return bytesWritten, nil
}

// exportToZsh exports records to zsh history format
func exportToZsh(writer io.Writer, records []*storage.CommandRecord) (int64, error) {
	bufWriter := bufio.NewWriter(writer)
	defer bufWriter.Flush()

	var bytesWritten int64

	for _, record := range records {
		timestamp := time.UnixMilli(record.Timestamp).Unix()
		duration := record.Duration / 1000 // Convert milliseconds to seconds
		
		// Zsh format: : timestamp:duration;command
		line := fmt.Sprintf(": %d:%d;%s\n", timestamp, duration, record.Command)
		n, err := bufWriter.WriteString(line)
		if err != nil {
			return bytesWritten, err
		}
		bytesWritten += int64(n)
	}

	return bytesWritten, nil
}



// exportToCSV exports records to CSV format
func exportToCSV(writer io.Writer, records []*storage.CommandRecord) (int64, error) {
	bufWriter := bufio.NewWriter(writer)
	defer bufWriter.Flush()

	var bytesWritten int64

	// Write CSV header
	header := "timestamp,command,exit_code,duration_ms,working_dir,session_id,hostname,user,shell\n"
	n, err := bufWriter.WriteString(header)
	if err != nil {
		return bytesWritten, err
	}
	bytesWritten += int64(n)

	for _, record := range records {
		timestamp := time.UnixMilli(record.Timestamp).Format(time.RFC3339)
		
		// Escape CSV fields
		command := escapeCSVField(record.Command)
		workingDir := escapeCSVField(record.WorkingDir)
		
		line := fmt.Sprintf("%s,%s,%d,%d,%s,%s,%s,%s,%s\n",
			timestamp,
			command,
			record.ExitCode,
			record.Duration,
			workingDir,
			record.SessionID,
			record.Hostname,
			record.User,
			record.Shell,
		)
		
		n, err := bufWriter.WriteString(line)
		if err != nil {
			return bytesWritten, err
		}
		bytesWritten += int64(n)
	}

	return bytesWritten, nil
}

// exportToPlain exports records to plain text format
func exportToPlain(writer io.Writer, records []*storage.CommandRecord) (int64, error) {
	bufWriter := bufio.NewWriter(writer)
	defer bufWriter.Flush()

	var bytesWritten int64

	for _, record := range records {
		timestamp := time.UnixMilli(record.Timestamp).Format("2006-01-02 15:04:05")
		line := fmt.Sprintf("[%s] %s\n", timestamp, record.Command)
		
		n, err := bufWriter.WriteString(line)
		if err != nil {
			return bytesWritten, err
		}
		bytesWritten += int64(n)
	}

	return bytesWritten, nil
}

// escapeCSVField escapes a field for CSV format
func escapeCSVField(field string) string {
	// If field contains comma, newline, or double quote, wrap in quotes and escape quotes
	if strings.ContainsAny(field, ",\n\r\"") {
		field = strings.ReplaceAll(field, "\"", "\"\"")
		return "\"" + field + "\""
	}
	return field
}

// GetSupportedFormats returns a list of supported export formats
func GetSupportedFormats() []ExportFormat {
	return []ExportFormat{
		FormatJSON,
		FormatBash,
		FormatZsh,
		FormatCSV,
		FormatPlain,
	}
}

// ValidateExportFormat checks if the given format is supported
func ValidateExportFormat(format string) (ExportFormat, error) {
	f := ExportFormat(strings.ToLower(format))
	
	for _, supported := range GetSupportedFormats() {
		if f == supported {
			return f, nil
		}
	}
	
	return "", fmt.Errorf("unsupported export format: %s. Supported formats: %v", format, GetSupportedFormats())
}

// GenerateDefaultOutputPath generates a default output file path based on format and timestamp
func GenerateDefaultOutputPath(format ExportFormat, outputDir string) string {
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("commandchronicles_export_%s.%s", timestamp, string(format))
	
	if outputDir == "" {
		outputDir = "."
	}
	
	return filepath.Join(outputDir, filename)
}