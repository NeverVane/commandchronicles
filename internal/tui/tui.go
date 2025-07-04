package tui

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"

	"github.com/NeverVane/commandchronicles/internal/auth"
	"github.com/NeverVane/commandchronicles/internal/cache"
	"github.com/NeverVane/commandchronicles/internal/config"
	"github.com/NeverVane/commandchronicles/internal/deletion"
	"github.com/NeverVane/commandchronicles/internal/logger"
	"github.com/NeverVane/commandchronicles/internal/search"
	"github.com/NeverVane/commandchronicles/internal/sentry"
	"github.com/NeverVane/commandchronicles/internal/stats"
	"github.com/NeverVane/commandchronicles/internal/storage"
	securestorage "github.com/NeverVane/commandchronicles/pkg/storage"
)

// TUIOptions configures the TUI behavior
type TUIOptions struct {
	InitialQuery string
	FuzzyEnabled bool
	MaxResults   int
}

// TUI modes for different interaction states
type TUIMode int

const (
	ModeSearch TUIMode = iota
	ModeHelp
	ModeDetails
	ModeStats
	ModeDeleteConfirm
	ModeWipeConfirm
	ModeNoteEdit
)

// TUISession represents an active TUI session with all required services
type TUISession struct {
	authManager     *auth.AuthManager
	storage         *securestorage.SecureStorage
	cache           *cache.Cache
	searchService   *search.SearchService
	deletionService *deletion.DeletionService
	sessionKey      []byte
	logger          *logger.Logger
	config          *config.Config
}

// CommandItem represents a command record for the list component
type CommandItem struct {
	record *storage.CommandRecord
}

func (i CommandItem) FilterValue() string {
	return i.record.Command
}

func (i CommandItem) Title() string {
	// Add panic recovery with Sentry capture
	defer func() {
		if r := recover(); r != nil {
			if sentry.IsEnabled() {
				sentry.CaptureError(fmt.Errorf("panic in CommandItem.Title: %v", r), "tui", "title_render", map[string]string{
					"command":     i.record.Command,
					"working_dir": "[REDACTED]",
					"exit_code":   fmt.Sprintf("%d", i.record.ExitCode),
				})
				sentry.Flush(2 * time.Second)
			}

			// Re-panic so bubbletea can handle it
			panic(r)
		}
	}()

	cursor := "  "
	status := "✓"
	statusColor := lipgloss.Color("10") // Green

	if i.record.ExitCode != 0 {
		status = "✗"
		statusColor = lipgloss.Color("9") // Red
	}

	statusStyle := lipgloss.NewStyle().Foreground(statusColor).Bold(true)
	commandStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("15"))
	dirStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	// Get terminal width for responsive layout
	termWidth := 100 // Default fallback
	if fd := int(syscall.Stdout); term.IsTerminal(fd) {
		if w, _, err := term.GetSize(fd); err == nil && w > 0 {
			termWidth = w
		}
	}

	// Calculate available space for context info
	baseText := cursor + status + " " + i.record.Command
	baseWidth := len(baseText)

	// Reserve space for time info in description (approximate)
	timeWidth := 25                                              // "ran 2h ago | took 150ms" plus margins
	availableForContext := termWidth - baseWidth - timeWidth - 5 // 5 for safety margin

	// Build context info with progressive truncation
	var contextParts []string
	var totalContextWidth int

	// Add git branch first (higher priority)
	if i.record.GitBranch != "" {
		gitInfo := fmt.Sprintf("• %s", i.record.GitBranch)
		if totalContextWidth+len(gitInfo)+2 < availableForContext { // 2 for separators
			contextParts = append(contextParts, gitInfo)
			totalContextWidth += len(gitInfo) + 2
		}
	}

	// Add working directory if space allows
	if i.record.WorkingDir != "" && availableForContext > 10 {
		dir := i.record.WorkingDir
		maxDirWidth := availableForContext - totalContextWidth - 6 // 6 for "in " and separators

		if maxDirWidth > 8 { // Only show if we have reasonable space
			if len(dir) > maxDirWidth {
				pathParts := strings.Split(dir, "/")
				if len(pathParts) > 1 {
					// Try just the last directory
					lastDir := pathParts[len(pathParts)-1]
					if len(lastDir)+4 <= maxDirWidth { // 4 for ".../"
						dir = ".../" + lastDir
					} else if len(lastDir) <= maxDirWidth-3 { // 3 for "..."
						startIndex := len(lastDir) - (maxDirWidth - 3)
						if startIndex >= 0 {
							dir = "..." + lastDir[startIndex:]
						} else {
							dir = "..." + lastDir
						}
					} else {
						dir = "..." // Just show ellipsis if even last dir is too long
					}
				} else {
					// Single path component, truncate it
					if maxDirWidth > 4 {
						dir = dir[:maxDirWidth-3] + "..."
					} else {
						dir = "..."
					}
				}
			}
			dirInfo := fmt.Sprintf("in %s", dir)
			contextParts = append(contextParts, dirInfo)
		}
	}

	// Build final command text with execution time on same line
	commandText := i.record.Command
	if len(contextParts) > 0 {
		contextText := strings.Join(contextParts, " ")
		commandText += " " + dirStyle.Render(fmt.Sprintf("(%s)", contextText))
	}

	// Add execution time info to the same line
	timeAgo := formatTimeAgo(i.record.Timestamp)
	duration := formatDuration(i.record.Duration)
	var timeText string
	if timeAgo == "now" {
		timeText = fmt.Sprintf("%s | took %s", timeAgo, duration)
	} else {
		timeText = fmt.Sprintf("%s ago | took %s", timeAgo, duration)
	}

	// Create a layout with command on left and time right-aligned to terminal border
	timeStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	// Get terminal width for proper right alignment
	termWidth = 100 // Default fallback
	if fd := int(syscall.Stdout); term.IsTerminal(fd) {
		if w, _, err := term.GetSize(fd); err == nil && w > 0 {
			termWidth = w - 6 // Account for list margins
		}
	}

	// Add note indicator if command has a note
	noteIndicator := ""
	if i.record.Note != "" {
		noteIndicator = lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Render("● ")
	}

	leftPart := cursor + statusStyle.Render(status) + " " + noteIndicator + commandStyle.Render(commandText)
	rightPart := timeStyle.Render(timeText)

	// Use lipgloss to create proper spacing for right alignment
	return lipgloss.NewStyle().
		Width(termWidth).
		Render(
			lipgloss.JoinHorizontal(
				lipgloss.Left,
				leftPart,
				lipgloss.NewStyle().
					Width(termWidth-lipgloss.Width(leftPart)-lipgloss.Width(rightPart)).
					Render(""),
				rightPart,
			),
		)
}

func (i CommandItem) Description() string {
	// Return empty since we moved all info to the title line
	return ""
}

// keyMap defines key bindings
type keyMap struct {
	Up       key.Binding
	Down     key.Binding
	Left     key.Binding
	Right    key.Binding
	Help     key.Binding
	Quit     key.Binding
	Enter    key.Binding
	Execute  key.Binding
	Tab      key.Binding
	Fuzzy    key.Binding
	Syntax   key.Binding
	Success  key.Binding
	Failure  key.Binding
	Clear    key.Binding
	Refresh  key.Binding
	Stats    key.Binding
	Delete   key.Binding
	Wipe     key.Binding
	NoteEdit key.Binding
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Help, k.Quit}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Enter, k.Execute, k.Tab},
		{k.Fuzzy, k.Syntax, k.Success, k.Failure},
		{k.Clear, k.Refresh, k.Stats, k.Delete, k.Wipe},
		{k.NoteEdit, k.Help, k.Quit},
	}
}

var keys = keyMap{
	Up: key.NewBinding(
		key.WithKeys("up"),
		key.WithHelp("↑", "move up"),
	),
	Down: key.NewBinding(
		key.WithKeys("down"),
		key.WithHelp("↓", "move down"),
	),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "toggle help"),
	),
	Quit: key.NewBinding(
		key.WithKeys("ctrl+c"),
		key.WithHelp("ctrl+c", "quit"),
	),
	Enter: key.NewBinding(
		key.WithKeys("enter", "\r", "\n", "ctrl+m"),
		key.WithHelp("enter", "inject"),
	),
	Execute: key.NewBinding(
		key.WithKeys("ctrl+j", "ctrl+enter"),
		key.WithHelp("ctrl+j", "execute"),
	),
	Tab: key.NewBinding(
		key.WithKeys("tab"),
		key.WithHelp("tab", "details"),
	),
	Fuzzy: key.NewBinding(
		key.WithKeys("ctrl+f"),
		key.WithHelp("ctrl+f", "toggle fuzzy"),
	),
	Syntax: key.NewBinding(
		key.WithKeys("ctrl+h"),
		key.WithHelp("ctrl+h", "toggle syntax"),
	),
	Success: key.NewBinding(
		key.WithKeys("ctrl+s"),
		key.WithHelp("ctrl+s", "success only"),
	),
	Failure: key.NewBinding(
		key.WithKeys("ctrl+x"),
		key.WithHelp("ctrl+x", "failures only"),
	),
	Clear: key.NewBinding(
		key.WithKeys("ctrl+k"),
		key.WithHelp("ctrl+k", "clear"),
	),
	Refresh: key.NewBinding(
		key.WithKeys("ctrl+l"),
		key.WithHelp("ctrl+l", "refresh"),
	),
	Stats: key.NewBinding(
		key.WithKeys("ctrl+t"),
		key.WithHelp("ctrl+t", "stats"),
	),
	Delete: key.NewBinding(
		key.WithKeys("delete", "ctrl+d"),
		key.WithHelp("del/ctrl+d", "delete record"),
	),
	Wipe: key.NewBinding(
		key.WithKeys("ctrl+w"),
		key.WithHelp("ctrl+w", "wipe all"),
	),
	NoteEdit: key.NewBinding(
		key.WithKeys("ctrl+n"),
		key.WithHelp("ctrl+n", "edit note"),
	),
}

// model represents the TUI state using bubbles components
type model struct {
	session *TUISession
	opts    *TUIOptions

	// UI Components
	searchInput textinput.Model
	list        list.Model
	help        help.Model
	noteEditor  textinput.Model

	// State
	mode            TUIMode
	loading         bool
	err             error
	searchStartTime time.Time
	searchDuration  time.Duration
	totalRecords    int
	filteredRecords int

	// Filtering state
	showSuccessOnly  bool
	showFailuresOnly bool
	fuzzyEnabled     bool
	syntaxEnabled    bool
	activeTimeFilter *search.TimeFilter
	timeParser       *search.TimeParser

	// Deletion state
	showDeleteConfirm bool
	deleteTargetID    int64
	deleteTargetCmd   string

	// Wipe confirmation state
	showWipeConfirm bool
	wipeRecordCount int

	// Terminal dimensions
	width  int
	height int

	// Stats mode state
	statsEngine               *stats.StatsEngine
	baseCommands              []list.Item
	extendedCommands          []list.Item
	statsData                 *stats.StatsResult
	baseCommandsList          list.Model
	extendedCommandsList      list.Model
	selectedBaseCommand       string
	heatmapData               [][]int // 7 rows (days) x 53 cols (weeks)
	focusedPane               string  // "base" or "extended"
	selectedExtendedCommand   string
	extendedCommandHighlights map[string][]time.Time // command -> dates when used
	commandTimestamps         map[string][]int64     // baseCommand -> timestamps
	extendedTimestamps        map[string][]int64     // fullCommand -> timestamps

	// Session working set to maintain loaded records
	sessionWorkingSet []*storage.CommandRecord
	maxWorkingSetSize int

	// Note editing state
	noteEditingRecordID int64
	noteEditingRecord   *storage.CommandRecord
	noteEditOriginal    string
	noteEditSuccess     bool
	noteEditError       error

	// Key bindings
	keys keyMap
}

// Launch launches the TUI with proper initialization
func Launch(cfg *config.Config, opts *TUIOptions) error {
	if opts == nil {
		opts = &TUIOptions{
			FuzzyEnabled: true,
			MaxResults:   cfg.Cache.HotCacheSize,
		}
	}

	log := logger.GetLogger().WithComponent("tui")
	log.Info().Msg("Starting modern TUI with bubbles components")

	// Initialize session
	session, err := initializeSession(cfg, log)
	if err != nil {
		return fmt.Errorf("failed to initialize TUI session: %w", err)
	}
	defer session.cleanup()

	// Create and run TUI model
	m := newModel(session, opts)
	program := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseAllMotion())

	log.Info().Msg("Launching modern TUI interface")
	_, err = program.Run()
	if err != nil {
		return fmt.Errorf("TUI execution failed: %w", err)
	}

	return nil
}

// newModel creates a new TUI model with bubbles components
func newModel(session *TUISession, opts *TUIOptions) model {
	// Initialize search input
	ti := textinput.New()
	ti.Placeholder = "Search commands... (or try: 1h, today, since 2d)"
	ti.Focus() // Start with focus to allow immediate typing
	ti.CharLimit = 256
	ti.Prompt = ""
	ti.Width = 50
	ti.SetValue(opts.InitialQuery)

	// Initialize note editor
	noteEditor := textinput.New()
	noteEditor.Placeholder = "Enter your note here... (max 1000 characters)"
	noteEditor.CharLimit = 1000
	noteEditor.Prompt = ""
	noteEditor.Width = 80

	// Initialize list
	items := []list.Item{}
	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = delegate.Styles.SelectedTitle.
		Foreground(lipgloss.Color("12")).
		Bold(true).
		PaddingTop(0).
		PaddingBottom(0).
		MarginTop(0).
		MarginBottom(0)
	delegate.Styles.SelectedDesc = delegate.Styles.SelectedDesc.
		Foreground(lipgloss.Color("8")).
		PaddingTop(0).
		PaddingBottom(0).
		MarginTop(0).
		MarginBottom(0)

	// Make rows more compact
	delegate.SetHeight(2)  // Keep 2 lines but make selection more targeted
	delegate.SetSpacing(0) // Remove spacing between items

	l := list.New(items, delegate, 0, 0)
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.SetShowHelp(false)
	l.SetShowPagination(false)
	l.SetShowTitle(false)

	// Disable conflicting key bindings
	l.KeyMap.CursorUp.SetKeys("up")
	l.KeyMap.CursorDown.SetKeys("down")
	l.KeyMap.NextPage.SetKeys()
	l.KeyMap.PrevPage.SetKeys()
	l.KeyMap.GoToStart.SetKeys()
	l.KeyMap.GoToEnd.SetKeys()
	l.KeyMap.Filter.SetKeys()
	l.KeyMap.ClearFilter.SetKeys()
	// Disable list's default Enter handling so our custom handler works
	l.KeyMap.Quit.SetKeys()
	l.KeyMap.ForceQuit.SetKeys()
	l.KeyMap.ShowFullHelp.SetKeys()
	l.KeyMap.CloseFullHelp.SetKeys()
	l.Styles.Title = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("12")).
		MarginLeft(2)

	// Initialize help
	h := help.New()

	return model{
		session:            session,
		opts:               opts,
		searchInput:        ti,
		list:               l,
		help:               h,
		noteEditor:         noteEditor,
		mode:               ModeSearch,
		fuzzyEnabled:       opts.FuzzyEnabled,
		syntaxEnabled:      true,
		timeParser:         search.NewTimeParser(),
		keys:               keys,
		commandTimestamps:  make(map[string][]int64),
		extendedTimestamps: make(map[string][]int64),
		sessionWorkingSet:  make([]*storage.CommandRecord, 0),
		maxWorkingSetSize:  session.config.Cache.HotCacheSize * 10, // Allow 10x cache size in working set
	}
}

// Init implements tea.Model
func (m model) Init() tea.Cmd {
	return textinput.Blink
}

// Update implements tea.Model
// Update handles all messages and updates the model
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {

	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		// Check if this is the first window size message
		isFirstResize := m.width == 0

		m.width = msg.Width
		m.height = msg.Height

		// Update components with new dimensions
		headerHeight := m.calculateHeaderHeight()
		footerHeight := 3 // Help (more compact)
		listHeight := m.height - headerHeight - footerHeight
		if listHeight < 10 {
			listHeight = 10
		}

		m.list.SetSize(m.width-4, listHeight)
		m.searchInput.Width = m.width - 20

		// Update stats components if in stats mode
		if m.mode == ModeStats {
			statsListHeight := m.height - 22 // Account for heatmap + headers
			if statsListHeight < 10 {
				statsListHeight = 10
			}
			availableWidth := m.width - 20
			if availableWidth < 60 {
				availableWidth = 60
			}
			statsListWidth := availableWidth / 2
			m.baseCommandsList.SetSize(statsListWidth, statsListHeight)
			m.extendedCommandsList.SetSize(statsListWidth, statsListHeight)
		}

		// Perform initial search after first window resize
		if isFirstResize {
			return m, m.performSearch()
		}

		// Always trigger re-render on resize for proper layout updates
		return m, nil

	case tea.KeyMsg:
		// Handle global quit keys first
		if key.Matches(msg, m.keys.Quit) {
			return m, tea.Quit
		}

		// Handle ESC key for navigation back
		if msg.String() == "esc" {
			switch m.mode {
			case ModeHelp, ModeDetails, ModeStats, ModeDeleteConfirm:
				// Go back to search mode
				m.mode = ModeSearch
				m.deleteTargetID = 0
				m.deleteTargetCmd = ""
				return m, nil
			case ModeNoteEdit:
				// Cancel note editing and go back to details
				m.mode = ModeDetails
				m.noteEditingRecordID = 0
				m.noteEditingRecord = nil
				m.noteEditOriginal = ""
				m.noteEditError = nil
				return m, nil
			default:
				// In search mode, ESC quits the application
				return m, tea.Quit
			}
		}

		switch m.mode {
		case ModeHelp:
			return m.handleHelpKeys(msg)
		case ModeDetails:
			return m.handleDetailsKeys(msg)
		case ModeStats:
			return m.handleStatsKeys(msg)
		case ModeDeleteConfirm:
			return m.handleDeleteConfirmKeys(msg)
		case ModeWipeConfirm:
			return m.handleWipeConfirmKeys(msg)
		case ModeNoteEdit:
			return m.handleNoteEditKeys(msg)
		default:
			return m.handleSearchKeys(msg)
		}

	case searchResultMsg:
		m.loading = false
		if msg.searchStartTime != nil {
			m.searchDuration = time.Since(*msg.searchStartTime)
		}

		// Store the time filter state
		m.activeTimeFilter = msg.timeFilter

		if msg.err != nil {
			m.err = msg.err
		} else {
			// Update session working set with new records
			m.updateSessionWorkingSet(msg.results)

			// Convert records to list items
			items := make([]list.Item, len(msg.results))
			for i, record := range msg.results {
				items[i] = CommandItem{record: record}
			}

			// Update list
			m.list.SetItems(items)
			m.filteredRecords = len(msg.results)
			m.totalRecords = int(msg.totalCount)
			m.err = nil

			if len(items) > 0 {
				m.list.Select(0)
			}
		}

	case extendedCommandsMsg:
		return m.handleExtendedCommandsMsg(msg)

	case performSearchMsg:
		return m, m.performSearch()

	case deletionResultMsg:
		// Reset any confirmation modes
		m.mode = ModeSearch
		m.showDeleteConfirm = false
		m.showWipeConfirm = false

		if msg.err != nil {
			m.err = msg.err
		} else {
			m.err = nil
			// Clear session working set to prevent stale data after deletion
			m.clearSessionWorkingSet("record deletion")
			// Refresh search results after deletion
			return m, m.performSearch()
		}
		return m, nil

	case tea.MouseMsg:
		// Handle mouse scroll events
		if msg.Type == tea.MouseWheelUp {
			// Scroll up (previous item)
			if m.list.Index() > 0 {
				m.list.CursorUp()
			}
		} else if msg.Type == tea.MouseWheelDown {
			// Scroll down (next item)
			if m.list.Index() < len(m.list.Items())-1 {
				m.list.CursorDown()
			}
		}
	}

	// Update components
	switch m.mode {
	case ModeSearch:
		// Note: search input and list updates are handled in handleSearchKeys
		break
	}

	return m, tea.Batch(cmds...)
}

// View implements tea.Model
func (m model) View() string {
	if m.width == 0 {
		return "Initializing..."
	}

	switch m.mode {
	case ModeHelp:
		return m.renderHelp()
	case ModeDetails:
		return m.renderDetails()
	case ModeStats:
		return m.renderStats()
	case ModeDeleteConfirm:
		return m.renderDeleteConfirm()
	case ModeWipeConfirm:
		return m.renderWipeConfirm()
	case ModeNoteEdit:
		return m.renderNoteEdit()
	default:
		return m.renderSearch()
	}
}

// renderSearch renders the main search interface
func (m model) renderSearch() string {
	var topSections []string

	// Header with title and counters
	header := m.renderHeader()
	topSections = append(topSections, header)

	// Search input
	searchSection := m.renderSearchInput()
	topSections = append(topSections, searchSection)

	// Status line with counts and timing
	status := m.renderStatus()
	topSections = append(topSections, status)

	// Error display
	if m.err != nil {
		errorMsg := lipgloss.NewStyle().
			Foreground(lipgloss.Color("9")).
			MarginLeft(2).
			Render(fmt.Sprintf("Error: %v", m.err))
		topSections = append(topSections, errorMsg)
	}

	// Loading indicator
	if m.loading {
		loading := lipgloss.NewStyle().
			Foreground(lipgloss.Color("11")).
			MarginLeft(2).
			Render("🔍 Searching...")
		topSections = append(topSections, loading)
	}

	// Create exactly two lines of help text with proper styling
	line1 := "↑/↓: navigate • enter: copy • ctrl+j: execute • tab: details • ctrl+f: fuzzy • ctrl+s: success only"
	line2 := "ctrl+x: failures • ctrl+t: stats • ctrl+k: clear • ctrl+l: refresh • ?: help • ctrl+c/esc: quit"
	helpView := lipgloss.NewStyle().
		Foreground(lipgloss.Color("8")).
		MarginLeft(2).
		Render(line1 + "\n" + line2)

	// Join top sections
	topContent := lipgloss.JoinVertical(lipgloss.Left, topSections...)
	topHeight := lipgloss.Height(topContent)
	helpHeight := lipgloss.Height(helpView)

	// Calculate available height for list - be more conservative to ensure help text fits
	availableHeight := m.height - topHeight - helpHeight - 4 // Extra margin for safety

	// List of commands
	var listContent string
	if !m.loading && m.err == nil {
		if availableHeight > 5 {
			m.list.SetSize(m.width-4, availableHeight)
		}
		listContent = m.list.View()
	} else if !m.loading && len(m.list.Items()) == 0 {
		// Show message when no records found
		listContent = lipgloss.NewStyle().
			Foreground(lipgloss.Color("8")).
			MarginLeft(2).
			Render("No commands found. Try adjusting your search or check if you have any recorded commands.")
	}

	// Calculate spacing to push help to bottom - ensure help text is always visible
	contentHeight := topHeight + lipgloss.Height(listContent)
	remainingHeight := m.height - contentHeight - helpHeight - 3 // Extra margin
	if remainingHeight < 1 {
		remainingHeight = 1 // Always leave at least one line
	}

	spacing := strings.Repeat("\n", remainingHeight)

	// Add left margin to help view to align with other components
	helpWithMargin := lipgloss.NewStyle().
		MarginLeft(2).
		Render(helpView)

	return topContent + "\n\n" + listContent + spacing + helpWithMargin
}

// renderHeader renders the header with title and counters
func (m model) renderHeader() string {
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("12")).
		MarginLeft(2).
		Render("CommandChronicles")

	// Total records counter (top right)
	totalCounter := ""
	if m.totalRecords > 0 {
		totalCounter = lipgloss.NewStyle().
			Foreground(lipgloss.Color("8")).
			Render(fmt.Sprintf("Total: %d records", m.totalRecords))
	}

	// Create header with title left-aligned and counter right-aligned
	headerWidth := m.width
	titleWidth := lipgloss.Width(title)
	counterWidth := lipgloss.Width(totalCounter)
	padding := headerWidth - titleWidth - counterWidth - 2

	if padding < 1 {
		padding = 1
	}

	header := title + strings.Repeat(" ", padding) + totalCounter

	return header
}

// renderSearchInput renders the search input section
func (m model) renderSearchInput() string {
	searchStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("12")).
		Padding(0, 1).
		MarginLeft(2).
		MarginRight(2)

	// Add filter indicators
	var indicators []string
	if m.fuzzyEnabled {
		indicators = append(indicators, lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Render("FUZZY"))
	}
	if m.showSuccessOnly {
		indicators = append(indicators, lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Render("SUCCESS"))
	}
	if m.showFailuresOnly {
		indicators = append(indicators, lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Render("FAILURES"))
	}
	if !m.syntaxEnabled {
		indicators = append(indicators, lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render("NO-SYNTAX"))
	}

	searchContent := m.searchInput.View()
	if len(indicators) > 0 {
		indicatorText := " [" + strings.Join(indicators, " ") + "]"
		searchContent += lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render(indicatorText)
	}

	return searchStyle.Render(searchContent)
}

// renderStatus renders the status line with counts and timing
func (m model) renderStatus() string {
	if m.loading || (m.filteredRecords == 0 && m.searchInput.Value() == "") {
		return ""
	}

	var parts []string

	// Displayed records count
	if m.filteredRecords > 0 {
		listSize := len(m.list.Items())
		if listSize < m.filteredRecords {
			parts = append(parts, fmt.Sprintf("    %d/%d", listSize, m.filteredRecords))
		} else {
			parts = append(parts, fmt.Sprintf("  %d", m.filteredRecords))
		}
	}

	// Search timing
	if m.searchDuration > 0 {
		timing := fmt.Sprintf("Search time: %v", m.searchDuration.Truncate(time.Millisecond))
		parts = append(parts, timing)
	}

	// Active time filter
	if m.activeTimeFilter != nil && m.activeTimeFilter.HasTimeFilter {
		timeFilterDesc := m.activeTimeFilter.FormatTimeFilter()
		if timeFilterDesc != "" {
			parts = append(parts, fmt.Sprintf("Time: %s", timeFilterDesc))
		}
	}

	// Selected item position
	if m.filteredRecords > 0 {
		selectedIdx := m.list.Index()
		parts = append(parts, fmt.Sprintf("Selected: %d/%d", selectedIdx+1, m.filteredRecords))
	}

	if len(parts) == 0 {
		return ""
	}

	statusText := strings.Join(parts, " | ")
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("8")).
		MarginLeft(2).
		Render(statusText)
}

// handleSearchKeys handles key input in search mode
func (m model) handleSearchKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	// If search input has focus, check for Enter key to blur it
	if m.searchInput.Focused() && (msg.String() == "enter" || msg.String() == "\r" || msg.String() == "\n") {
		m.searchInput.Blur()
	}

	// Check for Enter and Execute keys first, before list gets them
	switch {
	case key.Matches(msg, m.keys.Enter):
		if len(m.list.Items()) > 0 {
			if item, ok := m.list.SelectedItem().(CommandItem); ok {
				// Write command to temp file for shell to read
				tmpFile := "/tmp/ccr_selected_command"
				if err := os.WriteFile(tmpFile, []byte(item.record.Command), 0600); err == nil {
					return m, tea.Quit
				}
			}
		}
		return m, nil

	case key.Matches(msg, m.keys.Execute):
		if len(m.list.Items()) > 0 {
			if item, ok := m.list.SelectedItem().(CommandItem); ok {
				// Write command to temp file with execute flag
				tmpFile := "/tmp/ccr_selected_command"
				// Add a newline and "exec" flag to indicate it should be executed
				content := item.record.Command + "\nexec"
				if err := os.WriteFile(tmpFile, []byte(content), 0600); err == nil {
					return m, tea.Quit
				}
			}
		}
		return m, nil

	case key.Matches(msg, m.keys.Quit):
		if m.searchInput.Value() != "" {
			m.searchInput.SetValue("")
			m.resetFilters()
			return m, m.performSearch()
		}
		return m, tea.Quit

	case key.Matches(msg, m.keys.Tab):
		if len(m.list.Items()) > 0 {
			m.mode = ModeDetails
		}

	case key.Matches(msg, m.keys.Help):
		m.mode = ModeHelp

	case key.Matches(msg, m.keys.Fuzzy):
		m.fuzzyEnabled = !m.fuzzyEnabled
		m.session.logger.Info().
			Bool("fuzzy_enabled", m.fuzzyEnabled).
			Str("current_query", m.searchInput.Value()).
			Msg("Toggled fuzzy search - performing new search")
		return m, m.performSearch()

	case key.Matches(msg, m.keys.Syntax):
		m.syntaxEnabled = !m.syntaxEnabled

	case key.Matches(msg, m.keys.Success):
		m.showSuccessOnly = !m.showSuccessOnly
		m.showFailuresOnly = false
		return m, m.performSearch()

	case key.Matches(msg, m.keys.Failure):
		m.showFailuresOnly = !m.showFailuresOnly
		m.showSuccessOnly = false
		return m, m.performSearch()

	case key.Matches(msg, m.keys.Clear):
		m.searchInput.SetValue("")
		m.resetFilters()
		return m, m.performSearch()

	case key.Matches(msg, m.keys.Refresh):
		return m, m.performSearch()

	case key.Matches(msg, m.keys.Stats):
		return m.enterStatsMode()

	case key.Matches(msg, m.keys.Delete):
		// Delete the currently selected record
		if len(m.list.Items()) > 0 {
			if item, ok := m.list.SelectedItem().(CommandItem); ok {
				m.mode = ModeDeleteConfirm
				m.deleteTargetID = item.record.ID
				m.deleteTargetCmd = item.record.Command
				return m, nil
			}
		}

	case key.Matches(msg, m.keys.NoteEdit):
		// Edit note for the currently selected record
		if len(m.list.Items()) > 0 {
			if item, ok := m.list.SelectedItem().(CommandItem); ok {
				return m.enterNoteEditMode(item.record)
			}
		}

	case key.Matches(msg, m.keys.Wipe):
		// Wipe all command history
		return m.handleWipeCommand()

	case key.Matches(msg, m.keys.Up), key.Matches(msg, m.keys.Down):
		// Let the list handle navigation keys
		m.list, cmd = m.list.Update(msg)
		return m, cmd

	case msg.Type == tea.KeyRunes, msg.Type == tea.KeySpace, msg.Type == tea.KeyBackspace:
		// Handle typing keys in search input only if it has focus
		if !m.searchInput.Focused() {
			// Give focus to search input for typing
			m.searchInput.Focus()
		}
		m.searchInput, cmd = m.searchInput.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}

		if msg.Type == tea.KeyBackspace && m.searchInput.Value() == "" {
			cmds = append(cmds, m.performSearch())
		} else if msg.Type != tea.KeyBackspace || m.searchInput.Value() != "" {
			cmds = append(cmds, m.performSearchDelayed())
		}
		return m, tea.Batch(cmds...)
	}

	// Default: pass other keys to list, but explicitly exclude our handled keys
	switch {
	case key.Matches(msg, m.keys.Enter),
		key.Matches(msg, m.keys.Execute),
		key.Matches(msg, m.keys.Quit),
		key.Matches(msg, m.keys.Tab),
		key.Matches(msg, m.keys.Fuzzy),
		key.Matches(msg, m.keys.Syntax),
		key.Matches(msg, m.keys.Success),
		key.Matches(msg, m.keys.Failure),
		key.Matches(msg, m.keys.Clear),
		key.Matches(msg, m.keys.Refresh),
		key.Matches(msg, m.keys.Stats),
		key.Matches(msg, m.keys.NoteEdit):
		// Don't pass these keys to list
	default:
		// Pass unhandled keys to list
		m.list, cmd = m.list.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	}

	return m, tea.Batch(cmds...)
}

// calculateHeaderHeight dynamically calculates header height based on content
func (m model) calculateHeaderHeight() int {
	baseHeight := 7 // Title + search + basic status + spacing

	// Add extra height if we have active filters that might wrap the status line
	extraHeight := 0

	// Check if we have multiple status components that might cause wrapping
	statusComponents := 0

	if m.filteredRecords > 0 {
		statusComponents++ // Record count
	}
	if m.searchDuration > 0 {
		statusComponents++ // Search timing
	}
	if m.activeTimeFilter != nil && m.activeTimeFilter.HasTimeFilter {
		statusComponents++ // Time filter description
	}
	if m.filteredRecords > 0 {
		statusComponents++ // Selected item position
	}
	if m.showSuccessOnly || m.showFailuresOnly {
		statusComponents++ // Filter indicators in search input
	}

	// If we have many status components or narrow width, add extra height
	if statusComponents > 3 || m.width < 100 {
		extraHeight = 1
	}

	return baseHeight + extraHeight
}

// handleHelpKeys handles key input in help mode
func (m model) handleHelpKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Help), key.Matches(msg, m.keys.Quit):
		m.mode = ModeSearch
	}
	return m, nil
}

// handleDetailsKeys handles key input in details mode
func (m model) handleDetailsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Tab), key.Matches(msg, m.keys.Quit):
		m.mode = ModeSearch
	case key.Matches(msg, m.keys.Enter):
		if len(m.list.Items()) > 0 {
			if item, ok := m.list.SelectedItem().(CommandItem); ok {
				fmt.Print(item.record.Command)
				return m, tea.Quit
			}
		}
	case key.Matches(msg, m.keys.Execute):
		if len(m.list.Items()) > 0 {
			if item, ok := m.list.SelectedItem().(CommandItem); ok {
				// Direct execution using exec.Command
				return m, tea.Sequence(
					tea.Quit,
					tea.ExecProcess(exec.Command("sh", "-c", item.record.Command), func(err error) tea.Msg {
						if err != nil {
							fmt.Fprintf(os.Stderr, "Error executing command: %v\n", err)
						}
						return nil
					}),
				)
			}
		}
	case key.Matches(msg, m.keys.NoteEdit):
		// Start note editing mode
		if len(m.list.Items()) > 0 {
			if item, ok := m.list.SelectedItem().(CommandItem); ok {
				return m.enterNoteEditMode(item.record)
			}
		}
	}
	return m, nil
}

// enterNoteEditMode initializes note editing mode for a specific command
func (m model) enterNoteEditMode(record *storage.CommandRecord) (tea.Model, tea.Cmd) {
	m.mode = ModeNoteEdit
	m.noteEditingRecordID = record.ID
	m.noteEditingRecord = record
	m.noteEditOriginal = record.Note
	m.noteEditError = nil
	m.noteEditSuccess = false

	// Set up the note editor with current note content
	m.noteEditor.SetValue(record.Note)
	m.noteEditor.Focus()

	return m, nil
}

// handleNoteEditKeys handles key input in note editing mode
func (m model) handleNoteEditKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg.String() {
	case "enter", "ctrl+s":
		// Save the note
		return m.saveNote()
	case "esc":
		// Cancel note editing (handled in main Update method)
		return m, nil
	default:
		// Handle regular text input
		m.noteEditor, cmd = m.noteEditor.Update(msg)
		return m, cmd
	}
}

// saveNote saves the current note content to storage
func (m model) saveNote() (tea.Model, tea.Cmd) {
	if m.noteEditingRecord == nil {
		m.noteEditError = fmt.Errorf("no record selected for note editing")
		return m, nil
	}

	newNote := strings.TrimSpace(m.noteEditor.Value())

	// Validate note length
	if len(newNote) > 1000 {
		m.noteEditError = fmt.Errorf("note exceeds maximum length of 1000 characters")
		return m, nil
	}

	var err error

	if newNote == "" {
		// Delete the note if empty
		err = m.session.storage.DeleteNote(m.noteEditingRecordID)
	} else if m.noteEditOriginal == "" {
		// Add new note
		err = m.session.storage.AddNote(m.noteEditingRecordID, newNote)
	} else {
		// Update existing note
		err = m.session.storage.UpdateNote(m.noteEditingRecordID, newNote)
	}

	if err != nil {
		m.noteEditError = err
		return m, nil
	}

	// Update the record in memory
	m.noteEditingRecord.Note = newNote

	// Update the record in the session working set
	for i, record := range m.sessionWorkingSet {
		if record.ID == m.noteEditingRecordID {
			m.sessionWorkingSet[i].Note = newNote
			break
		}
	}

	// Update the list item
	for i, item := range m.list.Items() {
		if cmdItem, ok := item.(CommandItem); ok && cmdItem.record.ID == m.noteEditingRecordID {
			cmdItem.record.Note = newNote
			// Update the list - we need to rebuild the items list
			items := m.list.Items()
			items[i] = cmdItem
			m.list.SetItems(items)
			break
		}
	}

	m.noteEditSuccess = true
	m.noteEditError = nil

	// Return to details mode
	m.mode = ModeDetails
	return m, nil
}

// renderNoteEdit renders the note editing screen
func (m model) renderNoteEdit() string {
	if m.noteEditingRecord == nil {
		return "No command selected for note editing"
	}

	var content strings.Builder

	// Title
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("11")).
		MarginLeft(2).
		Render("Edit Note")
	content.WriteString(title + "\n\n")

	// Command context
	commandTitle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("12")).
		MarginLeft(2).
		Render("Command:")
	content.WriteString(commandTitle + "\n")

	commandText := lipgloss.NewStyle().
		Foreground(lipgloss.Color("15")).
		MarginLeft(4).
		Render(m.noteEditingRecord.Command)
	content.WriteString(commandText + "\n\n")

	// Note editor
	noteTitle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("11")).
		MarginLeft(2).
		Render("Note:")
	content.WriteString(noteTitle + "\n")

	// Note input field
	noteInput := lipgloss.NewStyle().
		MarginLeft(4).
		Render(m.noteEditor.View())
	content.WriteString(noteInput + "\n\n")

	// Character count
	charCount := len(m.noteEditor.Value())
	charCountColor := lipgloss.Color("8")
	if charCount > 900 {
		charCountColor = lipgloss.Color("11") // Yellow warning
	}
	if charCount > 1000 {
		charCountColor = lipgloss.Color("9") // Red error
	}

	charCountText := lipgloss.NewStyle().
		Foreground(charCountColor).
		MarginLeft(4).
		Render(fmt.Sprintf("Characters: %d/1000", charCount))
	content.WriteString(charCountText + "\n")

	// Error message
	if m.noteEditError != nil {
		errorText := lipgloss.NewStyle().
			Foreground(lipgloss.Color("9")).
			MarginLeft(4).
			Render(fmt.Sprintf("Error: %v", m.noteEditError))
		content.WriteString("\n" + errorText + "\n")
	}

	// Success message
	if m.noteEditSuccess {
		successText := lipgloss.NewStyle().
			Foreground(lipgloss.Color("10")).
			MarginLeft(4).
			Render("Note saved successfully!")
		content.WriteString("\n" + successText + "\n")
	}

	// Footer
	content.WriteString("\n")
	footer := lipgloss.NewStyle().
		Foreground(lipgloss.Color("8")).
		MarginLeft(2).
		Render("Enter/Ctrl+S: save • Esc: cancel")
	content.WriteString(footer)

	return content.String()
}

// renderHelp renders the help screen
func (m model) renderHelp() string {
	var content strings.Builder

	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("12")).
		MarginLeft(2).
		Render("CommandChronicles - Keyboard Shortcuts")
	content.WriteString(title + "\n\n")

	// Custom help content with correct navigation instructions
	helpText := lipgloss.NewStyle().
		MarginLeft(2).
		Render(`Navigation:
  ↑/↓        Navigate through command list
  mouse      Scroll wheel to navigate
  enter      Copy command (inject into shell)
  ctrl+j     Execute command directly
  tab        View detailed command information

Notes:
  ctrl+n     Edit note for selected command

Search:
  Type anything to search (all letters/numbers work!)
  ctrl+f     Toggle fuzzy search mode
  ctrl+s     Toggle success-only filter
  ctrl+x     Toggle failure-only filter
  ctrl+k     Clear search input
  ctrl+l     Refresh search results
  ctrl+t     Show statistics view

Time Search:
  1h         Commands from last hour
  2d         Commands from last 2 days
  since 1h   Commands since 1 hour ago
  last 3d    Commands from last 3 days
  today      Commands from today
  yesterday  Commands from yesterday
  this week  Commands from this week
  1h-30m     Commands between 1 hour and 30 minutes ago

Deletion:
  del/ctrl+d Delete selected command
  ctrl+w     Wipe all command history

General:
  ?          Show/hide this help
  ctrl+c     Quit application
  esc        Go back / Quit from main view`)

	content.WriteString(helpText)

	footer := lipgloss.NewStyle().
		Foreground(lipgloss.Color("8")).
		MarginTop(2).
		MarginLeft(2).
		Render("Press ? or Esc to return to search")
	content.WriteString("\n\n" + footer)

	return content.String()
}

// renderDetails renders the detailed view
func (m model) renderDetails() string {
	if len(m.list.Items()) == 0 {
		return "No command selected"
	}

	item, ok := m.list.SelectedItem().(CommandItem)
	if !ok {
		return "Invalid command selected"
	}

	record := item.record
	var content strings.Builder

	// Title
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("12")).
		MarginLeft(2).
		Render("Command Details")
	content.WriteString(title + "\n\n")

	// Command
	commandTitle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("11")).
		MarginLeft(2).
		Render("Command:")
	content.WriteString(commandTitle + "\n")

	commandText := lipgloss.NewStyle().
		Foreground(lipgloss.Color("15")).
		MarginLeft(4).
		Render(record.Command)
	content.WriteString(commandText + "\n\n")

	// Execution details
	execTitle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("11")).
		MarginLeft(2).
		Render("Execution:")
	content.WriteString(execTitle + "\n")

	var exitText string
	if record.ExitCode == 0 {
		exitText = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Render("✓ Success (0)")
	} else {
		exitText = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Render(fmt.Sprintf("✗ Failed (%d)", record.ExitCode))
	}

	details := []string{
		fmt.Sprintf("Exit Code:  %s", exitText),
		fmt.Sprintf("Duration:   %s", formatDuration(record.Duration)),
		fmt.Sprintf("Executed:   %s (%s)",
			time.UnixMilli(record.Timestamp).Format("2006-01-02 15:04:05"),
			formatTimeAgo(record.Timestamp)),
	}

	for _, detail := range details {
		content.WriteString(lipgloss.NewStyle().MarginLeft(4).Render(detail) + "\n")
	}
	content.WriteString("\n")

	// Context
	contextTitle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("11")).
		MarginLeft(2).
		Render("Context:")
	content.WriteString(contextTitle + "\n")

	contextDetails := []string{
		fmt.Sprintf("Directory:  %s", record.WorkingDir),
	}

	if record.User != "" {
		contextDetails = append(contextDetails, fmt.Sprintf("User:       %s", record.User))
	}
	if record.Hostname != "" {
		contextDetails = append(contextDetails, fmt.Sprintf("Hostname:   %s", record.Hostname))
	}
	if record.Shell != "" {
		contextDetails = append(contextDetails, fmt.Sprintf("Shell:      %s", record.Shell))
	}
	if record.SessionID != "" {
		sessionID := record.SessionID
		if len(sessionID) > 16 {
			sessionID = sessionID[:16] + "..."
		}
		contextDetails = append(contextDetails, fmt.Sprintf("Session:    %s", sessionID))
	}

	for _, detail := range contextDetails {
		content.WriteString(lipgloss.NewStyle().MarginLeft(4).Render(detail) + "\n")
	}

	// Git info
	if record.GitRoot != "" || record.GitBranch != "" || record.GitCommit != "" {
		content.WriteString("\n")
		gitTitle := lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("11")).
			MarginLeft(2).
			Render("Git Information:")
		content.WriteString(gitTitle + "\n")

		if record.GitRoot != "" {
			content.WriteString(lipgloss.NewStyle().MarginLeft(4).Render(fmt.Sprintf("Repository: %s", record.GitRoot)) + "\n")
		}
		if record.GitBranch != "" {
			content.WriteString(lipgloss.NewStyle().MarginLeft(4).Render(fmt.Sprintf("Branch:     %s", record.GitBranch)) + "\n")
		}
		if record.GitCommit != "" {
			commit := record.GitCommit
			if len(commit) > 8 {
				commit = commit[:8]
			}
			content.WriteString(lipgloss.NewStyle().MarginLeft(4).Render(fmt.Sprintf("Commit:     %s", commit)) + "\n")
		}
	}

	// Notes section
	if record.Note != "" {
		content.WriteString("\n")
		noteTitle := lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("11")).
			MarginLeft(2).
			Render("Note:")
		content.WriteString(noteTitle + "\n")

		noteText := lipgloss.NewStyle().
			Foreground(lipgloss.Color("15")).
			MarginLeft(4).
			Render(record.Note)
		content.WriteString(noteText + "\n")
	}

	// Footer
	content.WriteString("\n")
	footer := lipgloss.NewStyle().
		Foreground(lipgloss.Color("8")).
		MarginLeft(2).
		Render("Enter: select • Tab/Esc: return to search • Ctrl+N: edit note")
	content.WriteString(footer)

	return content.String()
}

// enterStatsMode initializes and enters stats mode
func (m model) enterStatsMode() (tea.Model, tea.Cmd) {
	// Initialize stats engine if not already done
	if m.statsEngine == nil {
		m.statsEngine = stats.NewStatsEngine(m.session.config, m.session.storage, m.session.authManager)
	}

	// Generate stats data
	statsResult, err := m.statsEngine.GenerateStats(&stats.StatsOptions{
		Period: stats.PeriodAll,
		TopN:   20,
	})
	if err != nil {
		m.err = err
		return m, nil
	}

	m.statsData = statsResult

	// Initialize base commands list and collect timestamps
	baseItems := make([]list.Item, len(statsResult.TopCommands))
	for i, cmd := range statsResult.TopCommands {
		baseItems[i] = StatsCommandItem{
			command:     cmd.Command,
			count:       cmd.Count,
			successRate: cmd.SuccessRate,
		}

		// Collect timestamps for this base command for heatmap (synchronously)
		req := &search.SearchRequest{
			Query:          "",
			Limit:          1000,
			UseFuzzySearch: false,
			UseCache:       true,
		}

		response, err := m.session.searchService.Search(req)
		if err == nil {
			var timestamps []int64
			for _, record := range response.Records {
				cmdFields := strings.Fields(strings.TrimSpace(record.Command))
				if len(cmdFields) > 0 && cmdFields[0] == cmd.Command {
					timestamps = append(timestamps, record.Timestamp)
				}
			}

			m.commandTimestamps[cmd.Command] = timestamps
			m.session.logger.Debug().
				Str("base_command", cmd.Command).
				Int("timestamps_collected", len(timestamps)).
				Msg("Collected base command timestamps")
		}
	}

	m.baseCommands = baseItems
	m.baseCommandsList = list.New(baseItems, list.NewDefaultDelegate(), 0, 0)
	m.baseCommandsList.SetShowStatusBar(false)
	m.baseCommandsList.SetShowHelp(false)
	m.baseCommandsList.SetShowTitle(false)

	// Initialize extended commands list (empty initially)
	m.extendedCommandsList = list.New([]list.Item{}, list.NewDefaultDelegate(), 0, 0)
	m.extendedCommandsList.SetShowStatusBar(false)
	m.extendedCommandsList.SetShowHelp(false)
	m.extendedCommandsList.SetShowTitle(false)

	// Select first base command and load its extended commands
	if len(baseItems) > 0 {
		m.baseCommandsList.Select(0)
		firstCmd := statsResult.TopCommands[0].Command
		m.selectedBaseCommand = firstCmd
		m.focusedPane = "base"
		return m.loadExtendedCommands(firstCmd)
	}

	m.mode = ModeStats
	m.focusedPane = "base"
	return m, nil
}

// loadExtendedCommands loads extended commands for a base command
func (m model) loadExtendedCommands(baseCommand string) (tea.Model, tea.Cmd) {
	// Clear selected extended command when loading new ones to refresh heatmap
	m.selectedExtendedCommand = ""

	return tea.Model(m), func() tea.Msg {
		m.session.logger.Debug().
			Str("base_command", baseCommand).
			Msg("Loading extended commands")

		// Search for all commands - we'll filter client-side for better results
		req := &search.SearchRequest{
			Query:          "",
			Limit:          1000,
			UseFuzzySearch: false,
			UseCache:       true,
		}

		response, err := m.session.searchService.Search(req)
		if err != nil {
			m.session.logger.Error().
				Err(err).
				Str("base_command", baseCommand).
				Msg("Failed to search for extended commands")
			return extendedCommandsMsg{err: err}
		}

		m.session.logger.Debug().
			Int("total_records", len(response.Records)).
			Str("base_command", baseCommand).
			Msg("Retrieved records for filtering")

		// Filter to only commands that start with base command (exact match of first word)
		var extendedCommands []*storage.CommandRecord
		commandCounts := make(map[string]int)
		uniqueCommands := make(map[string]*storage.CommandRecord)
		baseTimestamps := make([]int64, 0)
		extendedTimestamps := make(map[string][]int64)

		for _, record := range response.Records {
			cmd := strings.Fields(strings.TrimSpace(record.Command))
			if len(cmd) > 0 && cmd[0] == baseCommand {
				// Collect timestamps for base command
				baseTimestamps = append(baseTimestamps, record.Timestamp)

				// Group by full command to count occurrences
				fullCmd := record.Command
				commandCounts[fullCmd]++

				// Collect timestamps for extended commands
				if extendedTimestamps[fullCmd] == nil {
					extendedTimestamps[fullCmd] = make([]int64, 0)
				}
				extendedTimestamps[fullCmd] = append(extendedTimestamps[fullCmd], record.Timestamp)

				// Store unique commands (keep the most recent one)
				if existing, exists := uniqueCommands[fullCmd]; !exists || record.Timestamp > existing.Timestamp {
					uniqueCommands[fullCmd] = record
				}
			}
		}

		// Convert map to slice
		for _, record := range uniqueCommands {
			extendedCommands = append(extendedCommands, record)
		}

		m.session.logger.Debug().
			Int("extended_commands_found", len(extendedCommands)).
			Int("unique_commands", len(commandCounts)).
			Int("base_timestamps", len(baseTimestamps)).
			Str("base_command", baseCommand).
			Msg("Filtered extended commands")

		return extendedCommandsMsg{
			baseCommand:        baseCommand,
			commands:           extendedCommands,
			counts:             commandCounts,
			baseTimestamps:     baseTimestamps,
			extendedTimestamps: extendedTimestamps,
		}
	}
}

// handleStatsKeys handles key input in stats mode
func (m model) handleStatsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch {
	case key.Matches(msg, m.keys.Quit), key.Matches(msg, m.keys.Stats):
		m.mode = ModeSearch
		return m, nil

	case key.Matches(msg, m.keys.Tab):
		// Switch focus between panes
		if m.focusedPane == "base" {
			m.focusedPane = "extended"
		} else {
			m.focusedPane = "base"
		}
		return m, nil

	case key.Matches(msg, m.keys.Up):
		if m.focusedPane == "base" {
			if m.baseCommandsList.Index() > 0 {
				m.baseCommandsList.CursorUp()
				// Load extended commands for newly selected base command
				if item, ok := m.baseCommandsList.SelectedItem().(StatsCommandItem); ok {
					m.selectedBaseCommand = item.command
					m.selectedExtendedCommand = ""
					return m.loadExtendedCommands(item.command)
				}
			}
		} else {
			m.extendedCommandsList.CursorUp()
			// Update selected extended command for highlighting and refresh heatmap
			if item, ok := m.extendedCommandsList.SelectedItem().(StatsCommandItem); ok {
				m.selectedExtendedCommand = item.fullCommand
				m.session.logger.Debug().
					Str("selected_extended_command", m.selectedExtendedCommand).
					Str("focused_pane", m.focusedPane).
					Int("available_timestamps", len(m.extendedTimestamps[m.selectedExtendedCommand])).
					Msg("Extended command selection changed - heatmap should refresh")
			}
		}
		return m, nil

	case key.Matches(msg, m.keys.Down):
		if m.focusedPane == "base" {
			if m.baseCommandsList.Index() < len(m.baseCommandsList.Items())-1 {
				m.baseCommandsList.CursorDown()
				// Load extended commands for newly selected base command
				if item, ok := m.baseCommandsList.SelectedItem().(StatsCommandItem); ok {
					m.selectedBaseCommand = item.command
					m.selectedExtendedCommand = ""
					return m.loadExtendedCommands(item.command)
				}
			}
		} else {
			if m.extendedCommandsList.Index() < len(m.extendedCommandsList.Items())-1 {
				m.extendedCommandsList.CursorDown()
				// Update selected extended command for highlighting and refresh heatmap
				if item, ok := m.extendedCommandsList.SelectedItem().(StatsCommandItem); ok {
					m.selectedExtendedCommand = item.fullCommand
					m.session.logger.Debug().
						Str("selected_extended_command", m.selectedExtendedCommand).
						Str("focused_pane", m.focusedPane).
						Int("available_timestamps", len(m.extendedTimestamps[m.selectedExtendedCommand])).
						Msg("Extended command selection changed - heatmap should refresh")
				}
			}
		}
		return m, nil

	case key.Matches(msg, m.keys.Enter):
		// Copy selected command
		if m.focusedPane == "base" {
			if item, ok := m.baseCommandsList.SelectedItem().(StatsCommandItem); ok {
				fmt.Print(item.command)
				return m, tea.Quit
			}
		} else {
			if item, ok := m.extendedCommandsList.SelectedItem().(StatsCommandItem); ok {
				if item.fullCommand != "" {
					fmt.Print(item.fullCommand)
				} else {
					fmt.Print(item.command)
				}
				return m, tea.Quit
			}
		}
		return m, nil
	}

	return m, cmd
}

// renderStats renders the stats view with heatmap and command lists
func (m model) renderStats() string {
	if m.width == 0 {
		return "Initializing stats..."
	}

	var sections []string

	// Header
	header := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("12")).
		MarginLeft(2).
		Render("📊 Command Statistics")
	sections = append(sections, header)

	// Heatmap section (top row)
	if m.statsData != nil {
		heatmap := m.renderHeatmap()
		sections = append(sections, heatmap)
	}

	// Command lists section (bottom row)
	commandsSection := m.renderCommandLists()
	sections = append(sections, commandsSection)

	// Footer
	footer := lipgloss.NewStyle().
		Foreground(lipgloss.Color("8")).
		MarginLeft(2).
		Render("↑/↓: navigate • tab: switch pane • enter: copy • ctrl+t/esc: back to search")
	sections = append(sections, footer)

	return lipgloss.JoinVertical(lipgloss.Left, sections...)
}

// renderHeatmap renders a GitHub-style activity heatmap
func (m model) renderHeatmap() string {
	if m.statsData == nil {
		return ""
	}

	// Create a full year heatmap visualization (GitHub style) - 12 months, 4 weeks each
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("11")).
		MarginLeft(2).
		MarginTop(1).
		Render(fmt.Sprintf("Weekly Activity for '%s' (Past 12 Months)", m.selectedBaseCommand))

	heatmapLines := []string{title}

	// Get current time for date calculations
	now := time.Now()
	// Start from exactly 11 months before to include current month
	startDate := now.AddDate(0, -11, 0)

	// Add spacing after title
	heatmapLines = append(heatmapLines, "")

	// Create weekly dots view (48 weeks = 12 months)
	const totalWeeks = 48
	weeklyActivity := make([]int, totalWeeks)
	weeklyExtendedActivity := make([]int, totalWeeks)

	// Get base command timestamps and group by week
	if baseTimestamps, exists := m.commandTimestamps[m.selectedBaseCommand]; exists {
		m.session.logger.Debug().
			Str("base_command", m.selectedBaseCommand).
			Int("total_timestamps", len(baseTimestamps)).
			Str("start_date", startDate.Format("2006-01-02")).
			Msg("Processing base command timestamps")

		for _, timestamp := range baseTimestamps {
			cmdTime := time.UnixMilli(timestamp)
			if cmdTime.After(startDate) && cmdTime.Before(now.AddDate(0, 0, 1)) {
				weeksSince := int(cmdTime.Sub(startDate).Hours() / (24 * 7))
				if weeksSince >= 0 && weeksSince < totalWeeks {
					weeklyActivity[weeksSince]++
					if weeksSince < 5 { // Debug first few weeks
						m.session.logger.Debug().
							Str("cmd_time", cmdTime.Format("2006-01-02")).
							Int("weeks_since", weeksSince).
							Int("new_count", weeklyActivity[weeksSince]).
							Msg("Added activity to week")
					}
				}
			}
		}
	} else {
		m.session.logger.Debug().
			Str("base_command", m.selectedBaseCommand).
			Msg("No base command timestamps found")
	}

	// Get extended command timestamps if focused
	if m.focusedPane == "extended" && m.selectedExtendedCommand != "" {
		if extTimestamps, exists := m.extendedTimestamps[m.selectedExtendedCommand]; exists {
			m.session.logger.Debug().
				Str("extended_command", m.selectedExtendedCommand).
				Int("total_timestamps", len(extTimestamps)).
				Msg("Processing extended command timestamps")

			for _, timestamp := range extTimestamps {
				cmdTime := time.UnixMilli(timestamp)
				if cmdTime.After(startDate) && cmdTime.Before(now.AddDate(0, 0, 1)) {
					weeksSince := int(cmdTime.Sub(startDate).Hours() / (24 * 7))
					if weeksSince >= 0 && weeksSince < totalWeeks {
						weeklyExtendedActivity[weeksSince]++
					}
				}
			}
		}
	}

	// Create weekly dots line with left margin
	dotsLine := "     "
	for week := 0; week < totalWeeks; week++ {
		var dot string
		isHighlighted := m.focusedPane == "extended" && weeklyExtendedActivity[week] > 0
		baseActivity := weeklyActivity[week]

		// Debug all weeks to see activity distribution
		if baseActivity > 0 || week < 10 {
			m.session.logger.Debug().
				Int("week", week).
				Int("base_activity", baseActivity).
				Int("extended_activity", weeklyExtendedActivity[week]).
				Bool("highlighted", isHighlighted).
				Msg("Week activity debug")
		}

		if isHighlighted {
			// Orange for selected extended command activity
			dot = lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Render("●")
		} else {
			// Green intensity based on base command activity - use more distinct colors
			switch baseActivity {
			case 0:
				dot = lipgloss.NewStyle().Foreground(lipgloss.Color("237")).Render("○") // Less (empty circle)
			case 1:
				dot = lipgloss.NewStyle().Foreground(lipgloss.Color("238")).Render("●") // Very dark gray
			case 2:
				dot = lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Render("●") // Dark green
			case 3:
				dot = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Render("●") // Bright green
			default: // 4+
				dot = lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("●") // Very bright green
			}
		}

		dotsLine += dot + " "

		// Add extra spacing between months (every ~4 weeks)
		if (week+1)%4 == 0 && week < totalWeeks-1 {
			dotsLine += "  "
		}
	}

	heatmapLines = append(heatmapLines, dotsLine)
	heatmapLines = append(heatmapLines, "")

	// Create month labels for 12 months with left margin and proper alignment
	monthsLine := "     "
	for i := 0; i < 12; i++ {
		monthDate := startDate.AddDate(0, i, 0)
		monthName := monthDate.Format("Jan")

		// Each month has 4 weeks: 4 dots + 4 spaces = 8 chars, plus 2 extra spaces between months = 10 total
		if i < 11 {
			monthsLine += fmt.Sprintf("%-10s", monthName)
		} else {
			monthsLine += monthName // Last month doesn't need padding
		}
	}

	heatmapLines = append(heatmapLines, lipgloss.NewStyle().
		Foreground(lipgloss.Color("8")).
		Render(monthsLine))

	// Add proper legend with actual colors matching the dots
	legendText := "     Less "
	legendText += lipgloss.NewStyle().Foreground(lipgloss.Color("237")).Render("○") + " "
	legendText += lipgloss.NewStyle().Foreground(lipgloss.Color("238")).Render("●") + " "
	legendText += lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Render("●") + " "
	legendText += lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Render("●") + " "
	legendText += lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("●") + " "
	legendText += lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("More") // Use same green as brightest square

	// Show orange highlighting legend when focused on extended commands
	if m.selectedExtendedCommand != "" && m.focusedPane == "extended" {
		legendText += "     " + lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Render("▢") + " " +
			lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Render("Selected command")
	}

	legendStyled := lipgloss.NewStyle().
		Foreground(lipgloss.Color("8")).
		MarginTop(1).
		Render(legendText)
	heatmapLines = append(heatmapLines, legendStyled)

	// Add bottom spacing
	heatmapLines = append(heatmapLines, "")

	return lipgloss.JoinVertical(lipgloss.Left, heatmapLines...)
}

// renderCommandLists renders the base and extended command lists side by side
func (m model) renderCommandLists() string {
	listHeight := m.height - 22 // Account for header, larger heatmap, legend, and footer
	if listHeight < 10 {
		listHeight = 10
	}

	// Set list sizes - make them more centered and responsive
	availableWidth := m.width - 20 // Leave margin for centering
	if availableWidth < 60 {
		availableWidth = 60 // Minimum width
	}
	listWidth := availableWidth / 2 // Split available width
	m.baseCommandsList.SetSize(listWidth, listHeight)
	m.extendedCommandsList.SetSize(listWidth, listHeight)

	// Base commands (left) - add focus indicator
	baseTitleText := "Base Commands"
	baseTitleColor := lipgloss.Color("11")
	if m.focusedPane == "base" {
		baseTitleText += " ●"
		baseTitleColor = lipgloss.Color("12") // Brighter blue when focused
	}
	baseTitle := lipgloss.NewStyle().
		Bold(true).
		Foreground(baseTitleColor).
		MarginTop(1).
		Align(lipgloss.Center).
		Width(listWidth).
		Render(baseTitleText)

	baseList := m.baseCommandsList.View()
	leftColumn := lipgloss.JoinVertical(lipgloss.Left, baseTitle, baseList)

	// Extended commands (right) - add focus indicator
	extendedTitleText := fmt.Sprintf("'%s' Commands", m.selectedBaseCommand)
	extendedTitleColor := lipgloss.Color("11")
	if m.focusedPane == "extended" {
		extendedTitleText += " ●"
		extendedTitleColor = lipgloss.Color("12") // Brighter blue when focused
	}
	extendedTitle := lipgloss.NewStyle().
		Bold(true).
		Foreground(extendedTitleColor).
		MarginTop(1).
		Align(lipgloss.Center).
		Width(listWidth).
		Render(extendedTitleText)

	extendedList := m.extendedCommandsList.View()
	rightColumn := lipgloss.JoinVertical(lipgloss.Left, extendedTitle, extendedList)

	// Center the entire column layout responsively
	spacerWidth := 10
	combinedWidth := listWidth + listWidth + spacerWidth
	leftMargin := (m.width - combinedWidth) / 2
	if leftMargin < 0 {
		leftMargin = 0
		spacerWidth = max(2, spacerWidth-(combinedWidth-m.width)) // Reduce spacer if needed
	}

	// Add spacing between columns
	spacer := strings.Repeat(" ", spacerWidth)

	// Combine columns side by side with spacing and centering
	columnsContent := lipgloss.JoinHorizontal(lipgloss.Top, leftColumn, spacer, rightColumn)

	// Add left margin for centering and bottom margin
	return strings.Repeat(" ", leftMargin) + columnsContent + "\n\n"
}

// StatsCommandItem represents a command in the stats lists
type StatsCommandItem struct {
	command     string
	count       int
	successRate float64
	fullCommand string // For extended commands
}

func (i StatsCommandItem) FilterValue() string {
	if i.fullCommand != "" {
		return i.fullCommand
	}
	return i.command
}

func (i StatsCommandItem) Title() string {
	if i.fullCommand != "" {
		return i.fullCommand
	}
	return fmt.Sprintf("%s (%d uses)", i.command, i.count)
}

func (i StatsCommandItem) Description() string {
	if i.fullCommand != "" {
		if i.count > 0 {
			return fmt.Sprintf("%d uses", i.count)
		}
		return "Recent usage"
	}
	return fmt.Sprintf("Success rate: %.1f%%", i.successRate)
}

// Message types for stats mode
type extendedCommandsMsg struct {
	baseCommand        string
	commands           []*storage.CommandRecord
	counts             map[string]int
	baseTimestamps     []int64
	extendedTimestamps map[string][]int64
	err                error
}

// Update method needs to handle extendedCommandsMsg
func (m model) handleExtendedCommandsMsg(msg extendedCommandsMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		m.err = msg.err
		return m, nil
	}

	m.session.logger.Debug().
		Int("commands_received", len(msg.commands)).
		Str("base_command", msg.baseCommand).
		Msg("Processing extended commands message")

	// Store timestamps for heatmap calculations
	m.commandTimestamps[msg.baseCommand] = msg.baseTimestamps
	m.extendedTimestamps = msg.extendedTimestamps

	// Debug logging for extended timestamps
	m.session.logger.Debug().
		Str("base_command", msg.baseCommand).
		Int("base_timestamps", len(msg.baseTimestamps)).
		Int("extended_commands", len(msg.extendedTimestamps)).
		Msg("Stored timestamps for heatmap calculations")

	for cmd, timestamps := range msg.extendedTimestamps {
		m.session.logger.Debug().
			Str("extended_command", cmd).
			Int("timestamp_count", len(timestamps)).
			Msg("Extended command timestamp details")
	}

	// Convert to list items
	items := make([]list.Item, len(msg.commands))
	for i, cmd := range msg.commands {
		count := 1
		if msg.counts != nil {
			if c, exists := msg.counts[cmd.Command]; exists {
				count = c
			}
		}
		items[i] = StatsCommandItem{
			command:     msg.baseCommand,
			fullCommand: cmd.Command,
			count:       count,
		}
	}

	m.extendedCommands = items
	m.extendedCommandsList.SetItems(items)
	m.mode = ModeStats

	// Select first extended command if available
	if len(items) > 0 {
		m.extendedCommandsList.Select(0)
		if item, ok := items[0].(StatsCommandItem); ok {
			m.selectedExtendedCommand = item.fullCommand
		}
	}

	m.session.logger.Debug().
		Int("list_items_set", len(items)).
		Str("base_command", msg.baseCommand).
		Msg("Extended commands list updated")

	return m, nil
}

// performSearch executes a search
func (m model) performSearch() tea.Cmd {
	return func() tea.Msg {
		searchStartTime := time.Now()

		query := strings.TrimSpace(m.searchInput.Value())

		// Parse time expressions from query
		timeFilter := m.timeParser.ParseTimeExpression(query)

		// Update the model's active time filter
		m.activeTimeFilter = timeFilter

		// Use the remaining query after time expression removal
		effectiveQuery := timeFilter.OriginalQuery

		// Debug logging
		m.session.logger.Debug().
			Str("original_query", query).
			Str("effective_query", effectiveQuery).
			Bool("has_time_filter", timeFilter.HasTimeFilter).
			Bool("fuzzy_enabled", m.fuzzyEnabled).
			Int("max_results", m.opts.MaxResults).
			Bool("show_success_only", m.showSuccessOnly).
			Bool("show_failures_only", m.showFailuresOnly).
			Msg("Starting search operation")

		var req *search.SearchRequest
		if effectiveQuery == "" && !timeFilter.HasTimeFilter {
			// For empty query, use session working set if available, otherwise fetch from cache
			if len(m.sessionWorkingSet) > 0 {
				m.session.logger.Debug().
					Int("working_set_size", len(m.sessionWorkingSet)).
					Msg("Using session working set for empty query")

				// Filter working set records
				filteredResults := m.sessionWorkingSet
				if m.showSuccessOnly {
					var filtered []*storage.CommandRecord
					for _, record := range m.sessionWorkingSet {
						if record.ExitCode == 0 {
							filtered = append(filtered, record)
						}
					}
					filteredResults = filtered
				} else if m.showFailuresOnly {
					var filtered []*storage.CommandRecord
					for _, record := range m.sessionWorkingSet {
						if record.ExitCode != 0 {
							filtered = append(filtered, record)
						}
					}
					filteredResults = filtered
				}

				return searchResultMsg{
					results:         filteredResults,
					totalCount:      int64(len(filteredResults)),
					searchStartTime: &searchStartTime,
					timeFilter:      timeFilter,
				}
			}

			// Fallback to cache/database search
			req = &search.SearchRequest{
				Query:          "",
				Limit:          max(m.session.config.Cache.HotCacheSize, len(m.sessionWorkingSet)),
				UseFuzzySearch: false,
				UseCache:       true,
				MaxBatches:     10,
			}
			m.session.logger.Debug().Msg("Using empty query to fetch recent commands")
		} else {
			// Use larger limit when we have a working set to search beyond current records
			searchLimit := m.session.config.Cache.HotCacheSize
			if len(m.sessionWorkingSet) > 0 {
				searchLimit = max(searchLimit*3, len(m.sessionWorkingSet)+50) // Search beyond working set
			}

			req = &search.SearchRequest{
				Query:          effectiveQuery,
				Limit:          searchLimit,
				UseFuzzySearch: m.fuzzyEnabled && effectiveQuery != "",
				UseCache:       true,
				MaxBatches:     20, // Increased to search deeper in database
				Since:          timeFilter.Since,
				Until:          timeFilter.Until,
			}
			m.session.logger.Debug().
				Str("effective_query", effectiveQuery).
				Bool("fuzzy", m.fuzzyEnabled).
				Bool("has_time_filter", timeFilter.HasTimeFilter).
				Msg("Using specific query with time filter")
		}

		m.session.logger.Debug().
			Bool("fuzzy_enabled", req.UseFuzzySearch).
			Str("query", query).
			Int("limit", req.Limit).
			Msg("Calling search service")
		response, err := m.session.searchService.Search(req)
		if err != nil {
			m.session.logger.Error().
				Err(err).
				Str("query", query).
				Bool("fuzzy_enabled", req.UseFuzzySearch).
				Msg("Search operation failed")
			return searchResultMsg{err: fmt.Errorf("search failed: %w", err), timeFilter: timeFilter}
		}

		m.session.logger.Debug().
			Int("total_records", len(response.Records)).
			Int("total_matches", response.TotalMatches).
			Msg("Search completed successfully")

		// Apply filters
		filteredResults := response.Records
		if m.showSuccessOnly {
			var filtered []*storage.CommandRecord
			for _, record := range response.Records {
				if record.ExitCode == 0 {
					filtered = append(filtered, record)
				}
			}
			filteredResults = filtered
			m.session.logger.Debug().
				Int("before_filter", len(response.Records)).
				Int("after_success_filter", len(filtered)).
				Msg("Applied success-only filter")
		} else if m.showFailuresOnly {
			var filtered []*storage.CommandRecord
			for _, record := range response.Records {
				if record.ExitCode != 0 {
					filtered = append(filtered, record)
				}
			}
			filteredResults = filtered
			m.session.logger.Debug().
				Int("before_filter", len(response.Records)).
				Int("after_failure_filter", len(filtered)).
				Msg("Applied failure-only filter")
		}

		m.session.logger.Debug().
			Int("final_results_count", len(filteredResults)).
			Msg("Returning search results")

		return searchResultMsg{
			results:         filteredResults,
			totalCount:      int64(response.TotalMatches),
			searchStartTime: &searchStartTime,
			timeFilter:      timeFilter,
		}
	}
}

// performSearchDelayed performs search with a small delay for typing
func (m model) performSearchDelayed() tea.Cmd {
	return tea.Tick(time.Millisecond*300, func(t time.Time) tea.Msg {
		return performSearchMsg{}
	})
}

// handleDeleteConfirmKeys handles key input in delete confirmation mode
func (m model) handleDeleteConfirmKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y", "Y":
		// Confirm deletion
		m.mode = ModeSearch
		return m, m.performDeletion(m.deleteTargetID)
	case "n", "N":
		// Cancel deletion
		m.mode = ModeSearch
		m.deleteTargetID = 0
		m.deleteTargetCmd = ""
		return m, nil
	}
	return m, nil
}

// handleWipeConfirmKeys handles key input in wipe confirmation mode
func (m model) handleWipeConfirmKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y", "Y":
		// Confirm wipe - perform wipe operation
		m.mode = ModeSearch
		m.showWipeConfirm = false
		return m, m.performWipe()
	case "n", "N":
		// Cancel wipe
		m.mode = ModeSearch
		m.showWipeConfirm = false
		m.wipeRecordCount = 0
		return m, nil
	}
	return m, nil
}

// handleWipeCommand handles the wipe all command
func (m model) handleWipeCommand() (model, tea.Cmd) {
	// Get total record count for confirmation
	m.wipeRecordCount = m.totalRecords
	m.mode = ModeWipeConfirm
	m.showWipeConfirm = true
	return m, nil
}

// performWipe executes the wipe operation
func (m model) performWipe() tea.Cmd {
	return func() tea.Msg {
		m.session.logger.Info().
			Int("total_records", m.wipeRecordCount).
			Msg("Starting wipe operation")

		// Execute wipe operation through deletion service
		result, err := m.session.deletionService.DeleteAll("", false)
		if err != nil {
			m.session.logger.Error().
				Err(err).
				Msg("Wipe operation failed")
			return deletionResultMsg{
				deletedCount: 0,
				err:          fmt.Errorf("wipe failed: %w", err),
			}
		}

		m.session.logger.Info().
			Int64("deleted_count", result.DeletedCount).
			Msg("Wipe operation completed successfully")

		return deletionResultMsg{
			deletedCount: result.DeletedCount,
			err:          nil,
		}
	}
}

// renderDeleteConfirm renders the delete confirmation dialog
func (m model) renderDeleteConfirm() string {
	var content strings.Builder

	// Header
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("9")).
		MarginLeft(2).
		Render("⚠️  DELETE COMMAND")
	content.WriteString(title + "\n\n")

	// Command to be deleted
	cmdStyle := lipgloss.NewStyle().
		Background(lipgloss.Color("1")).
		Foreground(lipgloss.Color("15")).
		Padding(0, 1).
		MarginLeft(2)

	// Label style for consistent alignment
	labelStyle := lipgloss.NewStyle().MarginLeft(2)

	content.WriteString(labelStyle.Render("Command to delete:") + "\n")
	content.WriteString(cmdStyle.Render(m.deleteTargetCmd) + "\n\n")

	// Record ID
	content.WriteString(labelStyle.Render(fmt.Sprintf("Record ID: %d", m.deleteTargetID)) + "\n\n")

	// Warning
	warningStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("9")).
		MarginLeft(2)
	content.WriteString(warningStyle.Render("This action cannot be undone!") + "\n\n")

	// Confirmation prompt
	promptStyle := lipgloss.NewStyle().
		Bold(true).
		MarginLeft(2)
	content.WriteString(promptStyle.Render("Delete this command? (y/N): ") + "\n\n")

	// Instructions
	instructionStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("8")).
		MarginLeft(2)
	content.WriteString(instructionStyle.Render("Press 'y' to confirm, 'n' to cancel, ESC to go back"))

	return content.String()
}

// renderWipeConfirm renders the wipe confirmation dialog
func (m model) renderWipeConfirm() string {
	var content strings.Builder

	// Header
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("9")).
		MarginLeft(2).
		Render("🚨 WIPE ALL COMMAND HISTORY")
	content.WriteString(title + "\n\n")

	// Record count
	countStyle := lipgloss.NewStyle().
		Background(lipgloss.Color("1")).
		Foreground(lipgloss.Color("15")).
		Padding(0, 1).
		MarginLeft(2)

	labelStyle := lipgloss.NewStyle().MarginLeft(2)

	content.WriteString(labelStyle.Render("Total records to delete:") + "\n")
	content.WriteString(countStyle.Render(fmt.Sprintf("%d commands", m.wipeRecordCount)) + "\n\n")

	// Strong warning
	warningStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("9")).
		Bold(true).
		MarginLeft(2)
	content.WriteString(warningStyle.Render("⚠️  THIS WILL PERMANENTLY DELETE ALL COMMAND HISTORY!") + "\n")
	content.WriteString(warningStyle.Render("⚠️  THIS ACTION CANNOT BE UNDONE!") + "\n\n")

	// Additional warning
	content.WriteString(labelStyle.Render("This will remove:") + "\n")
	content.WriteString(labelStyle.Render("• All command records") + "\n")
	content.WriteString(labelStyle.Render("• All metadata and context") + "\n")
	content.WriteString(labelStyle.Render("• All search history") + "\n\n")

	// Confirmation prompt
	promptStyle := lipgloss.NewStyle().
		Bold(true).
		MarginLeft(2)
	content.WriteString(promptStyle.Render("Are you sure you want to WIPE ALL history? (y/N): ") + "\n\n")

	// Instructions
	instructionStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("8")).
		MarginLeft(2)
	content.WriteString(instructionStyle.Render("Press 'y' to confirm wipe, 'n' to cancel, ESC to go back"))

	return content.String()
}

// performDeletion performs the actual deletion of a record
func (m model) performDeletion(recordID int64) tea.Cmd {
	return func() tea.Msg {
		result, err := m.session.deletionService.DeleteRecord(recordID, false)
		if err != nil {
			return deletionResultMsg{err: fmt.Errorf("deletion failed: %w", err)}
		}
		return deletionResultMsg{deletedCount: result.DeletedCount}
	}
}

// resetFilters resets all search filters
func (m model) resetFilters() model {
	m.showSuccessOnly = false
	m.showFailuresOnly = false
	return m
}

// updateSessionWorkingSet merges new records into the session working set
func (m *model) updateSessionWorkingSet(newRecords []*storage.CommandRecord) {
	if len(newRecords) == 0 {
		return
	}

	initialSize := len(m.sessionWorkingSet)

	m.session.logger.Debug().
		Int("initial_working_set_size", initialSize).
		Int("incoming_records", len(newRecords)).
		Int("max_size", m.maxWorkingSetSize).
		Msg("Before updating session working set")

	// Create a map to track existing records by ID to avoid duplicates
	existingIDs := make(map[int64]bool)
	for _, record := range m.sessionWorkingSet {
		existingIDs[record.ID] = true
	}

	// Add new records that aren't already in the working set
	addedCount := 0
	duplicateCount := 0
	for _, record := range newRecords {
		if !existingIDs[record.ID] {
			m.sessionWorkingSet = append(m.sessionWorkingSet, record)
			addedCount++
			m.session.logger.Debug().
				Int64("record_id", record.ID).
				Str("command", record.Command).
				Msg("Added new record to working set")
		} else {
			duplicateCount++
			m.session.logger.Debug().
				Int64("record_id", record.ID).
				Str("command", record.Command).
				Msg("Skipped duplicate record")
		}
	}

	// Sort by timestamp (most recent first)
	sort.Slice(m.sessionWorkingSet, func(i, j int) bool {
		return m.sessionWorkingSet[i].Timestamp > m.sessionWorkingSet[j].Timestamp
	})

	// Trim to max size if necessary
	trimmedCount := 0
	if len(m.sessionWorkingSet) > m.maxWorkingSetSize {
		trimmedCount = len(m.sessionWorkingSet) - m.maxWorkingSetSize
		m.sessionWorkingSet = m.sessionWorkingSet[:m.maxWorkingSetSize]
	}

	m.session.logger.Debug().
		Int("final_working_set_size", len(m.sessionWorkingSet)).
		Int("added_records", addedCount).
		Int("duplicate_records", duplicateCount).
		Int("trimmed_records", trimmedCount).
		Int("size_change", len(m.sessionWorkingSet)-initialSize).
		Msg("Updated session working set")
}

// clearSessionWorkingSet clears the session working set with logging
func (m *model) clearSessionWorkingSet(reason string) {
	oldSize := len(m.sessionWorkingSet)
	m.sessionWorkingSet = make([]*storage.CommandRecord, 0)

	m.session.logger.Debug().
		Int("previous_size", oldSize).
		Str("reason", reason).
		Msg("Cleared session working set")
}

// Message types
type searchResultMsg struct {
	results         []*storage.CommandRecord
	totalCount      int64
	err             error
	searchStartTime *time.Time
	timeFilter      *search.TimeFilter
}

type performSearchMsg struct{}

type deletionResultMsg struct {
	deletedCount int64
	err          error
}

// Helper functions
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func formatTimeAgo(timestamp int64) string {
	t := time.UnixMilli(timestamp)
	duration := time.Since(t)

	if duration < time.Minute {
		return "now"
	} else if duration < time.Hour {
		minutes := int(duration.Minutes())
		return fmt.Sprintf("%dm", minutes)
	} else if duration < 24*time.Hour {
		hours := int(duration.Hours())
		return fmt.Sprintf("%dh", hours)
	} else {
		days := int(duration.Hours() / 24)
		if days == 1 {
			return "1d"
		}
		return fmt.Sprintf("%dd", days)
	}
}

func formatDuration(durationMs int64) string {
	if durationMs < 1000 {
		return fmt.Sprintf("%dms", durationMs)
	} else if durationMs < 60000 {
		seconds := float64(durationMs) / 1000
		if seconds < 10 {
			return fmt.Sprintf("%.1fs", seconds)
		}
		return fmt.Sprintf("%.0fs", seconds)
	} else {
		minutes := float64(durationMs) / 60000
		return fmt.Sprintf("%.1fm", minutes)
	}
}

// initializeSession performs the complete initialization sequence
func initializeSession(cfg *config.Config, log *logger.Logger) (*TUISession, error) {
	log.Debug().Msg("Step 1: Initializing auth manager")

	// Step 1: Initialize auth manager
	authMgr, err := auth.NewAuthManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize auth manager: %w", err)
	}

	// Step 2: Get or create session key
	log.Debug().Msg("Step 2: Getting session key")
	sessionKey, err := getSessionKey(authMgr, log)
	if err != nil {
		authMgr.Close()
		return nil, fmt.Errorf("failed to get session key: %w", err)
	}

	// Step 3: Initialize and unlock storage
	log.Debug().Msg("Step 3: Initializing secure storage")
	storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
		Config:              cfg,
		CreateIfMissing:     true,
		ValidatePermissions: true,
		EnableSecureDelete:  true,
	})
	if err != nil {
		authMgr.Close()
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}

	log.Debug().Msg("Step 4: Unlocking storage with session key")
	if err := storage.UnlockWithKey(sessionKey); err != nil {
		storage.Close()
		authMgr.Close()
		return nil, fmt.Errorf("failed to unlock storage: %w", err)
	}

	// Step 5: Initialize cache
	log.Debug().Msg("Step 5: Initializing cache")
	hybridCache := cache.NewCache(&cfg.Cache, storage)

	// Step 6: Initialize search service
	log.Debug().Msg("Step 6: Initializing search service")
	searchService := search.NewSearchService(hybridCache, storage, cfg)

	fuzzyIndexPath := filepath.Join(cfg.DataDir, "search_index")

	// Check if fuzzy index exists, rebuild only if missing
	_, err = os.Stat(fuzzyIndexPath)
	rebuildIndex := os.IsNotExist(err)
	if rebuildIndex {
		log.Info().Msg("Fuzzy search index not found, will rebuild")
	} else {
		log.Debug().Msg("Fuzzy search index exists, skipping rebuild")
	}

	searchOpts := &search.SearchOptions{
		EnableCache:       true,
		EnableFuzzySearch: true,
		WarmupCache:       true,
		DefaultLimit:      20,
		DefaultTimeout:    30 * time.Second,
		FuzzyIndexPath:    fuzzyIndexPath,
		RebuildFuzzyIndex: rebuildIndex,
	}

	log.Debug().
		Bool("enable_fuzzy", searchOpts.EnableFuzzySearch).
		Str("fuzzy_index_path", searchOpts.FuzzyIndexPath).
		Msg("Initializing search service with fuzzy search")

	if err := searchService.Initialize(searchOpts); err != nil {
		hybridCache.Close()
		storage.Close()
		authMgr.Close()
		return nil, fmt.Errorf("failed to initialize search service: %w", err)
	}

	// Check and rebuild fuzzy index if stale
	log.Debug().Msg("Checking fuzzy search index staleness")
	if err := searchService.CheckAndRebuildStaleIndex(); err != nil {
		log.Warn().Err(err).Msg("Failed to check/rebuild stale fuzzy index, fuzzy search may not work optimally")
	}

	log.Info().Msg("All TUI services initialized successfully")

	// Step 7: Initialize deletion service
	log.Debug().Msg("Step 7: Initializing deletion service")
	deletionService := deletion.NewDeletionService(storage, hybridCache, searchService, authMgr, cfg)

	return &TUISession{
		authManager:     authMgr,
		storage:         storage,
		cache:           hybridCache,
		searchService:   searchService,
		deletionService: deletionService,
		sessionKey:      sessionKey,
		logger:          log,
		config:          cfg,
	}, nil
}

// getSessionKey handles session key retrieval or authentication
func getSessionKey(authMgr *auth.AuthManager, log *logger.Logger) ([]byte, error) {
	// Clean up expired sessions
	if err := authMgr.CleanupExpiredSessions(); err != nil {
		log.WithError(err).Debug().Msg("Failed to cleanup expired sessions")
	}

	// Check if session is active
	if authMgr.IsSessionActive() {
		log.Debug().Msg("Active session found, loading session key")
		return authMgr.LoadSessionKey()
	}

	// No active session, need to authenticate
	log.Debug().Msg("No active session, authentication required")

	// Get user info
	user, err := authMgr.GetUser()
	if err != nil {
		return nil, fmt.Errorf("no user found - please run 'ccr init' first: %w", err)
	}

	// Prompt for password
	fmt.Printf("Enter password for %s: ", user.Username)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}

	// Verify password and get session key
	keys, err := authMgr.VerifyPassword(user.Username, string(password))
	if err != nil {
		// Clear password from memory
		for i := range password {
			password[i] = 0
		}
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Clear password from memory
	for i := range password {
		password[i] = 0
	}

	// Store session key for future use
	if err := authMgr.StoreSessionKey(keys.LocalKey); err != nil {
		return nil, fmt.Errorf("failed to store session key: %w", err)
	}

	log.Debug().Msg("Authentication successful, session key obtained")
	return keys.LocalKey, nil
}

// cleanup properly closes all session resources
func (s *TUISession) cleanup() {
	s.logger.Debug().Msg("Cleaning up TUI session resources")

	if s.searchService != nil {
		s.searchService.Close()
	}
	if s.cache != nil {
		s.cache.Close()
	}
	if s.storage != nil {
		s.storage.Close()
	}
	if s.authManager != nil {
		s.authManager.Close()
	}

	s.logger.Debug().Msg("TUI session cleanup completed")
}
