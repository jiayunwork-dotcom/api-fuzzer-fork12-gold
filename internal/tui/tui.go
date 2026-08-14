package tui

import (
	"fmt"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/api-fuzzer/apifuzzer/internal/core"
	"github.com/api-fuzzer/apifuzzer/internal/progress"
)

type TUIModel struct {
	mu sync.RWMutex

	state        *core.TUIState
	program      *tea.Program
	quitting     bool
	commandChan  chan TUICommand
}

type TUICommand interface{}

type UpdateStatsMsg struct {
	State *core.TUIState
}

type AddIssueMsg struct {
	Issue *core.Issue
}

type SetInitMessagesMsg struct {
	Messages []string
}

type PauseMsg struct{}
type ResumeMsg struct{}
type SkipMsg struct{}
type QPSUpMsg struct{}
type QPSDownMsg struct{}
type ExportMsg struct{}
type PanelFocusMsg struct{}

func NewTUIModel(initialState *core.TUIState) *TUIModel {
	return &TUIModel{
		state:       initialState,
		commandChan: make(chan TUICommand, 100),
	}
}

func (m *TUIModel) Init() tea.Cmd {
	return nil
}

func (m *TUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "p":
			m.state.IsPaused = !m.state.IsPaused
			m.commandChan <- PauseMsg{}
		case "s":
			m.commandChan <- SkipMsg{}
		case "+":
			m.commandChan <- QPSUpMsg{}
		case "-":
			m.commandChan <- QPSDownMsg{}
		case "d":
			m.commandChan <- ExportMsg{}
		case "tab":
			m.state.FocusedPanel = (m.state.FocusedPanel + 1) % 4
		}

	case UpdateStatsMsg:
		m.state = msg.State

	case AddIssueMsg:
		if len(m.state.RecentIssues) >= 20 {
			m.state.RecentIssues = m.state.RecentIssues[1:]
		}
		m.state.RecentIssues = append(m.state.RecentIssues, msg.Issue)
		m.state.IssueCount++

	case SetInitMessagesMsg:
		m.state.InitMessages = msg.Messages
	}

	return m, nil
}

func (m *TUIModel) View() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.quitting {
		return "Shutting down...\n"
	}

	return lipgloss.JoinVertical(
		lipgloss.Top,
		m.renderStatusBar(),
		lipgloss.JoinHorizontal(
			lipgloss.Top,
			m.renderMainPanel(),
			m.renderRightPanel(),
		),
		m.renderCoverageBar(),
		m.renderHelpBar(),
	)
}

func (m *TUIModel) renderStatusBar() string {
	style := lipgloss.NewStyle().
		Background(lipgloss.Color("#0f3460")).
		Foreground(lipgloss.Color("#ffffff")).
		Padding(0, 2).
		Bold(true)

	pauseIndicator := ""
	if m.state.IsPaused {
		pauseIndicator = " [PAUSED]"
	}

	etaStr := "calculating..."
	if m.state.Progress != nil && !m.state.Progress.ETA.IsZero() {
		etaStr = progress.FormatETA(m.state.Progress.ETA)
	}

	content := fmt.Sprintf(
		"QPS: %.1f | Done: %d/%d | Time: %s | Issues: %d | ETA: %s%s",
		m.state.CurrentQPS,
		m.state.CompletedTests,
		m.state.TotalTests,
		formatDuration(m.state.Runtime),
		m.state.IssueCount,
		etaStr,
		pauseIndicator,
	)

	return style.Render(content)
}

func (m *TUIModel) renderMainPanel() string {
	style := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#535353")).
		Padding(1, 2).
		Width(100).
		Height(20)

	if m.state.FocusedPanel == 0 {
		style = style.BorderForeground(lipgloss.Color("#00d4ff"))
	}

	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00d4ff")).
		Render("Recent Issues")

	var issues []string
	for i := len(m.state.RecentIssues) - 1; i >= 0 && i >= len(m.state.RecentIssues)-15; i-- {
		issue := m.state.RecentIssues[i]
		severityColor := getSeverityColor(issue.Severity)
		issueLine := lipgloss.NewStyle().
			Foreground(severityColor).
			Render(fmt.Sprintf("[%s] %s %s - %s",
				strings.ToUpper(string(issue.Severity)),
				issue.Method,
				issue.Endpoint,
				issue.Type,
			))
		issues = append(issues, issueLine)
	}

	if len(issues) == 0 {
		issues = append(issues, lipgloss.NewStyle().
			Foreground(lipgloss.Color("#666666")).
			Render("No issues found yet..."))
	}

	content := lipgloss.JoinVertical(lipgloss.Top, title, "", strings.Join(issues, "\n"))
	return style.Render(content)
}

func (m *TUIModel) renderRightPanel() string {
	style := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#535353")).
		Padding(1, 2).
		Width(40).
		Height(20)

	if m.state.FocusedPanel == 1 {
		style = style.BorderForeground(lipgloss.Color("#00d4ff"))
	}

	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00d4ff")).
		Render("Current Activity")

	endpoint := m.state.CurrentEndpoint
	if endpoint == "" {
		endpoint = "Waiting..."
	}

	strategy := string(m.state.CurrentStrategy)
	if strategy == "" {
		strategy = "None"
	}

	lines := []string{
		fmt.Sprintf("Endpoint: %s", endpoint),
		"",
		fmt.Sprintf("Strategy: %s", strategy),
		"",
	}

	if m.state.IsPaused && m.state.Progress != nil {
		lines = append(lines,
			fmt.Sprintf("Progress: %.1f%%", m.state.Progress.PercentComplete),
			fmt.Sprintf("Remaining: %s", progress.FormatDuration(m.state.Progress.EstimatedTimeLeft)),
		)
	}

	if m.state.TimeoutWarning != "" {
		lines = append(lines, "",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color("#ff4757")).
				Bold(true).
				Render("⚠ "+m.state.TimeoutWarning),
		)
	}

	if len(m.state.InitMessages) > 0 {
		lines = append(lines, "",
			lipgloss.NewStyle().
				Foreground(lipgloss.Color("#888888")).
				Render("─ Init Log ─"),
		)
		for _, msg := range m.state.InitMessages {
			lines = append(lines,
				lipgloss.NewStyle().
					Foreground(lipgloss.Color("#666666")).
					Render(msg),
			)
		}
	}

	content := lipgloss.JoinVertical(lipgloss.Top, title, "", strings.Join(lines, "\n"))
	return style.Render(content)
}

func (m *TUIModel) renderCoverageBar() string {
	style := lipgloss.NewStyle().
		Background(lipgloss.Color("#16213e")).
		Padding(1, 2)

	if m.state.FocusedPanel == 2 {
		style = style.Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#00d4ff"))
	}

	endpointCov := 0.0
	paramCov := 0.0
	respCov := 0.0

	if m.state.Coverage != nil {
		endpointCov = m.state.Coverage.EndpointCoverage()
		paramCov = calculateParamCoverage(m.state.Coverage)
		respCov = calculateResponseCoverage(m.state.Coverage)
	}

	barWidth := 30

	lines := []string{
		"Coverage",
		"",
		fmt.Sprintf("Endpoints:  %s %.1f%%", renderProgressBar(endpointCov, barWidth), endpointCov),
		fmt.Sprintf("Params:     %s %.1f%%", renderProgressBar(paramCov, barWidth), paramCov),
		fmt.Sprintf("Responses:  %s %.1f%%", renderProgressBar(respCov, barWidth), respCov),
	}

	return style.Render(strings.Join(lines, "\n"))
}

func (m *TUIModel) renderHelpBar() string {
	style := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#666666")).
		Padding(0, 2)

	keys := []string{
		"q: Quit",
		"p: Pause/Resume",
		"s: Skip",
		"+/-: QPS",
		"d: Export",
		"Tab: Focus",
	}

	return style.Render(strings.Join(keys, " | "))
}

func getSeverityColor(severity core.Severity) lipgloss.Color {
	switch severity {
	case core.SeverityCritical:
		return lipgloss.Color("#ff4757")
	case core.SeverityHigh:
		return lipgloss.Color("#ff6b81")
	case core.SeverityMedium:
		return lipgloss.Color("#ffa502")
	case core.SeverityLow:
		return lipgloss.Color("#70a1ff")
	default:
		return lipgloss.Color("#7bed9f")
	}
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%02d:%02d", m, s)
}

func renderProgressBar(percent float64, width int) string {
	filled := int(percent / 100 * float64(width))
	if filled > width {
		filled = width
	}

	bar := "["
	bar += strings.Repeat("█", filled)
	if filled < width {
		bar += strings.Repeat("░", width-filled)
	}
	bar += "]"
	return bar
}

func calculateParamCoverage(cov *core.Coverage) float64 {
	total := 0
	tested := 0
	for _, params := range cov.ParamsTested {
		for _, variants := range params {
			for _, t := range variants {
				total++
				if t {
					tested++
				}
			}
		}
	}
	if total == 0 {
		return 0
	}
	return float64(tested) / float64(total) * 100
}

func calculateResponseCoverage(cov *core.Coverage) float64 {
	total := 0
	tested := 0
	for _, codes := range cov.ResponseCodes {
		for _, t := range codes {
			total++
			if t {
				tested++
			}
		}
	}
	if total == 0 {
		return 0
	}
	return float64(tested) / float64(total) * 100
}

func (m *TUIModel) GetCommandChan() <-chan TUICommand {
	return m.commandChan
}

func (m *TUIModel) SetProgram(p *tea.Program) {
	m.program = p
}

func (m *TUIModel) SendUpdate(state *core.TUIState) {
	if m.program != nil {
		m.program.Send(UpdateStatsMsg{State: state})
	}
}

func (m *TUIModel) SendIssue(issue *core.Issue) {
	if m.program != nil {
		m.program.Send(AddIssueMsg{Issue: issue})
	}
}

func (m *TUIModel) SendInitMessages(messages []string) {
	if m.program != nil {
		m.program.Send(SetInitMessagesMsg{Messages: messages})
	}
}
