// Package console provides the command input panel with history and log output.
package console

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"
	"github.com/vmvarela/iptablestutorial/internal/ui/theme"
)

// SubmitMsg is sent when user presses Enter with a command.
type SubmitMsg struct{ Command string }

// SendPacketMsg is sent when user presses Ctrl+E, F5 or types "enviar mensajero".
type SendPacketMsg struct{}

type logEntry struct {
	Command string
	Result  string
	IsError bool
}

// Model is the console panel with a text input and command log.
type Model struct {
	input   textinput.Model
	history []string // last 10 commands
	log     []logEntry
	hint    string // shown when log is empty
	width   int
	height  int
	focused bool
}

// New creates a new console panel.
func New() Model {
	ti := textinput.New()
	ti.Placeholder = `iptables -A INPUT -p tcp -j ACCEPT   (Ctrl+E: enviar mensajero)`
	ti.Focus()
	return Model{
		input: ti,
		hint:  `escribe "enviar mensajero" + Enter  (o Ctrl+E)`,
	}
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd {
	return textinput.Blink
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (Model, tea.Cmd) {
	var cmds []tea.Cmd

	if msg, ok := msg.(tea.KeyMsg); ok {
		switch msg.Type {
		case tea.KeyEnter:
			cmdStr := m.input.Value()
			m.input.SetValue("")
			if cmdStr == "enviar mensajero" {
				return m, func() tea.Msg { return SendPacketMsg{} }
			}
			if cmdStr != "" {
				m.history = append(m.history, cmdStr)
				if len(m.history) > 10 {
					m.history = m.history[len(m.history)-10:]
				}
				return m, func() tea.Msg { return SubmitMsg{Command: cmdStr} }
			}
			return m, nil
		case tea.KeyCtrlE, tea.KeyF5:
			return m, func() tea.Msg { return SendPacketMsg{} }
		}
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	cmds = append(cmds, cmd)
	return m, tea.Batch(cmds...)
}

// View renders the console panel.
func (m Model) View() string {
	title := theme.TitleStyle.Render("Consola de Guardias")
	inputView := m.input.View()

	titleHeight := lipgloss.Height(title)
	inputHeight := lipgloss.Height(inputView)
	available := m.height - titleHeight - inputHeight - 2
	if available < 0 {
		available = 0
	}

	var logLines []string
	start := len(m.log) - available
	if start < 0 {
		start = 0
	}
	for _, entry := range m.log[start:] {
		prefix := "> " + entry.Command
		if entry.IsError {
			logLines = append(logLines, prefix)
			logLines = append(logLines, theme.DangerStyle.Render("  "+entry.Result))
		} else {
			logLines = append(logLines, prefix)
			logLines = append(logLines, theme.SuccessStyle.Render("  "+entry.Result))
		}
	}

	var logContent string
	if len(m.log) == 0 && m.hint != "" {
		logContent = theme.MutedStyle.Render("  → " + m.hint)
	} else {
		logContent = strings.Join(logLines, "\n")
	}

	return lipgloss.JoinVertical(lipgloss.Left,
		title,
		logContent,
		inputView,
	)
}

// SetSize updates the panel dimensions.
func (m *Model) SetSize(width, height int) {
	m.width = width
	m.height = height
	m.input.Width = width - 4
	if m.input.Width < 10 {
		m.input.Width = 10
	}
}

// Focus gives the input focus.
func (m *Model) Focus() {
	m.focused = true
	m.input.Focus()
}

// Blur removes focus from the input.
func (m *Model) Blur() {
	m.focused = false
	m.input.Blur()
}

// AddLog appends a command result to the log.
func (m *Model) AddLog(command, result string, isError bool) {
	m.log = append(m.log, logEntry{Command: command, Result: result, IsError: isError})
}
