// Package castle shows a visual ASCII castle and network diagram.
package castle

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/vmvarela/iptablestutorial/internal/levels"
	"github.com/vmvarela/iptablestutorial/internal/ui/theme"
)

// Model displays the castle and connected hosts.
type Model struct {
	level  *levels.Level
	packet *animPacket
	width  int
	height int
}

type animPacket struct {
	srcName string
	dstName string
	step    int
}

type animTickMsg struct{}

// New creates a new castle panel.
func New() Model {
	return Model{}
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (Model, tea.Cmd) {
	if _, ok := msg.(animTickMsg); ok {
		if m.packet != nil {
			m.packet.step++
			if m.packet.step > 5 {
				m.packet = nil
				return m, nil
			}
			return m, tea.Tick(200*time.Millisecond, func(time.Time) tea.Msg {
				return animTickMsg{}
			})
		}
	}
	return m, nil
}

// View renders the castle diagram.
func (m Model) View() string {
	title := theme.TitleStyle.Render("Castillo de las Reglas")
	if m.level == nil {
		return lipgloss.JoinVertical(lipgloss.Left, title, theme.MutedStyle.Render("Sin nivel cargado."))
	}

	castleArt := `       /\
      /  \
     /    \
    |______|
    |  ||  |
    |__||__|`

	var leftHosts, rightHosts []string
	for _, h := range m.level.Red.Hosts {
		if h.Zona == "barrio" {
			leftHosts = append(leftHosts, fmt.Sprintf("%s (%s)", h.Nombre, h.IP))
		} else {
			rightHosts = append(rightHosts, fmt.Sprintf("%s (%s)", h.Nombre, h.IP))
		}
	}
	leftStr := strings.Join(leftHosts, "\n")
	rightStr := strings.Join(rightHosts, "\n")
	if leftStr == "" {
		leftStr = "(vacío)"
	}
	if rightStr == "" {
		rightStr = "(vacío)"
	}

	packetIndicator := ""
	if m.packet != nil {
		packetIndicator = theme.AccentStyle.Render("  ✉  ")
	}

	content := fmt.Sprintf("%s\n%s\n%s\n%s\n%s",
		theme.MutedStyle.Render(leftStr),
		packetIndicator,
		theme.InfoStyle.Render(castleArt),
		packetIndicator,
		theme.MutedStyle.Render(rightStr),
	)

	return lipgloss.JoinVertical(lipgloss.Left, title, content)
}

// SetSize updates the panel dimensions.
func (m *Model) SetSize(width, height int) {
	m.width = width
	m.height = height
}

// SetLevel sets the current level for the diagram.
func (m *Model) SetLevel(l *levels.Level) {
	m.level = l
}

// AnimatePacket starts a packet animation between two hosts.
func (m *Model) AnimatePacket(src, dst string) tea.Cmd {
	m.packet = &animPacket{srcName: src, dstName: dst, step: 0}
	return tea.Tick(200*time.Millisecond, func(time.Time) tea.Msg {
		return animTickMsg{}
	})
}
