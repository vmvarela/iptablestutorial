// Package story provides a scrollable panel that shows the level story text and mission.
package story

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/lipgloss"
	"github.com/vmvarela/iptablestutorial/internal/ui/theme"
)

// Model shows the level title, narrative story and mission objective.
type Model struct {
	viewport viewport.Model
	titulo   string
	cuento   string
	mision   string
	width    int
	height   int
	ready    bool
	pistas   []string
}

// New creates a new story panel.
func New() Model {
	return Model{}
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (Model, tea.Cmd) {
	if !m.ready {
		return m, nil
	}
	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	return m, cmd
}

// View renders the story panel.
func (m Model) View() string {
	if !m.ready {
		return "Cargando historia..."
	}
	title := theme.TitleStyle.Render(m.titulo)
	missionBox := theme.AccentStyle.Render("Misión: " + m.mision)
	parts := []string{title, m.viewport.View(), missionBox}
	if len(m.pistas) > 0 {
		hintsTitle := theme.MutedStyle.Render("💡 Pistas:")
		var hintLines []string
		for i, h := range m.pistas {
			hintLines = append(hintLines, theme.MutedStyle.Render(fmt.Sprintf("  %d. %s", i+1, h)))
		}
		parts = append(parts, hintsTitle)
		parts = append(parts, hintLines...)
	}
	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

// SetPistas updates the hints for the current level.
func (m *Model) SetPistas(pistas []string) {
	m.pistas = pistas
}

// SetLevel updates the story content for the current level.
func (m *Model) SetLevel(titulo, cuento, mision string) {
	m.titulo = titulo
	m.cuento = cuento
	m.mision = mision
	if m.ready {
		m.viewport.SetContent(wrapText(cuento, m.viewport.Width))
	}
}

// SetSize sets the panel dimensions and initialises the viewport.
func (m *Model) SetSize(width, height int) {
	m.width = width
	m.height = height

	titleHeight := lipgloss.Height(theme.TitleStyle.Render(m.titulo))
	missionHeight := lipgloss.Height(theme.AccentStyle.Render("Misión: " + m.mision))
	vpHeight := height - titleHeight - missionHeight - 2
	if vpHeight < 3 {
		vpHeight = 3
	}

	if !m.ready {
		m.viewport = viewport.New(width, vpHeight)
		m.ready = true
	} else {
		m.viewport.Width = width
		m.viewport.Height = vpHeight
	}

	if m.cuento != "" {
		m.viewport.SetContent(wrapText(m.cuento, width))
	}
}

func wrapText(s string, width int) string {
	if width <= 0 {
		return s
	}
	return lipgloss.NewStyle().Width(width).Render(s)
}
