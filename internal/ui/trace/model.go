// Package trace shows the packet evaluation trace.
package trace

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/vmvarela/iptablestutorial/internal/engine"
	"github.com/vmvarela/iptablestutorial/internal/ui/theme"
)

// Model displays the packet evaluation trace.
type Model struct {
	steps   []engine.TraceStep
	verdict engine.Verdict
	packet  *engine.Packet
	width   int
	height  int
	offset  int
	// Prueba context
	pruebIdx      int
	pruebTotal    int
	pruebDesc     string
	recompensa    string
	levelComplete bool
	hasNextLevel  bool
	// Last evaluation result
	lastEsperado string
	lastPassed   bool
}

// New creates a new trace panel.
func New() Model {
	return Model{}
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (Model, tea.Cmd) {
	if msg, ok := msg.(tea.KeyMsg); ok {
		switch msg.String() {
		case "j", "down":
			m.offset++
		case "k", "up":
			if m.offset > 0 {
				m.offset--
			}
		}
	}
	return m, nil
}

// View renders the trace panel.
func (m Model) View() string {
	title := theme.TitleStyle.Render("Traza del Mensajero")

	var lines []string

	// Level complete: show reward and call-to-action
	if m.levelComplete {
		lines = append(lines, theme.SuccessStyle.Render("✓ ¡Nivel completado!"))
		if m.recompensa != "" {
			lines = append(lines, "")
			lines = append(lines, m.recompensa)
		}
		lines = append(lines, "")
		if m.hasNextLevel {
			lines = append(lines, theme.AccentStyle.Render("→  n  para el siguiente nivel"))
		} else {
			lines = append(lines, theme.SuccessStyle.Render("¡Has completado todos los niveles!"))
		}
		content := strings.Join(lines, "\n")
		return lipgloss.JoinVertical(lipgloss.Left, title, content)
	}

	// No packet yet — show contextual prompt
	if m.packet == nil {
		if m.pruebTotal > 0 {
			pruebLine := fmt.Sprintf("Siguiente: %s  (%d/%d)", m.pruebDesc, m.pruebIdx+1, m.pruebTotal)
			lines = append(lines, theme.MutedStyle.Render(pruebLine))
			lines = append(lines, "")
		}
		lines = append(lines, theme.InfoStyle.Render("↩  Ctrl+E  para enviar un mensajero"))
		content := strings.Join(lines, "\n")
		return lipgloss.JoinVertical(lipgloss.Left, title, content)
	}

	// Progress line — show which prueba just ran and how many passed
	if m.pruebTotal > 0 {
		passed := m.pruebIdx
		var progressLine string
		if m.lastPassed {
			progressLine = fmt.Sprintf("✓ Prueba %d/%d — ¡correcto!", passed, m.pruebTotal)
			lines = append(lines, theme.SuccessStyle.Render(progressLine))
		} else {
			progressLine = fmt.Sprintf("✗ Prueba %d/%d — incorrecto", passed, m.pruebTotal)
			lines = append(lines, theme.DangerStyle.Render(progressLine))
		}
	}

	// Packet info
	pkt := m.packet
	packetLine := fmt.Sprintf("📦 %s → %s:%d [%s]",
		pkt.SrcIP.String(),
		pkt.DstIP.String(),
		pkt.DstPort,
		pkt.Proto.String(),
	)
	lines = append(lines, theme.InfoStyle.Render(packetLine))

	// Verdict + expected comparison
	var verdictStr string
	switch m.verdict {
	case engine.VerdictAccept:
		verdictStr = theme.SuccessStyle.Render("ACCEPT")
	case engine.VerdictDrop:
		verdictStr = theme.DangerStyle.Render("DROP")
	case engine.VerdictReject:
		verdictStr = theme.DangerStyle.Render("REJECT")
	default:
		verdictStr = theme.MutedStyle.Render(m.verdict.String())
	}
	lines = append(lines, fmt.Sprintf("Veredicto: %s", verdictStr))
	if m.lastEsperado != "" && !m.lastPassed {
		lines = append(lines, theme.DangerStyle.Render(fmt.Sprintf("  esperado: %s — revisá tus reglas", m.lastEsperado)))
	}

	// Trace steps
	if len(m.steps) == 0 {
		lines = append(lines, theme.MutedStyle.Render("Sin pasos de traza."))
	} else {
		for _, step := range m.steps {
			ruleDesc := "política por defecto"
			if step.RuleIdx >= 0 {
				ruleDesc = fmt.Sprintf("regla %d", step.RuleIdx+1)
			}
			line := fmt.Sprintf("cadena %s/%s, %s → %s", step.Table, step.Chain, ruleDesc, step.Verdict.String())
			lines = append(lines, line)
		}
	}

	content := strings.Join(lines, "\n")
	contentLines := strings.Split(content, "\n")

	offset := m.offset
	if offset >= len(contentLines) {
		offset = len(contentLines) - 1
		if offset < 0 {
			offset = 0
		}
	}
	visible := contentLines[offset:]
	if len(visible) > m.height {
		visible = visible[:m.height]
	}
	view := strings.Join(visible, "\n")

	return lipgloss.JoinVertical(lipgloss.Left, title, view)
}

// SetSize updates the panel dimensions.
func (m *Model) SetSize(width, height int) {
	m.width = width
	m.height = height
}

// SetTrace updates the trace data.
func (m *Model) SetTrace(t engine.Trace, v engine.Verdict, pkt engine.Packet) {
	m.steps = t.Steps
	m.verdict = v
	m.packet = &pkt
}

// SetLastResult records whether the last sent packet matched the expected verdict.
func (m *Model) SetLastResult(esperado string, passed bool) {
	m.lastEsperado = esperado
	m.lastPassed = passed
}

// SetContext updates the prueba progress context shown in the panel.
func (m *Model) SetContext(pruebIdx, pruebTotal int, pruebDesc, recompensa string, levelComplete, hasNextLevel bool) {
	m.pruebIdx = pruebIdx
	m.pruebTotal = pruebTotal
	m.pruebDesc = pruebDesc
	m.recompensa = recompensa
	m.levelComplete = levelComplete
	m.hasNextLevel = hasNextLevel
}

// Clear resets the trace.
func (m *Model) Clear() {
	m.steps = nil
	m.verdict = engine.VerdictContinue
	m.packet = nil
}
