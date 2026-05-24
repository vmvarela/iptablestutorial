// Package guards shows the current iptables rules grouped by chain.
package guards

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/vmvarela/iptablestutorial/internal/engine"
	"github.com/vmvarela/iptablestutorial/internal/translate"
	"github.com/vmvarela/iptablestutorial/internal/ui/theme"
)

// Model displays the firewall rules grouped by table and chain.
type Model struct {
	rs            *engine.Ruleset
	initialCounts map[string]int // pre-loaded rule count per "table/chain"
	width         int
	height        int
	offset        int // scroll offset
}

// New creates a new guards panel with the given ruleset.
func New(rs *engine.Ruleset) Model {
	return Model{rs: rs}
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

// View renders the rules list.
func (m Model) View() string {
	if m.rs == nil {
		return "Sin reglas"
	}

	chains := []struct{ table, chain string }{
		{"filter", "INPUT"},
		{"filter", "OUTPUT"},
		{"filter", "FORWARD"},
	}

	var lines []string
	lines = append(lines, theme.TitleStyle.Render("Guardias del Castillo"))
	for _, cc := range chains {
		c, ok := m.rs.Chain(cc.table, cc.chain)
		if !ok {
			continue
		}
		// Highlight DROP policy in red
		policyStr := c.Policy.String()
		var policyRendered string
		if policyStr == "DROP" {
			policyRendered = theme.DangerStyle.Render(policyStr)
		} else {
			policyRendered = theme.SuccessStyle.Render(policyStr)
		}
		header := fmt.Sprintf("%s/%s (política: %s)", cc.table, cc.chain, policyRendered)
		lines = append(lines, theme.InfoStyle.Render(header))

		preloaded := m.initialCounts[cc.table+"/"+cc.chain]
		if len(c.Rules) == 0 {
			lines = append(lines, theme.MutedStyle.Render("  (vacío)"))
		} else {
			for i, r := range c.Rules {
				human := translate.Humanize(r)
				ipt := translate.ToIPTables(r)
				if i < preloaded {
					// Pre-loaded rule: show dimmed with "(inicial)" marker
					lines = append(lines, theme.MutedStyle.Render(fmt.Sprintf("  %d. %s  (inicial)", i+1, human)))
					lines = append(lines, theme.MutedStyle.Render("     "+ipt))
				} else {
					lines = append(lines, fmt.Sprintf("  %d. %s", i+1, human))
					lines = append(lines, theme.MutedStyle.Render("     "+ipt))
				}
			}
		}
		lines = append(lines, "")
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
	return strings.Join(visible, "\n")
}

// SetSize updates the panel dimensions.
func (m *Model) SetSize(width, height int) {
	m.width = width
	m.height = height
}

// SetRuleset updates the displayed ruleset.
func (m *Model) SetRuleset(rs *engine.Ruleset) {
	m.rs = rs
}

// SetInitialCounts records how many rules per chain were pre-loaded at level start.
// Key format: "table/chain" (e.g. "filter/INPUT").
func (m *Model) SetInitialCounts(counts map[string]int) {
	m.initialCounts = counts
}
