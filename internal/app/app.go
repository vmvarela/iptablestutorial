// Package app implements the main Bubble Tea model for the game.
package app

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	zone "github.com/lrstanley/bubblezone"

	"github.com/vmvarela/iptablestutorial/internal/engine"
	"github.com/vmvarela/iptablestutorial/internal/levels"
	"github.com/vmvarela/iptablestutorial/internal/progress"
	"github.com/vmvarela/iptablestutorial/internal/ui/castle"
	"github.com/vmvarela/iptablestutorial/internal/ui/console"
	"github.com/vmvarela/iptablestutorial/internal/ui/guards"
	"github.com/vmvarela/iptablestutorial/internal/ui/story"
	"github.com/vmvarela/iptablestutorial/internal/ui/theme"
	"github.com/vmvarela/iptablestutorial/internal/ui/trace"
)

// buildTopology construye un engine.Topology a partir de la configuración de red de un nivel.
// Añade todas las IPs de interfaz a LocalIPs para que el router multi-zona funcione.
func buildTopology(red levels.Red) *engine.Topology {
	firewallIP := netip.MustParseAddr("192.168.1.1")
	if red.FirewallIP != "" {
		if ip, err := netip.ParseAddr(red.FirewallIP); err == nil {
			firewallIP = ip
		}
	}

	topo := &engine.Topology{
		LocalIPs: []netip.Addr{firewallIP},
	}

	for _, ifaz := range red.Interfaces {
		pfx, err := netip.ParsePrefix(ifaz.CIDR)
		if err != nil {
			continue
		}
		iface := engine.Interface{
			Name:     ifaz.Nombre,
			Zone:     ifaz.Zona,
			Prefixes: []netip.Prefix{pfx},
		}
		// Si la interfaz tiene IP explícita, usarla; si no, detectar por el CIDR.
		if ifaz.IP != "" {
			if ip, err2 := netip.ParseAddr(ifaz.IP); err2 == nil {
				iface.IP = ip
				topo.LocalIPs = append(topo.LocalIPs, ip)
			}
		} else if pfx.Contains(firewallIP) {
			iface.IP = firewallIP
		}
		topo.Interfaces = append(topo.Interfaces, iface)
	}

	return topo
}

type layout int

const (
	layoutWide layout = iota
	layoutMedium
	layoutNarrow
)

type activePanel int

const (
	panelStory activePanel = iota
	panelCastle
	panelGuards
	panelConsole
	panelTrace
)

// cmdResultMsg carries the result of applying an iptables command.
type cmdResultMsg struct {
	command string
	err     error
}

// evalResultMsg carries the result of sending a packet through the evaluator.
type evalResultMsg struct {
	verdict engine.Verdict
	trace   engine.Trace
	packet  engine.Packet
}

// Model is the main Bubble Tea model for the game.
type Model struct {
	width, height int
	layout        layout
	zone          *zone.Manager

	// Game state
	rs       *engine.Ruleset
	ev       *engine.Evaluator
	levels   []*levels.Level
	levelIdx int
	prog     *progress.Progress
	store    progress.Store

	// Sub-models
	story   story.Model
	castle  castle.Model
	guards  guards.Model
	console console.Model
	trace   trace.Model

	// Active panel for tab navigation
	active activePanel

	// Last results
	lastVerdict   engine.Verdict
	lastTrace     engine.Trace
	pruebIdx      int
	levelComplete bool

	// UI state
	showHelp bool
}

// New creates the main model, loading levels and progress.
func New(store progress.Store) (Model, error) { //nolint:gocyclo // initialization handles all level fields
	prog, err := store.Load()
	if err != nil {
		return Model{}, fmt.Errorf("cargando progreso: %w", err)
	}

	allLevels, err := levels.LoadAll()
	if err != nil {
		return Model{}, fmt.Errorf("cargando niveles: %w", err)
	}
	if len(allLevels) == 0 {
		return Model{}, fmt.Errorf("no hay niveles disponibles")
	}

	levelIdx := prog.UnlockedUntil
	if levelIdx < 0 {
		levelIdx = 0
	}
	if levelIdx >= len(allLevels) {
		levelIdx = len(allLevels) - 1
	}

	lvl := allLevels[levelIdx]

	rs := engine.NewRuleset()
	for _, cmdStr := range lvl.ReglasIniciales {
		cmdStr = strings.TrimSpace(cmdStr)
		if cmdStr == "" {
			continue
		}
		cmd, err := engine.ParseLine(cmdStr)
		if err != nil {
			return Model{}, fmt.Errorf("parseando regla inicial %q: %w", cmdStr, err)
		}
		if err := engine.Apply(rs, cmd); err != nil {
			return Model{}, fmt.Errorf("aplicando regla inicial %q: %w", cmdStr, err)
		}
	}

	for chain, policyStr := range lvl.Politicas {
		var target engine.Target
		switch policyStr {
		case "ACCEPT":
			target = engine.Accept
		case "DROP":
			target = engine.Drop
		default:
			return Model{}, fmt.Errorf("política desconocida %q para cadena %s", policyStr, chain)
		}
		if err := rs.SetPolicy("filter", chain, target); err != nil {
			return Model{}, fmt.Errorf("estableciendo política %s/%s: %w", "filter", chain, err)
		}
	}

	topo := buildTopology(lvl.Red)
	ev := engine.NewEvaluator(rs, topo)

	zm := zone.New()

	m := Model{
		layout:   layoutNarrow,
		zone:     zm,
		rs:       rs,
		ev:       ev,
		levels:   allLevels,
		levelIdx: levelIdx,
		prog:     prog,
		store:    store,
		story:    story.New(),
		castle:   castle.New(),
		guards:   guards.New(rs),
		console:  console.New(),
		trace:    trace.New(),
		active:   panelStory,
	}

	m.story.SetLevel(lvl.Titulo, lvl.Cuento, lvl.Mision)
	m.story.SetPistas(lvl.Pistas)
	m.castle.SetLevel(lvl)

	// Record how many rules per chain were pre-loaded (so guards panel can mark them).
	initialCounts := snapshotRuleCounts(rs)
	(&m.guards).SetInitialCounts(initialCounts)

	initialDesc := ""
	if len(lvl.Pruebas) > 0 {
		initialDesc = lvl.Pruebas[0].Descripcion
	}
	m.trace.SetContext(0, len(lvl.Pruebas), initialDesc, lvl.Recompensa, false, levelIdx+1 < len(allLevels))

	return m, nil
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.story.Init(),
		m.castle.Init(),
		m.guards.Init(),
		m.console.Init(),
		m.trace.Init(),
	)
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) { //nolint:gocyclo,funlen // main Bubble Tea Update handles all message types
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.updateLayout()
		m.distributeSizes()

	case tea.KeyMsg:
		// When help overlay is open, consume keys (q still quits, esc/? close)
		if m.showHelp {
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case "esc", "?":
				m.showHelp = false
			}
			return m, nil
		}
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "?":
			m.showHelp = true
			return m, nil
		case "ctrl+e", "ctrl+p":
			return m, func() tea.Msg { return console.SendPacketMsg{} }
		case "right", "n":
			if m.levelComplete && m.levelIdx+1 < len(m.levels) {
				m.loadLevel(m.levelIdx + 1)
				return m, nil
			}
		case "tab":
			m.active = (m.active + 1) % 5
			m.updateFocus()
			return m, nil
		case "shift+tab":
			m.active = (m.active + 4) % 5
			m.updateFocus()
			return m, nil
		}

	case tea.MouseMsg:
		if m.zone != nil && msg.Action == tea.MouseActionRelease && msg.Button == tea.MouseButtonLeft {
			panels := []struct {
				id    string
				panel activePanel
			}{
				{"panel-0", panelStory},
				{"panel-1", panelCastle},
				{"panel-2", panelGuards},
				{"panel-3", panelConsole},
				{"panel-4", panelTrace},
			}
			for _, p := range panels {
				z := m.zone.Get(p.id)
				if z != nil && z.InBounds(msg) {
					m.active = p.panel
					m.updateFocus()
					return m, nil
				}
			}
		}

	case console.SubmitMsg:
		cmdStr := strings.TrimSpace(msg.Command)
		var result string
		var isError bool
		cmdParsed, err := engine.ParseLine(cmdStr)
		if err != nil {
			result = err.Error()
			isError = true
		} else {
			if err := engine.Apply(m.rs, cmdParsed); err != nil {
				result = err.Error()
				isError = true
			} else {
				result = "OK"
			}
		}
		(&m.console).AddLog(cmdStr, result, isError)
		(&m.guards).SetRuleset(m.rs)
		return m, nil

	case console.SendPacketMsg:
		return m, m.sendPacketCmd()

	case evalResultMsg:
		m.lastVerdict = msg.verdict
		m.lastTrace = msg.trace
		(&m.trace).SetTrace(msg.trace, msg.verdict, msg.packet)

		// Check if this prueba result matches expected and advance
		lvl := m.levels[m.levelIdx]
		esperado := ""
		passed := false
		if m.pruebIdx < len(lvl.Pruebas) {
			esperado = lvl.Pruebas[m.pruebIdx].Esperado
			var verdictStr string
			switch msg.verdict {
			case engine.VerdictAccept:
				verdictStr = "ACCEPT"
			case engine.VerdictDrop:
				verdictStr = "DROP"
			case engine.VerdictReject:
				verdictStr = "REJECT"
			}
			if verdictStr == esperado {
				passed = true
				m.pruebIdx++
				if m.pruebIdx >= len(lvl.Pruebas) {
					// All pruebas passed — level complete
					m.levelComplete = true
					m.pruebIdx = 0
					if m.prog != nil && m.levelIdx >= m.prog.UnlockedUntil {
						m.prog.UnlockedUntil = m.levelIdx + 1
						_ = m.store.Save(m.prog)
					}
				}
			}
		}
		(&m.trace).SetLastResult(esperado, passed)
		// Update trace context with current progress
		nextDesc := ""
		if !m.levelComplete && m.pruebIdx < len(lvl.Pruebas) {
			nextDesc = lvl.Pruebas[m.pruebIdx].Descripcion
		}
		(&m.trace).SetContext(m.pruebIdx, len(lvl.Pruebas), nextDesc, lvl.Recompensa, m.levelComplete, m.levelIdx+1 < len(m.levels))
		return m, nil

	case cmdResultMsg:
		if msg.err != nil {
			(&m.console).AddLog(msg.command, msg.err.Error(), true)
		} else {
			(&m.console).AddLog(msg.command, "OK", false)
		}
		(&m.guards).SetRuleset(m.rs)
		return m, nil
	}

	// Update sub-models
	var cmd tea.Cmd
	m.story, cmd = m.story.Update(msg)
	cmds = append(cmds, cmd)

	m.castle, cmd = m.castle.Update(msg)
	cmds = append(cmds, cmd)

	m.guards, cmd = m.guards.Update(msg)
	cmds = append(cmds, cmd)

	m.console, cmd = m.console.Update(msg)
	cmds = append(cmds, cmd)

	m.trace, cmd = m.trace.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

// View implements tea.Model.
func (m Model) View() string {
	if m.width == 0 || m.height == 0 {
		return "Cargando..."
	}
	if m.width < 80 || m.height < 24 {
		return m.viewTooSmall()
	}
	if m.showHelp {
		return m.viewHelp()
	}
	switch m.layout {
	case layoutWide:
		return m.viewWide()
	case layoutMedium:
		return m.viewMedium()
	default:
		return m.viewNarrow()
	}
}

func (m *Model) updateLayout() {
	switch {
	case m.width >= 120:
		m.layout = layoutWide
	case m.width >= 80:
		m.layout = layoutMedium
	default:
		m.layout = layoutNarrow
	}
}

func (m *Model) updateFocus() {
	m.console.Blur()
	if m.active == panelConsole {
		m.console.Focus()
	}
}

func (m *Model) distributeSizes() {
	switch m.layout {
	case layoutWide:
		topH := (m.height - 1) * 70 / 100
		botH := m.height - 1 - topH
		storyW := m.width * 30 / 100
		castleW := m.width * 40 / 100
		guardsW := m.width - storyW - castleW
		halfW := m.width / 2

		m.story.SetSize(storyW, topH)
		m.castle.SetSize(castleW, topH)
		m.guards.SetSize(guardsW, topH)
		m.console.SetSize(halfW, botH)
		m.trace.SetSize(halfW, botH)

	case layoutMedium:
		topH := (m.height - 1) * 40 / 100
		midH := (m.height - 1) * 40 / 100
		botH := m.height - 1 - topH - midH
		halfW := m.width / 2

		m.story.SetSize(halfW, topH)
		m.guards.SetSize(halfW, topH)
		m.castle.SetSize(halfW, midH)
		m.trace.SetSize(halfW, midH)
		m.console.SetSize(m.width, botH)

	case layoutNarrow:
		headerH := 1
		footerH := 1
		consoleH := 4
		panelH := m.height - headerH - consoleH - footerH
		if panelH < 5 {
			panelH = 5
		}

		m.story.SetSize(m.width, panelH)
		m.castle.SetSize(m.width, panelH)
		m.guards.SetSize(m.width, panelH)
		m.trace.SetSize(m.width, panelH)
		m.console.SetSize(m.width, consoleH)
	}
}

func (m Model) viewWide() string {
	topLeft := m.renderPanel(m.story.View(), panelStory)
	topCenter := m.renderPanel(m.castle.View(), panelCastle)
	topRight := m.renderPanel(m.guards.View(), panelGuards)
	botLeft := m.renderPanel(m.console.View(), panelConsole)
	botRight := m.renderPanel(m.trace.View(), panelTrace)

	topRow := lipgloss.JoinHorizontal(lipgloss.Top, topLeft, topCenter, topRight)
	botRow := lipgloss.JoinHorizontal(lipgloss.Top, botLeft, botRight)
	out := lipgloss.JoinVertical(lipgloss.Left, topRow, botRow, m.footer())
	if m.zone != nil {
		out = m.zone.Scan(out)
	}
	return out
}

func (m Model) viewMedium() string {
	topLeft := m.renderPanel(m.story.View(), panelStory)
	topRight := m.renderPanel(m.guards.View(), panelGuards)
	midLeft := m.renderPanel(m.castle.View(), panelCastle)
	midRight := m.renderPanel(m.trace.View(), panelTrace)
	bottom := m.renderPanel(m.console.View(), panelConsole)

	topRow := lipgloss.JoinHorizontal(lipgloss.Top, topLeft, topRight)
	midRow := lipgloss.JoinHorizontal(lipgloss.Top, midLeft, midRight)
	out := lipgloss.JoinVertical(lipgloss.Left, topRow, midRow, bottom, m.footer())
	if m.zone != nil {
		out = m.zone.Scan(out)
	}
	return out
}

func (m Model) viewNarrow() string {
	panelNames := [5]string{"Historia", "Castillo", "Guardias", "Consola", "Rastro"}
	header := theme.TitleStyle.Render("Silvia") + theme.MutedStyle.Render(" — ") +
		m.levels[m.levelIdx].Titulo +
		theme.MutedStyle.Render(" · ") +
		theme.InfoStyle.Render(panelNames[m.active]) +
		theme.MutedStyle.Render(" [Tab]")
	var panel string
	switch m.active {
	case panelStory:
		panel = m.renderPanel(m.story.View(), panelStory)
	case panelCastle:
		panel = m.renderPanel(m.castle.View(), panelCastle)
	case panelGuards:
		panel = m.renderPanel(m.guards.View(), panelGuards)
	case panelTrace:
		panel = m.renderPanel(m.trace.View(), panelTrace)
	case panelConsole:
		panel = m.renderPanel(m.console.View(), panelConsole)
	}
	var out string
	if m.active == panelConsole {
		out = lipgloss.JoinVertical(lipgloss.Left, header, panel, m.footer())
	} else {
		bottom := m.renderPanel(m.console.View(), panelConsole)
		out = lipgloss.JoinVertical(lipgloss.Left, header, panel, bottom, m.footer())
	}
	if m.zone != nil {
		out = m.zone.Scan(out)
	}
	return out
}

func (m Model) renderPanel(content string, p activePanel) string {
	style := theme.PanelStyle
	if m.active == p {
		style = theme.ActivePanelStyle
	} else {
		content = theme.DimStyle.Render(content)
	}
	if m.zone != nil {
		id := fmt.Sprintf("panel-%d", p)
		content = m.zone.Mark(id, content)
	}
	return style.Render(content)
}

// loadLevel resets all game state and loads the level at the given index.
func (m *Model) loadLevel(idx int) {
	if idx < 0 || idx >= len(m.levels) {
		return
	}
	lvl := m.levels[idx]
	m.levelIdx = idx
	m.pruebIdx = 0
	m.levelComplete = false

	// Re-build ruleset and evaluator for the new level.
	rs := engine.NewRuleset()
	for _, cmdStr := range lvl.ReglasIniciales {
		cmdStr = strings.TrimSpace(cmdStr)
		if cmdStr == "" {
			continue
		}
		cmd, err := engine.ParseLine(cmdStr)
		if err != nil {
			continue
		}
		_ = engine.Apply(rs, cmd)
	}
	for chain, policyStr := range lvl.Politicas {
		var target engine.Target
		switch policyStr {
		case "ACCEPT":
			target = engine.Accept
		case "DROP":
			target = engine.Drop
		default:
			continue
		}
		_ = rs.SetPolicy("filter", chain, target)
	}
	topo := buildTopology(lvl.Red)

	m.rs = rs
	m.ev = engine.NewEvaluator(rs, topo)

	// Reset sub-models.
	m.story = story.New()
	m.castle = castle.New()
	m.guards = guards.New(rs)
	m.console = console.New()
	m.trace = trace.New()

	m.story.SetLevel(lvl.Titulo, lvl.Cuento, lvl.Mision)
	m.story.SetPistas(lvl.Pistas)
	m.castle.SetLevel(lvl)

	initialCounts := snapshotRuleCounts(rs)
	(&m.guards).SetInitialCounts(initialCounts)

	initialDesc := ""
	if len(lvl.Pruebas) > 0 {
		initialDesc = lvl.Pruebas[0].Descripcion
	}
	m.trace.SetContext(0, len(lvl.Pruebas), initialDesc, lvl.Recompensa, false, idx+1 < len(m.levels))

	m.active = panelStory
	m.updateFocus()
	m.distributeSizes()
}

func (m Model) sendPacketCmd() tea.Cmd {
	return func() tea.Msg {
		lvl := m.levels[m.levelIdx]
		if len(lvl.Pruebas) == 0 {
			return evalResultMsg{
				verdict: engine.VerdictContinue,
				trace:   engine.Trace{},
				packet:  engine.Packet{},
			}
		}
		idx := m.pruebIdx
		if idx >= len(lvl.Pruebas) {
			idx = 0
		}
		p := lvl.Pruebas[idx]
		srcIP, err := netip.ParseAddr(p.SrcIP)
		if err != nil {
			srcIP = netip.Addr{}
		}
		dstIP, err := netip.ParseAddr(p.DstIP)
		if err != nil {
			dstIP = netip.Addr{}
		}
		proto, _ := engine.ParseProto(p.Proto)
		state, err := engine.ParseConnStates(p.Estado)
		if err != nil {
			state = 0
		}
		pkt := engine.Packet{
			SrcIP:    srcIP,
			DstIP:    dstIP,
			DstPort:  uint16(p.DstPort), //nolint:gosec // value is a validated port number 0-65535
			Proto:    proto,
			State:    state,
			InIface:  p.InIface,
			OutIface: p.OutIface,
		}
		ctx := context.Background()
		verdict, tr, err := m.ev.Send(ctx, pkt)
		_ = err // Ignore evaluator errors for MVP.
		return evalResultMsg{
			verdict: verdict,
			trace:   tr,
			packet:  pkt,
		}
	}
}

// footer returns a single-line contextual help bar.
func (m Model) footer() string {
	parts := []string{}
	if m.levelComplete {
		if m.levelIdx+1 < len(m.levels) {
			parts = append(parts, theme.SuccessStyle.Render("[→/n]")+" siguiente nivel")
		} else {
			parts = append(parts, theme.SuccessStyle.Render("¡Juego completado!"))
		}
	} else {
		switch m.active {
		case panelConsole:
			parts = append(parts, theme.MutedStyle.Render("[Enter]")+" ejecutar")
			parts = append(parts, theme.MutedStyle.Render("[Ctrl+E]")+" enviar mensajero")
		case panelGuards, panelTrace:
			parts = append(parts, theme.MutedStyle.Render("[j/k]")+" scroll")
		case panelStory:
			parts = append(parts, theme.MutedStyle.Render("[↑/↓]")+" scroll")
		}
		parts = append(parts,
			theme.MutedStyle.Render("[Tab]")+" foco",
			theme.MutedStyle.Render("[Ctrl+E]")+" mensajero",
		)
	}
	parts = append(parts,
		theme.MutedStyle.Render("[q]")+" salir",
		theme.MutedStyle.Render("[?]")+" ayuda",
	)
	return strings.Join(parts, "  ")
}

// viewTooSmall renders a message when the terminal is below minimum size.
func (m Model) viewTooSmall() string {
	msg := theme.DangerStyle.Render("Terminal demasiado pequeña") + "\n" +
		theme.MutedStyle.Render("Mínimo requerido: 80×24 — actual: ") +
		fmt.Sprintf("%d×%d", m.width, m.height)
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, msg)
}

// viewHelp renders the full-screen help overlay.
func (m Model) viewHelp() string {
	content := strings.Join([]string{
		theme.TitleStyle.Render("Atajos de Teclado"),
		"",
		theme.InfoStyle.Render("Global"),
		"  " + theme.AccentStyle.Render("[Tab] / [Shift+Tab]") + "  Cambiar panel activo",
		"  " + theme.AccentStyle.Render("[Ctrl+E]") + "             Enviar mensajero de prueba",
		"  " + theme.AccentStyle.Render("[→ / n]") + "             Siguiente nivel (al completar)",
		"  " + theme.AccentStyle.Render("[q]") + "                  Salir",
		"  " + theme.AccentStyle.Render("[?]") + "                  Abrir/cerrar esta ayuda",
		"",
		theme.InfoStyle.Render("Historia / Rastro / Guardias"),
		"  " + theme.AccentStyle.Render("[j] / [↓]") + "            Desplazar hacia abajo",
		"  " + theme.AccentStyle.Render("[k] / [↑]") + "            Desplazar hacia arriba",
		"",
		theme.InfoStyle.Render("Consola"),
		"  " + theme.AccentStyle.Render("[Enter]") + "               Ejecutar comando iptables",
		"  " + theme.AccentStyle.Render("[Ctrl+E]") + "              Enviar mensajero de prueba",
		`  ` + theme.AccentStyle.Render(`"enviar mensajero"`) + `    Alias para enviar mensajero`,
		"",
		theme.MutedStyle.Render("Pulsa [?] o [Esc] para cerrar"),
	}, "\n")

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(theme.ColorAccent).
		Padding(1, 3).
		Render(content)

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
}

// snapshotRuleCounts returns how many rules each chain currently has.
// Used to distinguish pre-loaded rules from user-added ones in the guards panel.
func snapshotRuleCounts(rs *engine.Ruleset) map[string]int {
	counts := map[string]int{}
	for _, cc := range []struct{ t, c string }{
		{"filter", "INPUT"},
		{"filter", "OUTPUT"},
		{"filter", "FORWARD"},
	} {
		if ch, ok := rs.Chain(cc.t, cc.c); ok && len(ch.Rules) > 0 {
			counts[cc.t+"/"+cc.c] = len(ch.Rules)
		}
	}
	return counts
}
