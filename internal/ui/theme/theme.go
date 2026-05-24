// Package theme defines the color palette and lipgloss styles for the game.
package theme

import "github.com/charmbracelet/lipgloss"

// Color palette — castle/medieval theme.
// NO_COLOR is respected automatically via termenv/lipgloss.
var (
	ColorAccent     = lipgloss.AdaptiveColor{Light: "3", Dark: "#FFD700"}  // gold
	ColorSuccess    = lipgloss.AdaptiveColor{Light: "2", Dark: "#00FF88"}  // green
	ColorDanger     = lipgloss.AdaptiveColor{Light: "1", Dark: "#FF4444"}   // red
	ColorInfo       = lipgloss.AdaptiveColor{Light: "4", Dark: "#4488FF"}  // blue
	ColorMuted      = lipgloss.AdaptiveColor{Light: "8", Dark: "#888888"}  // gray
	ColorBorder     = lipgloss.AdaptiveColor{Light: "8", Dark: "#666666"}
	ColorTitle      = lipgloss.AdaptiveColor{Light: "3", Dark: "#FFA500"}  // orange
	ColorBackground = lipgloss.AdaptiveColor{Light: "15", Dark: "#1a1a2e"}
	ColorText       = lipgloss.AdaptiveColor{Light: "0", Dark: "#e0e0e0"}
)

// Panel styles
var (
	PanelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorBorder).
			Padding(0, 1)

	ActivePanelStyle = PanelStyle.
				BorderForeground(ColorAccent)

	TitleStyle = lipgloss.NewStyle().
			Foreground(ColorTitle).
			Bold(true)

	SuccessStyle = lipgloss.NewStyle().Foreground(ColorSuccess)
	DangerStyle  = lipgloss.NewStyle().Foreground(ColorDanger)
	InfoStyle    = lipgloss.NewStyle().Foreground(ColorInfo)
	MutedStyle   = lipgloss.NewStyle().Foreground(ColorMuted)
	AccentStyle  = lipgloss.NewStyle().Foreground(ColorAccent)

	// DimStyle applies a faint/dim effect for inactive panels without overriding hue.
	DimStyle = lipgloss.NewStyle().Faint(true)

	// BaseStyle is the application background used to fill the terminal.
	BaseStyle = lipgloss.NewStyle().
			Background(ColorBackground).
			Foreground(ColorText)
)
