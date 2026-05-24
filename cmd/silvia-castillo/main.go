// Silvia y el Castillo de las Reglas — entrada principal.
package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	zone "github.com/lrstanley/bubblezone"

	"github.com/vmvarela/iptablestutorial/internal/app"
	"github.com/vmvarela/iptablestutorial/internal/progress"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	store, err := progress.NewFileStore()
	if err != nil {
		return fmt.Errorf("error al cargar progreso: %w", err)
	}

	m, err := app.New(store)
	if err != nil {
		return fmt.Errorf("error al inicializar: %w", err)
	}

	z := zone.New()
	defer z.Close()

	p := tea.NewProgram(
		m,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	if _, err := p.Run(); err != nil {
		return fmt.Errorf("error: %w", err)
	}
	return nil
}
