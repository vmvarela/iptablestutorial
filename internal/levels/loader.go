package levels

import (
	"errors"
	"fmt"
	"sort"

	"embed"

	"gopkg.in/yaml.v3"
)

//go:embed data/*.yaml
var dataFS embed.FS

// ErrLevelNotFound se devuelve cuando no existe un nivel con el ID solicitado.
var ErrLevelNotFound = errors.New("nivel no encontrado")

// LoadAll carga todos los niveles embebidos, ordenados por nombre de archivo.
func LoadAll() ([]*Level, error) {
	entries, err := dataFS.ReadDir("data")
	if err != nil {
		return nil, fmt.Errorf("leyendo directorio data: %w", err)
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	var levels []*Level
	for _, name := range names {
		b, err := dataFS.ReadFile("data/" + name)
		if err != nil {
			return nil, fmt.Errorf("leyendo %s: %w", name, err)
		}
		lvl, err := loadOne(b)
		if err != nil {
			return nil, fmt.Errorf("parseando %s: %w", name, err)
		}
		levels = append(levels, lvl)
	}
	return levels, nil
}

// Get devuelve un nivel concreto por su ID.
// Si no existe, devuelve ErrLevelNotFound.
func Get(id string) (*Level, error) {
	all, err := LoadAll()
	if err != nil {
		return nil, err
	}
	for _, lvl := range all {
		if lvl.ID == id {
			return lvl, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrLevelNotFound, id)
}

// loadOne parsea un único archivo YAML en una estructura Level.
func loadOne(data []byte) (*Level, error) {
	var lvl Level
	if err := yaml.Unmarshal(data, &lvl); err != nil {
		return nil, err
	}
	return &lvl, nil
}
