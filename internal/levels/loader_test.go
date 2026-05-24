package levels

import (
	"errors"
	"testing"
)

func TestLoadAll(t *testing.T) {
	levels, err := LoadAll()
	if err != nil {
		t.Fatalf("LoadAll() error = %v", err)
	}
	if len(levels) != 8 {
		t.Fatalf("LoadAll() len = %d, want 8", len(levels))
	}
	for _, lvl := range levels {
		if lvl.ID == "" {
			t.Errorf("level with empty ID")
		}
	}
}

func TestGet_Found(t *testing.T) {
	lvl, err := Get("01-observar")
	if err != nil {
		t.Fatalf("Get(\"01-observar\") error = %v", err)
	}
	if lvl.Titulo == "" {
		t.Errorf("Get(\"01-observar\") Titulo empty")
	}
}

func TestGet_NotFound(t *testing.T) {
	_, err := Get("no-existe")
	if err == nil {
		t.Fatalf("Get(\"no-existe\") expected error, got nil")
	}
	if !errors.Is(err, ErrLevelNotFound) {
		t.Fatalf("Get(\"no-existe\") error = %v, want wrap ErrLevelNotFound", err)
	}
}
