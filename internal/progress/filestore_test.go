package progress

import (
	"path/filepath"
	"testing"
)

func TestFileStoreRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("save and load", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		fs, err := NewFileStoreAt(filepath.Join(dir, "progreso.json"))
		if err != nil {
			t.Fatalf("creating filestore: %v", err)
		}

		want := &Progress{
			UnlockedUntil: 3,
			Completed:     []string{"aventura-1", "aventura-2"},
		}

		if err := fs.Save(want); err != nil {
			t.Fatalf("saving progress: %v", err)
		}

		got, err := fs.Load()
		if err != nil {
			t.Fatalf("loading progress: %v", err)
		}

		if got.UnlockedUntil != want.UnlockedUntil {
			t.Errorf("UnlockedUntil = %d, want %d", got.UnlockedUntil, want.UnlockedUntil)
		}
		if len(got.Completed) != len(want.Completed) {
			t.Errorf("Completed = %v, want %v", got.Completed, want.Completed)
		} else {
			for i := range want.Completed {
				if got.Completed[i] != want.Completed[i] {
					t.Errorf("Completed[%d] = %q, want %q", i, got.Completed[i], want.Completed[i])
				}
			}
		}
	})

	t.Run("fresh start", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		fs, err := NewFileStoreAt(filepath.Join(dir, "nonexistent.json"))
		if err != nil {
			t.Fatalf("creating filestore: %v", err)
		}

		got, err := fs.Load()
		if err != nil {
			t.Fatalf("loading progress: %v", err)
		}

		if got.UnlockedUntil != 0 {
			t.Errorf("UnlockedUntil = %d, want 0", got.UnlockedUntil)
		}
		if len(got.Completed) != 0 {
			t.Errorf("Completed = %v, want empty", got.Completed)
		}
	})
}
