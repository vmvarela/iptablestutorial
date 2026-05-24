package progress

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// FileStore persists progress to a JSON file.
type FileStore struct {
	path string
}

// NewFileStore creates a FileStore that saves to the default config path.
// The path is os.UserConfigDir() + "/silvia-castillo/progreso.json".
// The parent directory is created if it does not exist.
func NewFileStore() (*FileStore, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("getting user config dir: %w", err)
	}
	p := filepath.Join(dir, "silvia-castillo", "progreso.json")
	return newFileStoreAt(p)
}

// NewFileStoreAt creates a FileStore that saves to the given path.
// The parent directory is created if it does not exist.
func NewFileStoreAt(path string) (*FileStore, error) {
	return newFileStoreAt(path)
}

func newFileStoreAt(path string) (*FileStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("creating config directory: %w", err)
	}
	return &FileStore{path: path}, nil
}

// Load reads the progress from disk. If the file does not exist, it returns a
// fresh Progress with UnlockedUntil set to 0 and an empty Completed slice.
func (fs *FileStore) Load() (*Progress, error) {
	data, err := os.ReadFile(fs.path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Progress{UnlockedUntil: 0, Completed: []string{}}, nil
		}
		return nil, fmt.Errorf("reading progress file: %w", err)
	}
	var p Progress
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("unmarshaling progress: %w", err)
	}
	return &p, nil
}

// Save writes the progress to disk atomically using a temporary file and rename.
func (fs *FileStore) Save(p *Progress) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling progress: %w", err)
	}
	tmp := fs.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := os.Rename(tmp, fs.path); err != nil {
		return fmt.Errorf("renaming temp file: %w", err)
	}
	return nil
}
