package progress

// Progress tracks the player's progress through adventures.
type Progress struct {
	UnlockedUntil int      `json:"unlocked_until"` // max adventure index unlocked (0-based)
	Completed     []string `json:"completed"`       // slice of completed adventure IDs
}

// Store is the interface for persisting progress.
type Store interface {
	Load() (*Progress, error)
	Save(p *Progress) error
}
