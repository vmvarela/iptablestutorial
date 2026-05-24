package engine

// Chain es una cadena de reglas con una política por defecto opcional.
//
// Las cadenas predefinidas (INPUT, OUTPUT, FORWARD, PREROUTING, POSTROUTING)
// tienen siempre una política. Las cadenas de usuario tienen Policy == nil.
type Chain struct {
	Name    string
	Policy  Target // nil en cadenas de usuario
	Rules   []Rule
	Builtin bool // true si es una cadena predefinida
}

// NewBuiltinChain crea una cadena predefinida con la política dada.
func NewBuiltinChain(name string, policy Target) *Chain {
	return &Chain{
		Name:    name,
		Policy:  policy,
		Builtin: true,
	}
}

// NewUserChain crea una cadena de usuario (sin política).
func NewUserChain(name string) *Chain {
	return &Chain{
		Name:    name,
		Builtin: false,
	}
}

// RuleCount devuelve el número de reglas en la cadena.
func (c *Chain) RuleCount() int { return len(c.Rules) }

// clone devuelve una copia profunda de la cadena.
func (c *Chain) clone() *Chain {
	nc := &Chain{
		Name:    c.Name,
		Policy:  c.Policy,
		Builtin: c.Builtin,
		Rules:   make([]Rule, len(c.Rules)),
	}
	for i, r := range c.Rules {
		// Matchers son inmutables por diseño (punteros a structs no compartidos).
		nr := Rule{
			Target:   r.Target,
			Comment:  r.Comment,
			Matchers: make([]Matcher, len(r.Matchers)),
		}
		copy(nr.Matchers, r.Matchers)
		nc.Rules[i] = nr
	}
	return nc
}
