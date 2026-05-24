package engine

import "fmt"

// Ruleset contiene el conjunto completo de tablas y cadenas del firewall simulado.
//
// No es seguro para uso concurrente; el llamador debe sincronizar el acceso
// si varios goroutines lo usan (en la práctica el Update de Bubble Tea es
// secuencial, por lo que no se necesita sincronización adicional).
type Ruleset struct {
	tables map[string]*Table
}

// NewRuleset crea un Ruleset con las tablas filter y nat inicializadas
// con sus cadenas predefinidas y política ACCEPT.
func NewRuleset() *Ruleset {
	rs := &Ruleset{tables: make(map[string]*Table)}
	rs.tables["filter"] = newFilterTable()
	rs.tables["nat"] = newNATTable()
	return rs
}

// Reset restablece el Ruleset a su estado inicial (políticas ACCEPT, sin reglas).
func (rs *Ruleset) Reset() {
	rs.tables["filter"] = newFilterTable()
	rs.tables["nat"] = newNATTable()
}

// Clone devuelve una copia profunda del Ruleset.
func (rs *Ruleset) Clone() *Ruleset {
	nrs := &Ruleset{tables: make(map[string]*Table, len(rs.tables))}
	for k, v := range rs.tables {
		nrs.tables[k] = v.clone()
	}
	return nrs
}

// table devuelve la tabla solicitada o ErrTableNotFound.
func (rs *Ruleset) table(name string) (*Table, error) {
	t, ok := rs.tables[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrTableNotFound, name)
	}
	return t, nil
}

// GetChain devuelve la cadena solicitada o un error si no existe.
func (rs *Ruleset) GetChain(table, chain string) (*Chain, error) {
	t, err := rs.table(table)
	if err != nil {
		return nil, err
	}
	c, ok := t.Chains[chain]
	if !ok {
		return nil, fmt.Errorf("%w: %s/%s", ErrChainNotFound, table, chain)
	}
	return c, nil
}

// Chain devuelve la cadena y un bool indicando si existe.
func (rs *Ruleset) Chain(table, chain string) (*Chain, bool) {
	t, ok := rs.tables[table]
	if !ok {
		return nil, false
	}
	c, ok := t.Chains[chain]
	return c, ok
}

// AppendRule añade una regla al final de la cadena.
func (rs *Ruleset) AppendRule(table, chain string, r Rule) error {
	c, err := rs.GetChain(table, chain)
	if err != nil {
		return err
	}
	c.Rules = append(c.Rules, r)
	return nil
}

// InsertRule inserta una regla en la posición pos (1-based como en iptables).
// pos == 1 inserta al principio; pos == 0 equivale a AppendRule.
func (rs *Ruleset) InsertRule(table, chain string, pos int, r Rule) error {
	c, err := rs.GetChain(table, chain)
	if err != nil {
		return err
	}
	if pos <= 0 || pos > len(c.Rules)+1 {
		// Fuera de rango → insertar al principio (comportamiento de iptables -I sin pos)
		pos = 1
	}
	idx := pos - 1
	c.Rules = append(c.Rules, Rule{}) // ampliar
	copy(c.Rules[idx+1:], c.Rules[idx:])
	c.Rules[idx] = r
	return nil
}

// DeleteByIndex borra la regla en la posición idx (0-based).
func (rs *Ruleset) DeleteByIndex(table, chain string, idx int) error {
	c, err := rs.GetChain(table, chain)
	if err != nil {
		return err
	}
	if idx < 0 || idx >= len(c.Rules) {
		return fmt.Errorf("%w: índice %d en %s/%s (tiene %d reglas)",
			ErrRuleOutOfRange, idx, table, chain, len(c.Rules))
	}
	c.Rules = append(c.Rules[:idx], c.Rules[idx+1:]...)
	return nil
}

// DeleteBySpec borra la primera regla que sea igual a r.
func (rs *Ruleset) DeleteBySpec(table, chain string, r Rule) error {
	c, err := rs.GetChain(table, chain)
	if err != nil {
		return err
	}
	for i, existing := range c.Rules {
		if existing.Equal(r) {
			c.Rules = append(c.Rules[:i], c.Rules[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("%w: regla no encontrada en %s/%s", ErrRuleOutOfRange, table, chain)
}

// ReplaceRule reemplaza la regla en la posición idx (0-based).
func (rs *Ruleset) ReplaceRule(table, chain string, idx int, r Rule) error {
	c, err := rs.GetChain(table, chain)
	if err != nil {
		return err
	}
	if idx < 0 || idx >= len(c.Rules) {
		return fmt.Errorf("%w: índice %d en %s/%s", ErrRuleOutOfRange, idx, table, chain)
	}
	c.Rules[idx] = r
	return nil
}

// FlushChain elimina todas las reglas de una cadena.
func (rs *Ruleset) FlushChain(table, chain string) error {
	c, err := rs.GetChain(table, chain)
	if err != nil {
		return err
	}
	c.Rules = nil
	return nil
}

// FlushAllChains elimina todas las reglas de todas las cadenas de una tabla.
func (rs *Ruleset) FlushAllChains(table string) error {
	t, err := rs.table(table)
	if err != nil {
		return err
	}
	for _, c := range t.Chains {
		c.Rules = nil
	}
	return nil
}

// SetPolicy establece la política por defecto de una cadena predefinida.
// Solo se permiten ACCEPT y DROP como políticas.
func (rs *Ruleset) SetPolicy(table, chain string, target Target) error {
	c, err := rs.GetChain(table, chain)
	if err != nil {
		return err
	}
	if !c.Builtin {
		return fmt.Errorf("%w: %s no es una cadena predefinida", ErrInvalidPolicy, chain)
	}
	switch target.String() {
	case "ACCEPT", "DROP":
		c.Policy = target
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrInvalidPolicy, target.String())
	}
}

// NewChain crea una nueva cadena de usuario en la tabla indicada.
func (rs *Ruleset) NewChain(table, chain string) error {
	t, err := rs.table(table)
	if err != nil {
		return err
	}
	if _, exists := t.Chains[chain]; exists {
		return fmt.Errorf("%w: %s", ErrChainExists, chain)
	}
	t.Chains[chain] = NewUserChain(chain)
	return nil
}

// DeleteChain borra una cadena de usuario vacía.
func (rs *Ruleset) DeleteChain(table, chain string) error {
	t, err := rs.table(table)
	if err != nil {
		return err
	}
	c, ok := t.Chains[chain]
	if !ok {
		return fmt.Errorf("%w: %s", ErrChainNotFound, chain)
	}
	if c.Builtin {
		return fmt.Errorf("%w: %s", ErrBuiltinChain, chain)
	}
	if len(c.Rules) > 0 {
		return fmt.Errorf("%w: %s", ErrChainNotEmpty, chain)
	}
	delete(t.Chains, chain)
	return nil
}

// Rules devuelve una copia de las reglas de una cadena.
func (rs *Ruleset) Rules(table, chain string) ([]Rule, error) {
	c, err := rs.GetChain(table, chain)
	if err != nil {
		return nil, err
	}
	result := make([]Rule, len(c.Rules))
	copy(result, c.Rules)
	return result, nil
}

// Tables devuelve los nombres de las tablas disponibles.
func (rs *Ruleset) Tables() []string {
	names := make([]string, 0, len(rs.tables))
	for k := range rs.tables {
		names = append(names, k)
	}
	return names
}
