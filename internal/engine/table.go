package engine

// Table agrupa las cadenas de una tabla iptables (filter, nat, …).
type Table struct {
	Name   string
	Chains map[string]*Chain
}

// newFilterTable crea la tabla filter con sus cadenas predefinidas (política ACCEPT).
func newFilterTable() *Table {
	t := &Table{
		Name:   "filter",
		Chains: make(map[string]*Chain),
	}
	t.Chains["INPUT"] = NewBuiltinChain("INPUT", Accept)
	t.Chains["OUTPUT"] = NewBuiltinChain("OUTPUT", Accept)
	t.Chains["FORWARD"] = NewBuiltinChain("FORWARD", Accept)
	return t
}

// newNATTable crea la tabla nat con sus cadenas predefinidas.
func newNATTable() *Table {
	t := &Table{
		Name:   "nat",
		Chains: make(map[string]*Chain),
	}
	t.Chains["PREROUTING"] = NewBuiltinChain("PREROUTING", Accept)
	t.Chains["OUTPUT"] = NewBuiltinChain("OUTPUT", Accept)
	t.Chains["POSTROUTING"] = NewBuiltinChain("POSTROUTING", Accept)
	return t
}

// clone devuelve una copia profunda de la tabla.
func (t *Table) clone() *Table {
	nt := &Table{
		Name:   t.Name,
		Chains: make(map[string]*Chain, len(t.Chains)),
	}
	for k, v := range t.Chains {
		nt.Chains[k] = v.clone()
	}
	return nt
}
