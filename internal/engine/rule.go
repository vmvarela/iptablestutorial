package engine

// Rule es una regla de iptables: una lista ordenada de matchers y un objetivo.
//
// Una regla matchea un paquete cuando TODOS sus matchers devuelven true.
// Si no hay matchers, la regla siempre matchea (equivale a -j TARGET sin condiciones).
type Rule struct {
	Matchers []Matcher
	Target   Target
	Comment  string // comentario opcional visible en la UI
}

// Matches devuelve true si el paquete satisface todos los matchers de la regla.
func (r Rule) Matches(pkt Packet) bool {
	for _, m := range r.Matchers {
		if !m.Matches(pkt) {
			return false
		}
	}
	return true
}

// Equal devuelve true si dos reglas son equivalentes (mismos matchers y objetivo).
// Usado por DeleteBySpec para encontrar la primera regla idéntica.
func (r Rule) Equal(other Rule) bool {
	if len(r.Matchers) != len(other.Matchers) {
		return false
	}
	if r.Target.String() != other.Target.String() {
		return false
	}
	for i, m := range r.Matchers {
		if m.String() != other.Matchers[i].String() {
			return false
		}
	}
	return true
}
