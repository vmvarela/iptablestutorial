package engine

import (
	"net/netip"
	"strings"
)

// Matcher determina si un paquete cumple un criterio de regla.
type Matcher interface {
	// Matches devuelve true si el paquete satisface este criterio.
	Matches(pkt Packet) bool
	// String devuelve la representación CLI del matcher (p.ej. "-s 10.0.0.0/24").
	String() string
}

// Compile-time interface checks.
var (
	_ Matcher = (*SrcIPMatcher)(nil)
	_ Matcher = (*DstIPMatcher)(nil)
	_ Matcher = (*ProtoMatcher)(nil)
	_ Matcher = (*SrcPortMatcher)(nil)
	_ Matcher = (*DstPortMatcher)(nil)
	_ Matcher = (*InIfaceMatcher)(nil)
	_ Matcher = (*OutIfaceMatcher)(nil)
	_ Matcher = (*StateMatcher)(nil)
)

// ---- IP matchers ----------------------------------------------------------

// SrcIPMatcher hace match por IP/CIDR origen.
type SrcIPMatcher struct {
	Prefix netip.Prefix
	Negate bool
}

// Matches returns true if the packet's source IP matches the prefix.
func (m *SrcIPMatcher) Matches(pkt Packet) bool {
	ok := m.Prefix.Contains(pkt.SrcIP)
	if m.Negate {
		return !ok
	}
	return ok
}
func (m *SrcIPMatcher) String() string {
	neg := ""
	if m.Negate {
		neg = "! "
	}
	return neg + "-s " + m.Prefix.String()
}

// DstIPMatcher hace match por IP/CIDR destino.
type DstIPMatcher struct {
	Prefix netip.Prefix
	Negate bool
}

// Matches returns true if the packet's destination IP matches the prefix.
func (m *DstIPMatcher) Matches(pkt Packet) bool {
	ok := m.Prefix.Contains(pkt.DstIP)
	if m.Negate {
		return !ok
	}
	return ok
}
func (m *DstIPMatcher) String() string {
	neg := ""
	if m.Negate {
		neg = "! "
	}
	return neg + "-d " + m.Prefix.String()
}

// ---- Protocol matcher ----------------------------------------------------

// ProtoMatcher hace match por protocolo.
type ProtoMatcher struct {
	Proto  Proto
	Negate bool
}

// Matches returns true if the packet's protocol matches.
func (m *ProtoMatcher) Matches(pkt Packet) bool {
	// ProtoAll matchea cualquier protocolo.
	if m.Proto == ProtoAll {
		return !m.Negate
	}
	ok := pkt.Proto == m.Proto
	if m.Negate {
		return !ok
	}
	return ok
}
func (m *ProtoMatcher) String() string {
	neg := ""
	if m.Negate {
		neg = "! "
	}
	return neg + "-p " + m.Proto.String()
}

// ---- Port matchers -------------------------------------------------------

// SrcPortMatcher hace match por rango de puerto origen.
type SrcPortMatcher struct {
	Lo, Hi uint16 // Lo == Hi para un puerto único
	Negate bool
}

// Matches returns true if the packet's source port is within the range.
func (m *SrcPortMatcher) Matches(pkt Packet) bool {
	ok := pkt.SrcPort >= m.Lo && pkt.SrcPort <= m.Hi
	if m.Negate {
		return !ok
	}
	return ok
}
func (m *SrcPortMatcher) String() string {
	neg := ""
	if m.Negate {
		neg = "! "
	}
	if m.Lo == m.Hi {
		return neg + "--sport " + itoa(int(m.Lo))
	}
	return neg + "--sport " + itoa(int(m.Lo)) + ":" + itoa(int(m.Hi))
}

// DstPortMatcher hace match por rango de puerto destino.
type DstPortMatcher struct {
	Lo, Hi uint16
	Negate bool
}

// Matches returns true if the packet's destination port is within the range.
func (m *DstPortMatcher) Matches(pkt Packet) bool {
	ok := pkt.DstPort >= m.Lo && pkt.DstPort <= m.Hi
	if m.Negate {
		return !ok
	}
	return ok
}
func (m *DstPortMatcher) String() string {
	neg := ""
	if m.Negate {
		neg = "! "
	}
	if m.Lo == m.Hi {
		return neg + "--dport " + itoa(int(m.Lo))
	}
	return neg + "--dport " + itoa(int(m.Lo)) + ":" + itoa(int(m.Hi))
}

// ---- Interface matchers --------------------------------------------------

// InIfaceMatcher hace match por interfaz de entrada. Soporta wildcard con '*'.
type InIfaceMatcher struct {
	Iface  string
	Negate bool
}

// Matches returns true if the packet's input interface matches the pattern.
func (m *InIfaceMatcher) Matches(pkt Packet) bool {
	ok := ifaceMatches(pkt.InIface, m.Iface)
	if m.Negate {
		return !ok
	}
	return ok
}
func (m *InIfaceMatcher) String() string {
	neg := ""
	if m.Negate {
		neg = "! "
	}
	return neg + "-i " + m.Iface
}

// OutIfaceMatcher hace match por interfaz de salida. Soporta wildcard con '*'.
type OutIfaceMatcher struct {
	Iface  string
	Negate bool
}

// Matches returns true if the packet's output interface matches the pattern.
func (m *OutIfaceMatcher) Matches(pkt Packet) bool {
	ok := ifaceMatches(pkt.OutIface, m.Iface)
	if m.Negate {
		return !ok
	}
	return ok
}
func (m *OutIfaceMatcher) String() string {
	neg := ""
	if m.Negate {
		neg = "! "
	}
	return neg + "-o " + m.Iface
}

// ifaceMatches comprueba si una interfaz concreta coincide con un patrón
// que puede terminar en '*' como wildcard.
func ifaceMatches(iface, pattern string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(iface, pattern[:len(pattern)-1])
	}
	return iface == pattern
}

// ---- State matcher -------------------------------------------------------

// StateMatcher hace match por máscara de estados conntrack.
type StateMatcher struct {
	States ConnState // máscara de bits; basta con que uno coincida
	Negate bool
}

// Matches returns true if the packet's conntrack state overlaps with the mask.
func (m *StateMatcher) Matches(pkt Packet) bool {
	ok := pkt.State&m.States != 0
	if m.Negate {
		return !ok
	}
	return ok
}
func (m *StateMatcher) String() string {
	neg := ""
	if m.Negate {
		neg = "! "
	}
	return neg + "-m state --state " + stateString(m.States)
}

// stateString convierte una máscara de ConnState a lista separada por comas.
func stateString(mask ConnState) string {
	var parts []string
	if mask&StateNew != 0 {
		parts = append(parts, "NEW")
	}
	if mask&StateEstablished != 0 {
		parts = append(parts, "ESTABLISHED")
	}
	if mask&StateRelated != 0 {
		parts = append(parts, "RELATED")
	}
	if mask&StateInvalid != 0 {
		parts = append(parts, "INVALID")
	}
	if mask&StateUntracked != 0 {
		parts = append(parts, "UNTRACKED")
	}
	return strings.Join(parts, ",")
}
