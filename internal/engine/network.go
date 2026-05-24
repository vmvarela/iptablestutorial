package engine

import "net/netip"

// Topology describe la topología de red del firewall simulado.
//
// Para Capa 1 (filter/INPUT) basta con indicar las IPs locales.
// Para Capa 3 (multired) se añaden interfaces con zonas.
type Topology struct {
	// LocalIPs es la lista de IPs que pertenecen al propio firewall (el castillo).
	LocalIPs []netip.Addr
	// Interfaces describe las interfaces de red del firewall.
	Interfaces []Interface
}

// IsLocal devuelve true si la IP dada pertenece al propio firewall.
func (t *Topology) IsLocal(ip netip.Addr) bool {
	for _, local := range t.LocalIPs {
		if local == ip {
			return true
		}
	}
	return false
}

// InIfaceFor devuelve el nombre de interfaz por la que entran los paquetes
// cuya IP origen es srcIP. Devuelve "lo" para tráfico local y "" si desconocido.
func (t *Topology) InIfaceFor(srcIP netip.Addr) string {
	if t.IsLocal(srcIP) {
		return "lo"
	}
	return t.ifaceForIP(srcIP)
}

// OutIfaceFor devuelve el nombre de interfaz por la que salen los paquetes
// cuya IP destino es dstIP. Devuelve "lo" para tráfico local y "" si desconocido.
func (t *Topology) OutIfaceFor(dstIP netip.Addr) string {
	if t.IsLocal(dstIP) {
		return "lo"
	}
	return t.ifaceForIP(dstIP)
}

// ifaceForIP encuentra la interfaz cuyo CIDR contiene ip.
// Las subredes específicas (no 0.0.0.0/0) se comprueban primero;
// 0.0.0.0/0 actúa como ruta por defecto.
func (t *Topology) ifaceForIP(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	var defaultIface string
	for _, iface := range t.Interfaces {
		for _, pfx := range iface.Prefixes {
			if pfx.Bits() == 0 {
				defaultIface = iface.Name
				continue
			}
			if pfx.Contains(ip) {
				return iface.Name
			}
		}
	}
	return defaultIface
}

// InterfaceIP devuelve la IP del firewall en la interfaz con el nombre dado.
// Si no se encuentra, devuelve la primera LocalIP o un Addr vacío.
func (t *Topology) InterfaceIP(name string) netip.Addr {
	for _, iface := range t.Interfaces {
		if iface.Name == name && iface.IP.IsValid() {
			return iface.IP
		}
	}
	if len(t.LocalIPs) > 0 {
		return t.LocalIPs[0]
	}
	return netip.Addr{}
}

// Interface describe una interfaz de red del firewall.
type Interface struct {
	Name     string         // p.ej. "eth0"
	Prefixes []netip.Prefix // subredes asignadas
	Zone     string         // "barrio", "mundo", "dmz", etc.
	IP       netip.Addr     // IP del firewall en esta interfaz (para MASQUERADE)
}

// Host es un host virtual en la topología simulada.
type Host struct {
	Name  string
	IP    netip.Addr
	Zone  string
	Iface string // interfaz del firewall por la que llega/sale
}

// DefaultTopology devuelve una topología mínima con una sola IP local.
func DefaultTopology(localIP netip.Addr) *Topology {
	return &Topology{
		LocalIPs: []netip.Addr{localIP},
	}
}
