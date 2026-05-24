package engine

import "net/netip"

// Proto representa un protocolo de red.
type Proto uint8

const (
	// ProtoAll corresponde a cualquier protocolo (valor 0 en iptables).
	ProtoAll Proto = 0
	// ProtoICMP corresponde al protocolo ICMP (1).
	ProtoICMP Proto = 1
	// ProtoTCP corresponde al protocolo TCP (6).
	ProtoTCP Proto = 6
	// ProtoUDP corresponde al protocolo UDP (17).
	ProtoUDP Proto = 17
)

// String devuelve el nombre del protocolo.
func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMP:
		return "icmp"
	default:
		return "all"
	}
}

// ParseProto convierte un string de protocolo al tipo Proto.
// Devuelve ProtoAll y false si no se reconoce.
func ParseProto(s string) (Proto, bool) {
	switch s {
	case "tcp":
		return ProtoTCP, true
	case "udp":
		return ProtoUDP, true
	case "icmp":
		return ProtoICMP, true
	case "all", "0":
		return ProtoAll, true
	default:
		return ProtoAll, false
	}
}

// ConnState es una máscara de bits de estados de conntrack de Netfilter.
type ConnState uint8

const (
	// StateNew corresponde a NEW: primera trama de una nueva conexión.
	StateNew ConnState = 1 << iota
	// StateEstablished corresponde a ESTABLISHED: respuesta a una conexión conocida.
	StateEstablished
	// StateRelated corresponde a RELATED: relacionado con una conexión existente.
	StateRelated
	// StateInvalid corresponde a INVALID: paquete no identificable.
	StateInvalid
	// StateUntracked corresponde a UNTRACKED: conntrack desactivado para este paquete.
	StateUntracked
)

// String devuelve el nombre del estado conntrack.
func (s ConnState) String() string {
	switch s {
	case StateNew:
		return "NEW"
	case StateEstablished:
		return "ESTABLISHED"
	case StateRelated:
		return "RELATED"
	case StateInvalid:
		return "INVALID"
	case StateUntracked:
		return "UNTRACKED"
	default:
		return "UNKNOWN"
	}
}

// ParseConnStates parsea una lista de estados separada por comas, como
// "NEW,ESTABLISHED". Devuelve la máscara resultante y un error si algún
// estado no se reconoce.
func ParseConnStates(s string) (ConnState, error) {
	var mask ConnState
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			tok := s[start:i]
			switch tok {
			case "NEW":
				mask |= StateNew
			case "ESTABLISHED":
				mask |= StateEstablished
			case "RELATED":
				mask |= StateRelated
			case "INVALID":
				mask |= StateInvalid
			case "UNTRACKED":
				mask |= StateUntracked
			default:
				return 0, &ParseError{Line: s, Pos: start, Msg: "estado conntrack desconocido: " + tok}
			}
			start = i + 1
		}
	}
	return mask, nil
}

// Packet representa un paquete de red que atraviesa el firewall simulado.
//
// Es un tipo por valor (inmutable). Usa los métodos With* para obtener
// copias modificadas en los rewrites de NAT.
type Packet struct {
	SrcIP    netip.Addr
	DstIP    netip.Addr
	SrcPort  uint16
	DstPort  uint16
	Proto    Proto
	InIface  string    // interfaz de entrada (p.ej. "eth0")
	OutIface string    // interfaz de salida  (p.ej. "eth1")
	State    ConnState // estado conntrack del paquete
}

// WithSrcIP devuelve una copia del paquete con la IP origen reemplazada.
func (p Packet) WithSrcIP(ip netip.Addr) Packet { p.SrcIP = ip; return p }

// WithDstIP devuelve una copia del paquete con la IP destino reemplazada.
func (p Packet) WithDstIP(ip netip.Addr) Packet { p.DstIP = ip; return p }

// WithSrcPort devuelve una copia del paquete con el puerto origen reemplazado.
func (p Packet) WithSrcPort(port uint16) Packet { p.SrcPort = port; return p }

// WithDstPort devuelve una copia del paquete con el puerto destino reemplazado.
func (p Packet) WithDstPort(port uint16) Packet { p.DstPort = port; return p }

// WithState devuelve una copia del paquete con el estado conntrack reemplazado.
func (p Packet) WithState(s ConnState) Packet { p.State = s; return p }

// WithInIface devuelve una copia del paquete con la interfaz de entrada reemplazada.
func (p Packet) WithInIface(iface string) Packet { p.InIface = iface; return p }

// WithOutIface devuelve una copia del paquete con la interfaz de salida reemplazada.
func (p Packet) WithOutIface(iface string) Packet { p.OutIface = iface; return p }
