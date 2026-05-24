package engine

import (
	"context"
	"net/netip"
	"strconv"
)

// Verdict es la decisión final tomada para un paquete.
type Verdict int

const (
	// VerdictContinue indica que no hubo match y la evaluación continúa.
	VerdictContinue Verdict = iota
	// VerdictAccept indica que el paquete debe ser aceptado.
	VerdictAccept
	// VerdictDrop indica que el paquete debe ser descartado silenciosamente.
	VerdictDrop
	// VerdictReject indica que el paquete debe ser rechazado con respuesta ICMP.
	VerdictReject
	// VerdictReturn indica que la evaluación debe volver a la cadena padre.
	VerdictReturn
	// VerdictJump es un veredicto interno que indica salto a otra cadena.
	VerdictJump
)

// String devuelve el nombre del veredicto.
func (v Verdict) String() string {
	switch v {
	case VerdictAccept:
		return "ACCEPT"
	case VerdictDrop:
		return "DROP"
	case VerdictReject:
		return "REJECT"
	case VerdictReturn:
		return "RETURN"
	case VerdictJump:
		return "JUMP"
	default:
		return "CONTINUE"
	}
}

// Target es el objetivo de una regla: decide qué hacer con un paquete cuando matchea.
type Target interface {
	// Apply aplica el objetivo al paquete y devuelve el veredicto y el paquete
	// (posiblemente modificado en rewrites NAT).
	Apply(ctx context.Context, pkt Packet) (Verdict, Packet, error)
	// String devuelve la representación CLI del objetivo (p.ej. "ACCEPT").
	String() string
}

// Jumper es implementado por los objetivos que saltan a otra cadena (JUMP).
type Jumper interface {
	Target
	// ChainName devuelve el nombre de la cadena destino.
	ChainName() string
}

// Compile-time interface checks.
var (
	_ Target = acceptTarget{}
	_ Target = dropTarget{}
	_ Target = (*rejectTarget)(nil)
	_ Target = returnTarget{}
	_ Jumper = (*jumpTarget)(nil)
	_ Target = (*logTarget)(nil)
	_ Target = (*dnatTarget)(nil)
	_ Target = (*snatTarget)(nil)
	_ Target = (*masqueradeTarget)(nil)
)

// ---- ACCEPT ---------------------------------------------------------------

type acceptTarget struct{}

// Accept es el singleton del objetivo ACCEPT.
var Accept Target = acceptTarget{} //nolint:gochecknoglobals // Accept is a singleton target used as a value constant

func (acceptTarget) Apply(_ context.Context, pkt Packet) (Verdict, Packet, error) {
	return VerdictAccept, pkt, nil
}
func (acceptTarget) String() string { return "ACCEPT" }

// ---- DROP -----------------------------------------------------------------

type dropTarget struct{}

// Drop es el singleton del objetivo DROP.
var Drop Target = dropTarget{} //nolint:gochecknoglobals // Drop is a singleton target used as a value constant

func (dropTarget) Apply(_ context.Context, pkt Packet) (Verdict, Packet, error) {
	return VerdictDrop, pkt, nil
}
func (dropTarget) String() string { return "DROP" }

// ---- REJECT ---------------------------------------------------------------

type rejectTarget struct {
	icmpType string
}

// Reject devuelve un objetivo REJECT con el tipo ICMP dado.
// Si icmpType es "", se usa "icmp-port-unreachable".
func Reject(icmpType string) Target {
	if icmpType == "" {
		icmpType = "icmp-port-unreachable"
	}
	return &rejectTarget{icmpType: icmpType}
}

func (r *rejectTarget) Apply(_ context.Context, pkt Packet) (Verdict, Packet, error) {
	return VerdictReject, pkt, nil
}
func (r *rejectTarget) String() string {
	if r.icmpType == "icmp-port-unreachable" {
		return "REJECT"
	}
	return "REJECT --reject-with " + r.icmpType
}

// IcmpType devuelve el tipo ICMP del rechazo.
func (r *rejectTarget) IcmpType() string { return r.icmpType }

// ---- RETURN ---------------------------------------------------------------

type returnTarget struct{}

// Return es el singleton del objetivo RETURN.
var Return Target = returnTarget{} //nolint:gochecknoglobals // Return is a singleton target used as a value constant

func (returnTarget) Apply(_ context.Context, pkt Packet) (Verdict, Packet, error) {
	return VerdictReturn, pkt, nil
}
func (returnTarget) String() string { return "RETURN" }

// ---- JUMP -----------------------------------------------------------------

type jumpTarget struct {
	chain string
}

// Jump devuelve un objetivo que salta a la cadena nombrada.
func Jump(chain string) Jumper {
	return &jumpTarget{chain: chain}
}

func (j *jumpTarget) Apply(_ context.Context, pkt Packet) (Verdict, Packet, error) {
	return VerdictJump, pkt, nil
}
func (j *jumpTarget) String() string    { return j.chain }
func (j *jumpTarget) ChainName() string { return j.chain }

// ---- LOG ------------------------------------------------------------------

type logTarget struct {
	prefix string
}

// Log devuelve un objetivo LOG con el prefijo dado.
// El objetivo LOG no altera el flujo: la evaluación continúa a la siguiente regla.
func Log(prefix string) Target {
	return &logTarget{prefix: prefix}
}

func (l *logTarget) Apply(_ context.Context, pkt Packet) (Verdict, Packet, error) {
	// En la simulación el LOG no produce output real; solo continúa.
	return VerdictContinue, pkt, nil
}
func (l *logTarget) String() string {
	if l.prefix == "" {
		return "LOG"
	}
	return "LOG --log-prefix " + l.prefix
}

// Prefix devuelve el prefijo del log.
func (l *logTarget) Prefix() string { return l.prefix }

// ---- DNAT -----------------------------------------------------------------

type dnatTarget struct {
	toAddr netip.Addr
	toPort uint16 // 0 = no cambiar puerto
}

// DNAT crea un objetivo de NAT destino que reescribe DstIP (y opcionalmente DstPort).
// Es terminal: devuelve VerdictAccept para continuar el pipeline.
func DNAT(toAddr netip.Addr, toPort uint16) Target {
	return &dnatTarget{toAddr: toAddr, toPort: toPort}
}

func (d *dnatTarget) Apply(_ context.Context, pkt Packet) (Verdict, Packet, error) {
	pkt = pkt.WithDstIP(d.toAddr)
	if d.toPort > 0 {
		pkt = pkt.WithDstPort(d.toPort)
	}
	return VerdictAccept, pkt, nil
}

func (d *dnatTarget) String() string {
	s := "DNAT --to-destination " + d.toAddr.String()
	if d.toPort > 0 {
		s += ":" + strconv.Itoa(int(d.toPort))
	}
	return s
}

// ToAddr devuelve la dirección de destino del DNAT.
func (d *dnatTarget) ToAddr() netip.Addr { return d.toAddr }

// ---- SNAT -----------------------------------------------------------------

type snatTarget struct {
	toAddr netip.Addr
}

// SNAT crea un objetivo de NAT origen que reescribe SrcIP.
// Es terminal: devuelve VerdictAccept para continuar el pipeline.
func SNAT(toAddr netip.Addr) Target {
	return &snatTarget{toAddr: toAddr}
}

func (s *snatTarget) Apply(_ context.Context, pkt Packet) (Verdict, Packet, error) {
	return VerdictAccept, pkt.WithSrcIP(s.toAddr), nil
}

func (s *snatTarget) String() string {
	return "SNAT --to-source " + s.toAddr.String()
}

// ---- MASQUERADE -----------------------------------------------------------

type masqueradeTarget struct{}

// Masquerade crea un objetivo MASQUERADE que reescribe SrcIP a la IP de la
// interfaz de salida. La reescritura real la realiza el pipeline del Evaluator,
// ya que requiere acceso a la topología.
// Es terminal: devuelve VerdictAccept.
func Masquerade() Target {
	return &masqueradeTarget{}
}

func (m *masqueradeTarget) Apply(_ context.Context, pkt Packet) (Verdict, Packet, error) {
	// La reescritura de SrcIP se realiza en evalChain usando la topología.
	return VerdictAccept, pkt, nil
}

func (m *masqueradeTarget) String() string { return "MASQUERADE" }
