package engine

import (
	"context"
	"fmt"
	"net/netip"
)

// Evaluator evalúa paquetes contra un Ruleset siguiendo el pipeline de Netfilter.
//
// Modo simple (sin interfaces en la topología):
//   - pkt.DstIP ∈ localIPs  →  filter/INPUT
//   - pkt.SrcIP ∈ localIPs  →  filter/OUTPUT
//   - en otro caso           →  filter/FORWARD
//
// Modo multi-zona (con interfaces en la topología):
//   - Tráfico entrante (SrcIP no local):
//       nat/PREROUTING → routing → filter/INPUT o FORWARD → nat/POSTROUTING (solo FORWARD)
//   - Tráfico generado localmente (SrcIP local):
//       filter/OUTPUT → nat/POSTROUTING
//
// El Evaluator es stateless respecto al Ruleset: lee pero no modifica.
// El Ruleset puede cambiar entre llamadas a Send (el jugador añade/quita reglas).
type Evaluator struct {
	rs   *Ruleset
	topo *Topology
	cfg  evalConfig
}

// NewEvaluator crea un Evaluator con el Ruleset y la topología dados.
func NewEvaluator(rs *Ruleset, topo *Topology, opts ...EvalOption) *Evaluator {
	cfg := evalConfig{
		maxDepth: defaultMaxDepth,
		tracing:  true,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	// Añadir las IPs locales de la topología si no se han especificado por opción.
	if topo != nil && len(cfg.localIPs) == 0 {
		cfg.localIPs = append(cfg.localIPs, topo.LocalIPs...)
	}
	return &Evaluator{rs: rs, topo: topo, cfg: cfg}
}

// Send evalúa un paquete a través del pipeline de Netfilter y devuelve el
// veredicto final junto con la traza de evaluación.
func (e *Evaluator) Send(ctx context.Context, pkt Packet) (Verdict, Trace, error) {
	if err := ctx.Err(); err != nil {
		return VerdictDrop, Trace{}, fmt.Errorf("contexto cancelado: %w", err)
	}

	var trace Trace

	// Modo retro-compatible: sin interfaces → pipeline simple (solo filter).
	if e.topo == nil || len(e.topo.Interfaces) == 0 {
		chain := e.routeChain(pkt)
		verdict, _, err := e.evalChain(ctx, pkt, "filter", chain, 0, &trace)
		if err != nil {
			return VerdictDrop, trace, err
		}
		return verdict, trace, nil
	}

	// Modo multi-zona: pipeline Netfilter completo con resolución de interfaces.
	pkt = e.assignInterfaces(pkt)

	if e.isLocal(pkt.SrcIP) {
		return e.evalLocalOut(ctx, pkt, &trace)
	}
	return e.evalForward(ctx, pkt, &trace)
}

// assignInterfaces rellena InIface/OutIface del paquete a partir de la topología
// si no están ya establecidos.
func (e *Evaluator) assignInterfaces(pkt Packet) Packet {
	if pkt.InIface == "" && e.topo != nil {
		pkt.InIface = e.topo.InIfaceFor(pkt.SrcIP)
	}
	if pkt.OutIface == "" && e.topo != nil {
		pkt.OutIface = e.topo.OutIfaceFor(pkt.DstIP)
	}
	return pkt
}

// evalForward evalúa un paquete entrante (SrcIP no local) siguiendo el pipeline:
//
//	nat/PREROUTING → routing → filter/FORWARD o INPUT → nat/POSTROUTING (solo FORWARD)
func (e *Evaluator) evalForward(ctx context.Context, pkt Packet, trace *Trace) (Verdict, Trace, error) {
	// 1. nat/PREROUTING (puede DNAT, cambiando DstIP/DstPort).
	verdict, pkt, err := e.evalChain(ctx, pkt, "nat", "PREROUTING", 0, trace)
	if err != nil {
		return VerdictDrop, *trace, err
	}
	if verdict == VerdictDrop || verdict == VerdictReject {
		return verdict, *trace, nil
	}

	// 2. Decisión de routing tras posible DNAT.
	filterChain := "FORWARD"
	if e.isLocal(pkt.DstIP) {
		filterChain = "INPUT"
	} else if e.topo != nil {
		// Actualizar OutIface ya que DstIP puede haber cambiado por DNAT.
		pkt.OutIface = e.topo.OutIfaceFor(pkt.DstIP)
	}

	// 3. filter/FORWARD o filter/INPUT.
	verdict, pkt, err = e.evalChain(ctx, pkt, "filter", filterChain, 0, trace)
	if err != nil {
		return VerdictDrop, *trace, err
	}
	if verdict != VerdictAccept {
		return verdict, *trace, nil
	}

	// 4. nat/POSTROUTING solo para tráfico FORWARD (no para INPUT local).
	if filterChain != "FORWARD" {
		return verdict, *trace, nil
	}
	return e.evalPostrouting(ctx, pkt, trace)
}

// evalLocalOut evalúa un paquete generado localmente (SrcIP local):
//
//	filter/OUTPUT → nat/POSTROUTING
func (e *Evaluator) evalLocalOut(ctx context.Context, pkt Packet, trace *Trace) (Verdict, Trace, error) {
	// 1. filter/OUTPUT.
	verdict, pkt, err := e.evalChain(ctx, pkt, "filter", "OUTPUT", 0, trace)
	if err != nil {
		return VerdictDrop, *trace, err
	}
	if verdict != VerdictAccept {
		return verdict, *trace, nil
	}

	// 2. nat/POSTROUTING.
	return e.evalPostrouting(ctx, pkt, trace)
}

// evalPostrouting evalúa la cadena nat/POSTROUTING.
func (e *Evaluator) evalPostrouting(ctx context.Context, pkt Packet, trace *Trace) (Verdict, Trace, error) {
	verdict, _, err := e.evalChain(ctx, pkt, "nat", "POSTROUTING", 0, trace)
	if err != nil {
		return VerdictDrop, *trace, err
	}
	return verdict, *trace, nil
}

// routeChain determina la cadena filter apropiada según la dirección del paquete.
// Solo se usa en el modo retro-compatible (sin interfaces).
func (e *Evaluator) routeChain(pkt Packet) string {
	if e.isLocal(pkt.DstIP) {
		return "INPUT"
	}
	if e.isLocal(pkt.SrcIP) {
		return "OUTPUT"
	}
	return "FORWARD"
}

// isLocal devuelve true si la IP pertenece al firewall (el castillo).
func (e *Evaluator) isLocal(ip netip.Addr) bool {
	if e.topo != nil {
		return e.topo.IsLocal(ip)
	}
	for _, local := range e.cfg.localIPs {
		if local == ip {
			return true
		}
	}
	return false
}

// evalChain evalúa el paquete a través de la cadena dada y devuelve el veredicto.
// depth controla la recursión máxima para evitar loops.
func (e *Evaluator) evalChain( //nolint:gocyclo // Netfilter pipeline evaluation handles all verdict types
	ctx context.Context,
	pkt Packet,
	table, chain string,
	depth int,
	trace *Trace,
) (Verdict, Packet, error) {
	if depth > e.cfg.maxDepth {
		return VerdictDrop, pkt, ErrMaxDepthExceeded
	}
	if err := ctx.Err(); err != nil {
		return VerdictDrop, pkt, fmt.Errorf("contexto cancelado: %w", err)
	}

	c, err := e.rs.GetChain(table, chain)
	if err != nil {
		return VerdictDrop, pkt, err
	}

	for i, rule := range c.Rules {
		if !rule.Matches(pkt) {
			continue
		}

		verdict, pkt2, err2 := rule.Target.Apply(ctx, pkt)
		if err2 != nil {
			return VerdictDrop, pkt, err2
		}

		// MASQUERADE: reescribir SrcIP con la IP del firewall en la interfaz de salida.
		if _, isMasq := rule.Target.(*masqueradeTarget); isMasq && e.topo != nil {
			if ip := e.topo.InterfaceIP(pkt2.OutIface); ip.IsValid() {
				pkt2 = pkt2.WithSrcIP(ip)
			}
		}

		if e.cfg.tracing && trace != nil {
			trace.add(table, chain, i, verdict, pkt2)
		}

		switch verdict {
		case VerdictAccept:
			return VerdictAccept, pkt2, nil
		case VerdictDrop:
			return VerdictDrop, pkt2, nil
		case VerdictReject:
			return VerdictReject, pkt2, nil
		case VerdictReturn:
			return VerdictReturn, pkt2, nil
		case VerdictJump:
			j, ok := rule.Target.(Jumper)
			if !ok {
				return VerdictDrop, pkt2, fmt.Errorf("target %s no implementa Jumper", rule.Target.String())
			}
			v, pkt3, err3 := e.evalChain(ctx, pkt2, table, j.ChainName(), depth+1, trace)
			if err3 != nil {
				return VerdictDrop, pkt3, err3
			}
			if v == VerdictReturn || v == VerdictContinue {
				// RETURN desde cadena de usuario → continuar en la cadena padre.
				pkt = pkt3
				continue
			}
			return v, pkt3, nil
		case VerdictContinue:
			// LOG target: continuar con el paquete posiblemente modificado.
			pkt = pkt2
			continue
		}
	}

	// Ninguna regla coincidió (o todas continuaron) → aplicar política por defecto.
	if c.Policy != nil {
		v, pkt2, _ := c.Policy.Apply(ctx, pkt)
		if e.cfg.tracing && trace != nil {
			trace.add(table, chain, -1, v, pkt2)
		}
		return v, pkt2, nil
	}

	// Cadena de usuario sin match → RETURN implícito.
	return VerdictReturn, pkt, nil
}
