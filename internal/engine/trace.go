package engine

// TraceStep registra un paso de la evaluación de un paquete.
type TraceStep struct {
	Table   string  // tabla (p.ej. "filter")
	Chain   string  // cadena (p.ej. "INPUT")
	RuleIdx int     // índice de la regla (0-based); -1 = política por defecto
	Verdict Verdict // veredicto aplicado en este paso
	Pkt     Packet  // estado del paquete en este paso (puede variar tras NAT)
}

// Trace es el registro completo de la evaluación de un paquete a través del pipeline.
type Trace struct {
	Steps []TraceStep
}

// add añade un paso a la traza.
func (t *Trace) add(table, chain string, ruleIdx int, verdict Verdict, pkt Packet) {
	t.Steps = append(t.Steps, TraceStep{
		Table:   table,
		Chain:   chain,
		RuleIdx: ruleIdx,
		Verdict: verdict,
		Pkt:     pkt,
	})
}

// LastPkt devuelve el estado del paquete en el último paso, o el paquete vacío
// si la traza está vacía.
func (t *Trace) LastPkt() Packet {
	if len(t.Steps) == 0 {
		return Packet{}
	}
	return t.Steps[len(t.Steps)-1].Pkt
}
