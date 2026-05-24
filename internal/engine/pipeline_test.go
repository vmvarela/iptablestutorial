package engine_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/vmvarela/iptablestutorial/internal/engine"
)

// helpers

func mustParseAddr(s string) netip.Addr {
	return netip.MustParseAddr(s)
}

func newEval(localIP string) (*engine.Ruleset, *engine.Evaluator) {
	rs := engine.NewRuleset()
	topo := engine.DefaultTopology(mustParseAddr(localIP))
	ev := engine.NewEvaluator(rs, topo)
	return rs, ev
}

func mustApplyLine(t *testing.T, rs *engine.Ruleset, line string) {
	t.Helper()
	cmd, err := engine.ParseLine(line)
	if err != nil {
		t.Fatalf("ParseLine(%q): %v", line, err)
	}
	if err2 := engine.Apply(rs, cmd); err2 != nil {
		t.Fatalf("Apply(%q): %v", line, err2)
	}
}

// newPktTo construye un paquete TCP destinado a la IP local del castillo.
func newPktTo(dstIP string, dstPort uint16) engine.Packet {
	return engine.Packet{
		SrcIP:   mustParseAddr("203.0.113.1"),
		DstIP:   mustParseAddr(dstIP),
		SrcPort: 54321,
		DstPort: dstPort,
		Proto:   engine.ProtoTCP,
		State:   engine.StateNew,
	}
}

// ---- routeChain (INPUT/OUTPUT/FORWARD) ----------------------------------

func TestEvaluator_RouteToINPUT(t *testing.T) {
	t.Parallel()
	_, ev := newEval("10.0.0.1")

	// Paquete destino=local → debe atravesar INPUT (política ACCEPT por defecto).
	pkt := newPktTo("10.0.0.1", 80)
	verdict, _, err := ev.Send(context.Background(), pkt)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if verdict != engine.VerdictAccept {
		t.Errorf("verdict=%v; want ACCEPT (política default)", verdict)
	}
}

func TestEvaluator_RouteToOUTPUT(t *testing.T) {
	t.Parallel()
	_, ev := newEval("10.0.0.1")

	// Paquete origen=local → OUTPUT.
	pkt := engine.Packet{
		SrcIP:   mustParseAddr("10.0.0.1"),
		DstIP:   mustParseAddr("203.0.113.99"),
		SrcPort: 12345,
		DstPort: 80,
		Proto:   engine.ProtoTCP,
		State:   engine.StateNew,
	}
	verdict, _, err := ev.Send(context.Background(), pkt)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if verdict != engine.VerdictAccept {
		t.Errorf("verdict=%v; want ACCEPT", verdict)
	}
}

func TestEvaluator_RouteToFORWARD(t *testing.T) {
	t.Parallel()
	_, ev := newEval("10.0.0.1")

	// Ni src ni dst es local → FORWARD.
	pkt := engine.Packet{
		SrcIP:   mustParseAddr("192.168.1.2"),
		DstIP:   mustParseAddr("203.0.113.99"),
		SrcPort: 12345,
		DstPort: 80,
		Proto:   engine.ProtoTCP,
	}
	verdict, _, err := ev.Send(context.Background(), pkt)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if verdict != engine.VerdictAccept {
		t.Errorf("verdict=%v; want ACCEPT (política default FORWARD)", verdict)
	}
}

// ---- Reglas simples -------------------------------------------------

func TestEvaluator_DropPort80(t *testing.T) {
	t.Parallel()
	rs, ev := newEval("10.0.0.1")
	mustApplyLine(t, rs, "-A INPUT -p tcp --dport 80 -j DROP")

	pkt := newPktTo("10.0.0.1", 80)
	verdict, _, err := ev.Send(context.Background(), pkt)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if verdict != engine.VerdictDrop {
		t.Errorf("verdict=%v; want DROP", verdict)
	}
}

func TestEvaluator_AcceptPort443_DropDefault(t *testing.T) {
	t.Parallel()
	rs, ev := newEval("10.0.0.1")
	// Política DROP + solo acepta 443.
	mustApplyLine(t, rs, "-P INPUT DROP")
	mustApplyLine(t, rs, "-A INPUT -p tcp --dport 443 -j ACCEPT")

	// Puerto 443 → ACCEPT.
	pkt443 := newPktTo("10.0.0.1", 443)
	v443, _, err := ev.Send(context.Background(), pkt443)
	if err != nil {
		t.Fatalf("Send 443: %v", err)
	}
	if v443 != engine.VerdictAccept {
		t.Errorf("443: verdict=%v; want ACCEPT", v443)
	}

	// Puerto 80 → DROP (política).
	pkt80 := newPktTo("10.0.0.1", 80)
	v80, _, err := ev.Send(context.Background(), pkt80)
	if err != nil {
		t.Fatalf("Send 80: %v", err)
	}
	if v80 != engine.VerdictDrop {
		t.Errorf("80: verdict=%v; want DROP", v80)
	}
}

func TestEvaluator_RejectPort22(t *testing.T) {
	t.Parallel()
	rs, ev := newEval("10.0.0.1")
	mustApplyLine(t, rs, "-A INPUT -p tcp --dport 22 -j REJECT")

	pkt := newPktTo("10.0.0.1", 22)
	verdict, _, err := ev.Send(context.Background(), pkt)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if verdict != engine.VerdictReject {
		t.Errorf("verdict=%v; want REJECT", verdict)
	}
}

func TestEvaluator_LogDoesNotStop(t *testing.T) {
	t.Parallel()
	rs, ev := newEval("10.0.0.1")
	// LOG seguido de DROP → el paquete debe ser DROPeado (LOG no interrumpe).
	mustApplyLine(t, rs, `-A INPUT -p tcp --dport 80 -j LOG --log-prefix "INTENTO: "`)
	mustApplyLine(t, rs, "-A INPUT -p tcp --dport 80 -j DROP")

	pkt := newPktTo("10.0.0.1", 80)
	verdict, _, err := ev.Send(context.Background(), pkt)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if verdict != engine.VerdictDrop {
		t.Errorf("verdict=%v; want DROP (LOG no debe interrumpir)", verdict)
	}
}

// ---- ESTABLISHED/RELATED (aventura 4) ----------------------------------

func TestEvaluator_EstablishedAllowed(t *testing.T) {
	t.Parallel()
	rs, ev := newEval("10.0.0.1")
	mustApplyLine(t, rs, "-P INPUT DROP")
	mustApplyLine(t, rs, "-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")

	pkt := engine.Packet{
		SrcIP:   mustParseAddr("203.0.113.1"),
		DstIP:   mustParseAddr("10.0.0.1"),
		Proto:   engine.ProtoTCP,
		DstPort: 80,
		State:   engine.StateEstablished,
	}
	verdict, _, err := ev.Send(context.Background(), pkt)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if verdict != engine.VerdictAccept {
		t.Errorf("verdict=%v; want ACCEPT para ESTABLISHED", verdict)
	}
}

func TestEvaluator_NewBlocked(t *testing.T) {
	t.Parallel()
	rs, ev := newEval("10.0.0.1")
	mustApplyLine(t, rs, "-P INPUT DROP")
	mustApplyLine(t, rs, "-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")

	pkt := engine.Packet{
		SrcIP:   mustParseAddr("203.0.113.1"),
		DstIP:   mustParseAddr("10.0.0.1"),
		Proto:   engine.ProtoTCP,
		DstPort: 80,
		State:   engine.StateNew,
	}
	verdict, _, err := ev.Send(context.Background(), pkt)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if verdict != engine.VerdictDrop {
		t.Errorf("verdict=%v; want DROP para NEW", verdict)
	}
}

// ---- Cadenas de usuario (JUMP/RETURN) ----------------------------------

func TestEvaluator_JumpUserChain_Accept(t *testing.T) {
	t.Parallel()
	rs, ev := newEval("10.0.0.1")

	mustApplyLine(t, rs, "-N GUARDIAS")
	mustApplyLine(t, rs, "-A GUARDIAS -p tcp --dport 80 -j ACCEPT")
	mustApplyLine(t, rs, "-A INPUT -j GUARDIAS")

	pkt := newPktTo("10.0.0.1", 80)
	verdict, _, err := ev.Send(context.Background(), pkt)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if verdict != engine.VerdictAccept {
		t.Errorf("verdict=%v; want ACCEPT via GUARDIAS", verdict)
	}
}

func TestEvaluator_JumpUserChain_ReturnContinues(t *testing.T) {
	t.Parallel()
	rs, ev := newEval("10.0.0.1")

	// GUARDIAS solo matchea 443; si se llega con otro puerto hace RETURN
	// y continúa en INPUT → política ACCEPT → aceptado.
	mustApplyLine(t, rs, "-N GUARDIAS")
	mustApplyLine(t, rs, "-A GUARDIAS -p tcp --dport 443 -j DROP")
	mustApplyLine(t, rs, "-A INPUT -j GUARDIAS")

	// Puerto 80 no matchea en GUARDIAS → RETURN → INPUT continúa → ACCEPT.
	pkt := newPktTo("10.0.0.1", 80)
	verdict, _, err := ev.Send(context.Background(), pkt)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if verdict != engine.VerdictAccept {
		t.Errorf("verdict=%v; want ACCEPT (RETURN de cadena usuario)", verdict)
	}
}

// ---- Detección de ciclos (maxDepth) ------------------------------------

func TestEvaluator_MaxDepth(t *testing.T) {
	t.Parallel()
	rs, ev := newEval("10.0.0.1")

	// Crear cadena que salta a sí misma (ciclo).
	mustApplyLine(t, rs, "-N LOOP")
	mustApplyLine(t, rs, "-A LOOP -j LOOP")
	mustApplyLine(t, rs, "-A INPUT -j LOOP")

	pkt := newPktTo("10.0.0.1", 80)
	_, _, err := ev.Send(context.Background(), pkt)
	if err == nil {
		t.Error("Send debería devolver error por ciclo (maxDepth)")
	}
}

// ---- Traza --------------------------------------------------------------

func TestEvaluator_TraceNotEmpty(t *testing.T) {
	t.Parallel()
	rs, ev := newEval("10.0.0.1")
	mustApplyLine(t, rs, "-A INPUT -p tcp --dport 80 -j ACCEPT")

	pkt := newPktTo("10.0.0.1", 80)
	_, trace, err := ev.Send(context.Background(), pkt)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(trace.Steps) == 0 {
		t.Error("traza vacía, debería tener al menos un paso")
	}
}

func TestEvaluator_TraceDisabled(t *testing.T) {
	t.Parallel()
	rs := engine.NewRuleset()
	topo := engine.DefaultTopology(mustParseAddr("10.0.0.1"))
	ev := engine.NewEvaluator(rs, topo, engine.WithTracing(false))

	mustApplyLine(t, rs, "-A INPUT -p tcp --dport 80 -j ACCEPT")

	pkt := newPktTo("10.0.0.1", 80)
	_, trace, err := ev.Send(context.Background(), pkt)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(trace.Steps) != 0 {
		t.Errorf("traza debería estar vacía con WithTracing(false), tiene %d pasos", len(trace.Steps))
	}
}

// ---- Contexto cancelado -------------------------------------------------

func TestEvaluator_CancelledContext(t *testing.T) {
	t.Parallel()
	_, ev := newEval("10.0.0.1")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelado antes de Send

	pkt := newPktTo("10.0.0.1", 80)
	_, _, err := ev.Send(ctx, pkt)
	if err == nil {
		t.Error("Send con contexto cancelado debería devolver error")
	}
}

// ---- Filtro por IP origen ----------------------------------------------

func TestEvaluator_SrcIPFilter(t *testing.T) {
	t.Parallel()
	rs, ev := newEval("10.0.0.1")
	mustApplyLine(t, rs, "-P INPUT DROP")
	mustApplyLine(t, rs, "-A INPUT -s 192.168.1.0/24 -j ACCEPT")

	// IP dentro del rango permitido.
	pktOK := engine.Packet{
		SrcIP:   mustParseAddr("192.168.1.50"),
		DstIP:   mustParseAddr("10.0.0.1"),
		Proto:   engine.ProtoTCP,
		DstPort: 80,
		State:   engine.StateNew,
	}
	v1, _, err := ev.Send(context.Background(), pktOK)
	if err != nil {
		t.Fatalf("Send ok: %v", err)
	}
	if v1 != engine.VerdictAccept {
		t.Errorf("192.168.1.50: verdict=%v; want ACCEPT", v1)
	}

	// IP fuera del rango.
	pktBlock := engine.Packet{
		SrcIP:   mustParseAddr("10.20.30.40"),
		DstIP:   mustParseAddr("10.0.0.1"),
		Proto:   engine.ProtoTCP,
		DstPort: 80,
		State:   engine.StateNew,
	}
	v2, _, err := ev.Send(context.Background(), pktBlock)
	if err != nil {
		t.Fatalf("Send block: %v", err)
	}
	if v2 != engine.VerdictDrop {
		t.Errorf("10.20.30.40: verdict=%v; want DROP", v2)
	}
}
