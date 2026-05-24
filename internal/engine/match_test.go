package engine_test

import (
	"net/netip"
	"testing"

	"github.com/vmvarela/iptablestutorial/internal/engine"
)

func TestProtoString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		proto engine.Proto
		want  string
	}{
		{engine.ProtoTCP, "tcp"},
		{engine.ProtoUDP, "udp"},
		{engine.ProtoICMP, "icmp"},
		{engine.ProtoAll, "all"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.proto.String(); got != tt.want {
				t.Errorf("Proto.String() = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestParseProto(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  engine.Proto
		ok    bool
	}{
		{"tcp", engine.ProtoTCP, true},
		{"udp", engine.ProtoUDP, true},
		{"icmp", engine.ProtoICMP, true},
		{"all", engine.ProtoAll, true},
		{"0", engine.ProtoAll, true},
		{"xyz", engine.ProtoAll, false},
		{"", engine.ProtoAll, false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			got, ok := engine.ParseProto(tt.input)
			if ok != tt.ok {
				t.Errorf("ParseProto(%q) ok=%v; want %v", tt.input, ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Errorf("ParseProto(%q) = %v; want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseConnStates(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  engine.ConnState
		isErr bool
	}{
		{"NEW", engine.StateNew, false},
		{"ESTABLISHED", engine.StateEstablished, false},
		{"RELATED", engine.StateRelated, false},
		{"INVALID", engine.StateInvalid, false},
		{"NEW,ESTABLISHED", engine.StateNew | engine.StateEstablished, false},
		{"NEW,ESTABLISHED,RELATED", engine.StateNew | engine.StateEstablished | engine.StateRelated, false},
		{"UNKNOWN", 0, true},
		{"NEW,BAD", 0, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			got, err := engine.ParseConnStates(tt.input)
			if tt.isErr {
				if err == nil {
					t.Errorf("ParseConnStates(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseConnStates(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("ParseConnStates(%q) = %v; want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestPacketWith(t *testing.T) {
	t.Parallel()
	orig := engine.Packet{
		SrcIP:   netip.MustParseAddr("10.0.0.1"),
		DstIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: 1234,
		DstPort: 80,
		Proto:   engine.ProtoTCP,
		State:   engine.StateNew,
	}

	newIP := netip.MustParseAddr("192.168.1.1")
	p2 := orig.WithSrcIP(newIP)
	if p2.SrcIP != newIP {
		t.Errorf("WithSrcIP: got %v; want %v", p2.SrcIP, newIP)
	}
	// Original no debe cambiar (inmutabilidad).
	if orig.SrcIP == newIP {
		t.Error("WithSrcIP mutó el paquete original")
	}

	p3 := orig.WithDstPort(443)
	if p3.DstPort != 443 {
		t.Errorf("WithDstPort: got %d; want 443", p3.DstPort)
	}
	if orig.DstPort != 80 {
		t.Error("WithDstPort mutó el paquete original")
	}
}

func TestSrcIPMatcher(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		prefix string
		negate bool
		srcIP  string
		want   bool
	}{
		{"coincide exacto", "10.0.0.5/32", false, "10.0.0.5", true},
		{"coincide CIDR", "10.0.0.0/24", false, "10.0.0.100", true},
		{"no coincide", "10.0.0.0/24", false, "192.168.1.1", false},
		{"negado coincide→false", "10.0.0.5/32", true, "10.0.0.5", false},
		{"negado no coincide→true", "10.0.0.5/32", true, "192.168.1.1", true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pfx := netip.MustParsePrefix(tt.prefix)
			m := &engine.SrcIPMatcher{Prefix: pfx, Negate: tt.negate}
			pkt := engine.Packet{SrcIP: netip.MustParseAddr(tt.srcIP)}
			if got := m.Matches(pkt); got != tt.want {
				t.Errorf("SrcIPMatcher.Matches() = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestDstPortMatcher(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		lo, hi  uint16
		negate  bool
		dstPort uint16
		want    bool
	}{
		{"puerto exacto coincide", 80, 80, false, 80, true},
		{"puerto exacto no coincide", 80, 80, false, 81, false},
		{"rango coincide", 80, 90, false, 85, true},
		{"rango límite inferior", 80, 90, false, 80, true},
		{"rango límite superior", 80, 90, false, 90, true},
		{"rango fuera", 80, 90, false, 91, false},
		{"negado coincide→false", 80, 80, true, 80, false},
		{"negado no coincide→true", 80, 80, true, 443, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := &engine.DstPortMatcher{Lo: tt.lo, Hi: tt.hi, Negate: tt.negate}
			pkt := engine.Packet{DstPort: tt.dstPort}
			if got := m.Matches(pkt); got != tt.want {
				t.Errorf("DstPortMatcher.Matches() = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestStateMatcher(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		states engine.ConnState
		negate bool
		pktSt  engine.ConnState
		want   bool
	}{
		{"NEW coincide", engine.StateNew, false, engine.StateNew, true},
		{"ESTABLISHED no coincide con NEW", engine.StateNew, false, engine.StateEstablished, false},
		{"máscara múltiple", engine.StateNew | engine.StateEstablished, false, engine.StateEstablished, true},
		{"negado coincide→false", engine.StateNew, true, engine.StateNew, false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := &engine.StateMatcher{States: tt.states, Negate: tt.negate}
			pkt := engine.Packet{State: tt.pktSt}
			if got := m.Matches(pkt); got != tt.want {
				t.Errorf("StateMatcher.Matches() = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestProtoMatcher(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		proto  engine.Proto
		negate bool
		pktP   engine.Proto
		want   bool
	}{
		{"TCP coincide", engine.ProtoTCP, false, engine.ProtoTCP, true},
		{"TCP no coincide con UDP", engine.ProtoTCP, false, engine.ProtoUDP, false},
		{"All coincide con TCP", engine.ProtoAll, false, engine.ProtoTCP, true},
		{"negado TCP→false para TCP", engine.ProtoTCP, true, engine.ProtoTCP, false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := &engine.ProtoMatcher{Proto: tt.proto, Negate: tt.negate}
			pkt := engine.Packet{Proto: tt.pktP}
			if got := m.Matches(pkt); got != tt.want {
				t.Errorf("ProtoMatcher.Matches() = %v; want %v", got, tt.want)
			}
		})
	}
}
