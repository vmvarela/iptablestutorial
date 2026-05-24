package translate

import (
	"net/netip"
	"testing"

	"github.com/vmvarela/iptablestutorial/internal/engine"
)

func TestToIPTables(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rule engine.Rule
		want string
	}{
		{
			name: "simple accept no matchers",
			rule: engine.Rule{Target: engine.Accept},
			want: "-j ACCEPT",
		},
		{
			name: "tcp port 80 drop",
			rule: engine.Rule{
				Matchers: []engine.Matcher{
					&engine.ProtoMatcher{Proto: engine.ProtoTCP},
					&engine.DstPortMatcher{Lo: 80, Hi: 80},
				},
				Target: engine.Drop,
			},
			want: "-p tcp --dport 80 -j DROP",
		},
		{
			name: "cidr source accept",
			rule: engine.Rule{
				Matchers: []engine.Matcher{
					&engine.SrcIPMatcher{Prefix: netip.MustParsePrefix("192.168.1.0/24")},
				},
				Target: engine.Accept,
			},
			want: "-s 192.168.1.0/24 -j ACCEPT",
		},
		{
			name: "state established accept",
			rule: engine.Rule{
				Matchers: []engine.Matcher{
					&engine.StateMatcher{States: engine.StateEstablished},
				},
				Target: engine.Accept,
			},
			want: "-m state --state ESTABLISHED -j ACCEPT",
		},
		{
			name: "comment appended before target",
			rule: engine.Rule{
				Matchers: []engine.Matcher{
					&engine.ProtoMatcher{Proto: engine.ProtoUDP},
				},
				Target:  engine.Accept,
				Comment: "allow dns",
			},
			want: `-p udp -m comment --comment "allow dns" -j ACCEPT`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ToIPTables(tt.rule)
			if got != tt.want {
				t.Errorf("ToIPTables() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHumanize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rule engine.Rule
		want string
	}{
		{
			name: "simple accept",
			rule: engine.Rule{Target: engine.Accept},
			want: "Para todo, ¡déjalo pasar!.",
		},
		{
			name: "complex rule",
			rule: engine.Rule{
				Matchers: []engine.Matcher{
					&engine.ProtoMatcher{Proto: engine.ProtoTCP},
					&engine.DstPortMatcher{Lo: 80, Hi: 80},
					&engine.SrcIPMatcher{Prefix: netip.MustParsePrefix("10.0.0.0/8")},
					&engine.StateMatcher{States: engine.StateNew},
				},
				Target: engine.Drop,
			},
			want: "Si llega un mensajero tipo tcp, hacia el puerto 80, desde el reino 10.0.0.0/8, conexión nueva, ¡detenlo en silencio!.",
		},
		{
			name: "jump target",
			rule: engine.Rule{
				Matchers: []engine.Matcher{
					&engine.ProtoMatcher{Proto: engine.ProtoUDP},
				},
				Target: engine.Jump("CUSTOM"),
			},
			want: "Si llega un mensajero tipo udp, saltar a la cadena CUSTOM.",
		},
		{
			name: "negated matcher",
			rule: engine.Rule{
				Matchers: []engine.Matcher{
					&engine.ProtoMatcher{Proto: engine.ProtoICMP, Negate: true},
				},
				Target: engine.Accept,
			},
			want: "Si llega que NO sea un mensajero tipo icmp, ¡déjalo pasar!.",
		},
		{
			name: "port range",
			rule: engine.Rule{
				Matchers: []engine.Matcher{
					&engine.DstPortMatcher{Lo: 1000, Hi: 2000},
				},
				Target: engine.Accept,
			},
			want: "Si llega hacia el puerto entre 1000 y 2000, ¡déjalo pasar!.",
		},
		{
			name: "log target",
			rule: engine.Rule{
				Target: engine.Log("FW"),
			},
			want: "Para todo, registrar en el libro.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := Humanize(tt.rule)
			if got != tt.want {
				t.Errorf("Humanize() = %q, want %q", got, tt.want)
			}
		})
	}
}
