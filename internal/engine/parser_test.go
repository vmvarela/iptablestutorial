package engine_test

import (
	"testing"

	"github.com/vmvarela/iptablestutorial/internal/engine"
)

// ---- ParseLine: acciones principales ------------------------------------

func TestParseLine_Append(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		line    string
		table   string
		chain   string
		wantErr bool
	}{
		{
			name:  "append básico tcp 80",
			line:  "iptables -A INPUT -p tcp --dport 80 -j ACCEPT",
			table: "filter", chain: "INPUT",
		},
		{
			name:  "sin prefijo iptables",
			line:  "-A FORWARD -j DROP",
			table: "filter", chain: "FORWARD",
		},
		{
			name:  "tabla nat explícita",
			line:  "iptables -t nat -A PREROUTING -p tcp --dport 80 -j ACCEPT",
			table: "nat", chain: "PREROUTING",
		},
		{
			name:  "tabla explícita al final (no-op en simulación)",
			line:  "-A OUTPUT -j ACCEPT -t filter",
			table: "filter", chain: "OUTPUT",
		},
		{
			name:    "sin -j objetivo",
			line:    "-A INPUT -p tcp --dport 80",
			wantErr: true,
		},
		{
			name:    "línea vacía",
			line:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cmd, err := engine.ParseLine(tt.line)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseLine(%q) esperaba error, got nil", tt.line)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseLine(%q) error inesperado: %v", tt.line, err)
			}
			if cmd.Table != tt.table {
				t.Errorf("Table=%q; want %q", cmd.Table, tt.table)
			}
			if cmd.Chain != tt.chain {
				t.Errorf("Chain=%q; want %q", cmd.Chain, tt.chain)
			}
			if cmd.Action != engine.ActionAppend {
				t.Errorf("Action=%v; want ActionAppend", cmd.Action)
			}
		})
	}
}

func TestParseLine_Insert(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		line   string
		insPos int
	}{
		{
			name:   "insert sin posición → 1",
			line:   "-I INPUT -p tcp --dport 22 -j ACCEPT",
			insPos: 1,
		},
		{
			name:   "insert con posición 3",
			line:   "-I INPUT 3 -p tcp --dport 443 -j ACCEPT",
			insPos: 3,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cmd, err := engine.ParseLine(tt.line)
			if err != nil {
				t.Fatalf("ParseLine error: %v", err)
			}
			if cmd.Action != engine.ActionInsert {
				t.Errorf("Action=%v; want ActionInsert", cmd.Action)
			}
			if cmd.InsPos != tt.insPos {
				t.Errorf("InsPos=%d; want %d", cmd.InsPos, tt.insPos)
			}
		})
	}
}

func TestParseLine_Delete(t *testing.T) {
	t.Parallel()
	t.Run("delete por spec", func(t *testing.T) {
		t.Parallel()
		cmd, err := engine.ParseLine("-D INPUT -p tcp --dport 80 -j ACCEPT")
		if err != nil {
			t.Fatalf("error inesperado: %v", err)
		}
		if cmd.Action != engine.ActionDelete {
			t.Errorf("Action=%v; want ActionDelete", cmd.Action)
		}
	})
	t.Run("delete por índice", func(t *testing.T) {
		t.Parallel()
		cmd, err := engine.ParseLine("-D INPUT 2")
		if err != nil {
			t.Fatalf("error inesperado: %v", err)
		}
		if cmd.Action != engine.ActionDeleteIndex {
			t.Errorf("Action=%v; want ActionDeleteIndex", cmd.Action)
		}
		if cmd.DelIdx != 2 {
			t.Errorf("DelIdx=%d; want 2", cmd.DelIdx)
		}
	})
}

func TestParseLine_Replace(t *testing.T) {
	t.Parallel()
	cmd, err := engine.ParseLine("-R INPUT 2 -p tcp --dport 443 -j ACCEPT")
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if cmd.Action != engine.ActionReplace {
		t.Errorf("Action=%v; want ActionReplace", cmd.Action)
	}
	if cmd.InsPos != 2 {
		t.Errorf("InsPos=%d; want 2 (rulenum)", cmd.InsPos)
	}
}

func TestParseLine_Flush(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		line  string
		chain string
	}{
		{"flush cadena", "-F INPUT", "INPUT"},
		{"flush todo", "-F", ""},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cmd, err := engine.ParseLine(tt.line)
			if err != nil {
				t.Fatalf("error inesperado: %v", err)
			}
			if cmd.Action != engine.ActionFlush {
				t.Errorf("Action=%v; want ActionFlush", cmd.Action)
			}
			if cmd.Chain != tt.chain {
				t.Errorf("Chain=%q; want %q", cmd.Chain, tt.chain)
			}
		})
	}
}

func TestParseLine_Policy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		line       string
		chain      string
		policyStr  string
	}{
		{"policy ACCEPT", "-P INPUT ACCEPT", "INPUT", "ACCEPT"},
		{"policy DROP", "-P FORWARD DROP", "FORWARD", "DROP"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cmd, err := engine.ParseLine(tt.line)
			if err != nil {
				t.Fatalf("error inesperado: %v", err)
			}
			if cmd.Action != engine.ActionSetPolicy {
				t.Errorf("Action=%v; want ActionSetPolicy", cmd.Action)
			}
			if cmd.Chain != tt.chain {
				t.Errorf("Chain=%q; want %q", cmd.Chain, tt.chain)
			}
			if cmd.Policy == nil {
				t.Fatal("Policy es nil")
			}
			if cmd.Policy.String() != tt.policyStr {
				t.Errorf("Policy=%q; want %q", cmd.Policy.String(), tt.policyStr)
			}
		})
	}
}

func TestParseLine_NewDeleteChain(t *testing.T) {
	t.Parallel()
	t.Run("new chain", func(t *testing.T) {
		t.Parallel()
		cmd, err := engine.ParseLine("-N MISREGLAS")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if cmd.Action != engine.ActionNewChain {
			t.Errorf("Action=%v; want ActionNewChain", cmd.Action)
		}
		if cmd.Chain != "MISREGLAS" {
			t.Errorf("Chain=%q; want MISREGLAS", cmd.Chain)
		}
	})
	t.Run("delete chain", func(t *testing.T) {
		t.Parallel()
		cmd, err := engine.ParseLine("-X MISREGLAS")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if cmd.Action != engine.ActionDeleteChain {
			t.Errorf("Action=%v; want ActionDeleteChain", cmd.Action)
		}
	})
}

// ---- ParseLine: matchers -------------------------------------------------

func TestParseLine_Matchers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		line    string
		wantErr bool
	}{
		{
			name: "source IP",
			line: "-A INPUT -s 10.0.0.5 -j ACCEPT",
		},
		{
			name: "source CIDR",
			line: "-A INPUT -s 192.168.0.0/24 -j ACCEPT",
		},
		{
			name: "dst CIDR",
			line: "-A FORWARD -d 10.0.0.0/8 -j DROP",
		},
		{
			name: "sport range",
			line: "-A OUTPUT -p tcp --sport 1024:65535 -j ACCEPT",
		},
		{
			name: "dport exacto",
			line: "-A INPUT -p tcp --dport 443 -j ACCEPT",
		},
		{
			name: "in-interface",
			line: "-A INPUT -i eth0 -j ACCEPT",
		},
		{
			name: "out-interface",
			line: "-A FORWARD -o eth1 -j DROP",
		},
		{
			name: "connstate -m state",
			line: "-A INPUT -m state --state NEW,ESTABLISHED -j ACCEPT",
		},
		{
			name: "connstate -m conntrack",
			line: "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		},
		{
			name: "negación proto",
			line: "-A INPUT ! -p tcp -j DROP",
		},
		{
			name: "negación src",
			line: "-A INPUT ! -s 10.0.0.0/8 -j DROP",
		},
		{
			name: "REJECT con --reject-with",
			line: "-A INPUT -p tcp --dport 80 -j REJECT --reject-with tcp-reset",
		},
		{
			name: "LOG con --log-prefix",
			line: `-A INPUT -p tcp --dport 22 -j LOG --log-prefix "SSH: "`,
		},
		{
			name: "JUMP a cadena de usuario",
			line: "-A INPUT -p tcp -j MISREGLAS",
		},
		{
			name: "comment",
			line: `-A INPUT -p tcp --dport 80 -m comment --comment "http traffic" -j ACCEPT`,
		},
		{
			name:    "CIDR inválido",
			line:    "-A INPUT -s no-es-una-ip -j ACCEPT",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := engine.ParseLine(tt.line)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseLine(%q) esperaba error, got nil", tt.line)
				}
			} else {
				if err != nil {
					t.Errorf("ParseLine(%q) error inesperado: %v", tt.line, err)
				}
			}
		})
	}
}

// ---- Apply (parser → Ruleset) -------------------------------------------

func TestApply_AppendAndFlush(t *testing.T) {
	t.Parallel()
	rs := engine.NewRuleset()

	mustApply := func(t *testing.T, line string) {
		t.Helper()
		cmd, err := engine.ParseLine(line)
		if err != nil {
			t.Fatalf("ParseLine(%q): %v", line, err)
		}
		if err2 := engine.Apply(rs, cmd); err2 != nil {
			t.Fatalf("Apply(%q): %v", line, err2)
		}
	}

	mustApply(t, "-A INPUT -p tcp --dport 80 -j ACCEPT")
	mustApply(t, "-A INPUT -p tcp --dport 443 -j ACCEPT")

	rules, err := rs.Rules("filter", "INPUT")
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	if len(rules) != 2 {
		t.Errorf("len(rules)=%d; want 2", len(rules))
	}

	mustApply(t, "-F INPUT")
	rules, _ = rs.Rules("filter", "INPUT")
	if len(rules) != 0 {
		t.Errorf("tras -F: len(rules)=%d; want 0", len(rules))
	}
}

func TestApply_SetPolicy(t *testing.T) {
	t.Parallel()
	rs := engine.NewRuleset()
	cmd, err := engine.ParseLine("-P INPUT DROP")
	if err != nil {
		t.Fatalf("ParseLine: %v", err)
	}
	if err2 := engine.Apply(rs, cmd); err2 != nil {
		t.Fatalf("Apply: %v", err2)
	}
	c, err := rs.GetChain("filter", "INPUT")
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if c.Policy == nil || c.Policy.String() != "DROP" {
		t.Errorf("Policy=%v; want DROP", c.Policy)
	}
}

func TestApply_NewAndDeleteChain(t *testing.T) {
	t.Parallel()
	rs := engine.NewRuleset()

	mustApply := func(t *testing.T, line string) {
		t.Helper()
		cmd, err := engine.ParseLine(line)
		if err != nil {
			t.Fatalf("ParseLine: %v", err)
		}
		if err2 := engine.Apply(rs, cmd); err2 != nil {
			t.Fatalf("Apply: %v", err2)
		}
	}

	mustApply(t, "-N GUARDIAS")
	_, ok := rs.Chain("filter", "GUARDIAS")
	if !ok {
		t.Fatal("cadena GUARDIAS no creada")
	}

	mustApply(t, "-X GUARDIAS")
	_, ok = rs.Chain("filter", "GUARDIAS")
	if ok {
		t.Fatal("cadena GUARDIAS no borrada")
	}
}

// ---- Fuzz ----------------------------------------------------------------

// FuzzParseLine prueba que el parser no entre en pánico con entrada arbitraria.
func FuzzParseLine(f *testing.F) {
	seeds := []string{
		"-A INPUT -p tcp --dport 80 -j ACCEPT",
		"-D INPUT 1",
		"-P FORWARD DROP",
		"-N MYCHAINX",
		"-X MYCHAINX",
		"-F",
		"-I INPUT 1 -s 10.0.0.1 -j DROP",
		"iptables -t nat -A PREROUTING -p tcp --dport 80 -j ACCEPT",
		"-A INPUT -m state --state NEW,ESTABLISHED -j ACCEPT",
		"-A INPUT ! -p tcp -j DROP",
		"",
		"   ",
		"-A",
		"-D INPUT",
		"xyz --foo bar",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		// Solo comprobamos que no hay pánico; el error es aceptable.
		_, _ = engine.ParseLine(line)
	})
}
