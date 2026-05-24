package engine

import (
	"net/netip"
	"strings"
)

// Action representa la acción de un comando iptables.
type Action int

const (
	// ActionAppend añade una regla al final (-A).
	ActionAppend Action = iota
	// ActionInsert inserta una regla (-I).
	ActionInsert
	// ActionDelete borra una regla por especificación (-D rule-spec).
	ActionDelete
	// ActionDeleteIndex borra una regla por índice (-D chain rulenum).
	ActionDeleteIndex
	// ActionReplace reemplaza una regla (-R).
	ActionReplace
	// ActionFlush vacía una cadena (-F).
	ActionFlush
	// ActionZero pone a cero los contadores (-Z, no-op en la simulación).
	ActionZero
	// ActionNewChain crea una cadena de usuario (-N).
	ActionNewChain
	// ActionDeleteChain borra una cadena de usuario (-X).
	ActionDeleteChain
	// ActionSetPolicy establece la política por defecto (-P).
	ActionSetPolicy
	// ActionList lista las reglas (-L).
	ActionList
)

// ParsedCmd representa un comando iptables ya parseado.
type ParsedCmd struct {
	Table   string // "filter" por defecto
	Action  Action
	Chain   string
	InsPos  int    // posición para -I (1-based; 0 = comportamiento por defecto)
	DelIdx  int    // índice para -D rulenum (1-based)
	Rule    Rule   // para acciones que manipulan reglas
	Policy  Target // para -P
}

// ParseLine parsea una línea de comando iptables.
// El prefijo "iptables" es opcional. Devuelve un *ParsedCmd o un *ParseError.
func ParseLine(line string) (*ParsedCmd, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, &ParseError{Line: line, Pos: -1, Msg: "línea vacía"}
	}

	tokens := tokenize(line)
	if len(tokens) == 0 {
		return nil, &ParseError{Line: line, Pos: -1, Msg: "sin tokens"}
	}

	// Ignorar el prefijo "iptables" o "iptables6" si está presente.
	if tokens[0] == "iptables" || tokens[0] == "iptables6" {
		tokens = tokens[1:]
	}
	if len(tokens) == 0 {
		return nil, &ParseError{Line: line, Pos: -1, Msg: "comando vacío"}
	}

	p := &parser{tokens: tokens, line: line, pos: 0}
	return p.parse()
}

// Apply aplica un ParsedCmd a un Ruleset.
func Apply(rs *Ruleset, cmd *ParsedCmd) error {
	switch cmd.Action {
	case ActionAppend:
		return rs.AppendRule(cmd.Table, cmd.Chain, cmd.Rule)
	case ActionInsert:
		return rs.InsertRule(cmd.Table, cmd.Chain, cmd.InsPos, cmd.Rule)
	case ActionDelete:
		return rs.DeleteBySpec(cmd.Table, cmd.Chain, cmd.Rule)
	case ActionDeleteIndex:
		return rs.DeleteByIndex(cmd.Table, cmd.Chain, cmd.DelIdx-1) // convierte 1-based a 0-based
	case ActionReplace:
		idx := cmd.InsPos - 1 // InsPos se usa como rulenum en -R
		return rs.ReplaceRule(cmd.Table, cmd.Chain, idx, cmd.Rule)
	case ActionFlush:
		if cmd.Chain == "" {
			return rs.FlushAllChains(cmd.Table)
		}
		return rs.FlushChain(cmd.Table, cmd.Chain)
	case ActionZero:
		return nil // no-op en la simulación
	case ActionNewChain:
		return rs.NewChain(cmd.Table, cmd.Chain)
	case ActionDeleteChain:
		return rs.DeleteChain(cmd.Table, cmd.Chain)
	case ActionSetPolicy:
		return rs.SetPolicy(cmd.Table, cmd.Chain, cmd.Policy)
	case ActionList:
		return nil // no-op; la UI lee el Ruleset directamente
	default:
		return &ParseError{Line: "", Pos: -1, Msg: "acción desconocida"}
	}
}

// ---- Tokenizer -----------------------------------------------------------

// tokenize divide una línea en tokens respetando comillas simples y dobles.
func tokenize(line string) []string {
	var tokens []string
	var cur strings.Builder
	inSingle, inDouble := false, false

	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case ch == '\'' && !inDouble:
			inSingle = !inSingle
		case ch == '"' && !inSingle:
			inDouble = !inDouble
		case (ch == ' ' || ch == '\t') && !inSingle && !inDouble:
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

// ---- Parser --------------------------------------------------------------

type parser struct {
	tokens []string
	line   string
	pos    int
}

func (p *parser) peek() string {
	if p.pos >= len(p.tokens) {
		return ""
	}
	return p.tokens[p.pos]
}

func (p *parser) next() string {
	if p.pos >= len(p.tokens) {
		return ""
	}
	t := p.tokens[p.pos]
	p.pos++
	return t
}

func (p *parser) expect(what string) (string, error) {
	t := p.next()
	if t == "" {
		return "", &ParseError{Line: p.line, Pos: p.pos, Msg: "se esperaba " + what + " pero se llegó al final"}
	}
	return t, nil
}

func (p *parser) errorf(msg string) error {
	return &ParseError{Line: p.line, Pos: p.pos, Msg: msg}
}

func (p *parser) parse() (*ParsedCmd, error) { //nolint:gocyclo,funlen // parser dispatch is inherently complex
	cmd := &ParsedCmd{Table: "filter"}

	// Primer pase: buscar -t para la tabla (puede aparecer en cualquier posición).
	for i := 0; i < len(p.tokens)-1; i++ {
		if p.tokens[i] == "-t" || p.tokens[i] == "--table" {
			cmd.Table = p.tokens[i+1]
			// Eliminar -t TABLE de los tokens para simplificar el resto del parseo.
			p.tokens = append(p.tokens[:i], p.tokens[i+2:]...)
			break
		}
	}

	// Buscar la acción principal.
	action, err := p.parseAction()
	if err != nil {
		return nil, err
	}
	cmd.Action = action

	// Parsear la cadena.
	switch action {
	case ActionFlush, ActionZero, ActionList:
		// La cadena es opcional.
		if p.pos < len(p.tokens) && !strings.HasPrefix(p.peek(), "-") {
			cmd.Chain = p.next()
		}
	case ActionNewChain, ActionDeleteChain:
		chain, err2 := p.expect("nombre de cadena")
		if err2 != nil {
			return nil, err2
		}
		cmd.Chain = chain
	case ActionSetPolicy:
		chain, err2 := p.expect("nombre de cadena")
		if err2 != nil {
			return nil, err2
		}
		cmd.Chain = chain
		targetStr, err3 := p.expect("política (ACCEPT|DROP)")
		if err3 != nil {
			return nil, err3
		}
		t, err4 := parseTargetStr(targetStr)
		if err4 != nil {
			return nil, err4
		}
		cmd.Policy = t
	case ActionInsert, ActionReplace:
		chain, err2 := p.expect("nombre de cadena")
		if err2 != nil {
			return nil, err2
		}
		cmd.Chain = chain
		// Número de posición opcional para -I; obligatorio para -R.
		if p.pos < len(p.tokens) {
			if n, ok := parseUint(p.peek()); ok {
				p.next()
				cmd.InsPos = n
			} else if action == ActionReplace {
				return nil, p.errorf("-R requiere número de regla")
			}
		}
		if cmd.InsPos == 0 {
			cmd.InsPos = 1 // -I sin pos → insertar al principio
		}
		rule, err5 := p.parseRule()
		if err5 != nil {
			return nil, err5
		}
		cmd.Rule = rule
	case ActionDeleteIndex:
		chain, err2 := p.expect("nombre de cadena")
		if err2 != nil {
			return nil, err2
		}
		cmd.Chain = chain
		n, ok := parseUint(p.peek())
		if !ok {
			return nil, p.errorf("-D con número requiere un entero positivo")
		}
		p.next()
		cmd.DelIdx = n
	default: // ActionAppend, ActionDelete
		chain, err2 := p.expect("nombre de cadena")
		if err2 != nil {
			return nil, err2
		}
		cmd.Chain = chain
		rule, err3 := p.parseRule()
		if err3 != nil {
			return nil, err3
		}
		cmd.Rule = rule
	}

	return cmd, nil
}

// parseAction consume el token de acción (-A, -I, etc.).
func (p *parser) parseAction() (Action, error) {
	tok := p.next()
	switch tok {
	case "-A", "--append":
		return ActionAppend, nil
	case "-I", "--insert":
		return ActionInsert, nil
	case "-D", "--delete":
		// Si el siguiente token es un número, es -D chain rulenum.
		// Distinguimos tras parsear la cadena; usamos ActionDelete por ahora
		// y lo corregiremos en el caller.
		return p.resolveDelete(), nil
	case "-R", "--replace":
		return ActionReplace, nil
	case "-F", "--flush":
		return ActionFlush, nil
	case "-Z", "--zero":
		return ActionZero, nil
	case "-N", "--new-chain":
		return ActionNewChain, nil
	case "-X", "--delete-chain":
		return ActionDeleteChain, nil
	case "-P", "--policy":
		return ActionSetPolicy, nil
	case "-L", "--list":
		return ActionList, nil
	default:
		return 0, &ParseError{Line: p.line, Pos: p.pos - 1, Msg: "acción desconocida: " + tok}
	}
}

// resolveDelete determina si -D usa índice numérico o especificación de regla.
// Se llama justo tras consumir "-D"; peek a los tokens siguientes.
func (p *parser) resolveDelete() Action {
	// Si hay al menos 2 tokens y el segundo es numérico → -D chain rulenum.
	if p.pos+1 < len(p.tokens) {
		if _, ok := parseUint(p.tokens[p.pos+1]); ok {
			return ActionDeleteIndex
		}
	}
	return ActionDelete
}

// parseRule parsea los modificadores de regla: matchers + objetivo.
func (p *parser) parseRule() (Rule, error) { //nolint:gocyclo,funlen // rule parsing requires handling all iptables flags
	var matchers []Matcher
	var target Target
	var comment string
	var negate bool

	for p.pos < len(p.tokens) {
		tok := p.next()

		// Negación explícita "!"
		if tok == "!" {
			negate = true
			continue
		}

		switch tok {
		case "-p", "--protocol":
			val, err := p.expect("protocolo")
			if err != nil {
				return Rule{}, err
			}
			proto, ok := ParseProto(val)
			if !ok {
				return Rule{}, p.errorf("protocolo desconocido: " + val)
			}
			matchers = append(matchers, &ProtoMatcher{Proto: proto, Negate: negate})
			negate = false

		case "-s", "--source", "--src":
			val, err := p.expect("IP/CIDR origen")
			if err != nil {
				return Rule{}, err
			}
			pfx, err2 := parsePrefixOrAddr(val)
			if err2 != nil {
				return Rule{}, p.errorf("IP/CIDR inválido: " + val)
			}
			matchers = append(matchers, &SrcIPMatcher{Prefix: pfx, Negate: negate})
			negate = false

		case "-d", "--destination", "--dst":
			val, err := p.expect("IP/CIDR destino")
			if err != nil {
				return Rule{}, err
			}
			pfx, err2 := parsePrefixOrAddr(val)
			if err2 != nil {
				return Rule{}, p.errorf("IP/CIDR inválido: " + val)
			}
			matchers = append(matchers, &DstIPMatcher{Prefix: pfx, Negate: negate})
			negate = false

		case "--sport", "--source-port":
			val, err := p.expect("puerto origen")
			if err != nil {
				return Rule{}, err
			}
			lo, hi, err2 := parsePortRange(val)
			if err2 != nil {
				return Rule{}, err2
			}
			matchers = append(matchers, &SrcPortMatcher{Lo: lo, Hi: hi, Negate: negate})
			negate = false

		case "--dport", "--destination-port":
			val, err := p.expect("puerto destino")
			if err != nil {
				return Rule{}, err
			}
			lo, hi, err2 := parsePortRange(val)
			if err2 != nil {
				return Rule{}, err2
			}
			matchers = append(matchers, &DstPortMatcher{Lo: lo, Hi: hi, Negate: negate})
			negate = false

		case "-i", "--in-interface":
			val, err := p.expect("interfaz entrada")
			if err != nil {
				return Rule{}, err
			}
			matchers = append(matchers, &InIfaceMatcher{Iface: val, Negate: negate})
			negate = false

		case "-o", "--out-interface":
			val, err := p.expect("interfaz salida")
			if err != nil {
				return Rule{}, err
			}
			matchers = append(matchers, &OutIfaceMatcher{Iface: val, Negate: negate})
			negate = false

		case "-m", "--match":
			module, err := p.expect("módulo de match")
			if err != nil {
				return Rule{}, err
			}
			m, err2 := p.parseModule(module, negate)
			if err2 != nil {
				return Rule{}, err2
			}
			if m != nil {
				matchers = append(matchers, m)
			}
			negate = false

		case "-j", "--jump":
			val, err := p.expect("objetivo")
			if err != nil {
				return Rule{}, err
			}
			t, err2 := p.parseTargetWithArgs(val)
			if err2 != nil {
				return Rule{}, err2
			}
			target = t
			negate = false

		case "--comment":
			val, err := p.expect("comentario")
			if err != nil {
				return Rule{}, err
			}
			comment = val
			negate = false

		case "-t", "--table":
			// Ya fue procesada en parse(); ignorar.
			p.next()
			negate = false

		default:
			// Token desconocido — ignorar con gracia para tolerancia.
			negate = false
		}
	}

	if target == nil {
		return Rule{}, p.errorf("falta -j OBJETIVO")
	}

	return Rule{Matchers: matchers, Target: target, Comment: comment}, nil
}

// parseModule parsea los argumentos de un módulo -m.
func (p *parser) parseModule(module string, negModule bool) (Matcher, error) {
	switch strings.ToLower(module) {
	case "state":
		return p.parseStateModule(negModule)
	case "conntrack":
		return p.parseConntrackModule(negModule)
	case "comment":
		// -m comment --comment "texto" es manejado arriba; aquí solo skip.
		return nil, nil
	default:
		// Módulo desconocido: consumir flags hasta el siguiente -flag conocido.
		return nil, nil
	}
}

func (p *parser) parseStateModule(negModule bool) (Matcher, error) {
	if p.peek() != "--state" {
		return nil, p.errorf("-m state requiere --state STATES")
	}
	p.next()
	val, err := p.expect("estados conntrack")
	if err != nil {
		return nil, err
	}
	mask, err := ParseConnStates(val)
	if err != nil {
		return nil, err
	}
	return &StateMatcher{States: mask, Negate: negModule}, nil
}

func (p *parser) parseConntrackModule(negModule bool) (Matcher, error) {
	if p.peek() != "--ctstate" {
		return nil, p.errorf("-m conntrack requiere --ctstate STATES")
	}
	p.next()
	val, err := p.expect("estados conntrack")
	if err != nil {
		return nil, err
	}
	mask, err := ParseConnStates(val)
	if err != nil {
		return nil, err
	}
	return &StateMatcher{States: mask, Negate: negModule}, nil
}

// parseNATAddr parsea un argumento "--to-destination addr[:port]" o "--to-source addr".
func (p *parser) parseNATAddr(flag string) (netip.Addr, uint16, error) {
	if p.peek() != flag {
		return netip.Addr{}, 0, p.errorf("se esperaba " + flag)
	}
	p.next()
	val, err := p.expect("dirección NAT")
	if err != nil {
		return netip.Addr{}, 0, err
	}

	// Parsear "addr" o "addr:port" (solo IPv4 con puerto al final).
	if idx := strings.LastIndex(val, ":"); idx >= 0 {
		addrStr := val[:idx]
		portStr := val[idx+1:]
		addr, err2 := netip.ParseAddr(addrStr)
		if err2 != nil {
			return netip.Addr{}, 0, p.errorf("dirección NAT inválida: " + addrStr)
		}
		port, ok := parseUint(portStr)
		if !ok || port > 65535 {
			return netip.Addr{}, 0, p.errorf("puerto NAT inválido: " + portStr)
		}
		return addr, uint16(port), nil //nolint:gosec // validated ≤ 65535 above
	}

	addr, err2 := netip.ParseAddr(val)
	if err2 != nil {
		return netip.Addr{}, 0, p.errorf("dirección NAT inválida: " + val)
	}
	return addr, 0, nil
}

// parseTargetWithArgs parsea el objetivo y sus argumentos adicionales.
func (p *parser) parseTargetWithArgs(name string) (Target, error) {
	switch name {
	case "ACCEPT":
		return Accept, nil
	case "DROP":
		return Drop, nil
	case "RETURN":
		return Return, nil
	case "REJECT":
		icmpType := ""
		if p.peek() == "--reject-with" {
			p.next()
			val, err := p.expect("tipo ICMP de rechazo")
			if err != nil {
				return nil, err
			}
			icmpType = val
		}
		return Reject(icmpType), nil
	case "LOG":
		prefix := ""
		if p.peek() == "--log-prefix" {
			p.next()
			val, err := p.expect("prefijo de log")
			if err != nil {
				return nil, err
			}
			prefix = val
		}
		return Log(prefix), nil
	case "DNAT":
		toAddr, toPort, err := p.parseNATAddr("--to-destination")
		if err != nil {
			return nil, err
		}
		return DNAT(toAddr, toPort), nil
	case "SNAT":
		toAddr, _, err := p.parseNATAddr("--to-source")
		if err != nil {
			return nil, err
		}
		return SNAT(toAddr), nil
	case "MASQUERADE":
		// Ignorar --to-ports si aparece (no relevante en la simulación).
		if p.peek() == "--to-ports" {
			p.next()
			p.next()
		}
		return Masquerade(), nil
	default:
		// Cualquier otro nombre se trata como cadena de usuario.
		return Jump(name), nil
	}
}

// parseTargetStr parsea un nombre de objetivo simple (sin argumentos adicionales).
func parseTargetStr(s string) (Target, error) {
	switch s {
	case "ACCEPT":
		return Accept, nil
	case "DROP":
		return Drop, nil
	case "REJECT":
		return Reject(""), nil
	case "RETURN":
		return Return, nil
	default:
		return nil, &ParseError{Line: s, Pos: 0, Msg: "objetivo de política no válido: " + s}
	}
}

// ---- Helpers -------------------------------------------------------------

// parsePrefixOrAddr convierte una cadena IP o IP/CIDR a netip.Prefix.
// Si no tiene máscara, crea un prefijo de un solo host (/32 o /128).
func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(addr, bits), nil
}

// parsePortRange parsea "port" o "port:port" y devuelve (lo, hi).
func parsePortRange(s string) (uint16, uint16, error) {
	if idx := strings.Index(s, ":"); idx >= 0 {
		lo, ok1 := parseUint(s[:idx])
		hi, ok2 := parseUint(s[idx+1:])
		if !ok1 || !ok2 || lo > hi || lo > 65535 || hi > 65535 {
			return 0, 0, &ParseError{Line: s, Pos: 0, Msg: "rango de puertos inválido: " + s}
		}
		return uint16(lo), uint16(hi), nil //nolint:gosec // values validated ≤ 65535 above
	}
	n, ok := parseUint(s)
	if !ok || n > 65535 {
		return 0, 0, &ParseError{Line: s, Pos: 0, Msg: "puerto inválido: " + s}
	}
	return uint16(n), uint16(n), nil //nolint:gosec // value validated ≤ 65535 above
}

// parseUint convierte un string a int sin usar strconv (evita dependencia).
// Devuelve (0, false) si el string no es un entero positivo válido.
func parseUint(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}
