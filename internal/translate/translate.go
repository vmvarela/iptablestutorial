package translate

import (
	"strconv"
	"strings"

	"github.com/vmvarela/iptablestutorial/internal/engine"
)

// ToIPTables serializa una regla del motor a su representación en línea de
// comandos de iptables (sin el prefijo -A CADENA).
//
// El formato es: [matchers...] [-m comment --comment "<comentario>"] -j TARGET.
func ToIPTables(r engine.Rule) string {
	var parts []string
	for _, m := range r.Matchers {
		parts = append(parts, m.String())
	}
	if r.Comment != "" {
		parts = append(parts, `-m comment --comment "`+r.Comment+`"`)
	}
	parts = append(parts, "-j", r.Target.String())
	return strings.Join(parts, " ")
}

// Humanize devuelve una descripción amigable en español de una regla,
// explicada como si fuera un guardia en un castillo medieval para un
// público adolescente.
func Humanize(r engine.Rule) string {
	var descs []string
	for _, m := range r.Matchers {
		desc := humanizeMatcher(m)
		if desc != "" {
			descs = append(descs, desc)
		}
	}

	var sb strings.Builder
	if len(descs) > 0 {
		sb.WriteString("Si llega ")
		sb.WriteString(strings.Join(descs, ", "))
	} else {
		sb.WriteString("Para todo")
	}
	sb.WriteString(", ")
	sb.WriteString(humanizeTarget(r.Target))
	sb.WriteString(".")
	return sb.String()
}

func humanizeMatcher(m engine.Matcher) string { //nolint:gocyclo // type switch over all matcher types
	switch v := m.(type) {
	case *engine.ProtoMatcher:
		desc := "un mensajero tipo " + v.Proto.String()
		if v.Negate {
			return "que NO sea " + desc
		}
		return desc
	case *engine.SrcIPMatcher:
		desc := "desde el reino " + v.Prefix.String()
		if v.Negate {
			return "que NO sea " + desc
		}
		return desc
	case *engine.DstIPMatcher:
		desc := "hacia " + v.Prefix.String()
		if v.Negate {
			return "que NO sea " + desc
		}
		return desc
	case *engine.SrcPortMatcher:
		var desc string
		if v.Lo == v.Hi {
			desc = "desde el puerto " + strconv.Itoa(int(v.Lo))
		} else {
			desc = "desde el puerto entre " + strconv.Itoa(int(v.Lo)) + " y " + strconv.Itoa(int(v.Hi))
		}
		if v.Negate {
			return "que NO sea " + desc
		}
		return desc
	case *engine.DstPortMatcher:
		var desc string
		if v.Lo == v.Hi {
			desc = "hacia el puerto " + strconv.Itoa(int(v.Lo))
		} else {
			desc = "hacia el puerto entre " + strconv.Itoa(int(v.Lo)) + " y " + strconv.Itoa(int(v.Hi))
		}
		if v.Negate {
			return "que NO sea " + desc
		}
		return desc
	case *engine.InIfaceMatcher:
		desc := "por la entrada " + v.Iface
		if v.Negate {
			return "que NO sea " + desc
		}
		return desc
	case *engine.OutIfaceMatcher:
		desc := "por la salida " + v.Iface
		if v.Negate {
			return "que NO sea " + desc
		}
		return desc
	case *engine.StateMatcher:
		var states []string
		if v.States&engine.StateNew != 0 {
			states = append(states, "conexión nueva")
		}
		if v.States&engine.StateEstablished != 0 {
			states = append(states, "conexión ya conocida")
		}
		if v.States&engine.StateRelated != 0 {
			states = append(states, "conexión relacionada")
		}
		if v.States&engine.StateInvalid != 0 {
			states = append(states, "conexión inválida")
		}
		if v.States&engine.StateUntracked != 0 {
			states = append(states, "sin rastrear")
		}
		desc := strings.Join(states, ", ")
		if v.Negate {
			return "que NO sea " + desc
		}
		return desc
	default:
		return ""
	}
}

func humanizeTarget(t engine.Target) string {
	if j, ok := t.(engine.Jumper); ok {
		return "saltar a la cadena " + j.ChainName()
	}

	s := t.String()
	switch {
	case s == "ACCEPT":
		return "¡déjalo pasar!"
	case s == "DROP":
		return "¡detenlo en silencio!"
	case strings.HasPrefix(s, "REJECT"):
		return "¡recházalo con aviso!"
	case s == "RETURN":
		return "devolver al guardia anterior"
	case strings.HasPrefix(s, "LOG"):
		return "registrar en el libro"
	default:
		return "hacer algo misterioso (" + s + ")"
	}
}
