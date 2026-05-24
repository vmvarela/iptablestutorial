package engine

import "errors"

// Errores centinela del motor de simulación.
var (
	// ErrChainNotFound se devuelve cuando se referencia una chain inexistente.
	ErrChainNotFound = errors.New("engine: cadena no encontrada")

	// ErrTableNotFound se devuelve cuando se referencia una tabla inexistente.
	ErrTableNotFound = errors.New("engine: tabla no encontrada")

	// ErrInvalidPolicy se devuelve al intentar establecer una política no válida.
	ErrInvalidPolicy = errors.New("engine: política no válida (solo ACCEPT o DROP)")

	// ErrChainNotEmpty se devuelve al intentar borrar una chain con reglas.
	ErrChainNotEmpty = errors.New("engine: la cadena no está vacía")

	// ErrChainExists se devuelve al crear una chain que ya existe.
	ErrChainExists = errors.New("engine: la cadena ya existe")

	// ErrBuiltinChain se devuelve al intentar borrar una chain incorporada.
	ErrBuiltinChain = errors.New("engine: no se puede borrar una cadena predefinida")

	// ErrRuleOutOfRange se devuelve cuando el índice de regla está fuera de límites.
	ErrRuleOutOfRange = errors.New("engine: índice de regla fuera de rango")

	// ErrMaxDepthExceeded se devuelve al superar la profundidad máxima de recursión.
	ErrMaxDepthExceeded = errors.New("engine: profundidad máxima de recursión superada")
)

// ParseError describe un error de parseo de una línea iptables.
type ParseError struct {
	Line string
	Pos  int
	Msg  string
}

// Error implementa la interfaz error.
func (e *ParseError) Error() string {
	if e.Pos >= 0 {
		return "engine: error de parseo en posición " + itoa(e.Pos) + ": " + e.Msg + " (en: " + e.Line + ")"
	}
	return "engine: error de parseo: " + e.Msg + " (en: " + e.Line + ")"
}

// itoa convierte un int a string sin usar fmt.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
