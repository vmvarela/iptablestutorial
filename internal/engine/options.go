package engine

import "net/netip"

const defaultMaxDepth = 20

// evalConfig almacena la configuración del Evaluator.
type evalConfig struct {
	localIPs []netip.Addr
	maxDepth int
	tracing  bool
}

// EvalOption es una opción funcional para configurar el Evaluator.
type EvalOption func(*evalConfig)

// WithLocalIPs indica qué IPs pertenecen al propio firewall (el castillo).
// Los paquetes destinados a estas IPs atraviesan la cadena INPUT;
// los que salen de ellas usan OUTPUT; el resto, FORWARD.
func WithLocalIPs(ips ...netip.Addr) EvalOption {
	return func(c *evalConfig) {
		c.localIPs = append(c.localIPs, ips...)
	}
}

// WithMaxDepth configura la profundidad máxima de recursión de cadenas.
// El valor por defecto es 20.
func WithMaxDepth(n int) EvalOption {
	return func(c *evalConfig) {
		if n > 0 {
			c.maxDepth = n
		}
	}
}

// WithTracing activa o desactiva la recopilación de la traza de evaluación.
// Por defecto está activada.
func WithTracing(enabled bool) EvalOption {
	return func(c *evalConfig) {
		c.tracing = enabled
	}
}
