# Silvia y el Castillo de las Reglas

[![CI](https://github.com/vmvarela/iptablestutorial/actions/workflows/ci.yml/badge.svg)](https://github.com/vmvarela/iptablestutorial/actions/workflows/ci.yml)
[![Go version](https://img.shields.io/github/go-mod/go-version/vmvarela/iptablestutorial)](go.mod)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Un juego interactivo de terminal que enseña `iptables` y el modelo Netfilter de Linux a través de una metáfora medieval. Eres Silvia, guardiana de un castillo; los paquetes de red son mensajeros de reinos lejanos, y las reglas de firewall son los guardias que decides colocar en las puertas.

![Captura del juego](docs/screenshot.png)

## Quick Start

```bash
go install github.com/vmvarela/iptablestutorial/cmd/silvia-castillo@latest
silvia-castillo
```

O descarga el binario precompilado desde [Releases](https://github.com/vmvarela/iptablestutorial/releases).

El juego arranca directamente en el terminal. No requiere root, no toca `iptables` del sistema — todo es simulado en memoria.

## Cómo se juega

El juego tiene 8 niveles de dificultad creciente. Cada nivel plantea una misión de firewall:

1. Lee la historia y la misión en el panel **Historia** (izquierda).
2. Escribe comandos `iptables` reales en la **Consola** (parte inferior).
3. Envía un mensajero con `Ctrl+E` o escribiendo `enviar mensajero`.
4. El panel **Rastro del Mensajero** te muestra qué cadena procesó el paquete y con qué veredicto.
5. Cuando todos los mensajeros atraviesen el castillo según lo esperado, pasas al siguiente nivel.

```
# Ejemplo: bloquear tráfico UDP al puerto 666
-A INPUT -p udp --dport 666 -j DROP
```

No necesitas escribir `iptables` al principio — el juego acepta la sintaxis de opciones directamente.

### Niveles

| # | Título | Concepto |
|---|--------|----------|
| 1 | El Primer Día en el Castillo | Observar sin reglas |
| 2 | El Primer Guardia en la Puerta | Primera regla DROP |
| 3 | Bloquear por Tipo | Coincidencia por protocolo |
| 4 | Política DROP | Política por defecto |
| 5 | Los Tres Portones | Múltiples puertos y cadenas |
| 6 | La Barbacana | Cadenas de usuario |
| 7 | El Estandarte | Estado de conexión (ESTABLISHED, RELATED) |
| 8 | La Puerta Secreta | DNAT y reenvío de puertos |

### Atajos de teclado

| Tecla | Acción |
|-------|--------|
| `Tab` / `Shift+Tab` | Cambiar panel activo |
| `Ctrl+E` | Enviar mensajero de prueba |
| `Ctrl+N` | Siguiente nivel (si completado) |
| `Ctrl+R` | Reiniciar nivel actual |
| `↑` / `↓` | Navegar historial de comandos |
| `Ctrl+C` / `q` | Salir |

## Compilar desde el código fuente

```bash
git clone https://github.com/vmvarela/iptablestutorial
cd iptablestutorial
make build        # binario en ./bin/silvia-castillo
make test         # pasa la suite de tests
make lint         # golangci-lint
```

Requiere Go 1.22+.

## Bajo el capó

El motor de simulación (`internal/engine`) reproduce el pipeline Netfilter completo sin llamadas al sistema:

- Analiza la sintaxis de `iptables` (`-t`, `-A/-I/-D`, `-p`, `--dport`, `-j`, etc.)
- Evalúa paquetes a través de `nat/PREROUTING` → decisión de enrutado → `filter/INPUT` o `filter/FORWARD` → `nat/POSTROUTING`
- Soporta DNAT, SNAT, MASQUERADE, cadenas de usuario, y seguimiento de estado con `--state`
- Registra cada paso en una traza de ejecución que se muestra en tiempo real

El progreso se guarda en `~/.config/silvia-castillo/progreso.json`.

## Limitaciones

- Solo simula las tablas `filter` y `nat`. Las tablas `mangle` y `raw` no están implementadas.
- `--state INVALID` no está simulado.
- Los módulos de extensión avanzados (`-m iprange`, `-m multiport` con rangos, `-m string`) no están soportados.

## Licencia

MIT
