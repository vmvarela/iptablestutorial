# AGENTS.md

## Skills installed

Skills live in `.agents/skills/<name>/SKILL.md` and are tracked with SHA-256 hashes in `skills-lock.json`.

| Skill | Source | Use when |
|---|---|---|
| `golang-pro` | `jeffallan/claude-skills` | Writing Go: goroutines, channels, gRPC, generics, interfaces, pprof, table-driven tests |
| `methodical-programming` | `vmvarela/skills` | Implementing functions with formal correctness: pre/postconditions, loop invariants, recursion, proofs |
| `pragmatic-docs` | `vmvarela/skills` | Writing or rewriting any project documentation: READMEs, module docs, CONTRIBUTING, architecture notes |

Always load the relevant skill with the `skill` tool before starting work in its domain.

## Conventions

- **AGENTS.md must be updated** when a mistake is made during a session — add a brief note under "Lessons learned" so future agents avoid repeating it.
- AGENTS.md stays in English and stays concise; delete stale entries.

## Lessons learned

- **Firewall IP ≠ host IP**: `localIP` for `DefaultTopology` must be the firewall's own IP (`192.168.1.1`), not a host in the local zone (`192.168.1.10`). Always add `firewall_ip` to the YAML `red:` block and use it directly in `app.go` instead of searching hosts.
- **Backtick raw strings don't interpret `\n`**: ASCII art in backtick strings must use real newlines; `\n` inside backticks is a literal backslash-n.
- **Narrow layout double-render**: In narrow mode, always check whether the console is the active panel before adding a second `bottom` console block; skip `bottom` when `active == panelConsole`.
- **`SetPistas` is a separate method from `SetLevel`**: Adding hints to the story panel requires its own `SetPistas([]string)` method called from `app.go` after `SetLevel`, to avoid breaking the `SetLevel` signature.
