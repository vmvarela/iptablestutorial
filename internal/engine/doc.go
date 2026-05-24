// Package engine implementa una simulación pura en memoria de iptables/Netfilter.
//
// No realiza llamadas al sistema operativo. Todos los paquetes son tipos
// inmutables por valor; los rewrites devuelven copias. El evaluador recorre
// el pipeline PREROUTING → routing → INPUT/FORWARD → OUTPUT → POSTROUTING
// conforme a la semántica real de Netfilter.
//
// # Uso básico
//
//	rs := engine.NewRuleset()
//	cmd, _ := engine.ParseLine("iptables -A INPUT -p tcp --dport 80 -j ACCEPT")
//	_ = engine.Apply(rs, cmd)
//
//	topo := &engine.Topology{LocalIPs: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
//	ev   := engine.NewEvaluator(rs, topo)
//	pkt  := engine.Packet{DstIP: netip.MustParseAddr("10.0.0.1"), Proto: engine.ProtoTCP, DstPort: 80, State: engine.StateNew}
//	verdict, trace, _ := ev.Send(context.Background(), pkt)
package engine
