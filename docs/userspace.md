# Userspace Architecture

```
+-----------------------------------------------------------+
|                  Bloodhound Userspace                      |
|                                                           |
|  +-----------+    +-----------+    +------------------+   |
|  | Ring      |--->| Bounded sequencer                    | |
|  | Buffer    |    | raw + heartbeat + diagnostics        | |
|  | Consumer  |    +--------------------+-----------------+ |
|  +-----------+                         |                   |
|  Heartbeat + diagnostics --------------+                   |
|                                             v             |
|                                    +--------+---------+   |
|                                    | Deserialize raw  |   |
|                                    | + /proc enrich   |   |
|                                    +--------+---------+   |
|                                             v             |
|                                    +--------+---------+   |
|                                    | 5-tuple packet   |   |
|                                    | correlation      |   |
|                                    +--------+---------+   |
|                                             |             |
|                                             v             |
|                                    +--------+---------+   |
|                                    | JSON Serialize   |   |
|                                    +--------+---------+   |
|                                             |             |
|  drop counter poll -> stderr             stdout           |
+-----------------------------------------------------------+
```

- Async runtime: tokio for ring buffer polling
- Event processing: single-threaded async pipeline
- Ordering: per-producer FIFO plus successful bounded-sequencer admission;
  NDJSON line order is emission order, not inferred kernel causal order
- Output: NDJSON (newline-delimited JSON) to stdout, one BehaviorEvent per line
- Operational logs (startup, errors, drop count warnings): stderr
- Event evaluation is NOT performed by Bloodhound -- it emits raw events
  for downstream consumption

### 5-tuple packet correlation

PACKET events from TC hooks have no process context (no pid, auid, comm).
Userspace maintains a socket tracking table populated from Layer 3
`connect`/`bind` events, and joins PACKET events by 5-tuple (protocol,
src addr, dst addr, src port, dst port) to attribute packets to processes.
See [tracing.md](tracing.md) for details.

### Drop counter polling

Userspace periodically reads the BPF global drop counter and emits both
operator warnings on stderr and in-band HEARTBEAT loss state. A binary record
rejected by the deserializer becomes a bounded `DIAGNOSTIC/stream.health`
through the same sequencer.

DECIDED: No pre-filtering or aggregation. All events are emitted
unconditionally to stdout. Downstream consumers perform any filtering.
