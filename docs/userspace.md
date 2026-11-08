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
|                                    | (kernel events)  |   |
|                                    +--------+---------+   |
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
- Ordering: see [data-pipeline.md §Emission Ordering and Backpressure](data-pipeline.md#emission-ordering-and-backpressure)
- Output: NDJSON (newline-delimited JSON) to stdout, one BehaviorEvent per line
- Operational logs (startup, errors, drop count warnings): stderr
- Event evaluation is NOT performed by Bloodhound -- it emits raw events
  for downstream consumption

### 5-tuple packet correlation (Historical Note — Retired in Phase 2)

Live TC packet capture and 5-tuple packet correlation have been retired since Phase 2.
The deserializer retains decoding logic for historical packet events (kinds 100 and 101),
but no active socket tracking table or live packet join runs in userspace. Network
activity is traced via Layer 3 socket syscalls.

### Drop counter polling

Userspace periodically reads the BPF global drop counter and emits both
operator warnings on stderr and in-band HEARTBEAT loss state. A binary record
rejected by the deserializer becomes a bounded `DIAGNOSTIC/stream.health`
through the same sequencer.

DECIDED: No pre-filtering or aggregation. All events are emitted
unconditionally to stdout. Downstream consumers perform any filtering.
