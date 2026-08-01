# Ring buffer delivery diagnostics

## Problem

An eBPF producer can execute successfully while its expected NDJSON event remains missing.

The `training-peer-v1` incident exposed how easily attachment, eBPF execution, payload assembly, ring-buffer output, userspace consumption, deserialization, and observation can be confused.

## Answer

Instrument and verify each delivery boundary in order.

Build variable payloads through the established per-CPU assembly map, measure producer entry separately from successful ring-buffer output, and do not publish daemon readiness before consumer registration.

When an event is missing, inspect boundaries in this order:

1. collector validation and attachment
2. uprobe execution
3. ring-buffer output result
4. userspace consumption
5. deserialization
6. NDJSON observation

## Evidence

- A loader guard showed no peer attachment failure.
- Hit-counter slot 1 increased when the peer fixture ran.
- A second counter after `EVENTS.output()` increased in the same run.
- The collector passed in focused runs but failed after a daemon restart in the full suite.
- Final E2E produced the expected peer event shape through NDJSON.

## Failed attempts and mistakes

- We first suspected that the peer uprobe was not attached.
- We then suspected verifier rejection or a full ring buffer.
- We considered the peer decoder as the failure point before proving whether userspace received the record.
- The peer event initially used a stack-backed output shape instead of the established assembly-map pattern.
- One counter proved probe execution but could not prove `EVENTS.output()` success.
- We modified consumer polling before fully accounting for the earlier startup readiness marker.

## Notes

- Do not change multiple delivery boundaries before measuring the current one.
- `6adf027` exposed peer attachment failures in E2E.
- `2505d2f` moved peer output to the shared assembly map.
- `390d14b` and `212c20f` added entry and output boundary counters.
- `1e5ffcc` closed consumer startup and pending-record readiness gaps.
