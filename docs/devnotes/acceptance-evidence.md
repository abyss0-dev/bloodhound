# Acceptance evidence

## Problem

A collector could log successful attachment or pass decoder unit tests while its fixture still produced no semantic NDJSON event.

The investigation needed evidence that identified the last successful boundary instead of treating every timeout as the same failure.

## Answer

Accept a collector only when a real fixture completes the full observable path:

```text
fixture -> static probe -> eBPF program -> EVENTS ring buffer
        -> userspace deserializer -> NDJSON
```

Use attachment diagnostics and eBPF counters to locate failures, not as substitutes for end-to-end acceptance.

Negative cases must produce one bounded collector diagnostic and no partial semantic event.

## Evidence

- The semaphore collector logged successful attachment while its probe hit count remained zero.
- The peer collector's entry counter increased, proving that its uprobe executed.
- A second peer counter after `EVENTS.output()` also increased, proving successful ring-buffer output.
- The expected peer NDJSON record was still absent in failing runs, placing the failure after eBPF output.
- The guest could not expose `bpftool` program `run_cnt`, so acceptance could not depend on guest-global BPF statistics.
- Final fixture-based KVM E2E passed all 53 tests.

## Failed attempts and mistakes

- We initially treated an attach-success log as proof that the probe could fire.
- We treated a decoder unit test as proof that an event reached NDJSON.
- We expected `bpftool` program `run_cnt` to be available in the guest.
- We interpreted timeouts as collector failures before measuring attachment, execution, output, consumption, and observation separately.
- We first added one hit counter, then needed a second counter to distinguish probe entry from successful `EVENTS.output()`.

## Notes

- `2e50a97` replaced internal counters as acceptance with fixture event assertions.
- `390d14b` added collector hit counters.
- `212c20f` separated peer entry from successful ring-buffer output.
