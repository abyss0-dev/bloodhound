# Trusted USDT collector investigation notes

These notes record the failed assumptions, diagnostic steps, and new invariants discovered while implementing PR #40.

They are organized by failure domain rather than commit order.

Every topic uses the same order:

1. Problem
2. Answer
3. Evidence
4. Failed attempts and mistakes
5. Notes

- [Acceptance evidence](acceptance-evidence.md): why attach logs and unit tests were insufficient.
- [Collector scope and note ABI](collector-scope-and-note-abi.md): the configuration boundary and static-note operand model.
- [Readiness and restart boundaries](readiness-and-restarts.md): systemd state, consumer readiness, and output file behavior.
- [Ring buffer event delivery](ring-buffer-delivery.md): how the peer event was traced across the eBPF-to-NDJSON path.
- [Semaphore-backed probes](semaphore-backed-probes.md): perf-event attachment and the ELF file-offset requirement.
- [E2E observer load](e2e-observer-load.md): how the test reader created its own timeout pressure.
- [CI and KVM environment](ci-and-kvm.md): runner assumptions and guest dependency failures.

The final acceptance result was 53 passing KVM E2E tests plus successful CI and USDT unit/replay workflows on commit `1e5ffcc`.
