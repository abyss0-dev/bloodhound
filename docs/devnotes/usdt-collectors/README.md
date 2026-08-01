# Trusted USDT collector notes

These notes record feature-specific knowledge from implementing trusted static USDT collectors in PR #40.

They assume the compiled collector registry, `.note.stapsdt` validation, and fixture-to-NDJSON acceptance boundary introduced by that work.

- [Acceptance evidence](acceptance-evidence.md): why attach logs and unit tests were insufficient.
- [Collector scope and note ABI](collector-scope-and-note-abi.md): the configuration boundary and static-note operand model.
- [Semaphore-backed probes](semaphore-backed-probes.md): perf-event attachment and the ELF file-offset requirement.

The final implementation result was 53 passing KVM E2E tests plus successful CI and USDT unit/replay workflows on commit `1e5ffcc`.
