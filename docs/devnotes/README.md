# Bloodhound development notes

This directory stores reusable engineering knowledge discovered while developing and operating Bloodhound.

Notes should capture a concrete problem, the adopted answer, the evidence behind it, failed attempts, and any operational details worth preserving.

Use the following order for every topic note:

1. Problem
2. Answer
3. Evidence
4. Failed attempts and mistakes
5. Notes

Keep cross-cutting notes in this directory.

Create a subdirectory when several notes share feature-specific background that is not required for general Bloodhound development.

## Cross-cutting topics

- [Readiness and restart boundaries](readiness-and-restarts.md): systemd state, consumer readiness, and output file behavior.
- [Ring buffer delivery diagnostics](ring-buffer-delivery.md): locating failures across the eBPF-to-NDJSON path.
- [E2E observer load](e2e-observer-load.md): preventing polling from creating its own timeout pressure.
- [CI and KVM environment](ci-and-kvm.md): runner assumptions and guest dependency failures.

## Feature-specific topics

- [Trusted USDT collectors](usdt-collectors/README.md): static-note validation, collector acceptance, and semaphore-backed probes.
