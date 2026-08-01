# Readiness and restart boundaries

## Problem

Restart-sensitive USDT tests intermittently fired fixtures before the daemon could consume their records.

Automatic restarts also made the NDJSON line baseline unreliable.

## Answer

Define the readiness marker as completion of both BPF attachment and ring-buffer consumer registration.

The consumer sends a oneshot acknowledgement after `AsyncFd` registration, and the main task emits `BPF programs loaded and attached` only afterward.

Drain pending records before waiting, use `StandardOutput=append:`, and isolate output-file replacement tests with guaranteed fixture and service restoration.

## Evidence

- The service uses `Type=simple`, so `systemctl is-active` only proved process creation.
- The old marker was emitted before the ring-buffer fd was registered with Tokio.
- Focused tests passed while the same path failed after a daemon restart in the full suite.
- The old `StandardOutput=file:` behavior did not preserve the append position expected by the line-baseline reader.
- After the final readiness and output changes, `shutdown -> automatic restart -> training-shell-v3` passed five consecutive runs.
- The final full KVM suite passed 53/53 tests.

## Failed attempts and mistakes

- We treated `systemctl is-active` as daemon readiness.
- We replaced sleeps with polling but initially polled a marker that was itself emitted too early.
- We assumed the normal line-count baseline remained valid across daemon restarts.
- We expected longer sleeps to fix the race without defining the state being awaited.
- Draining before waiting reduced a pending-record gap but did not define startup readiness by itself.
- Recreating the output file fixed isolated replacement tests but not normal automatic restarts.

## Notes

- The marker is a synchronization boundary; NDJSON remains the behavioral proof.
- Replacement tests restore the canonical fixture and service in `finally`.
- `f72ffaf` replaced fixed restart sleeps with bounded state and NDJSON polling.
- `1e5ffcc` moved the marker behind consumer registration and made restart output append-safe.
