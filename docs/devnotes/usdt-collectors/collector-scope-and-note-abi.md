# Collector scope and note ABI

## Problem

The first design needed to support useful static USDT collection without turning runtime configuration into an untrusted tracing language.

It also needed to interpret static-note operands and multiple probe locations correctly before attempting a large real-world integration.

## Answer

Compile collector metadata, payload decoding, and BPF programs into Bloodhound.

Runtime configuration may only select a registered collector ID and set `enabled`.

Validate the fixed path, architecture, Build ID, provider/probe, and GAS operand forms before attachment, then attach every matching static location with a stable `attach_point_id`.

Use minimal static ELF fixtures to prove this contract independently of future Bash integration.

## Evidence

- `.note.stapsdt` stores operand expressions, not a promise that values follow a normal function ABI.
- One provider/probe pair can appear at multiple static note locations.
- Runtime-provided offsets or field mappings would directly control where and how the tracer reads process state.
- The final E2E suite proved two independent collector payloads, negative ABI cases, and multiple attach points.

## Failed attempts and mistakes

- We considered allowing runtime target paths, offsets, probe names, operands, or field mappings.
- We considered using a Bash build as the first acceptance fixture, which would have added compiler, packaging, and shell-semantic variables before the attachment contract was stable.
- We initially risked treating USDT operands as normal function parameters.
- We could have treated the first matching note as the whole probe and missed additional static locations.

## Notes

- Configuration selects trusted code; it does not define tracing code.
- `c6dac28` introduced the registry, fixed collectors, note validation, payloads, and fixtures.
- `b769c9f` moved E2E selection files into the rootfs input boundary.
