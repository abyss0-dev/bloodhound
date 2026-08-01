# Trusted in-tree USDT collectors

> Contributing to this feature? See
> [Developing trusted USDT collectors](development/usdt-collectors.md) for the
> architecture, code map, invariants, and change workflow.

Bloodhound can attach a semantic USDT collector only when it is compiled into
the Bloodhound distribution. This is an extension boundary for fixed training
materials, not a runtime plugin ABI.

## Configuration

USDT is deny-by-default. Pass one trusted selection file with
`--usdt-config`; without it Bloodhound attaches no USDT program.

```toml
collector = "training-shell-v3"
enabled = true
```

The only permitted keys are `collector` and `enabled`. `collector` must be a
registered compiled ID. In particular, paths to eBPF/native code, offsets,
provider/probe overrides, argument definitions, and field mappings are all
rejected during startup validation.

The current registry contains two independent collectors:

| Collector | Fixed target | USDT contract |
|---|---|---|
| `training-shell-v3` | `/opt/bloodhound/usdt-fixtures/training-shell-v3` | `abyss0_shell:simple_command_completed`, ABI v3 |
| `training-peer-v1` | `/opt/bloodhound/usdt-fixtures/training-peer-v1` | `abyss0_peer:task_finished`, ABI v1 |

For a production training material, changing the target binary or its USDT ABI
requires a new collector metadata entry and a new compiled eBPF program. It is
not a configuration change.

## Compatibility and diagnostics

Before attachment Bloodhound reads only the configured target path and checks:

1. ELF architecture;
2. GNU Build ID against the collector's fixed allowlist;
3. provider/probe and declared operands from `.note.stapsdt`;
4. each static note's semaphore, when present, has a file offset representable
   by Linux's fd-based uprobe PMU.

Semaphore-backed locations use the kernel `ref_ctr_offset` interface. The
kernel increments the fixture's reference count only after the link is live
and decrements it when the link fd is closed during shutdown or attachment
rollback. Aya owns ordinary uprobe links; Bloodhound owns only these additional
fd-based links because Aya 0.13 does not expose `ref_ctr_offset`.

No function-symbol fallback, runtime DSO scan, PID filter, or config-provided
offset is used. A failed check emits a bounded `DIAGNOSTIC` event with
`event.name = "usdt.collector"`, the collector ID, and a reason code. The
allowed reason codes are `disabled`, `unknown_collector`,
`unsupported_architecture`, `target_build_id_mismatch`, `probe_not_found`,
`abi_incompatible`, `semaphore_unavailable`, and `attach_failed`.

USDT events use `event.type = "USDT"`, `event.layer = "behavior"`, and a
`<provider>.<probe>` name. Collector fields use fixed-size scalar values and
bounded UTF-8 values only; no pointer, environment value, raw TTY input, or
unbounded command text is serialized.
