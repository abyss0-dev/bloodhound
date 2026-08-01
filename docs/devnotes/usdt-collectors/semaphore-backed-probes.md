# Semaphore-backed probes

## Problem

The semaphore-backed fixture logged successful attachment but never executed its collector program.

Several independent requirements were involved: raw perf-event attachment, BPF program installation, event enablement, link lifetime, and a valid ELF reference-counter offset.

## Answer

Use a dedicated semaphore-aware perf-event attachment path and keep its fds alive for the daemon lifetime.

Install and enable the BPF program with the full supported `perf_event_attr` ABI.

Place the fixture's writable semaphore counter in a file-backed `.probes` `PROGBITS` section so the kernel can register its `ref_ctr_offset`.

```c
volatile unsigned short usdt_semaphore
    __attribute__((section(".probes"), used)) = 0;
```

## Evidence

- Attachment logs succeeded while the collector hit counter remained zero.
- Enabling the perf event and correcting the attribute size still did not make the fixture fire.
- ELF inspection showed the semaphore symbol in `.bss`, with a virtual address but no bytes in the file image.
- Moving the counter to `.probes` gave it a file-backed offset.
- The semaphore-backed fixture then produced its semantic NDJSON event in E2E.

## Failed attempts and mistakes

- We assumed Aya's normal uprobe link behavior covered semaphore-backed probes.
- We treated successful `perf_event_open` as proof that samples were enabled.
- We initially omitted `PERF_EVENT_IOC_ENABLE` after installing the BPF program.
- We used a compact `perf_event_attr` definition before matching the full 128-byte ABI.
- We assumed a writable virtual address was sufficient for `ref_ctr_offset`.
- We spent several iterations on perf-event mechanics before checking whether the ELF location was file-backed.

## Notes

- A semaphore address in `.note.stapsdt` is insufficient when the symbol exists only in `.bss`.
- `20155f5` added the semaphore-aware attachment path and link lifetime handling.
- `20d0b26` enabled the raw perf event after BPF program installation.
- `8b0a59e` corrected the `perf_event_attr` ABI size.
- `1e5ffcc` moved the fixture counter into a file-backed ELF section.
- The eBPF hit counter used during this investigation was temporary and is not
  part of the production collector hot path.
