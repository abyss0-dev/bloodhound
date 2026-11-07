# Bloodhound: Technical Specification

> eBPF-based behavioral tracing daemon for isolated VMs.
> All design decisions have been finalized.


## Primary Goal

Trace ALL user-originated actions and their resulting effects within a VM,
and correlate them as a single unified stream of "user behavior." Memory
overhead is acceptable; completeness of observation is the top priority.

## Overview

Bloodhound is a resident daemon that traces user behavior inside isolated
VMs (QEMU/KVM). It captures kernel-level events attributable to
the target user -- syscalls, TTY I/O, and process lifecycle -- correlates
them via `auid`, and emits structured events as NDJSON to stdout.

```
+---------------------------------------------------------------+
|                      Guest VM (Ubuntu)                         |
|                                                               |
|  +------------+     +--------------------------------------+  |
|  | Target user|---->|            Kernel (eBPF)             |  |
|  | (fixed UID)|     |  +-------+ +------+ +------+         |  |
|  +------------+     |  |Layer 1| |Layer2| |Layer3|         |  |
|                     |  | (TTY) | |(exec)| |(sys) |         |  |
|                     |  +---+---+ +--+---+ +--+---+         |  |
|                     |      |        |        |             |  |
|                     |  [auid filter + daemon excl]         |  |
|                     |      |        |        |             |  |
|                     |      +--------+--------+             |  |
|                     |               |                      |  |
|                     |         ring buffer   LSM (opt-in)   |  |
|                     +---------------|---+-----------+      |  |
|                                     |                      |  |
|                     +---------------v-----------------------+  |
|                     |       Bloodhound (userspace)          |  |
|                     |  +----------------------------------+ |  |
|                     |  | Bounded Sequencer + Serializer   | |  |
|                     |  +----------------------------------+ |  |
|                     |  drop counter poll -> stderr          |  |
|                     |               |                       |  |
|                     +---------------v-----------------------+  |
|                                     |                          |
|                                  stdout (NDJSON)               |
|                           (future: virtio-serial)              |
+---------------------------------------------------------------+
```


## Environment and Constraints

| Item                | Status  | Value                                          |
|---------------------|---------|-------------------------------------------------|
| Host platform       | DECIDED | QEMU/KVM guest VM                               |
| OS                  | DECIDED | Ubuntu (LTS)                                    |
| Kernel version      | DECIDED | 6.8 (Ubuntu 24.04 LTS); pinned per VM image     |
| BTF support         | DECIDED | Required (CONFIG_DEBUG_INFO_BTF=y)              |
| BPF LSM support     | DECIDED | Optional (boot param: lsm=...,bpf for --enable-lsm) |
| Language            | DECIDED | Rust (Aya framework)                            |
| BPF-to-user pipe    | DECIDED | BPF ring buffer (BPF_MAP_TYPE_RINGBUF)          |
| Output destination  | DECIDED | stdout (future: virtio-serial)                  |
| Target user privs   | DECIDED | root with restricted capabilities               |
| Target user model   | DECIDED | Single fixed user per VM                        |
| Filtering strategy  | DECIDED | auid + sessionid (audit login UID + session ID) |
| Performance budget  | DECIDED | Qualitative: must not degrade user UX            |
| Output schema       | DECIDED | BehaviorEvent (see docs/schema.json)             |


## Known Limitations

| Limitation              | Scope    | Notes                                           |
|-------------------------|----------|-------------------------------------------------|
| io_uring I/O coverage   | DEFERRED | I/O submitted via io_uring rings bypasses syscall tracepoints. `io_uring_setup`/`enter`/`register` remain visible via Tier 1 raw_syscalls; submitted operations are not. See `docs/tracing.md` §Known Limitations §io_uring observation gap. |
| Protocol semantic parse | OUT OF SCOPE | DNS, TLS SNI, HTTP, etc. are emitted as raw packet bytes; downstream consumers parse. See `docs/tracing.md` §Protocol semantic extraction is out of scope. |


## Detailed Specifications

| Document                                           | Contents                              |
|----------------------------------------------------|---------------------------------------|
| [docs/filtering.md](docs/filtering.md)             | auid/sessionid filtering, target injection |
| [docs/tracing.md](docs/tracing.md)                 | 3-layer model, TTY, execve, syscalls, TC  |
| [docs/tamper-resistance.md](docs/tamper-resistance.md) | CAP restrictions, LSM hooks        |
| [docs/data-pipeline.md](docs/data-pipeline.md)     | Ring buffer, event format, timestamps |
| [docs/output-schema.md](docs/output-schema.md)     | BehaviorEvent JSON schema             |
| [docs/userspace.md](docs/userspace.md)             | Userspace architecture                |
| [docs/lifecycle.md](docs/lifecycle.md)             | Startup, shutdown, crash recovery, scope |
| [docs/testing.md](docs/testing.md)                 | Build environment, E2E test pipeline  |


## Technology Stack

| Component          | Choice          | Notes                              |
|--------------------|-----------------|------------------------------------|
| Language (BPF)     | Rust (no_std)   | Via aya-bpf                        |
| Language (user)    | Rust            | Via aya + tokio                    |
| BPF framework      | Aya             | Pure Rust, CO-RE support           |
| Async runtime      | tokio           | Ring buffer polling                |
| Kernel features    | BTF, BPF LSM   | Must be enabled in VM image        |
| Min kernel version | 6.8             | Ubuntu 24.04 LTS                   |
