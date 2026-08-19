# QEMU raw event fixtures

These files are base64-encoded ring-buffer records captured from the eBPF
programs, not records assembled by Rust test helpers. They were captured on
2026-08-20 from the repository's `e2e/rootfs.ext4` under QEMU/KVM with Linux
6.8.0-49-generic, using the collector built from commit `20d1a05` plus
temporary raw-record logging. The logging was removed after capture.

Each trigger was run separately after restarting the collector with logging
restricted to the expected `EventKind`. The emitted NDJSON event was selected
by its distinctive arguments, and the fixture was accepted only when exactly
one raw record had the same kernel timestamp and expected kind.

| Fixture | Trigger / selection |
| --- | --- |
| `tty_write` | `script` PTY wrote `BH_TTY_WRITE_GOLDEN` |
| `tty_read` | `script` PTY read `BH_TTY_READ_GOLDEN` |
| `execve` | executed `/usr/bin/true` |
| `raw_syscall` | Python called `getpid(2)` |
| `openat` | opened `/tmp/bh-golden-openat` for writing |
| `read` | read 7 bytes from `/etc/hostname` with `os.read` |
| `connect_ipv4` | connected to `127.0.0.1:18443` |
| `connect_ipv6` | connected to `[::1]:18444` |
| `clone` | Python called `fork(2)` |
| `mkdir` | created `/tmp/bh-golden-mkdir` |
| `rename` | invoked `rename(2)` for `/tmp/bh-golden-old` |
| `sendto` | sent 6 UDP bytes to `127.0.0.1:19090` |
| `lsm_task_kill` | sent signal 0 to a child process |
| `lsm_bpf` | unprivileged `bpftool prog show` |
| `lsm_setuid` | unprivileged Python called `setuid(getuid())` |
| `lsm_ptrace` | Python attempted one `PTRACE_ATTACH` |
| `packet_ingress` | sent a 16-byte UDP datagram over loopback; selected the 44-byte IPv4 packet |
