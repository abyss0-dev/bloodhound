# Filesystem observation implementation and measurement

Implementation and measured acceptance evidence for Bloodhound #52. The
evidence map below distinguishes runtime observations, decoder tests, and
explicit limits; it does not extend the guarantee beyond the managed fixture.

## Openat capture version 1

The existing fixed payload size is retained. The former two-byte padding now
contains `capture_version` and `capture_flags`; the former four-byte padding
contains signed `dirfd`. Version 0 and unrecognized versions decode with
`filename_status: unknown` and `file_identity_status: unknown`. Legacy numeric
fields remain available but do not prove complete identity acquisition.

Version 1 flags independently record device-read success (bit 0), inode-read
success (bit 1), complete pathname acquisition (bit 2), and pathname-read failure
(bit 3). A pathname reaching the buffer boundary is conservatively truncated.
The deserializer rejects inconsistent flags and missing declared pathname bytes.

NDJSON `file_identity_status` is `complete`, `partial`, or `unavailable` for a
successful open. An unsuccessful syscall has `not_attempted`; its negative
`return_code` describes the access failure. Only components with successful
reads are emitted, including valid zero values. Consumers must require
`complete` before using the pair as a complete identity.

`dev` retains the kernel encoding, `(major << 20) | minor`. Compare NDJSON
`dev_major` and `dev_minor` with userspace `major(st_dev)` and `minor(st_dev)`;
do not directly compare the two encoded device integers. `ino` is unchanged.

The actor header and pathname are captured at syscall entry. A thread-keyed map
owns the pathname until exit, independent of scratch-buffer reuse and CPU
migration. Task exit removes interrupted invocations before thread-group exit
filtering. The returned FD and its identity are sampled at syscall exit.
Post-receipt `/proc` enrichment is best-effort later information, not part of an
operation-time snapshot.

The FD traversal does not pin the returned file. Concurrent close/reuse can
produce a readable but different file and is not necessarily detectable.
Successful field reads also do not prove that fixed kernel layouts are correct.
Actor mount namespace, source view, path-embedded PID, and immutable process
identity are distinct facts. The collector does not infer their equivalence.

## Target measurement so far

An independent copy of the existing E2E rootfs was booted with KVM, two vCPUs,
and kernel `6.8.0-49-generic` (x86_64). Running-kernel BTF revealed three incorrect
pre-existing offsets. Corrected byte offsets are:

| Structure member | Previous | Measured |
|---|---:|---:|
| task_struct.files | 2848 | 3080 |
| files_struct.fdt | 32 | 32 |
| fdtable.max_fds | 0 | 0 |
| fdtable.fd | 8 | 8 |
| file.f_inode | 32 | 168 |
| inode.i_sb | 40 | 40 |
| inode.i_ino | 64 | 64 |
| super_block.s_dev | 0 | 16 |

After rebuilding and loading the BPF programs, `cat -- /etc/hostname` produced
an openat with complete filename and identity, inode 210 and device 253:0.
Userspace `stat` returned inode 210 and encoded device 64768; the kernel value
265289728 normalizes to the same 253:0. This single measurement verifies this
target's traversal, not other kernels, namespace workloads, or concurrency.

The fixed layouts are not a portability guarantee. A broader kernel contract
must validate the relevant layouts before certifying successful identity reads.

## Two-view workload

`e2e/fixtures/filesystem-observation.py` creates a private mount namespace with
a directory bind mount, a stable sleep process owned by UID 1000, and a common
backup directory. It runs each method with UID/AUID 1000 and records the method
PID, resolved executable, argv, exit status, stdout/stderr, and destination
identity/content hash after the operation. It removes its own resources on exit.

The latest method measurement is retained in [methods.json](filesystem-observation/methods.json).
That file includes event counts (including raw syscall numbers) for each method.
[methods.ndjson](filesystem-observation/methods.ndjson) retains the corresponding
exec, process-exit, and workload-path openat records, selected by immutable
process reference; unrelated startup and library reads are excluded from this
excerpt. Each retained exec record explicitly reports complete argv and filename
under the shared #33 contract; the method report includes immutable actor references.

| Method | Measured executable / argv prefix | Required observed proxy | Direct reinforcement |
|---|---|---|---|
| Process discovery | /usr/bin/ps; ps -p P -o pid=,comm= | exec + process_exit | Target binding remains downstream |
| Metadata | /usr/bin/stat; stat -- PATH | exec + process_exit | No rich stat result required |
| Namespace links | /usr/bin/readlink; readlink PATH | exec + process_exit | stdout is fixture measurement, not Bloodhound capture |
| Mount information | /usr/bin/cat; cat PATH | exec + process_exit | openat for specified mountinfo |
| Content | /usr/bin/cat; cat -- PATH | exec + process_exit | openat identity matches World-style stat observation |
| Copy and recopy | /usr/bin/cp; cp -- SOURCE DEST | exec + process_exit | source/destination openat; separate destination hash |

All 18 positive invocations succeeded; the missing-file and exited-target cats exited 1
and its failing openat reported `not_attempted` identity. The two sources had
different identities and content. Copying the old source produced its content;
copying and recopying the service source produced that source's content.
This is an operation/content measurement, not a Story success or retry decision.
No additional rich stat, mount-relation, or data-lineage collector was required
by these measured workloads. Complete argv remains a separate dependency.

The measurement exposed an existing `ptrace_access_check` defect: it denied
every request by the target AUID, including `/proc/P/root` reads unrelated to
the daemon. The hook now checks the actual target TGID and preserves earlier
LSM denials. This restores filesystem investigation while retaining the intended
daemon protection; it introduces no new enforcement policy.

Validation: `python3 -m pytest e2e/tests/test_filesystem_observation.py
--ssh-port=2252 -q` passed against the independent guest. The test checks both
views, sequential copy hashes, every method's exec/exit actor reference and
observed argv, direct cat file identities, and the missing-file failure.

## Concurrency and collection loss

`openat-concurrency.c` blocks eight distinct FIFO opens on CPU 0 in each of four
rounds. The parent confirms each child is inside syscall 257 via `/proc/P/syscall`,
moves half to CPU 1, performs 64 unrelated opens on CPU 0, then releases the FIFO
opens. All 32 recorded filenames, actors, returned FDs and identities matched
the children's own fstat results; 16 children reported completion on CPU 1.
This explicitly covers the entry-to-exit migration window and ordinary parallel
open scratch reuse, rather than relying on scheduler probability.

`openat-map-pressure.c` fills the isolated collector's entry map with impossible
task-ID keys, runs a successful target-AUID open, and removes every injected key.
The measured map capacity was 10240, the update failed with E2BIG (7), the child
exited 0, and cleanup reported no failures. Userspace emitted
`DIAGNOSTIC/openat.collection`, reason `entry_save_failed`, delta 1, with
`run_prefix_incomplete: true`. No operation location or actor is attributed to
this polled counter. The fault-injection helper is solely an isolated-guest test.

Both cases pass in the focused filesystem suite and the full guest regression.

## Shared argv dependency

The [#33 exec capture contract](../exec-capture.md) now supplies explicit argv
and filename status for both exec syscalls. The new 20-case guest test covers
complete, truncated, unreadable, and invalid-encoding inputs. Unit tests cover
unknown legacy completeness. The filesystem method test additionally requires
complete argv and filename; it no longer relies on short argument lengths.
The retained method measurement has been refreshed with this capability and
with file replacement, remount, and target-exit workloads.

## Sequential changes and negative paths

The extended fixture holds the old host file open while replacing its pathname,
then observes the new inode. It remounts a replacement directory in the target
process namespace between methods: the namespace link remains equal, mountinfo
changes, and the next cat open observes the replacement file identity. Finally
it terminates the target and verifies that `/proc/P/root` access fails. These
observations do not retroactively change earlier records and do not promise
instant detection of unobserved changes. PID-reuse separation is covered by the
existing lifecycle/stream unit tests and process E2E regression; namespace IDs
and path-embedded PIDs are not used as immutable view identities.

The openat negative-path fixture verifies EFAULT with filename read_error,
ENAMETOOLONG with truncated filename, ENOENT for an empty pathname, a successful
relative pathname with its captured dirfd, and EBADF for an invalid dirfd.
Failed accesses have not_attempted identity; valid relative access matches
fstat on the actual returned FD. Unit tests separately exercise partial and
unavailable identity decoding, including valid zero components. Lossy pathname
text is invalid_encoding even if the independent file identity is complete.

A privileged target-AUID `/proc/DAEMON/root` attempt verifies the narrowed ptrace
hook still emits a denial and preserves the daemon. Ordinary target-process
access succeeds in the two-view fixture. Together these test the actual hook's
scope rather than relying on DAC alone.

The focused filesystem suite passed all five tests. The final full guest E2E
run passed **64 tests** in 249.31 seconds on port 2252, with no skips or failures.
The workspace unit suite passed **206 tests**. The existing TTY limit test now
honors ssh_config so the suite can run against an independent guest port.

## Measured image provenance

The baseline is the existing E2E Ubuntu 24.04 rootfs, independently copied before
boot and then updated with the development collector. The method report records
os-release and executable versions: procps-ng 4.0.4 and GNU coreutils 9.4.
Hashes identify the baseline artifacts (not the writable guest after workload):

- baseline rootfs.ext4 SHA-256: `6bf588891d1ebf783b6b82a4488aaa0e2845d793c709b7cc534409893a9675eb`
- boot vmlinuz SHA-256: `9b7af34a5f065e1c8c80ea96fa13e9da492aa752ba7a105a2c86b0e46a3909aa`
- collector used for methods.json SHA-256: `76f8475cb98fee979b25b71f1eb45fc4ecceb29dbfb61b0a5eed1028eb562e3b`

The collector corresponds to the #33 implementation in 2e5fb2b; the fixture also
includes the subsequently added sequential-change cases. These hashes are
provenance, not a claim that the image is rebuilt byte-for-byte from Dockerfile.

## Acceptance evidence map

| #52 requirement | Evidence and scope |
|---|---|
| Two views and target image | Two-view fixture; methods.json os-release/kernel/tool versions; baseline hashes above |
| Finite methods, old-source copy, recopy | Methods table and retained argv/event records; test_two_namespace_methods verifies exec, completion, and separate content measurements |
| Concurrent opens and CPU migration | test_concurrent_openat_across_cpu_migration; 32 blocked opens, 16 forced migrations, returned-FD fstat comparison |
| Device normalization and acquisition states | Direct cat and relative-open fstat comparisons; openat_capture_status_does_not_infer_validity_from_values exercises complete, partial, unavailable, failed, and legacy cases |
| Collection loss vs existing stream loss | Real entry-map exhaustion and openat.collection; heartbeat/drop-counter and sequencer rejection unit tests; no invented missing-operation timestamp |
| Exit, PID reuse, file/namespace changes | Sequential replacement/remount/target-exit fixture; lifecycle::pid_reuse_is_keyed_by_kernel_process_identity and exit_releases_only_the_matching_process_instance; process creation/exit E2E |
| #33 dependency | Shared exec-capture.md; 20 real execve/execveat boundary/fault cases; legacy/unknown version and invalid-framing unit tests |
| Additional observation assessment | Finite workloads work through exec/exit proxies and available openat identities; no rich stat, mount-relation or data-lineage collector added |
| Public contract and regression | output-schema.md, exec-capture.md, tracing.md; workspace unit suite and full guest E2E |

Partial-identity decoding is tested with constructed payloads; it is not claimed
as a naturally occurring partial kernel read in the stable fixture. The target
layout is validated by BTF measurement and successful fstat comparison, not by
an automatic cross-kernel portability mechanism. No measurement here proves
arbitrary FD reuse races, unobserved changes, data transfer lineage, or learner
understanding. These are the explicit boundaries of the issue specification.
