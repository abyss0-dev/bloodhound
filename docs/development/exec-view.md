# Exec-entry filesystem view

Sanjaya filesystem methods need the invoking task's filesystem view. Audit UID
and session select actors but do not establish their root or mount namespace.
Inferring inheritance from missing clone or raw syscall flags is insufficient
when those records do not distinguish capture failure from zero.

Bloodhound emits `TRACEPOINT/exec_view` at the same exec entry used for argument
capture. The record carries exactly that entry's timestamp and immutable
`process_ref`. Consumers pair both values, never PID alone. A view record may
precede a failed exec; it does not establish successful execution or exit.
Missing either record must not be repaired from a different invocation.

The version-1, 24-byte payload contains root inode, kernel `dev_t`, mount
namespace inode number, and root mount ID. Userspace also publishes normalized
root device major/minor. The kernel reads each pointer-chain member using the
running kernel's BTF and rechecks the task's fs/nsproxy and root/namespace
pointer endpoints. This is a bounded entry observation, not an atomic kernel
snapshot or a claim that the view stayed unchanged during execution. It does
not certify argv semantics, pipeline absence, transferred bytes, or stdout.

`view_status` is `complete`, `unsupported` (a required BTF member is absent),
`unavailable` (a kernel read or identity check failed), or `changed` (pointer
endpoints differ). Failed captures publish no partial identity. Unknown wire
versions decode as `unknown`, with no identity. Existing exec argument capture
version and payload layout remain unchanged. The additional ring record uses
the existing loss accounting; losing it cannot establish a positive view match.

## Command Evidence boundary

The filesystem PoC consumer correlates an individual command's complete argv,
verified executable, immutable actor, successful exit and exec-entry view with
fresh pre/post World observations. A command within a pipeline or redirection
may satisfy that contract. Neither pipeline syntax absence nor standard
descriptor kinds are admission requirements. This weak Evidence does not
certify the whole pipeline, stdout delivery, viewing, understanding or byte
transfer. Bloodhound supplies observations; the consumer owns admission,
World binding and Evidence invalidation.

The view wire contract remains version 1 with exactly the same meaning. It
does not encode a command admission policy. Consumers must distinguish the
revised command Evidence contract from earlier shell-context-gated Evidence;
they must not silently reinterpret an old Evidence kind with weaker guarantees.

This kernel collector introduces no USDT dependency. Application semantic
probes must use the existing USDT contract and require a concrete unmet
observation need. Direct Bash internal-function probes, their CLI option and
the exec-stdio/fork-file experiments have been removed. Their wire event IDs
225, 226 and 227 remain reserved; exec view remains kind 224.

## Integrated producer validation (2026-09-21)

PR #54 now includes main commit
`dec0724912c6bf70bf6feac3209d37ece4cb2441` (PR #55), merged without rebasing
as `7c4864e4a073b2f3727c41e3bd701f1f9bbd2504`. The pre-existing duplicate-exit
defect described below is resolved by that integration. The
[process-exit contract](process-exit.md) documents atomic `BPF_NOEXIST` claims,
group-leader free cleanup and conservative collection-health reporting.

On the integrated source, `cargo test --workspace --offline --locked
--no-fail-fast` passed 213 tests (149 daemon, 13 common, 51 TUI).
`cargo clippy --workspace --all-targets --offline --locked` completed with
warnings and no errors. `make build-docker` succeeded and produced
`target/docker/bloodhound` with SHA-256
`de0994fad72be66145628884a7ffe7695e2fd50e555a05d42d2b83c22c5652ae`.
These checks used the merge source above; the subsequent changes are confined
to this document (excluded from the Docker build context).

Guest and CI acceptance for this integrated producer is recorded on PR #54
against its exact head. The measurements below belong to earlier sources and
do not establish guest or joint acceptance for the integrated source.

## Prior producer validation (before PR #55 integration; 2026-09-21)

`cargo test --workspace --offline --locked --no-fail-fast` passed 209 tests
(148 daemon, 10 common, 51 TUI). `cargo clippy --workspace --all-targets --offline
--locked` completed with existing warnings, and `make build-docker` produced
the static x86-64 musl binary with SHA-256
`1bc38f7f9989ffc93afff91b9845a091bcc87c5024f095acc3d4bafcbb54e332`.

That binary ran in a dedicated QEMU/KVM overlay on kernel `6.8.0-49-generic`
with **no USDT configuration**. After the attachment readiness marker, all
seven tests in `test_exec_view.py` and `test_exec_completeness.py` passed:

- Two distinct roots/namespaces matched guest measurements and exact execveat
  actor/timestamp pairs. The [prior four-record excerpt](exec-view/current-invocations.ndjson)
  comes from this pre-integration producer; the original excerpt below is separate.
- Sixteen concurrent actors made 48 exec attempts (32 failed, 16 successful).
  Every attempt had exactly one same-actor, same-timestamp view record.
- Ordinary, redirected and both redirected-pipeline commands launched through
  `/bin/sh` exposed complete argv, matching view and successful command exit.
  This verifies producer observations, not downstream Evidence or pipeline success.
- The existing 20-case execve/execveat argv completeness fixture passed.

The captured stream contained no USDT, Bash UPROBE, exec-stdio or fork-file
records. The removed `--bash-launch` option is rejected by argument parsing.
Consumer joint acceptance is a separate validation owned by Sanjaya; these
producer tests do not claim fresh World observations or Evidence admission.

Sanjaya subsequently recorded [pre-integration command-contract joint acceptance](https://github.com/abyss0-dev/sanjaya/blob/9ca47f1004e3fe4b2068099aff7c07b97ea328e5/scripts/e2e/filesystem/measured-command-evidence.json)
using producer `319c16c04e2e1f4c54115f3074f4f38765218896` and consumer
`c1a798eb9d5b822f18f499418423f1a8c43cacb2`. All 28 Evidence commands had exact
exec/view/exit pairing. Coverage included 16 normal operations, four grammar
negatives with positive barriers, four pipeline/redirection positives and
atomic withdrawal on source/mount/exit invalidation. The producer used only
`--uid 1000`, with zero Bash UPROBE, USDT or stdio observations. This validates
the new `FilesystemCommandEvidence` kind 4, not historical shell Evidence.

### Historical CI gate: concurrent process-exit duplication resolved by PR #55

The following records the failure before PR #55; it is retained as provenance.
The defect is now fixed on the integrated branch. Integrated guest and CI
acceptance is recorded separately on PR #54 against its exact head. At the time, **PR #54 was not
merge-ready**. The [E2E run on producer 319c16c](https://github.com/abyss0-dev/bloodhound/actions/runs/35580486916)
finished with 69 passes and one failure in the multithread `os._exit(7)` case
of `test_normal_exit_group_and_multithread_teardown_emit_once`. Its predicate
requires exactly one exit, so timeout does not distinguish missing events
from duplicates. The failure log does not preserve PID 757's full trace;
the precise cause of that individual CI failure remains unproven. Build and
USDT checks passed. Earlier local 70-test success and joint acceptance do not
override this failed CI gate.

A separate two-vCPU QEMU/KVM guest on kernel `6.8.0-49-generic` reproduced
duplicate exits with the then-current producer and unchanged main baseline:

| Producer exact source SHA | Attempts | One exit | Two exits | Missing exits | Maximum drop count |
| --- | ---: | ---: | ---: | ---: | ---: |
| `319c16c04e2e1f4c54115f3074f4f38765218896` | 200 | 195 | 5 | 0 | 0 |
| main `7a6c54f699f50e2db9e865e501275417f008f281`, first batch | 200 | 200 | 0 | 0 | 0 |
| same main, additional bounded batch | 1,000 | 973 | 27 | 0 | 0 |

The driver connected through SSH as `testuser`; `/proc/self/loginuid` and
all target events' AUID were 1000. Each attempt launched Python with
`import os,threading,time; threading.Thread(target=lambda: time.sleep(30),daemon=True).start(); print(os.getpid(),flush=True); os._exit(7)`.
Every target had a captured process start and exactly one successful exec
(PATH search also generated three failed exec attempts). All current-producer
exec attempts had view records. Duplicate exits shared the exact same TGID
and start-boottime identity, and also caused a second synthetic process start.
For example, current PID 1081/start 94826466637 and baseline PID 2319/start
359130732916 each emitted two code-7 exits. The baseline binary was built
from an isolated archive of the exact main commit; SHA-256:
`3dcbf45d7aacd3378c5f819786b098f66c90fb5e5de4225eb6e6bea403e6ff73`.

Before PR #55, `bloodhound-ebpf/src/lifecycle.rs:113` read shared `signal.live == 0` at
each task's exit tracepoint; it did not elect a single emitter. In
[Linux v6.8 do_exit](https://github.com/torvalds/linux/blob/v6.8/kernel/exit.c#L833),
the atomic decrement precedes the per-task tracepoint. Multiple exiting
threads can consequently observe zero. Userspace removes the actor after
the first exit and synthesizes another start before the second. Both
`bloodhound-ebpf/src/lifecycle.rs` and `bloodhound/src/lifecycle.rs` were
identical to main at that time. The repeated observations establish a pre-existing
lifecycle defect; they do not establish the unavailable CI PID's trace.

Local raw traces were retained at `/tmp/pr54-exit-current.ndjson`
(SHA-256 `1284e77035c05cebb98ef862911c5dcd076d22b4bc4a847d755b0e9fa25c1e74`)
and `/tmp/pr54-exit-main1000.ndjson`
(`ec4547bd87fff21b1293be2eee955a979935ea654cd994910b2c3b194282d7c2`),
with the driver at `/tmp/pr54-exit-repeat.py`. These host-local files are not
portable repository fixtures. No lifecycle redesign or test relaxation was
included in that #54 source, and the failed CI run was not retried at that
stage. PR #55 subsequently resolved the lifecycle defect and is now merged
into this branch; the failed historical CI result itself remains unchanged.

## Historical measurement

The following excerpt and test counts predate the scope reduction. They are
retained only as provenance for the original view measurement, not acceptance
evidence for the current producer. Fresh validation is recorded separately.

The E2E test executes a static program using an open executable fd, first in the
ordinary root and then after a new mount namespace and chroot. It checks root
device/inode, namespace inode, root mount ID, and the exact exec pairing against
guest measurements. The fixture tests sequential stable views; adversarial
concurrent fs_struct mutations and other kernels remain outside this result.

The measured [two-invocation excerpt](exec-view/invocations.ndjson) preserves
four original NDJSON lines from that test: one view and one successful execveat
for each actor. The ordinary view has root inode 2, namespace 4026531841, and
mount ID 23; the changed view has inode 131084, namespace 4026532209, and mount
ID 46. Both normalize to device 253:0. These are fixture observations, never
consumer defaults. The empty execveat filename reflects execution by fd and
does not qualify for Sanjaya's separate path-based finite-method grammar.

Measurement environment: independent QEMU/KVM guest, Ubuntu 24.04,
kernel `6.8.0-49-generic`, collector binary SHA-256
`84bb4e190eb953ba9f79aa83dd94a9177813b33298098bd8bbc543afda314f95`,
kernel image SHA-256
`9b7af34a5f065e1c8c80ea96fa13e9da492aa752ba7a105a2c86b0e46a3909aa`.
The excerpt SHA-256 is
`5572cfb2b030791c9d27041c163ff68c92ff9ce5f5af509492e5d408f3a0f565`.

Validation: 148 daemon and 10 common Rust tests passed; the full guest suite
passed all 65 tests in 272.09 seconds after attachment was ready. An earlier
run started immediately after `systemctl start` and missed the first argv
fixture's exec before attachment finished (64 passed, one failed). The isolated
argv/view rerun and the full ready run passed. `systemctl is-active` alone is
not a BPF attachment readiness signal; the guest log reported attachment about
four seconds after service start. No capture completeness is claimed for that
startup interval.
