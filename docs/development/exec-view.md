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
