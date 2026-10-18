# T2 candidate VM acceptance

The original section below records historical results for commit `811bdf55593dfa329c89faf3e35f4c93e32d559f` (parent `07c4b9a9cb857356dcca4e80fbf3068bb1aa4a07`). Its learner and management namespace identities were equal, so it did **not** satisfy the distinct-learner-namespace acceptance criterion and must not be treated as acceptance for the corrected candidate. The corrected results below are from commit `a61027578118ee93c90368fb2d9a4953afe2fa69`.

Both sets used `e2e/scripts/t2-owned-vm.sh`; Docker/rootfs preparation occurred before it acquired `/tmp/network-impl.DDNwog/vm.lock`, which remained held through QEMU cleanup.

## Focused producer acceptance

Command:

```sh
T2_VM_LOCK=/tmp/network-impl.DDNwog/vm.lock \
T2_TEST_FILE=test_exec_network_context.py \
T2_VM_READY_SECONDS=600 \
e2e/scripts/t2-owned-vm.sh
```

Result: `3 passed` in 7.97 seconds. The leader and non-leader successful exec cases each produced one `complete` context with exact actor and entry timestamp pairing. Both observed namespace identities were `{device: 4, inode: 4026531840}`, matching the target exec's namespace-FD `fstat`; the management namespace-FD `fstat` matched as well. The failed exec returned `-2` and had zero matching contexts. No collection diagnostic was observed.

Guest: Linux `6.8.0-49-generic`, x86_64. Startup BTF resolution reported `exec_netns: Some([3096, 40, 120, 16])`; nsfs calibration reported `valid=1 st_dev=4`.

Run artifacts: `t2-vm-bloodhound-t2-g8ohqzgu/` (focused) and `t2-vm-bloodhound-t2-e90jtool/` (full suite), including pytest output, provenance, acceptance records, guest provenance, Bloodhound journal, raw event output, and QEMU log. The `events.ndjson.gz` and `qemu.log.gz` files decompress byte-for-byte to the runner outputs. The full-suite raw `events.ndjson` was empty because the runner's final bulk SSH capture produced no bytes; individual tests obtained and validated events through their live SSH reads.

These run-artifact directories are not included in the repository; they are retained outside version control by the maintainer.

## Full regression suite

Command:

```sh
T2_VM_LOCK=/tmp/network-impl.DDNwog/vm.lock \
T2_VM_READY_SECONDS=600 \
e2e/scripts/t2-owned-vm.sh
```

Result: `81 passed, 0 failed` in 403.99 seconds. This includes exec completeness/view, process identity and exit, filesystem observation, TTY, syscall, LSM, schema/replay, packet, process creation, and all USDT tests. No tests were skipped or suppressed. Four `jsonschema.RefResolver` deprecation warnings remain.

## Corrected candidate focused producer acceptance

Measured source commit: `a61027578118ee93c90368fb2d9a4953afe2fa69`.

Command:

```sh
T2_VM_LOCK=/tmp/network-impl.DDNwog/vm.lock \
T2_TEST_FILE=test_exec_network_context.py \
T2_TEST_TIMEOUT=2400 bash e2e/scripts/t2-owned-vm.sh
```

Result: `3 passed` in 8.07 seconds. Leader and non-leader successful execs each had one `complete` context with exact actor and entry timestamp pairing. For both, learner FD `fstat` and emitted `netns` were `{device: 4, inode: 4026532209}`, while the management namespace FD was `{device: 4, inode: 4026531840}`: the nsfs device matched and the inode differed. Both events had `auid=1000`; the failed exec returned `-2` and had zero matching contexts. No collection diagnostics were observed.

Guest: Linux `6.8.0-49-generic`, x86_64. Evidence is in `t2-vm-bloodhound-t2-5uhhtjce/` (acceptance records, full captured events, journal, guest provenance, pytest output, compressed QEMU log, and provenance). `qemu.log.gz` decompresses byte-for-byte to the runner's QEMU log.

## Corrected candidate full regression

Measured source commit: `a61027578118ee93c90368fb2d9a4953afe2fa69`.

Command:

```sh
T2_VM_LOCK=/tmp/network-impl.DDNwog/vm.lock \
T2_TEST_TIMEOUT=2400 bash e2e/scripts/t2-owned-vm.sh
```

Result: `81 passed, 0 failed` in 524.76 seconds. This includes the corrected producer acceptance, exec completeness/view, process identity/exit, filesystem observation, TTY, syscall, LSM, schema/replay, packet, process creation, and USDT tests. No tests were skipped or suppressed; four `jsonschema.RefResolver` deprecation warnings remain. `t2-vm-bloodhound-t2-tsaqfbyk/` contains the full run artifacts and records `source_commit=a61027578118ee93c90368fb2d9a4953afe2fa69`; its `qemu.log.gz` decompresses byte-for-byte to the runner's QEMU log.

## Cleanup and prior runs

After both corrected runs, `/tmp/network-impl.DDNwog/vm.lock` was available; no owned QEMU process, Docker container/image, or run directory remained. Cleanup used the runner's PID/start-time and exact-image-path identity checks.

Tracked historical VM artifacts under `docs/evidence/t2-vm-*` retain their own provenance and are not evidence for the corrected candidate. The 30 pre-existing untracked historical evidence files were archived with their relative paths and verified hashes at `/tmp/network-impl.DDNwog/t2-historical-evidence-archive`; the archive is described in `t2-review.md`. The original 811bdf run above remains historical and failed the distinct-namespace criterion.

Gemini's final review reported no blockers, and Main approved T2 closure. The review record is `t2-review.md`.
