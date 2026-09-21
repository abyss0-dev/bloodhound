# Concurrent process exit

`sched_process_exit` runs after `do_exit` decrements `signal->live`.
Several exiting threads can therefore read zero and emit an exit for the same
`(tgid, start_boottime_ns)`. Testing zero alone is not a once-only decision.
The duplicate also caused userspace to synthesize another start after removing
the actor from its active set.

## Claim and reclamation

The producer inserts that immutable identity into `EXIT_CLAIMS` using
`BPF_NOEXIST`. Only the successful insert emits an exit. `EEXIST` suppresses a
duplicate. Other errors suppress the event and increment collection-health
counters. A ring-buffer failure retains the claim and uses the existing ring
drop counter.

The shared hash map has 10,240 entries and does not evict. An LRU map could
evict an exiting actor and allow another thread to claim it again. Claims remain
until the group leader's `sched_process_free`, including while it is a zombie.
Cleanup reads the freed task itself and requires `pid == tgid`; it does not follow
a worker's leader pointer or filter the unrelated current task's AUID.
During nonleader exec, `de_thread` exchanges task PIDs and preserves the process
start time, so the former leader does not remove the replacement's claim.
Cleanup attaches before the exit producer. Maps are private to the collector
session and are destroyed on shutdown.

`process_exit.collection` diagnostics distinguish capture, claim, and cleanup
failures from ring loss. They conservatively mark the run prefix incomplete;
they do not claim a precisely located gap or silently fall back to duplicate
emission. Existing processes do not need a previously observed fork to claim
their exit.

This change does not add UPROBE or USDT dependencies. It does not change the
userspace handling of arbitrary late observations: terminal tombstones and their
bounded retention policy are a separate lifecycle design problem.

## Regression

`e2e/tests/test_exit_group.py::test_concurrent_thread_group_exit_stress_emits_once`
terminates 1,000 Python processes, each with a sleeping daemon thread, using
`os._exit(7)`. Each driver reaps its children; observing the drivers' exits forms
the completion barrier before counting all child starts and exits. The test
also checks stable identity, successful exec coverage, and AUID. The driver
barrier does not synchronize asynchronous health polling; health counters are
validated separately.

On Ubuntu 24.04 / kernel `6.8.0-49-generic`, QEMU/KVM with two vCPUs and 2 GiB:

- Exact main `7a6c54f699f50e2db9e865e501275417f008f281`: the new test failed.
  992 processes had one exit; eight had two exits and two starts. No collection
  health or ring loss was reported. Earlier independent runs also reproduced
  the race; a short passing run is insufficient evidence of a fix.
- Fixed producer: the 1,000-process regression, PID reuse, leader-first exit,
  and nonleader exec tests passed. Rust workspace tests passed (210 tests).
  The initial guest binary was `f673c8ec369cd52fae454256dc179a6ab5ed622bbc3020ae63881d8571efcdee`.
  Final formatting/comment changes produced
  `a130665244548d1d4b937d9a191905cebe980df747bd968f195af22b9ef0dffd`;
  every BPF executable section is byte-identical between these artifacts.
  See the PR validation record for final-artifact guest and CI results.

The change intentionally remains separate from filesystem-view PR #54 because
the failing producer path is already present on main.
