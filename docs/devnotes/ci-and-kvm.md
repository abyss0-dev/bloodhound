# CI and KVM environment

## Problem

CI failures occurred in several unrelated phases: portable USDT tests, KVM availability, rootfs construction, guest boot, and privileged fixture execution.

Combining them made environment failures look like collector failures and slowed feedback from tests that did not require a VM.

## Answer

Use Takumi Runner, the self-hosted runner provided by GMO Flatt Security, as the default GitHub Actions runner.

As of 2026-08-01, Takumi Runner does not support KVM.

Use a GitHub-hosted `ubuntu-24.04` runner only for the KVM-dependent E2E workflow.

Start `cicd-sensor` before the E2E workload and send its host-side trace to the Takumi Manager. Authenticate to Shisho Cloud immediately before starting the sensor and pass the masked step output directly to it.

Run portable CI and USDT unit/replay jobs on `takumi-runner`, separate from privileged KVM E2E.

Keep explicit steps for binary build, KVM capability, rootfs construction, VM boot, daemon readiness, and fixture tests.

Fail early when KVM is unavailable, and install the complete guest kernel-tool and rootfs dependency chain explicitly.

## Evidence

- Some KVM failures occurred before pytest collection.
- USDT unit/replay tests did not require KVM and passed independently.
- `ci.yml` and `usdt.yml` use `takumi-runner`.
- Only `e2e.yml` uses the GitHub-hosted `ubuntu-24.04` runner and accesses `/dev/kvm`.
- Rootfs construction exposed missing kernel tools, HWE dependencies, and Jammy base packages in sequence.
- Once the environment chain was explicit, the current branch passed CI, USDT unit/replay, and KVM E2E workflows.
- The final GitHub KVM job passed all 53 tests.

## Failed attempts and mistakes

- We assumed that the presence of `/dev/kvm` meant the runner could execute the privileged suite.
- We initially treated unit/replay and KVM E2E as one CI concern.
- We temporarily moved both portable USDT tests and KVM E2E to GitHub-hosted runners, making the KVM exception broader than required.
- We attributed rootfs failures to the USDT implementation before locating the failing workflow step.
- We installed one missing guest package at a time, exposing another dependency on subsequent runs.
- A green portable workflow was temporarily easier to overread as evidence for the privileged fixture path.

## Notes

- CI phase separation is diagnostic structure, not only scheduling optimization.
- The runner policy is Takumi Runner by default, with a GitHub-hosted exception only for jobs that require unsupported capabilities such as KVM.
- `cicd-sensor` observes the GitHub-hosted runner and QEMU host process. Bloodhound remains responsible for observations from inside the QEMU guest.
- The Shisho Cloud bot used by E2E needs only the `Takumi Runnerトレース送信者` mission-specific role. Its ID is supplied through the `SHISHO_CICD_SENSOR_BOT_ID` GitHub Actions repository variable.
- GitHub refuses to forward the action's masked token as a job output, so OIDC authentication and sensor startup must share the E2E job. This gives the whole job `id-token: write`; keep the Shisho Cloud trust condition repository-scoped and keep authentication before checkout and other workload steps.
- Environment failures that occur before test collection are not collector acceptance results.
- `96bf64a` moved both USDT jobs to GitHub-hosted runners while investigating KVM failures.
- `370d0a9` split USDT unit/replay from KVM E2E.
- `af12018`, `f4c9f2a`, and `254aaba` completed the guest tool and rootfs dependency chain.
