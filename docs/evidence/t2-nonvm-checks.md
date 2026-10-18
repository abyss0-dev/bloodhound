# T2 non-VM candidate checks

The first table records non-VM checks from the earlier candidate; the correction-candidate table records reruns before source commit `a61027578118ee93c90368fb2d9a4953afe2fa69`.
They are separate from VM acceptance, which passed for that source commit and is recorded in `t2-vm-acceptance.md`.

| Command | Result |
| --- | --- |
| `rustup run nightly-2026-07-29 cargo test --workspace` | Passed: 216 tests (152 + 13 + 51); doc tests passed. |
| `rustup run nightly-2026-07-29 cargo test --package bloodhound usdt` | Passed: 11 tests. |
| `(cd bloodhound-ebpf && rustup run nightly-2026-07-29 cargo build --release)` | Passed. |
| `python3 -m pytest -q e2e/tests/test_network_context_schema.py e2e/tests/test_t2_process_identity.py` | Passed: 6 tests. |
| `rustup run nightly-2026-07-29 cargo clippy --workspace --all-targets` | Passed with existing warnings. |
| `make build-docker DOCKER_OUTPUT=/tmp/network-impl.DDNwog/t2-make-build-output` | Passed; emitted the x86_64 musl executable. |
| Temporary Docker build using `/tmp/network-impl.DDNwog/t2-cargo-musl-test.Dockerfile` and `cargo test --package bloodhound usdt --target x86_64-unknown-linux-musl` | Passed: 11 tests; build completed. The tagged temporary image was removed after confirming no containers used it. |
| `bash -n e2e/scripts/t2-owned-vm.sh`; `python3 -m pytest -q e2e/tests/test_t2_process_identity.py`; explicit build/lock/QEMU ordering assertion | Passed: 4 tests and ordering assertion. |
| `git diff --check` | Passed. |

Formatting remains a repository-baseline issue. `cargo fmt --all -- --check` reports existing formatting differences in untouched files, including `bloodhound-tui`; `rustfmt --check` on modified modules also reports extensive pre-existing style drift in legacy portions of `bloodhound/src/deserializer.rs` and adjacent code. Applying workspace or whole-file formatting would introduce unrelated churn, so no broad reformat was made.

A strict `cargo clippy --workspace --all-targets -- -D warnings` attempt fails on the existing `collapsible_match` lint in `bloodhound-tui/src/keybinds.rs:50`. The ordinary workspace Clippy check above succeeds; the unrelated TUI lint was not changed.

## Correction candidate checks (before its commit)

The following were rerun after reserving wire IDs 225/226/227, fixing pending-map cleanup on a failed sys_exit read, and changing producer acceptance to use a distinct guest-created network namespace. They complement, but do not replace, the candidate-bound focused and full VM acceptance recorded in `t2-vm-acceptance.md`.

| Command | Result |
| --- | --- |
| `rustup run nightly-2026-07-29 cargo test --workspace` | Passed: 216 tests (152 + 13 + 51); doc tests passed. |
| `rustup run nightly-2026-07-29 cargo test --package bloodhound usdt` | Passed: 11 tests. |
| `(cd bloodhound-ebpf && rustup run nightly-2026-07-29 cargo build --release)` | Passed. |
| `rustup run nightly-2026-07-29 cargo test -p bloodhound-common` | Passed: 13 tests; doc tests passed. |
| `rustup run nightly-2026-07-29 cargo clippy --workspace --all-targets` | Passed with existing warnings. |
| `rustup run nightly-2026-07-29 cargo clippy --package bloodhound-common --all-targets -- -D warnings` | Passed. |
| `python3 -m pytest -q e2e/tests/test_network_context_schema.py e2e/tests/test_t2_process_identity.py` | Passed: 6 tests. |
| `make build-docker DOCKER_OUTPUT=/tmp/network-impl.DDNwog/t2-make-build-output-corrected` | Passed; emitted the x86_64 musl executable. |
| `docker buildx build --platform linux/amd64 --file /tmp/network-impl.DDNwog/t2-cargo-musl-test.Dockerfile --output type=local,dest=/tmp/network-impl.DDNwog/t2-musl-output-corrected --progress=plain .` | Passed: musl USDT tests 11/11 and release build. Output was written to a temporary local directory; no tagged image was created. |
| Python compile, runner `bash -n`, changed-region rustfmt checks for `bloodhound-common/src/lib.rs` and the changed exec exit handler, and `git diff --check` | Passed. |
| `rustup run nightly-2026-07-29 cargo fmt --all -- --check` | Fails on repository baseline formatting drift, including untouched files. Changed common/exec-handler regions pass scoped rustfmt. |
| `rustup run nightly-2026-07-29 cargo clippy --workspace --all-targets -- -D warnings` | Fails on existing `clippy::collapsible_match` in untouched `bloodhound-tui/src/keybinds.rs:50`; strict Clippy on `bloodhound-common` passes. |
