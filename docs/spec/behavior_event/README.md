# Vendored BehaviorEvent schemas

These are exact blobs vendored from canonical source commit `51e967fb4c0489af471fffc5f9321a1556100738` of the read-only `abyss0-dev/workspace` repository. Runtime builds and tests consume only these local files.

- `behavior_event.schema.json`: SHA-256 `1d62f1b77167bb90e5f2f7c73f218db097a3e248d7b489f9b48344efcbc8ac83`
- `network_context.schema.json`: SHA-256 `5d914183b0e042a0fb8ab65a13c80b24f34498471a463b421e18162d09372d24`

The selected profile is guest monotonic nanoseconds, FIFO admission, existing `header.process_ref`, and `META/exec_entry_network_context`; the canonical base schema's epoch-seconds prose does not describe this profile. Context identity is measured at syscall entry. `device` is the `st_dev` value of a followed namespace FD after startup verification that the descriptor is on nsfs; per-entry inode is read from the current task's `nsproxy -> net_ns -> ns_common.inum`. Device calibration is not an actor-specific `/proc` enrichment. No actor inode is inferred from the daemon or from later procfs state.

The runtime must fail to `unavailable` when the calibration or required BTF/read is unavailable; pointer recheck disagreement is `changed`. Positive actor/time missing at entry is a collection-loss condition, not a schema-valid context. Linux nsfs singleton-superblock behavior must be verified on each supported target family and by the dedicated VM acceptance; this pin alone does not establish it.
