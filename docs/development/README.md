# Development guides

These guides explain how Bloodhound features are structured and how to change
them safely. They complement the user-facing documents in `docs/` and the
historical engineering notes in `docs/devnotes/`.

- [Trusted USDT collectors](usdt-collectors.md): architecture, trust boundary,
  code ownership, and the contribution path for a collector.
- [Exec-entry filesystem view](exec-view.md): runtime BTF acquisition,
  invocation pairing, incomplete capture and validation boundaries.
- [Filesystem observation](filesystem-observation.md): openat capture versioning,
  pathname acquisition, identity flags, and acceptance evidence.
- [Concurrent process exit](process-exit.md): thread exit deduplication,
  `EXIT_CLAIMS` lifecycle, and reclamation on process free.
