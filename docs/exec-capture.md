# Exec argument capture (#33)

This is the argv completeness contract used by filesystem observation (#52).
There is one shared collector for execve and execveat, not a filesystem-specific
argv parser. The captured argv is an entry-time read of user memory, not a
guarantee against concurrent userspace mutation before kernel consumption.

## Wire and consumer contract

The existing ExecvePayload and variable-data layout are unchanged. For Execve
and Execveat only, EventHeader's three formerly reserved bytes encode capture
version, argv status, and filename status. Version 1 status codes are 1 complete,
2 truncated, and 3 read error. Other event kinds retain their existing layout.
Old producers emit zero padding. Unknown versions do not certify completeness.

NDJSON contains `exec_capture_version`, `argv_status`, and `filename_status`.
Both statuses can be `complete`, `truncated`, `read_error`, `invalid_encoding`,
or `unknown`. The last two are determined by userspace: unrecognized wire
versions are unknown, and a lossy UTF-8 conversion is never labeled complete.
Known-version records with inconsistent lengths, invalid status codes, or
missing argv separators are rejected through the existing stream-health path.

Consumers performing positive argv-based command recognition must require
`exec_capture_version == 1`, `argv_status == complete`, and a separately verified
executable. When using the captured filename to identify that executable, also
require `filename_status == complete`. Missing fields in old NDJSON mean unknown,
not complete. The exec event's successful return denotes successful exec, not
successful method completion; use the same actor's process_exit separately.
An incomplete exec capture does not invalidate independent file/World facts.

Empty arguments are preserved, including a final empty argument. `argv` remains
an array of strings. Lossy text is retained for display with invalid_encoding
status; consumers must not treat those strings as exact original bytes.

## Acquisition limits

The collector reads at most 20 arguments, at most 255 content bytes per argument,
and uses a 4096-byte scratch buffer. To keep helper writes verifier-bounded, a
new argument requires a complete 256-byte slot below the reserved final byte;
the collector can therefore stop before every byte of the total buffer is used.
All such capacity stops are truncated. A string longer than 255 bytes is copied
as a 255-byte prefix, not a bitmask-wrapped length, and terminates acquisition.
Exactly 255 content bytes can be complete.

Only observing the vector's terminating NULL (or the explicitly NULL vector)
certifies complete argv acquisition. After 20 arguments the collector probes
the next pointer: NULL means complete, non-NULL truncated, unreadable read_error.
Unreadable argument pointers, unreadable strings, and failed internal copies
produce read_error, including when the syscall itself later succeeds. Probe
helpers cannot fault in user pages. Short argv alone never proves acquisition.

The filename boundary is conservative: a pathname reaching the entire read
buffer is marked truncated. Internal-copy failures clear the corresponding
length, so stale scratch contents are not emitted as that field.

## Verification

`e2e/fixtures/exec-completeness.c` exercises ten cases through each syscall:
short argv, empty arguments, exactly 20 entries, 21 entries, a 256-byte argument,
total-buffer exhaustion, invalid vector pointer, invalid string pointer,
invalid UTF-8, and an exactly 255-byte argument. Valid inputs are touched in
the child before exec to make positive cases independent of page residency;
fault cases retain their invalid pointers.

On the x86_64 6.8.0-49-generic guest, `test_exec_completeness.py` verified all
20 cases, including -EFAULT for invalid pointers, the full 255-byte prefix for
long arguments, and preservation of empty argv elements. Unit tests cover old
and unknown producers, invalid framing/statuses, and lossy text. Filesystem
method tests now explicitly require complete argv and filename acquisition.
