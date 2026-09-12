# Verified Bash launch boundary

`--bash-launch /usr/bin/bash` explicitly enables an in-tree entry/return
collector for the measured Ubuntu 24.04 x86-64 Bash 5.2.21 image. It is disabled
by default. The supplied path must be absolute and name a regular file of at
most 4 MiB. Startup reads the complete image, verifies stable size/timestamps
and SHA-256 `bc5945feb8bd26203ebfafea5ce1878bb2e32cb8fb50ab7ae395cfb1e1aaaef1`,
then attaches through the verified open file descriptor. Unknown images and
attachment failures fail startup; no offset, ABI, program or digest can be
supplied through configuration. The image must remain unmodified during the
run, as required by the managed-fixture contract.

This image has Build ID `2f77b36371c214e11670c7d9d92727e9a49f626b` and
`execute_command_internal` at file offset `0x4a280`. Its scalar arguments were
measured using the Sanjaya guest fixture before this integration. The function
signature is defined in GNU Bash 5.2
[execute_cmd.c](https://raw.githubusercontent.com/mirror/bash/bash-5.2/execute_cmd.c).

The fixed 24-byte payload uses event kind 227 and version 1. Entry phase 1
contains signed command type, unsigned command flags, asynchronous, pipe-in
and pipe-out. Status 1 means all fields were captured; status 2 means unavailable
and carries no arguments in NDJSON. Return phase 2 contains no entry arguments.
Unknown versions are rendered unknown without values. Partial/malformed known
payloads are rejected. The event names are `UPROBE/bash_command_entry` and
`UPROBE/bash_command_return`, with the normal immutable kernel actor header and
monotonic timestamp. No command strings, pointers or parsed method grammar are
exported. No per-command state or history is retained by this collector; it
uses the existing bounded ring buffer and capture-health path.

These events are observation boundaries, not Evidence. Consumers must handle
nesting, missing/duplicate records, return/exit boundaries and capacity before
binding a context to a particular fork. Return is not a method exit status.
Pipe descriptors are shell execution arguments before child redirection, not
FD identity or output-delivery proof. In particular, the inherited-pipe boolean
from the separate fork-files collector is insufficient for this distinction:
ordinary interactive Bash commands can also inherit a synchronization pipe.

Validation on kernel 6.8.0-49-generic: 154 daemon tests, 10 common tests and 51
TUI tests passed. The enabled guest collector passed five focused tests:
unknown-image rejection, ordinary true/stat, stdout-redirection pipeline and
stdin-redirection pipeline. Every measured command scope contains complete
entry/return records, while startup observations outside that scope are not
assumed complete. The measured producer SHA-256 is
`a9deee42ca1af3e18b91f4cc1750a4a7e5c201a604ecc4c5ba802ff31775dec1`.

Run the focused guest tests with `--bash-launch-enabled` and a daemon started
with the explicit image path. Without that flag they report a skip, so the
ordinary CI suite must not be cited as Bash-launch acceptance. Sanjaya ingestion,
bounded context correlation, replacement of fork-pipe admission and joint
positive/negative guest acceptance are still pending.
