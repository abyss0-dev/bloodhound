# E2E observer load

## Problem

Focused USDT tests passed while the full suite timed out around restart-sensitive shell events.

The VM did not show memory exhaustion or an OOM event, so the source of the timing pressure was unclear.

## Answer

Make polling cost proportional to new evidence.

Record the NDJSON line count at test start, fetch only `baseline + 1` onward with remote `tail`, and retain a separate fresh reader only for tests that intentionally replace the output file.

Treat the observer as part of the system load during timing investigations.

## Evidence

- The VM used about 310 MB of 2 GB and had about 1.66 GB available.
- The daemon remained active and no OOM record appeared.
- The NDJSON file had grown to roughly 11 MB and 58,000 lines.
- The old reader copied and parsed the full file every 100 ms.
- A 15-second wait could therefore perform up to 150 full-file copies and parses.
- After the reader change, the restart-sensitive sequence passed five consecutive runs.
- The final full KVM suite passed all 53 tests.

## Failed attempts and mistakes

- We initially suspected VM CPU or memory pressure.
- We increased observation time without first measuring the cost of one polling iteration.
- We optimized collector and readiness paths while the test reader continued generating repeated SCP and JSON work.
- A fresh output file helped replacement tests but did not prevent growth during the full suite.
- Longer timeouts allowed more expensive full-file polls and did not remove the cause.

## Notes

- Polling helpers must not reread history that cannot affect the current predicate.
- `f72ffaf` introduced bounded polling and isolated restart captures.
- `1e5ffcc` replaced whole-file SCP polling with baseline-relative remote reads.
