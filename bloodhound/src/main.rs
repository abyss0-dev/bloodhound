mod btf_offsets;
mod capture_health;
mod cli;
mod clock;
mod consumer;
mod deserializer;
mod drop_counter;
mod heartbeat;
mod lifecycle;
mod loader;
mod ready;
mod sequencer;
mod serializer;
mod shutdown;
mod usdt;

use anyhow::{bail, Context, Result};
use aya::maps::{ring_buf::RingBuf, PerCpuArray};
use clap::Parser;
use log::info;
use std::time::Duration;
use tokio::sync::mpsc;

use cli::Cli;
use sequencer::{SequencedInput, Sequencer};
use serializer::Serializer;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Cli::parse();
    // SAFETY: sysconf takes a constant selector and no pointers.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    anyhow::ensure!(page_size > 0, "failed to determine system page size");
    cli::validate_ring_buffer_size(args.ring_buffer_size, page_size as u64)?;
    let heartbeat_interval_ms = cli::heartbeat_interval_ms(args.heartbeat_interval)?;
    let startup = ready::StartupFacts {
        boot_id: ready::boot_id()?,
        auid: args.uid,
        daemon_pid: std::process::id(),
        heartbeat_interval_ms,
    };
    info!("Bloodhound starting: tracing uid={}", args.uid);
    eprintln!("Bloodhound starting: tracing uid={}", args.uid);

    let events_emitted = heartbeat::new_events_emitted_counter();
    let mut sequencer = Sequencer::new(args.uid, Serializer::new(), events_emitted.clone());
    // Create the one bounded admission path before any source can emit a
    // BehaviorEvent, including startup validation diagnostics.
    let (sequence_tx, mut sequence_rx) = mpsc::channel::<SequencedInput>(4096);

    let mut usdt_selections = Vec::new();
    for path in &args.usdt_config {
        match usdt::load_selection(path) {
            Ok(selection) => usdt_selections.push(selection),
            Err(error) => {
                // Startup validation is deliberately noisy and structured: a
                // bad trusted selection is never silently ignored.
                let event = usdt::selection_failure_diagnostic(path, &error);
                sequence_tx
                    .send(SequencedInput::Synthesized(Box::new(event)))
                    .await
                    .context("admitting startup diagnostic to event sequencer")?;
                let admitted = sequence_rx
                    .recv()
                    .await
                    .context("event sequencer closed before startup diagnostic")?;
                sequencer.accept(admitted)?;
                sequencer.flush()?;
                return Err(error);
            }
        }
    }

    // Load and attach BPF programs
    let (mut bpf, usdt_diagnostics, usdt_links, attach_report) =
        loader::load_and_attach(&args, &usdt_selections)?;

    // Admit readiness before starting any task that can emit, including the
    // immediately ticking collection monitors when startup counters are nonzero.
    let ready = ready::ready_event(
        &attach_report,
        loader::ring_buffer_size(&bpf)?,
        ready::nsfs_dev(),
        &startup,
    );
    sequence_tx
        .send(SequencedInput::Synthesized(Box::new(ready)))
        .await
        .context("admitting bloodhound_ready to event sequencer")?;

    // Set up shutdown handler
    let shutdown_tx = shutdown::shutdown_signal();
    let mut shutdown_rx = shutdown_tx.subscribe();

    // Set up drop counter and the BPF→userspace bridge that keeps it
    // up to date. Without the bridge, the BPF helper increments a
    // per-CPU map that nothing reads back, so the userspace counter
    // (and therefore heartbeat `gap_detected`) stays at 0 forever
    // — see issue #28.
    let drop_count = drop_counter::new_counter();
    tokio::spawn(drop_counter::poll_drop_counter(drop_count.clone()));

    let drop_count_map = bpf
        .take_map("DROP_COUNT")
        .context("DROP_COUNT map not found in BPF object")?;
    let drop_count_map: PerCpuArray<_, u64> = PerCpuArray::try_from(drop_count_map)?;
    let bridge_reader = drop_counter::BpfDropCountReader::new(drop_count_map);
    let (bridge_stop_tx, bridge_stop_rx) = tokio::sync::oneshot::channel();
    let bridge_handle = tokio::spawn(drop_counter::bridge_bpf_drop_counter(
        bridge_reader,
        drop_count.clone(),
        Duration::from_secs(1),
        bridge_stop_rx,
    ));

    let capture_map = bpf
        .take_map("OPENAT_FAILURES")
        .context("OPENAT_FAILURES map not found in BPF object")?;
    let capture_map: PerCpuArray<_, u64> = PerCpuArray::try_from(capture_map)?;
    let (capture_shutdown_tx, capture_shutdown_rx) = tokio::sync::oneshot::channel();
    let capture_handle = tokio::spawn(capture_health::monitor(
        "openat",
        &capture_health::OPENAT_REASONS,
        capture_map,
        sequence_tx.clone(),
        capture_shutdown_rx,
    ));

    let exec_map = bpf
        .take_map("EXEC_FAILURES")
        .context("EXEC_FAILURES map not found in BPF object")?;
    let exec_map: PerCpuArray<_, u64> = PerCpuArray::try_from(exec_map)?;
    let (exec_shutdown_tx, exec_shutdown_rx) = tokio::sync::oneshot::channel();
    let exec_health_handle = tokio::spawn(capture_health::monitor(
        "exec",
        &bloodhound_common::EXEC_FAILURE_REASONS,
        exec_map,
        sequence_tx.clone(),
        exec_shutdown_rx,
    ));

    let exit_map = bpf
        .take_map("EXIT_FAILURES")
        .context("EXIT_FAILURES map not found in BPF object")?;
    let exit_map: PerCpuArray<_, u64> = PerCpuArray::try_from(exit_map)?;
    let (exit_shutdown_tx, exit_shutdown_rx) = tokio::sync::oneshot::channel();
    let exit_health_handle = tokio::spawn(capture_health::monitor(
        "process_exit",
        &bloodhound_common::exit_claim::EXIT_FAILURE_REASONS,
        exit_map,
        sequence_tx.clone(),
        exit_shutdown_rx,
    ));

    // Set up ring buffer consumer
    let map = bpf.take_map("EVENTS").unwrap();
    let ring_buf = RingBuf::try_from(map)?;
    // All producers admit to this one bounded channel. Successful send order
    // is the canonical cross-producer order represented by NDJSON line order.
    let (consumer_ready_tx, consumer_ready_rx) = tokio::sync::oneshot::channel();
    let (consumer_shutdown_tx, consumer_shutdown_rx) = tokio::sync::oneshot::channel();

    // Spawn ring buffer consumer task
    let raw_tx = sequence_tx.clone();
    let mut consumer_handle = tokio::spawn(consumer::consume_ring_buffer(
        ring_buf,
        raw_tx,
        consumer_ready_tx,
        consumer_shutdown_rx,
    ));
    consumer_ready_rx
        .await
        .context("ring buffer consumer exited before becoming ready")?;
    info!("BPF programs loaded and attached");
    eprintln!("BPF programs loaded and attached");

    for diagnostic in usdt_diagnostics {
        sequence_tx
            .send(SequencedInput::Synthesized(Box::new(diagnostic)))
            .await
            .context("queueing USDT diagnostic")?;
    }

    // Heartbeat task: periodic synthesized events carrying drop deltas
    // and emission counts so downstream consumers can mark intervals
    // as undecidable when drops occurred.
    let heartbeat_tx = sequence_tx.clone();
    let heartbeat_drops = drop_count.clone();
    let heartbeat_emitted = events_emitted.clone();
    let heartbeat_interval = Duration::from_millis(u64::from(heartbeat_interval_ms));
    let (heartbeat_stop_tx, heartbeat_stop_rx) = tokio::sync::oneshot::channel();
    let heartbeat_handle = tokio::spawn(async move {
        heartbeat::run_heartbeat(
            heartbeat_interval,
            heartbeat_drops,
            heartbeat_emitted,
            heartbeat_tx,
            heartbeat_stop_rx,
        )
        .await
    });

    let drain_timeout = Duration::from_secs(5);
    // The main task no longer produces events. Dropping this sender ensures
    // the channel closes after the raw and heartbeat producers finish.
    drop(sequence_tx);

    // Main sequencing loop. There is one receiver and one fallible writer;
    // stdout failures therefore terminate the daemon instead of being logged
    // and ignored.
    loop {
        tokio::select! {
            input = sequence_rx.recv() => {
                match input {
                    Some(input) => sequencer.accept(input)?,
                    None => bail!("bounded event sequencer closed unexpectedly"),
                }
            }

            result = &mut consumer_handle => {
                result.context("ring buffer consumer task panicked")??;
                bail!("ring buffer consumer exited unexpectedly");
            }

            _ = shutdown_rx.recv() => {
                eprintln!("Shutting down...");
                break;
            }
        }
    }

    // Stop kernel production first, then ask the ring-buffer consumer to
    // perform one final drain into the same sequencer. The heartbeat sender
    // is removed so channel closure proves that every admitted item drained.
    // Exit claims are session-local and never pinned/reused. Either detach
    // order is safe: removing cleanup first retains claims (no re-emission),
    // removing exit first stops new claims. The whole object is then destroyed.
    // Health map FDs remain owned by the monitors for their final sample.
    let _ = heartbeat_stop_tx.send(());
    drop(bpf);
    drop(usdt_links);
    // Synchronous detach cannot be preempted by an async timeout.
    let deadline = tokio::time::Instant::now() + drain_timeout;
    let _ = capture_shutdown_tx.send(());
    let _ = exec_shutdown_tx.send(());
    let _ = exit_shutdown_tx.send(());
    let _ = consumer_shutdown_tx.send(());

    let producers = async {
        let (_, _, _, _, cursor) = tokio::try_join!(
            async {
                consumer_handle
                    .await
                    .context("ring buffer consumer task panicked")?
            },
            async {
                capture_handle
                    .await
                    .context("openat collection monitor panicked")
            },
            async {
                exec_health_handle
                    .await
                    .context("exec collection monitor panicked")
            },
            async {
                exit_health_handle
                    .await
                    .context("process exit collection monitor panicked")
            },
            async { heartbeat_handle.await.context("heartbeat task panicked") },
        )?;
        Ok(cursor)
    };
    let cursor = drain_until_closed(&mut sequence_rx, &mut sequencer, producers, deadline).await?;
    let _ = bridge_stop_tx.send(());
    let mut reader = tokio::time::timeout_at(deadline, bridge_handle)
        .await
        .context("incomplete shutdown: drop bridge timed out")?
        .context("drop bridge task panicked")?;
    finish_output(&mut sequencer, &mut reader, cursor, &events_emitted)?;
    eprintln!("Shutdown complete");
    Ok(())
}

/// Channel closure and producer completion are independent: the last sender
/// may be dropped before its task's JoinHandle becomes ready.
async fn drain_until_closed<W, F, T>(
    rx: &mut mpsc::Receiver<SequencedInput>,
    sequencer: &mut Sequencer<W>,
    producers: F,
    deadline: tokio::time::Instant,
) -> Result<T>
where
    W: std::io::Write,
    F: std::future::Future<Output = Result<T>>,
{
    tokio::pin!(producers);
    let mut closed = false;
    let mut joined = None;
    loop {
        if closed && joined.is_some() {
            return Ok(joined.unwrap());
        }
        tokio::select! {
            input = rx.recv(), if !closed => match input {
                Some(input) => sequencer.accept(input)?,
                None => closed = true,
            },
            result = &mut producers, if joined.is_none() => joined = Some(result?),
            _ = tokio::time::sleep_until(deadline) => {
                bail!("incomplete shutdown: bounded event sequencer did not drain within 5 seconds");
            }
        }
    }
}

fn finish_output<W: std::io::Write, R: drop_counter::DropCountReader>(
    sequencer: &mut Sequencer<W>,
    reader: &mut R,
    cursor: Option<heartbeat::Cursor>,
    emitted: &heartbeat::EventsEmittedCounter,
) -> Result<()> {
    use std::sync::atomic::Ordering;
    // Read even when heartbeats are disabled: shutdown must not silently
    // succeed if its final accounting sample failed.
    let total = reader
        .read_total()
        .context("reading final BPF drop count")?;
    if let Some(cursor) = cursor {
        let event = heartbeat::build_heartbeat(
            total.saturating_sub(cursor.drops),
            total,
            emitted
                .load(Ordering::Relaxed)
                .saturating_sub(cursor.emitted),
        );
        sequencer.accept(SequencedInput::Synthesized(Box::new(event)))?;
    }
    sequencer.flush()
}

#[cfg(test)]
mod final_tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn sequencer() -> Sequencer<Vec<u8>> {
        Sequencer::new(
            1000,
            Serializer::with_writer(Vec::new()),
            heartbeat::new_events_emitted_counter(),
        )
    }

    fn deadline() -> tokio::time::Instant {
        tokio::time::Instant::now() + Duration::from_secs(1)
    }

    #[tokio::test]
    async fn sender_close_join_race_1000_iterations() {
        for _ in 0..1000 {
            let (tx, mut rx) = mpsc::channel(1);
            let task = tokio::spawn(async move {
                drop(tx);
                tokio::task::yield_now().await;
            });
            drain_until_closed(
                &mut rx,
                &mut sequencer(),
                async {
                    task.await?;
                    Ok(())
                },
                deadline(),
            )
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn closed_channel_waits_for_delayed_join() {
        let (tx, mut rx) = mpsc::channel(1);
        drop(tx);
        let value = drain_until_closed(
            &mut rx,
            &mut sequencer(),
            async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok(42)
            },
            deadline(),
        )
        .await
        .unwrap();
        assert_eq!(value, 42);
    }

    #[tokio::test]
    async fn producer_error_and_panic_fail_shutdown() {
        for panic in [false, true] {
            let (tx, mut rx) = mpsc::channel(1);
            let task = tokio::spawn(async move {
                drop(tx);
                if panic {
                    panic!("producer panic");
                }
                bail!("producer error")
            });
            let result = drain_until_closed(
                &mut rx,
                &mut sequencer(),
                async {
                    let result: Result<()> = task.await?;
                    result
                },
                deadline(),
            )
            .await;
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    async fn leaked_sender_times_out_after_producers_join() {
        let (_tx, mut rx) = mpsc::channel(1);
        assert!(drain_until_closed(
            &mut rx,
            &mut sequencer(),
            async { Ok(()) },
            tokio::time::Instant::now() + Duration::from_millis(20)
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn capacity_one_drains_while_joining() {
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            for _ in 0..100 {
                tx.send(SequencedInput::Synthesized(Box::new(
                    heartbeat::build_heartbeat(0, 0, 0),
                )))
                .await
                .unwrap();
            }
        });
        drain_until_closed(
            &mut rx,
            &mut sequencer(),
            async {
                task.await?;
                Ok(())
            },
            deadline(),
        )
        .await
        .unwrap();
    }

    struct Reader(Result<u64>);
    impl drop_counter::DropCountReader for Reader {
        fn read_total(&mut self) -> Result<u64> {
            self.0.as_ref().copied().map_err(|e| anyhow::anyhow!("{e}"))
        }
    }

    #[test]
    fn final_read_failure_emits_nothing_and_disabled_emits_nothing() {
        let emitted = heartbeat::new_events_emitted_counter();
        let mut seq = Sequencer::new(1000, Serializer::with_writer(Vec::new()), emitted.clone());
        assert!(finish_output(
            &mut seq,
            &mut Reader(Err(anyhow::anyhow!("read failed"))),
            Some(heartbeat::Cursor::default()),
            &emitted
        )
        .is_err());
        assert_eq!(emitted.load(Ordering::Relaxed), 0);
        finish_output(&mut seq, &mut Reader(Ok(3)), None, &emitted).unwrap();
        assert_eq!(emitted.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn final_heartbeat_is_last_and_deltas_cover_pre_spawn_events() {
        let emitted = heartbeat::new_events_emitted_counter();
        let mut bytes = Vec::new();
        {
            let mut seq =
                Sequencer::new(1000, Serializer::with_writer(&mut bytes), emitted.clone());
            let report = loader::AttachReport {
                probes: 1,
                ..Default::default()
            };
            let startup = ready::StartupFacts::default();
            seq.accept(SequencedInput::Synthesized(Box::new(ready::ready_event(
                &report,
                4096,
                Some(4),
                &startup,
            ))))
            .unwrap();
            seq.accept(SequencedInput::Synthesized(Box::new(
                heartbeat::build_heartbeat(2, 2, 1),
            )))
            .unwrap();
            seq.accept(SequencedInput::Synthesized(Box::new(ready::ready_event(
                &report,
                4096,
                Some(4),
                &startup,
            ))))
            .unwrap();
            finish_output(
                &mut seq,
                &mut Reader(Ok(5)),
                Some(heartbeat::Cursor {
                    drops: 2,
                    emitted: 1,
                }),
                &emitted,
            )
            .unwrap();
        }
        let events: Vec<serde_json::Value> = std::str::from_utf8(&bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let last = events.last().unwrap();
        assert_eq!(last["event"]["type"], "HEARTBEAT");
        assert_eq!(last["args"]["drop_count_total"], 5);
        assert_eq!(last["args"]["drop_count_delta"], 3);
        assert_eq!(last["args"]["gap_detected"], true);
        assert_eq!(last["args"]["run_prefix_incomplete"], true);
        let heartbeats: Vec<_> = events
            .iter()
            .filter(|e| e["event"]["type"] == "HEARTBEAT")
            .collect();
        assert_eq!(
            heartbeats
                .iter()
                .map(|e| e["args"]["drop_count_delta"].as_u64().unwrap())
                .sum::<u64>(),
            5
        );
        assert_eq!(
            heartbeats
                .iter()
                .map(|e| e["args"]["events_emitted_delta"].as_u64().unwrap())
                .sum::<u64>(),
            (events.len() - 1) as u64
        );
    }

    struct FailedWriter(bool);
    impl std::io::Write for FailedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.0 {
                Err(std::io::Error::other("write failed"))
            } else {
                Ok(bytes.len())
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("flush failed"))
        }
    }

    #[test]
    fn final_write_and_flush_failures_propagate() {
        for fail_write in [true, false] {
            let emitted = heartbeat::new_events_emitted_counter();
            let mut seq = Sequencer::new(
                1000,
                Serializer::with_writer(FailedWriter(fail_write)),
                emitted.clone(),
            );
            assert!(finish_output(
                &mut seq,
                &mut Reader(Ok(3)),
                Some(heartbeat::Cursor::default()),
                &emitted
            )
            .is_err());
        }
    }
}
