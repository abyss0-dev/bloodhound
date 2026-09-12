mod bash_launch;
mod btf_offsets;
mod capture_health;
mod cli;
mod clock;
mod consumer;
mod deserializer;
mod drop_counter;
mod enricher;
mod heartbeat;
mod lifecycle;
mod loader;
mod packet_correlator;
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
    let (mut bpf, usdt_diagnostics, usdt_links) = loader::load_and_attach(&args, &usdt_selections)?;

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
    tokio::spawn(drop_counter::bridge_bpf_drop_counter(
        bridge_reader,
        drop_count.clone(),
        Duration::from_secs(1),
    ));

    let capture_map = bpf.take_map("OPENAT_FAILURES")
        .context("OPENAT_FAILURES map not found in BPF object")?;
    let capture_map: PerCpuArray<_, u64> = PerCpuArray::try_from(capture_map)?;
    let (capture_shutdown_tx, capture_shutdown_rx) = tokio::sync::oneshot::channel();
    let capture_handle = tokio::spawn(capture_health::monitor(
        capture_map, sequence_tx.clone(), capture_shutdown_rx,
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
    let heartbeat_interval = Duration::from_secs_f64(args.heartbeat_interval);
    let heartbeat_handle = tokio::spawn(async move {
        heartbeat::run_heartbeat(
            heartbeat_interval,
            heartbeat_drops,
            heartbeat_emitted,
            heartbeat_tx,
        )
        .await;
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
    drop(bpf);
    drop(usdt_links);
    heartbeat_handle.abort();
    let _ = capture_shutdown_tx.send(());
    let _ = consumer_shutdown_tx.send(());

    let deadline = tokio::time::Instant::now() + drain_timeout;
    let mut consumer_done = false;
    loop {
        tokio::select! {
            input = sequence_rx.recv() => {
                match input {
                    Some(input) => sequencer.accept(input)?,
                    None if consumer_done => break,
                    None => bail!("bounded event sequencer closed before consumer shutdown"),
                }
            }
            result = &mut consumer_handle, if !consumer_done => {
                result.context("ring buffer consumer task panicked during shutdown")??;
                consumer_done = true;
            }
            _ = tokio::time::sleep_until(deadline) => {
                bail!("incomplete shutdown: bounded event sequencer did not drain within 5 seconds");
            }
        }
    }

    capture_handle.await.context("openat collection monitor panicked")?;
    sequencer.flush()?;
    eprintln!("Shutdown complete");
    Ok(())
}
