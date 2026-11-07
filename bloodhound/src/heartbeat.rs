//! Periodic synthesised `HEARTBEAT` events.
//!
//! Issue #3: the in-kernel ring buffer can drop events under pressure,
//! and `DROP_COUNT` is a single polled counter with no placement in the
//! event stream. Downstream consumers therefore have no reliable way to
//! mark an interval as *undecidable* when drops occur — they either
//! trust every gap or treat every correlation as unsound.
//!
//! Keep the field contract in `docs/output-schema.md`, section
//! `event.type HEARTBEAT`, so consumers have one reference for interpreting
//! loss intervals rather than a second field list that can drift.
//!
//! The emission path is userspace-only. Events are pushed through an
//! mpsc channel and serialised by the main processing loop alongside
//! normal events so they share FIFO ordering and the same `Serializer`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::mpsc;
use tokio::time;

use crate::deserializer::{BehaviorEvent, EventClass, EventHeaderJson, EventTypeJson, Layer};
use crate::drop_counter::DropCounter;
use crate::sequencer::SequencedInput;

/// Shared counter incremented by the main loop each time an event is
/// serialised to stdout. The heartbeat task diff's this against its
/// previous sample to report `events_emitted_delta`.
pub type EventsEmittedCounter = Arc<AtomicU64>;

pub fn new_events_emitted_counter() -> EventsEmittedCounter {
    Arc::new(AtomicU64::new(0))
}

/// Samples represented by the last successfully admitted heartbeat.
/// Zero baselines include counts accumulated before the emitter starts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cursor {
    pub drops: u64,
    pub emitted: u64,
}

/// Emit periodic heartbeats until stopped or the receiver closes. Stop also
/// interrupts a backpressured send; only successful admission advances the
/// returned cursor. A zero interval returns None and disables the final
/// heartbeat as well.
pub async fn run_heartbeat(
    interval: Duration,
    drop_counter: DropCounter,
    events_emitted: EventsEmittedCounter,
    tx: mpsc::Sender<SequencedInput>,
    mut stop: tokio::sync::oneshot::Receiver<()>,
) -> Option<Cursor> {
    if interval.is_zero() {
        return None;
    }

    let mut ticker = time::interval(interval);
    // Skip the immediate first tick — `tokio::time::interval` fires at
    // t=0, which would produce a heartbeat before any events have been
    // counted.
    ticker.tick().await;

    let mut cursor = Cursor::default();

    loop {
        tokio::select! {
            biased;
            _ = &mut stop => return Some(cursor),
            _ = ticker.tick() => {}
        }

        let now_drops = drop_counter.load(Ordering::Relaxed);
        let now_emitted = events_emitted.load(Ordering::Relaxed);
        let event = build_heartbeat(
            now_drops.saturating_sub(cursor.drops),
            now_drops,
            now_emitted.saturating_sub(cursor.emitted),
            crate::clock::monotonic_now_ns(),
        );
        tokio::select! {
            biased;
            _ = &mut stop => return Some(cursor),
            result = tx.send(SequencedInput::Synthesized(Box::new(event))) => {
                if result.is_err() { return Some(cursor); }
                cursor = Cursor { drops: now_drops, emitted: now_emitted };
            }
        }
    }
}

/// Construct a single heartbeat event with the given deltas.
///
/// Kept separate from the emission loop so unit tests can exercise
/// the shape of the event without spinning up tokio.
pub fn build_heartbeat(drops_delta: u64, drops_total: u64, emitted_delta: u64, timestamp: u64) -> BehaviorEvent {
    let mut args = serde_json::Map::new();
    args.insert("drop_count_delta".into(), json!(drops_delta));
    args.insert("drop_count_total".into(), json!(drops_total));
    args.insert("events_emitted_delta".into(), json!(emitted_delta));
    if drops_total > 0 {
        args.insert("reason_code".into(), json!("ring_buffer_overflow"));
        args.insert("run_prefix_incomplete".into(), json!(true));
    }
    if drops_delta > 0 {
        args.insert("gap_detected".into(), json!(true));
    }

    BehaviorEvent {
        header: EventHeaderJson::unattributed(timestamp),
        event: EventTypeJson {
            event_type: EventClass::Heartbeat,
            name: "heartbeat".into(),
            layer: Layer::Behavior,
        },
        args: Some(serde_json::Value::Object(args)),
        return_code: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_bytes() {
        for (name, delta, total) in [("clean", 0, 0), ("gap", 3, 10), ("incomplete_prefix", 0, 10)] {
            insta::assert_snapshot!(format!("heartbeat_{name}_bytes"),
                serde_json::to_string(&build_heartbeat(delta, total, 100, 1_500_000_000)).unwrap());
        }
    }

    // ── event shape ──────────────────────────────────────────────────────

    #[test]
    fn heartbeat_has_expected_type_and_name() {
        let ev = build_heartbeat(0, 0, 0, 1);
        assert_eq!(ev.event.event_type, EventClass::Heartbeat);
        assert_eq!(ev.event.name, "heartbeat");
        assert_eq!(ev.event.layer, Layer::Behavior);
    }

    #[test]
    fn heartbeat_header_sentinels_signal_not_applicable() {
        let ev = build_heartbeat(0, 0, 0, 1);
        assert_eq!(ev.header.auid, 0);
        assert_eq!(ev.header.sessionid, 0);
        assert_eq!(ev.header.pid, 0);
        assert!(ev.header.ppid.is_none());
        assert_eq!(ev.header.comm, "");
    }

    #[test]
    fn zero_drops_omits_gap_flag() {
        let ev = build_heartbeat(0, 5, 100, 1);
        let args = ev.args.unwrap();
        assert_eq!(args["drop_count_delta"], 0);
        assert_eq!(args["drop_count_total"], 5);
        assert_eq!(args["events_emitted_delta"], 100);
        assert!(args.get("gap_detected").is_none());
    }

    #[test]
    fn nonzero_drops_sets_gap_flag() {
        let ev = build_heartbeat(3, 10, 100, 1);
        let args = ev.args.unwrap();
        assert_eq!(args["drop_count_delta"], 3);
        assert_eq!(args["gap_detected"], true);
        assert_eq!(args["reason_code"], "ring_buffer_overflow");
        assert_eq!(args["run_prefix_incomplete"], true);
    }

    #[test]
    fn clean_interval_does_not_repair_an_earlier_drop() {
        let ev = build_heartbeat(0, 10, 100, 1);
        let args = ev.args.unwrap();
        assert!(args.get("gap_detected").is_none());
        assert_eq!(args["reason_code"], "ring_buffer_overflow");
        assert_eq!(args["run_prefix_incomplete"], true);
    }

    #[test]
    fn new_process_run_starts_with_a_complete_prefix_and_reset_counter() {
        let ev = build_heartbeat(0, 0, 0, 1);
        let args = ev.args.unwrap();
        assert_eq!(args["drop_count_delta"], 0);
        assert_eq!(args["drop_count_total"], 0);
        assert!(args.get("reason_code").is_none());
        assert!(args.get("run_prefix_incomplete").is_none());
    }

    #[tokio::test]
    async fn stop_interrupts_full_send_without_advancing_cursor() {
        let (tx, mut rx) = mpsc::channel(1);
        tx.send(SequencedInput::Synthesized(Box::new(build_heartbeat(
            0, 0, 0, 1,
        ))))
        .await
        .unwrap();
        let drops = crate::drop_counter::new_counter();
        drops.store(7, Ordering::Relaxed);
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(run_heartbeat(
            Duration::from_millis(1),
            drops,
            new_events_emitted_counter(),
            tx,
            stopped,
        ));
        tokio::time::sleep(Duration::from_millis(20)).await;
        stop.send(()).unwrap();
        let cursor = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cursor, Some(Cursor::default()));
        assert!(rx.recv().await.is_some());
        assert!(rx.recv().await.is_none());
    }

    // ── emitter plumbing ─────────────────────────────────────────────────

    /// Zero interval must short-circuit the loop — downstream consumers
    /// that do not expect `HEARTBEAT` events opt out by setting this.
    #[tokio::test]
    async fn zero_interval_disables_emitter() {
        let drops = crate::drop_counter::new_counter();
        let emitted = new_events_emitted_counter();
        let (tx, mut rx) = mpsc::channel::<SequencedInput>(8);

        // Task should return immediately without sending anything.
        let (_stop, stopped) = tokio::sync::oneshot::channel();
        assert_eq!(
            run_heartbeat(Duration::ZERO, drops, emitted, tx, stopped).await,
            None
        );
        assert!(rx.try_recv().is_err());
    }

    /// Short real-time interval is enough to verify the loop does fire
    /// events without needing paused-time plumbing — the tick pacing is
    /// tokio's responsibility and not what this module needs to test.
    #[tokio::test]
    async fn emits_heartbeat_with_nonzero_deltas() {
        let drops = crate::drop_counter::new_counter();
        let emitted = new_events_emitted_counter();
        let (tx, mut rx) = mpsc::channel::<SequencedInput>(8);

        drops.fetch_add(3, Ordering::Relaxed);
        emitted.fetch_add(10, Ordering::Relaxed);

        let (stop, stopped) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(run_heartbeat(
            Duration::from_millis(50),
            drops.clone(),
            emitted.clone(),
            tx,
            stopped,
        ));

        let input = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("heartbeat did not arrive within expected window")
            .expect("channel closed unexpectedly");
        let SequencedInput::Synthesized(ev) = input else {
            panic!("heartbeat emitted a raw sequencer input");
        };

        assert_eq!(ev.event.event_type, EventClass::Heartbeat);
        let args = ev.args.unwrap();
        assert_eq!(args["drop_count_total"], 3);
        assert_eq!(args["drop_count_delta"], 3);
        assert_eq!(args["events_emitted_delta"], 10);
        stop.send(()).unwrap();
        assert_eq!(
            handle.await.unwrap(),
            Some(Cursor {
                drops: 3,
                emitted: 10
            })
        );
    }
}
