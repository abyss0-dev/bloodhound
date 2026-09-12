//! Openat collection loss precedes the ring buffer and has no precise placement
//! among operation events. Report a conservative incomplete run prefix.
use aya::maps::{MapData, PerCpuArray};
use serde_json::json;
use tokio::sync::{mpsc, oneshot};
use std::time::Duration;

use crate::clock::monotonic_now_ns;
use crate::deserializer::{BehaviorEvent, EventHeaderJson, EventTypeJson};
use crate::sequencer::SequencedInput;

const REASONS: [&str; 4] = [
    "entry_capture_failed", "entry_save_failed", "exit_capture_failed", "invocation_interrupted",
];

fn diagnostic(reason: &str, delta: Option<u64>, total: Option<u64>) -> BehaviorEvent {
    BehaviorEvent {
        header: EventHeaderJson {
            timestamp: monotonic_now_ns(), auid: 0, sessionid: 0, pid: 0,
            ppid: None, comm: String::new(), process_ref: None,
        },
        event: EventTypeJson {
            event_type: "DIAGNOSTIC".into(), name: "openat.collection".into(),
            layer: "behavior".into(),
        },
        proc: None,
        args: Some(json!({
            "reason_code": reason, "failure_count_delta": delta,
            "failure_count_total": total, "run_prefix_incomplete": true,
            "scope": "openat", "sampling": "userspace_poll",
        })),
        return_code: None,
    }
}

pub async fn monitor(
    map: PerCpuArray<MapData, u64>, tx: mpsc::Sender<SequencedInput>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let mut previous = [0u64; 4];
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    loop {
        let final_sample = tokio::select! {
            _ = ticker.tick() => false,
            _ = &mut shutdown => true,
        };
        for (index, reason) in REASONS.iter().enumerate() {
            let event = match map.get(&(index as u32), 0) {
                Ok(values) => {
                    let total: u64 = values.iter().sum();
                    let delta = total.saturating_sub(previous[index]);
                    previous[index] = total;
                    if delta == 0 { continue; }
                    diagnostic(reason, Some(delta), Some(total))
                }
                Err(_) => diagnostic("counter_read_failed", None, None),
            };
            if tx.send(SequencedInput::Synthesized(Box::new(event))).await.is_err() {
                return;
            }
        }
        if final_sample { return; }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_loss_has_its_own_scope_and_does_not_claim_event_placement() {
        let event = diagnostic("entry_save_failed", Some(2), Some(5));
        assert_eq!(event.event.name, "openat.collection");
        assert!(event.header.process_ref.is_none());
        let args = event.args.unwrap();
        assert_eq!(args["failure_count_delta"], 2);
        assert_eq!(args["failure_count_total"], 5);
        assert_eq!(args["run_prefix_incomplete"], true);
        assert!(args.get("drop_count_delta").is_none());
    }

    #[test]
    fn unreadable_counter_never_claims_zero_failures() {
        let args = diagnostic("counter_read_failed", None, None).args.unwrap();
        assert!(args["failure_count_total"].is_null());
        assert!(args["failure_count_delta"].is_null());
        assert_eq!(args["run_prefix_incomplete"], true);
    }
}
