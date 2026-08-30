//! The single admission and serialization path for BehaviorEvent output.

use anyhow::Result;
use serde_json::json;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::clock::monotonic_now_ns;
use crate::deserializer::{self, BehaviorEvent, EventHeaderJson, EventTypeJson};
use crate::enricher;
use crate::lifecycle::LifecycleSynthesizer;
use crate::packet_correlator::PacketCorrelator;
use crate::serializer::Serializer;

/// One item successfully admitted to Bloodhound's bounded output sequencer.
///
/// Tokio's bounded MPSC channel defines cross-producer admission order and
/// preserves FIFO for each producer. This enum deliberately carries raw BPF
/// records as well as synthesized events so neither can bypass that order.
pub enum SequencedInput {
    Raw(Vec<u8>),
    Synthesized(Box<BehaviorEvent>),
}

pub struct Sequencer<W: Write> {
    output: Serializer<W>,
    correlator: PacketCorrelator,
    lifecycle: LifecycleSynthesizer,
    events_emitted: Arc<AtomicU64>,
    deserialize_rejections: u64,
}

impl<W: Write> Sequencer<W> {
    pub fn new(target_auid: u32, output: Serializer<W>, events_emitted: Arc<AtomicU64>) -> Self {
        Self {
            output,
            correlator: PacketCorrelator::new(target_auid),
            lifecycle: LifecycleSynthesizer::new(),
            events_emitted,
            deserialize_rejections: 0,
        }
    }

    pub fn accept(&mut self, input: SequencedInput) -> Result<()> {
        match input {
            SequencedInput::Raw(raw) => self.accept_raw(&raw),
            SequencedInput::Synthesized(event) => self.write(&event),
        }
    }

    fn accept_raw(&mut self, raw: &[u8]) -> Result<()> {
        let decoded = match deserializer::deserialize_with_authority(raw) {
            Ok(event) => event,
            Err(error) => {
                self.deserialize_rejections = self.deserialize_rejections.saturating_add(1);
                eprintln!("Failed to deserialize event: {error}");
                let diagnostic = deserialize_rejection_diagnostic(self.deserialize_rejections);
                return self.write(&diagnostic);
            }
        };
        let mut event = decoded.event;

        enricher::enrich(&mut event);
        if event.event.event_type == "PACKET" {
            self.correlator.correlate(&mut event);
        }
        if event.event.name == "connect" || event.event.name == "bind" {
            self.correlator.record_socket(&event);
        }

        for precursor in self
            .lifecycle
            .before_observation(&event, decoded.lifecycle_seed_authority)
        {
            self.write(&precursor)?;
        }
        self.write(&event)?;
        for followup in self.lifecycle.after(&event) {
            self.write(&followup)?;
        }
        Ok(())
    }

    fn write(&mut self, event: &BehaviorEvent) -> Result<()> {
        self.output.write_event(event)?;
        self.events_emitted.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.output.flush()?;
        Ok(())
    }
}

fn deserialize_rejection_diagnostic(total: u64) -> BehaviorEvent {
    BehaviorEvent {
        header: EventHeaderJson {
            timestamp: monotonic_now_ns(),
            auid: 0,
            sessionid: 0,
            pid: 0,
            ppid: None,
            comm: String::new(),
            process_ref: None,
        },
        event: EventTypeJson {
            event_type: "DIAGNOSTIC".into(),
            name: "stream.health".into(),
            layer: "behavior".into(),
        },
        proc: None,
        args: Some(json!({
            "reason_code": "deserialize_rejected",
            "rejection_count_delta": 1,
            "rejection_count_total": total,
            "run_prefix_incomplete": true,
        })),
        return_code: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloodhound_common::{EventHeader, EventKind, RawSyscallPayload};

    fn as_bytes<T>(value: &T) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
        }
    }

    fn raw_syscall(timestamp: u64, syscall_nr: u64) -> Vec<u8> {
        let header = EventHeader {
            kind: EventKind::RawSyscall as u8,
            _pad: [0; 3],
            timestamp_ns: timestamp,
            auid: 1000,
            sessionid: 7,
            pid: 42,
            ppid: 1,
            process_start_boottime_ns: 99,
            comm: {
                let mut comm = [0; 16];
                comm[..4].copy_from_slice(b"test");
                comm
            },
        };
        let payload = RawSyscallPayload {
            syscall_nr,
            args: [0; 6],
            return_code: 0,
        };
        [as_bytes(&header), as_bytes(&payload)].concat()
    }

    fn synthesized(name: &str, timestamp: u64) -> BehaviorEvent {
        BehaviorEvent {
            header: EventHeaderJson {
                timestamp,
                auid: 0,
                sessionid: 0,
                pid: 0,
                ppid: None,
                comm: String::new(),
                process_ref: None,
            },
            event: EventTypeJson {
                event_type: "DIAGNOSTIC".into(),
                name: name.into(),
                layer: "behavior".into(),
            },
            proc: None,
            args: None,
            return_code: None,
        }
    }

    #[tokio::test]
    async fn one_writer_preserves_admission_order_and_reports_rejections_in_band() {
        let mut bytes = Vec::new();
        let emitted = Arc::new(AtomicU64::new(0));
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let synthesized_tx = tx.clone();
        let mut heartbeat = synthesized("heartbeat", 1);
        heartbeat.event.event_type = "HEARTBEAT".into();
        synthesized_tx
            .send(SequencedInput::Synthesized(Box::new(heartbeat)))
            .await
            .unwrap();
        tx.send(SequencedInput::Raw(raw_syscall(2, 999)))
            .await
            .unwrap();
        tx.send(SequencedInput::Raw(vec![0xff])).await.unwrap();
        tx.send(SequencedInput::Raw(raw_syscall(4, 998)))
            .await
            .unwrap();
        synthesized_tx
            .send(SequencedInput::Synthesized(Box::new(synthesized("last", 5))))
            .await
            .unwrap();
        drop(synthesized_tx);
        drop(tx);
        {
            let serializer = Serializer::with_writer(&mut bytes);
            let mut sequencer = Sequencer::new(1000, serializer, emitted.clone());
            while let Some(input) = rx.recv().await {
                sequencer.accept(input).unwrap();
            }
            sequencer.flush().unwrap();
        }

        let events: Vec<serde_json::Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let names: Vec<&str> = events
            .iter()
            .map(|event| event["event"]["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "heartbeat",
                "process_start",
                "999",
                "stream.health",
                "998",
                "last"
            ]
        );
        assert_eq!(events[3]["args"]["reason_code"], "deserialize_rejected");
        assert_eq!(events[3]["args"]["rejection_count_total"], 1);
        assert_eq!(emitted.load(Ordering::Relaxed), events.len() as u64);
    }

    #[test]
    fn every_rejection_advances_the_cumulative_count() {
        let mut bytes = Vec::new();
        {
            let serializer = Serializer::with_writer(&mut bytes);
            let mut sequencer = Sequencer::new(1000, serializer, Arc::new(AtomicU64::new(0)));
            sequencer.accept(SequencedInput::Raw(vec![])).unwrap();
            sequencer.accept(SequencedInput::Raw(vec![0xff])).unwrap();
            sequencer.flush().unwrap();
        }
        let events: Vec<serde_json::Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events[0]["args"]["rejection_count_total"], 1);
        assert_eq!(events[1]["args"]["rejection_count_total"], 2);
    }

    #[test]
    fn new_process_sequencer_resets_the_rejection_counter() {
        fn first_rejection_total() -> u64 {
            let mut bytes = Vec::new();
            {
                let serializer = Serializer::with_writer(&mut bytes);
                let mut sequencer =
                    Sequencer::new(1000, serializer, Arc::new(AtomicU64::new(0)));
                sequencer.accept(SequencedInput::Raw(vec![])).unwrap();
                sequencer.flush().unwrap();
            }
            let event: serde_json::Value =
                serde_json::from_slice(bytes.split(|byte| *byte == b'\n').next().unwrap()).unwrap();
            event["args"]["rejection_count_total"].as_u64().unwrap()
        }

        assert_eq!(first_rejection_total(), 1);
        assert_eq!(first_rejection_total(), 1);
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "downstream closed",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn stdout_failure_is_not_swallowed() {
        let serializer = Serializer::with_writer(FailingWriter);
        let mut sequencer = Sequencer::new(1000, serializer, Arc::new(AtomicU64::new(0)));
        let error = sequencer
            .accept(SequencedInput::Synthesized(Box::new(synthesized("event", 1))))
            .unwrap_err();
        assert!(error.to_string().contains("downstream closed"));
    }

    #[tokio::test]
    async fn bounded_channel_applies_userspace_backpressure() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        tx.try_send(SequencedInput::Synthesized(Box::new(synthesized("first", 1))))
            .unwrap();
        let error = tx
            .try_send(SequencedInput::Synthesized(Box::new(synthesized("second", 2))))
            .unwrap_err();
        assert!(matches!(
            error,
            tokio::sync::mpsc::error::TrySendError::Full(_)
        ));
    }
}
