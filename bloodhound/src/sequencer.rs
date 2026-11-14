//! The single admission and serialization path for BehaviorEvent output.

use anyhow::Result;
use serde_json::json;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::clock::monotonic_now_ns;
use crate::deserializer::{self, BehaviorEvent, EventClass, EventHeaderJson, EventTypeJson, Layer};
use crate::lifecycle::LifecycleSynthesizer;
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
    lifecycle: LifecycleSynthesizer,
    events_emitted: Arc<AtomicU64>,
    deserialize_rejections: u64,
}

impl<W: Write> Sequencer<W> {
    pub fn new(output: Serializer<W>, events_emitted: Arc<AtomicU64>) -> Self {
        Self {
            output,
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
                let diagnostic = deserialize_rejection_diagnostic(self.deserialize_rejections, monotonic_now_ns());
                return self.write(&diagnostic);
            }
        };
        for precursor in self.lifecycle.before_observation(&decoded) {
            self.write(&precursor)?;
        }
        self.write(&decoded.event)?;
        self.lifecycle.release_exit(&decoded);
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

fn deserialize_rejection_diagnostic(total: u64, timestamp: u64) -> BehaviorEvent {
    BehaviorEvent {
        header: EventHeaderJson::unattributed(timestamp),
        event: EventTypeJson {
            event_type: EventClass::Diagnostic,
            name: "stream.health".into(),
            layer: Layer::Behavior,
        },
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

    #[test]
    fn stream_health_bytes() {
        insta::assert_snapshot!("stream_health_bytes", serde_json::to_string(
            &deserialize_rejection_diagnostic(3, 1_500_000_000)).unwrap());
    }

    fn as_bytes<T>(value: &T) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
        }
    }

    fn raw_syscall(timestamp: u64, syscall_nr: u64) -> Vec<u8> {
        raw_syscall_for_process(timestamp, syscall_nr, 42, 1)
    }

    fn raw_syscall_for_process(timestamp: u64, syscall_nr: u64, pid: u32, ppid: u32) -> Vec<u8> {
        let header = EventHeader {
            kind: EventKind::RawSyscall as u8,
            capture: bloodhound_common::HeaderCapture::default(),
            timestamp_ns: timestamp,
            auid: 1000,
            sessionid: 7,
            pid,
            ppid,
            process_start_boottime_ns: 99,
            comm: {
                let mut comm = [0; 16];
                comm[..4].copy_from_slice(b"test");
                comm
            },
            tid: 42,
            ns: Default::default(),
        };
        let payload = RawSyscallPayload {
            syscall_nr,
            args: [0; 6],
            return_code: 0,
        };
        [as_bytes(&header), as_bytes(&payload)].concat()
    }

    #[test]
    fn raw_lifecycle_and_identity_diagnostic_bytes() {
        use bloodhound_common::{
            LsmTaskKillPayload, ProcessExitPayload, ProcessForkPayload, SignalGeneratePayload,
        };

        // Reuse the synthetic wire header, not decoded BehaviorEvent fixtures.
        let wire = |kind: EventKind, timestamp, pid, payload: &[u8]| {
            let mut bytes = raw_syscall_for_process(timestamp, 999, pid, 1);
            bytes.truncate(std::mem::size_of::<EventHeader>());
            bytes[0] = kind as u8;
            bytes.extend_from_slice(payload);
            bytes
        };
        let fork = ProcessForkPayload {
            parent_tgid: 777, // The diagnostic must use header.pid, not this field.
            child_tgid: 43,
            parent_start_boottime_ns: 0,
            child_start_boottime_ns: 100,
            clone_flags: 0,
        };
        let records = [
            wire(EventKind::ProcessStart, 1, 42, &[]),
            raw_syscall(2, 999),
            wire(EventKind::ProcessExit, 3, 42, as_bytes(&ProcessExitPayload {
                raw_status: 0, _pad: 0,
            })),
            raw_syscall(4, 999),
            wire(EventKind::ProcessFork, 5, 42, as_bytes(&fork)),
            wire(EventKind::ProcessFork, 6, 42, as_bytes(&fork)),
            wire(EventKind::LsmTaskKill, 7, 42, as_bytes(&LsmTaskKillPayload {
                target_pid: 44, signal: 15, target_start_boottime_ns: 0,
                return_code: 0, _pad: 0,
            })),
            // A fresh subject makes accidental authoritative seeding visible.
            wire(EventKind::SignalGenerate, 8, 45, as_bytes(&SignalGeneratePayload {
                target_tgid: 46, signal: 15, target_start_boottime_ns: 0,
                group: 1, result: bloodhound_common::SIGNAL_RESULT_DELIVERED,
            })),
        ];
        let mut output = Vec::new();
        let emitted = Arc::new(AtomicU64::new(0));
        {
            let mut sequencer = Sequencer::new(
                Serializer::with_writer(&mut output), emitted.clone(),
            );
            for record in records {
                sequencer.accept(SequencedInput::Raw(record)).unwrap();
            }
            sequencer.flush().unwrap();
        }
        assert_eq!(output.last(), Some(&b'\n'));
        let encoded = String::from_utf8(output).unwrap();
        let events: Vec<serde_json::Value> = encoded.lines()
            .map(|line| serde_json::from_str(line).unwrap()).collect();
        assert_eq!(emitted.load(Ordering::Relaxed) as usize, events.len());
        let starts: Vec<_> = events.iter()
            .filter(|event| event["event"]["name"] == "process_start").collect();
        // One raw start and one synthesized after exit; neither syscall after
        // the raw start nor the non-authoritative signal adds another start.
        assert_eq!(starts.len(), 2);
        assert!(starts.iter().all(|event| event["header"]["pid"] == 42));
        let diagnostics: Vec<_> = events.iter()
            .filter(|event| event["event"]["name"] == "process.identity").collect();
        assert_eq!(diagnostics.len(), 3);
        assert_eq!(diagnostics[0]["args"]["source"], "process_fork.parent_ref");
        assert_eq!(diagnostics[1]["args"]["source"], "task_kill.target_ref");
        assert_eq!(diagnostics[2]["args"]["source"], "signal_generate.target_ref");
        assert_eq!(diagnostics[0]["args"]["observed_tgid"], 42);
        assert_eq!(diagnostics[1]["args"]["observed_tgid"], 44);
        assert_eq!(diagnostics[2]["args"]["observed_tgid"], 46);
        // Snapshot the serializer's exact bytes, retaining field order and LF.
        insta::assert_snapshot!("raw_lifecycle_and_identity_diagnostic_bytes", encoded);
    }

    fn process_events(pid: u32, ppid: u32, repeat: bool) -> Vec<serde_json::Value> {
        let mut bytes = Vec::new();
        {
            let mut sequencer = Sequencer::new(
                Serializer::with_writer(&mut bytes),
                Arc::new(AtomicU64::new(0)),
            );
            sequencer
                .accept(SequencedInput::Raw(raw_syscall_for_process(
                    1, 999, pid, ppid,
                )))
                .unwrap();
            if repeat {
                sequencer
                    .accept(SequencedInput::Raw(raw_syscall_for_process(
                        2, 999, pid, ppid,
                    )))
                    .unwrap();
            }
            sequencer.flush().unwrap();
        }
        String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn repeated_observations_stay_unenriched() {
        let events = process_events(std::process::id(), 0, true);
        assert_eq!(
            events
                .iter()
                .filter(|event| event["event"]["name"] == "process_start")
                .count(),
            1
        );
        for event in events {
            assert!(event["header"].get("ppid").is_none());
        }
    }

    fn synthesized(name: &'static str, timestamp: u64) -> BehaviorEvent {
        BehaviorEvent {
            header: EventHeaderJson::unattributed(timestamp),
            event: EventTypeJson {
                event_type: EventClass::Diagnostic,
                name: name.into(),
                layer: Layer::Behavior,
            },
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
        heartbeat.event.event_type = EventClass::Heartbeat;
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
            .send(SequencedInput::Synthesized(Box::new(synthesized(
                "last", 5,
            ))))
            .await
            .unwrap();
        drop(synthesized_tx);
        drop(tx);
        {
            let serializer = Serializer::with_writer(&mut bytes);
            let mut sequencer = Sequencer::new(serializer, emitted.clone());
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
            let mut sequencer = Sequencer::new(serializer, Arc::new(AtomicU64::new(0)));
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
                let mut sequencer = Sequencer::new(serializer, Arc::new(AtomicU64::new(0)));
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
        let mut sequencer = Sequencer::new(serializer, Arc::new(AtomicU64::new(0)));
        let error = sequencer
            .accept(SequencedInput::Synthesized(Box::new(synthesized(
                "event", 1,
            ))))
            .unwrap_err();
        assert!(error.to_string().contains("downstream closed"));
    }

    #[tokio::test]
    async fn bounded_channel_applies_userspace_backpressure() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        tx.try_send(SequencedInput::Synthesized(Box::new(synthesized(
            "first", 1,
        ))))
        .unwrap();
        let error = tx
            .try_send(SequencedInput::Synthesized(Box::new(synthesized(
                "second", 2,
            ))))
            .unwrap_err();
        assert!(matches!(
            error,
            tokio::sync::mpsc::error::TrySendError::Full(_)
        ));
    }
}
