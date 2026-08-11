//! Bounded userspace completion of the kernel lifecycle stream.
//!
//! The eBPF lifecycle hooks emit process_start/fork/exit with a stable
//! `(tgid, group_leader.start_boottime_ns)` reference. This synthesizer only
//! supplies `process_start` for a process that predates tracer attachment and
//! is first encountered through another event. It never infers fork or exit
//! from raw syscalls.

use std::collections::HashMap;

use serde_json::json;

use crate::deserializer::{BehaviorEvent, EventHeaderJson, EventTypeJson, ProcessRefJson};

pub struct LifecycleSynthesizer {
    active: HashMap<u32, ProcessRefJson>,
}

impl LifecycleSynthesizer {
    pub fn new() -> Self {
        Self {
            active: HashMap::new(),
        }
    }

    /// Emit a process_start before the first observed event for a process that
    /// existed before the kernel fork hook was attached.
    pub fn before(&mut self, event: &BehaviorEvent) -> Vec<BehaviorEvent> {
        let Some(process_ref) = event.header.process_ref else {
            return Vec::new();
        };

        if event.event.event_type == "LIFECYCLE" && event.event.name == "process_start" {
            self.active.insert(process_ref.tgid, process_ref);
            return Vec::new();
        }

        if self.active.get(&process_ref.tgid) == Some(&process_ref) {
            return Vec::new();
        }
        self.active.insert(process_ref.tgid, process_ref);
        vec![make_process_start(event, process_ref)]
    }

    /// Kernel hooks already emitted fork/exit. Userspace only releases its
    /// bounded active-process entry after the matching whole-group exit.
    pub fn after(&mut self, event: &BehaviorEvent) -> Vec<BehaviorEvent> {
        if event.event.event_type == "LIFECYCLE" && event.event.name == "process_exit" {
            if let Some(process_ref) = event.header.process_ref {
                if self.active.get(&process_ref.tgid) == Some(&process_ref) {
                    self.active.remove(&process_ref.tgid);
                }
            }
        }
        Vec::new()
    }
}

fn make_process_start(triggering: &BehaviorEvent, process_ref: ProcessRefJson) -> BehaviorEvent {
    BehaviorEvent {
        header: clone_header(&triggering.header),
        event: EventTypeJson {
            event_type: "LIFECYCLE".into(),
            name: "process_start".into(),
            layer: "behavior".into(),
        },
        proc: triggering.proc.clone(),
        args: Some(json!({ "process_ref": process_ref })),
        return_code: None,
    }
}

fn clone_header(header: &EventHeaderJson) -> EventHeaderJson {
    header.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(pid: u32, start_boottime_ns: u64, event_type: &str, name: &str) -> BehaviorEvent {
        BehaviorEvent {
            header: EventHeaderJson {
                timestamp: 1.0,
                auid: 1000,
                sessionid: 1,
                pid,
                ppid: None,
                comm: "t".to_string(),
                process_ref: Some(ProcessRefJson {
                    tgid: pid,
                    start_boottime_ns,
                }),
            },
            event: EventTypeJson {
                event_type: event_type.to_string(),
                name: name.to_string(),
                layer: "behavior".to_string(),
            },
            proc: None,
            args: None,
            return_code: None,
        }
    }

    #[test]
    fn pid_reuse_is_keyed_by_kernel_process_identity() {
        let mut life = LifecycleSynthesizer::new();
        assert_eq!(
            life.before(&event(42, 100, "TRACEPOINT", "openat")).len(),
            1
        );
        assert_eq!(life.before(&event(42, 100, "TRACEPOINT", "read")).len(), 0);
        assert_eq!(
            life.before(&event(42, 200, "TRACEPOINT", "openat")).len(),
            1
        );
    }

    #[test]
    fn short_lived_process_start_uses_header_identity_without_procfs() {
        let mut life = LifecycleSynthesizer::new();
        let start = life
            .before(&event(999_999_999, 123_456, "TRACEPOINT", "openat"))
            .remove(0);
        let args = start.args.unwrap();
        assert_eq!(args["process_ref"]["tgid"], 999_999_999);
        assert_eq!(args["process_ref"]["start_boottime_ns"], 123_456);
        assert!(args.get("partial").is_none());
    }

    #[test]
    fn kernel_start_is_not_duplicated() {
        let mut life = LifecycleSynthesizer::new();
        let start = event(42, 100, "LIFECYCLE", "process_start");
        assert!(life.before(&start).is_empty());
        assert!(life
            .before(&event(42, 100, "TRACEPOINT", "openat"))
            .is_empty());
    }

    #[test]
    fn raw_clone_and_exit_group_do_not_synthesize_lifecycle() {
        let mut life = LifecycleSynthesizer::new();
        assert!(life
            .after(&event(42, 100, "TRACEPOINT", "clone"))
            .is_empty());
        assert!(life.after(&event(42, 100, "SYSCALL", "231")).is_empty());
    }

    #[test]
    fn exit_releases_only_the_matching_process_instance() {
        let mut life = LifecycleSynthesizer::new();
        let first = event(42, 100, "TRACEPOINT", "openat");
        life.before(&first);
        life.after(&event(42, 200, "LIFECYCLE", "process_exit"));
        assert!(life.before(&first).is_empty());
        life.after(&event(42, 100, "LIFECYCLE", "process_exit"));
        assert_eq!(life.before(&first).len(), 1);
    }

    #[test]
    fn event_without_process_identity_is_not_given_a_provisional_pid_identity() {
        let mut life = LifecycleSynthesizer::new();
        let mut ev = event(42, 100, "TRACEPOINT", "openat");
        ev.header.process_ref = None;
        assert!(life.before(&ev).is_empty());
    }
}
