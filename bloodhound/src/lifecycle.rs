//! Bounded userspace completion of the kernel lifecycle stream.
//!
//! The eBPF lifecycle hooks emit process_start/fork/exit with a stable
//! `(tgid, group_leader.start_boottime_ns)` reference. This synthesizer only
//! supplies `process_start` for a process that predates tracer attachment and
//! is first encountered through another event. It never infers fork or exit
//! from raw syscalls.

use std::collections::{HashMap, HashSet};

use serde_json::json;

use crate::deserializer::{
    process_start_args, BehaviorEvent, DecodedBehaviorEvent, EventClass, EventHeaderJson,
    EventTypeJson, IdentityDiagnosticSource, IdentityGap, Layer, LifecycleMarker,
    LifecycleSeedAuthority, ProcessRefJson,
};

pub struct LifecycleSynthesizer {
    active: HashMap<u32, ProcessRefJson>,
    identity_diagnostics: HashSet<IdentityDiagnosticSource>,
}

impl LifecycleSynthesizer {
    pub fn new() -> Self {
        Self {
            active: HashMap::new(),
            identity_diagnostics: HashSet::new(),
        }
    }

    /// Emit a process_start before the first observed event for a process that
    /// existed before the kernel fork hook was attached.
    pub fn before_observation(&mut self, decoded: &DecodedBehaviorEvent) -> Vec<BehaviorEvent> {
        let event = &decoded.event;
        let mut emitted = Vec::new();
        if let Some(gap) = decoded.identity_gap {
            if self.identity_diagnostics.insert(gap.source) {
                emitted.push(make_identity_diagnostic(event, gap));
            }
        }

        if decoded.lifecycle_seed_authority == LifecycleSeedAuthority::NonAuthoritative {
            return emitted;
        }

        let Some(process_ref) = event.header.process_ref else {
            return emitted;
        };

        if decoded.marker == Some(LifecycleMarker::Start) {
            self.active.insert(process_ref.tgid, process_ref);
            return emitted;
        }

        if self.active.get(&process_ref.tgid) == Some(&process_ref) {
            return emitted;
        }
        self.active.insert(process_ref.tgid, process_ref);
        emitted.push(make_process_start(event, process_ref));
        emitted
    }

    #[cfg(test)]
    fn before(&mut self, decoded: &DecodedBehaviorEvent) -> Vec<BehaviorEvent> {
        self.before_observation(decoded)
    }

    /// Kernel hooks already emitted fork/exit. Userspace only releases its
    /// bounded active-process entry after the matching whole-group exit.
    pub fn after(&mut self, decoded: &DecodedBehaviorEvent) -> Vec<BehaviorEvent> {
        let event = &decoded.event;
        if decoded.marker == Some(LifecycleMarker::Exit) {
            if let Some(process_ref) = event.header.process_ref {
                if self.active.get(&process_ref.tgid) == Some(&process_ref) {
                    self.active.remove(&process_ref.tgid);
                }
            }
        }
        Vec::new()
    }
}

fn make_identity_diagnostic(triggering: &BehaviorEvent, gap: IdentityGap) -> BehaviorEvent {
    BehaviorEvent {
        header: EventHeaderJson {
            auid: triggering.header.auid,
            sessionid: triggering.header.sessionid,
            ..EventHeaderJson::unattributed(triggering.header.timestamp)
        },
        event: EventTypeJson {
            event_type: EventClass::Diagnostic,
            name: "process.identity".into(),
            layer: Layer::Behavior,
        },
        proc: None,
        args: Some(json!({
            "reason_code": "stable_process_ref_unavailable",
            "source": gap.source.as_str(),
            "observed_tgid": gap.observed_tgid,
        })),
        return_code: None,
    }
}

fn make_process_start(triggering: &BehaviorEvent, process_ref: ProcessRefJson) -> BehaviorEvent {
    BehaviorEvent {
        header: clone_header(&triggering.header),
        event: EventTypeJson {
            event_type: EventClass::Lifecycle,
            name: "process_start".into(),
            layer: Layer::Behavior,
        },
        proc: None,
        args: process_start_args(Some(process_ref)),
        return_code: None,
    }
}

/// The synthesized record keeps the triggering identity but is not a hook
/// moment of that task, so it never carries `tid` or a namespace snapshot.
fn clone_header(header: &EventHeaderJson) -> EventHeaderJson {
    EventHeaderJson {
        task: None,
        ..header.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deserializer::{NamespaceSnapshotJson, TaskContext};
    use bloodhound_common::{NsSnapshot, NS_SLOTS, NS_STATUS_COMPLETE};

    fn event(
        pid: u32,
        start_boottime_ns: u64,
        event_type: EventClass,
        name: &'static str,
    ) -> DecodedBehaviorEvent {
        DecodedBehaviorEvent {
            marker: None,
            identity_gap: None,
            lifecycle_seed_authority: LifecycleSeedAuthority::Authoritative,
            event: BehaviorEvent {
                header: EventHeaderJson {
                    timestamp: 1,
                    auid: 1000,
                    sessionid: 1,
                    pid,
                    ppid: None,
                    comm: "t".to_string(),
                    process_ref: Some(ProcessRefJson {
                        tgid: pid,
                        start_boottime_ns,
                    }),
                    task: Some(TaskContext {
                        tid: pid,
                        ns: NamespaceSnapshotJson::from(&NsSnapshot {
                            inum: [7; NS_SLOTS],
                            status: [NS_STATUS_COMPLETE; NS_SLOTS],
                            _pad: 0,
                        }),
                    }),
                },
                event: EventTypeJson {
                    event_type,
                    name: name.into(),
                    layer: Layer::Behavior,
                },
                proc: None,
                args: None,
                return_code: None,
            },
        }
    }

    fn marked(pid: u32, start_boottime_ns: u64, marker: LifecycleMarker) -> DecodedBehaviorEvent {
        let mut decoded = event(pid, start_boottime_ns, EventClass::Lifecycle, "opaque");
        decoded.marker = Some(marker);
        decoded
    }

    #[test]
    fn synthesized_lifecycle_bytes() {
        let mut life = LifecycleSynthesizer::new();
        let triggering = event(42, 100, EventClass::Tracepoint, "openat");
        let start = life.before(&triggering).remove(0);
        insta::assert_snapshot!("synthesized_process_start_bytes", serde_json::to_string(&start).unwrap());
        let mut unknown = event(43, 0, EventClass::Tracepoint, "openat");
        unknown.event.header.process_ref = None;
        unknown.identity_gap = Some(IdentityGap {
            source: IdentityDiagnosticSource::EventHeader,
            observed_tgid: 43,
        });
        let diagnostic = life.before(&unknown).remove(0);
        insta::assert_snapshot!("process_identity_bytes", serde_json::to_string(&diagnostic).unwrap());
    }

    #[test]
    fn synthesized_start_never_copies_proc_enrichment() {
        let mut triggering = event(std::process::id(), 100, EventClass::Tracepoint, "openat");
        triggering.event.proc = Some(crate::deserializer::ProcInfo {
            main_executable: Some("/untrusted/exe".into()),
            cwd: Some("/untrusted/cwd".into()),
            tty: Some("/dev/pts/42".into()),
        });
        let mut life = LifecycleSynthesizer::new();
        let start = life.before(&triggering).remove(0);
        assert!(start.proc.is_none());
        assert_eq!(
            start.header.process_ref,
            triggering.event.header.process_ref
        );
        assert!(start.header.task.is_none());
    }

    #[test]
    fn pid_reuse_is_keyed_by_kernel_process_identity() {
        let mut life = LifecycleSynthesizer::new();
        assert_eq!(
            life.before(&event(42, 100, EventClass::Tracepoint, "openat")).len(),
            1
        );
        assert_eq!(life.before(&event(42, 100, EventClass::Tracepoint, "read")).len(), 0);
        assert_eq!(
            life.before(&event(42, 200, EventClass::Tracepoint, "openat")).len(),
            1
        );
    }

    #[test]
    fn short_lived_process_start_uses_header_identity_without_procfs() {
        let mut life = LifecycleSynthesizer::new();
        let start = life
            .before(&event(999_999_999, 123_456, EventClass::Tracepoint, "openat"))
            .remove(0);
        let args = start.args.unwrap();
        assert_eq!(args["process_ref"]["tgid"], 999_999_999);
        assert_eq!(args["process_ref"]["start_boottime_ns"], 123_456);
        assert!(args.get("partial").is_none());
        // The bootstrap record is synthesized, not a hook moment of the task.
        assert_eq!(start.header.pid, 999_999_999);
        assert!(start.header.task.is_none());
    }

    #[test]
    fn kernel_start_is_not_duplicated() {
        let mut life = LifecycleSynthesizer::new();
        let start = marked(42, 100, LifecycleMarker::Start);
        assert!(life.before(&start).is_empty());
        assert!(life
            .before(&event(42, 100, EventClass::Tracepoint, "openat"))
            .is_empty());
    }

    #[test]
    fn raw_clone_and_exit_group_do_not_synthesize_lifecycle() {
        let mut life = LifecycleSynthesizer::new();
        assert!(life
            .after(&event(42, 100, EventClass::Tracepoint, "clone"))
            .is_empty());
        assert!(life.after(&event(42, 100, EventClass::Syscall, "231")).is_empty());
    }

    #[test]
    fn signal_generation_after_exit_does_not_resurrect_the_source() {
        let mut life = LifecycleSynthesizer::new();
        let start = marked(42, 100, LifecycleMarker::Start);
        assert!(life.before(&start).is_empty());

        let exit = marked(42, 100, LifecycleMarker::Exit);
        assert!(life.before(&exit).is_empty());
        assert!(life.after(&exit).is_empty());

        let mut generated = event(42, 100, EventClass::Tracepoint, "signal_generate");
        generated.lifecycle_seed_authority = LifecycleSeedAuthority::NonAuthoritative;
        assert!(life
            .before_observation(&generated)
            .is_empty());

        assert_eq!(
            life.before(&event(42, 100, EventClass::Tracepoint, "openat")).len(),
            1
        );
    }

    #[test]
    fn exit_releases_only_the_matching_process_instance() {
        let mut life = LifecycleSynthesizer::new();
        let first = event(42, 100, EventClass::Tracepoint, "openat");
        life.before(&first);
        life.after(&marked(42, 200, LifecycleMarker::Exit));
        assert!(life.before(&first).is_empty());
        life.after(&marked(42, 100, LifecycleMarker::Exit));
        assert_eq!(life.before(&first).len(), 1);
    }

    #[test]
    fn event_without_process_identity_is_not_given_a_provisional_pid_identity() {
        let mut life = LifecycleSynthesizer::new();
        let mut ev = event(42, 100, EventClass::Tracepoint, "openat");
        ev.event.header.process_ref = None;
        ev.identity_gap = Some(IdentityGap {
            source: IdentityDiagnosticSource::EventHeader,
            observed_tgid: 42,
        });
        let emitted = life.before(&ev);
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].event.event_type, EventClass::Diagnostic);
        assert_eq!(emitted[0].event.name, "process.identity");
        assert_eq!(emitted[0].args.as_ref().unwrap()["source"], "event_header");
        assert!(life.before(&ev).is_empty(), "diagnostic must be bounded");
    }

    #[test]
    fn unavailable_fork_parent_emits_one_bounded_diagnostic() {
        let mut life = LifecycleSynthesizer::new();
        let mut fork = event(42, 100, EventClass::Lifecycle, "process_fork");
        fork.event.header.process_ref = None;
        fork.identity_gap = Some(IdentityGap {
            source: IdentityDiagnosticSource::ForkParent,
            observed_tgid: 42,
        });

        let emitted = life.before(&fork);
        assert_eq!(emitted.len(), 1);
        assert_eq!(
            emitted[0].args.as_ref().unwrap()["source"],
            "process_fork.parent_ref"
        );
        assert!(life.before(&fork).is_empty(), "diagnostic must be bounded");
    }

    #[test]
    fn unavailable_task_kill_target_emits_one_bounded_diagnostic() {
        let mut life = LifecycleSynthesizer::new();
        let start = marked(42, 100, LifecycleMarker::Start);
        life.before(&start);
        let mut task_kill = event(42, 100, EventClass::Lsm, "task_kill");
        task_kill.identity_gap = Some(IdentityGap {
            source: IdentityDiagnosticSource::TaskKillTarget,
            observed_tgid: 43,
        });

        let emitted = life.before(&task_kill);
        assert_eq!(emitted.len(), 1);
        assert_eq!(
            emitted[0].args.as_ref().unwrap()["source"],
            "task_kill.target_ref"
        );
        assert!(
            life.before(&task_kill).is_empty(),
            "diagnostic must be bounded"
        );
    }

    #[test]
    fn typed_facts_not_json_names_control_lifecycle() {
        let mut life = LifecycleSynthesizer::new();
        let misleading = event(42, 100, EventClass::Lifecycle, "process_start");
        assert_eq!(
            life.before(&misleading).len(),
            1,
            "name alone is not a start marker"
        );
        let misleading_exit = event(42, 100, EventClass::Lifecycle, "process_exit");
        life.after(&misleading_exit);
        assert!(
            life.before(&misleading).is_empty(),
            "name alone must not release identity"
        );
        let syscall = event(42, 100, EventClass::Syscall, "task_kill");
        assert!(
            life.before(&syscall).is_empty(),
            "name alone is not a target gap"
        );
    }

    #[test]
    fn diagnostic_uses_typed_target_before_authority_and_start_checks() {
        let mut life = LifecycleSynthesizer::new();
        let mut decoded = event(42, 100, EventClass::Tracepoint, "opaque");
        decoded.identity_gap = Some(IdentityGap {
            source: IdentityDiagnosticSource::SignalGenerateTarget,
            observed_tgid: 43,
        });
        // Deliberately inconsistent JSON must not become a second fact source.
        decoded.event.args = Some(json!({ "target_pid": 999, "target_ref": {} }));
        decoded.lifecycle_seed_authority = LifecycleSeedAuthority::NonAuthoritative;
        let emitted = life.before(&decoded);
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].args.as_ref().unwrap()["observed_tgid"], 43);
        assert!(life.before(&decoded).is_empty());

        decoded.identity_gap = Some(IdentityGap {
            source: IdentityDiagnosticSource::TaskKillTarget,
            observed_tgid: 0,
        });
        decoded.lifecycle_seed_authority = LifecycleSeedAuthority::Authoritative;
        let emitted = life.before(&decoded);
        assert_eq!(emitted.len(), 2);
        assert_eq!(emitted[0].event.name, "process.identity");
        assert_eq!(emitted[0].args.as_ref().unwrap()["observed_tgid"], 0);
        assert_eq!(emitted[1].event.name, "process_start");
        assert!(life.before(&decoded).is_empty());
    }

    #[test]
    fn unavailable_signal_generate_target_emits_one_bounded_diagnostic() {
        let mut life = LifecycleSynthesizer::new();
        let start = marked(42, 100, LifecycleMarker::Start);
        life.before(&start);
        let mut signal = event(42, 100, EventClass::Tracepoint, "signal_generate");
        signal.identity_gap = Some(IdentityGap {
            source: IdentityDiagnosticSource::SignalGenerateTarget,
            observed_tgid: 43,
        });

        let emitted = life.before(&signal);
        assert_eq!(emitted.len(), 1);
        assert_eq!(
            emitted[0].args.as_ref().unwrap()["source"],
            "signal_generate.target_ref"
        );
        assert!(life.before(&signal).is_empty(), "diagnostic must be bounded");
    }
}
