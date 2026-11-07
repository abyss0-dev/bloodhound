//! Trusted, in-tree USDT collector registry.
//!
//! This module deliberately keeps the VM supplied configuration small.  A
//! configuration can select an ID compiled into this binary and turn it on or
//! off; it can never provide an ELF path, an offset, BPF object, probe name,
//! or a memory-read rule.  Those are all collector metadata below.

mod decode;
mod elf;
mod perf;
mod registry;

pub(crate) use decode::decode_payload;
pub(crate) use registry::{load_selection, selection_failure_diagnostic, validate_selections, Selection};

use std::os::fd::OwnedFd;

use anyhow::{bail, Context, Result};
use serde_json::json;

use crate::deserializer::BehaviorEvent;
use elf::verify_target;
use perf::attach_uprobe_with_semaphore;
use registry::{collector, diagnostic, ReasonCode};

/// Attach exactly the precompiled program selected by trusted configuration.
///
/// The target is resolved only after `verify_target`; we deliberately pass no
/// PID to Aya so a verified executable is observed for every process that
/// executes it. Links remain owned by Aya's `Ebpf` instance and are therefore
/// torn down on daemon shutdown.
/// Owns fd-based uprobe links whose reference counters are maintained by the
/// kernel. Dropping an fd detaches the link and decrements its USDT semaphore.
#[derive(Default)]
pub(crate) struct AttachmentLinks {
    semaphore_links: Vec<OwnedFd>,
}

impl AttachmentLinks {
    fn checkpoint(&self) -> usize {
        self.semaphore_links.len()
    }
    fn rollback(&mut self, checkpoint: usize) {
        self.semaphore_links.truncate(checkpoint);
    }
}

pub(crate) fn attach_selected(
    bpf: &mut aya::Ebpf,
    selection: &Selection,
    links: &mut AttachmentLinks,
    report: &mut crate::loader::AttachReport,
) -> Vec<BehaviorEvent> {
    if !selection.enabled {
        return vec![diagnostic(
            &selection.collector_id,
            ReasonCode::Disabled,
            None,
            crate::clock::monotonic_now_ns(),
        )];
    }
    report.keys.insert(format!("usdt.{}", selection.collector_id), false);
    let Some(metadata) = collector(&selection.collector_id) else {
        return vec![diagnostic(
            &selection.collector_id,
            ReasonCode::UnknownCollector,
            None,
            crate::clock::monotonic_now_ns(),
        )];
    };
    let target = match verify_target(metadata) {
        Ok(target) => target,
        Err(reason) => {
            return vec![diagnostic(
                metadata.id,
                reason,
                Some(json!({"target_path": metadata.target_path})),
                crate::clock::monotonic_now_ns(),
            )]
        }
    };
    let attach_result: Result<()> = (|| {
        use aya::programs::uprobe::UProbeLinkId;
        use aya::programs::UProbe;
        let semaphore_checkpoint = links.checkpoint();
        let mut aya_links: Vec<(String, UProbeLinkId)> = Vec::new();
        let attachment_path = target.attachment_path();
        if target.probes.len() > metadata.maximum_attach_points {
            bail!("collector has more static locations than its compiled attach-point programs");
        }
        for (attach_point_id, probe) in target.probes.iter().enumerate() {
            let program_name = metadata.program_name(attach_point_id);
            let program: &mut UProbe = bpf
                .program_mut(&program_name)
                .with_context(|| {
                    format!("USDT program {program_name} is not in the embedded object")
                })?
                .try_into()?;
            program.load()?;
            let attached: Result<()> = if let Some(semaphore_offset) = probe.semaphore_file_offset {
                attach_uprobe_with_semaphore(
                    program,
                    &attachment_path,
                    probe.file_offset,
                    semaphore_offset,
                )
                .map(|fd| {
                    links.semaphore_links.push(fd);
                })
            } else {
                program
                    .attach(None, probe.file_offset, &attachment_path, None)
                    .map(|link_id| {
                        aya_links.push((program_name.clone(), link_id));
                    })
                    .map_err(Into::into)
            };
            if let Err(error) = attached {
                for (attached_program, link_id) in aya_links.into_iter().rev() {
                    if let Some(program) = bpf.program_mut(&attached_program) {
                        if let Ok(program) = <&mut UProbe>::try_from(program) {
                            let _ = program.detach(link_id);
                        }
                    }
                }
                links.rollback(semaphore_checkpoint);
                return Err(error);
            }
        }
        Ok(())
    })();
    match attach_result {
        Ok(()) => {
            report.probes += target.probes.len() as u32;
            report.keys.insert(format!("usdt.{}", selection.collector_id), true);
            Vec::new()
        }
        Err(error) => {
            // Keep the externally emitted diagnostic bounded and stable, but
            // retain Aya's verifier/attach error in the service journal.  An
            // attach failure otherwise looks indistinguishable from a probe
            // that attached successfully but never fired.
            log::warn!(
                "USDT collector {} failed to attach at {}: {error:#}",
                metadata.id,
                metadata.target_path,
            );
            vec![diagnostic(
                metadata.id,
                ReasonCode::AttachFailed,
                Some(json!({"target_path": metadata.target_path})),
                crate::clock::monotonic_now_ns(),
            )]
        }
    }
}
