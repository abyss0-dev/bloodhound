use anyhow::{Context, Result};
use aya::{
    maps::Array,
    programs::{kprobe::KProbeLinkId, trace_point::TracePointLinkId, KProbe, Lsm, RawTracePoint, TracePoint},
    Btf, EbpfLoader,
};
use log::{info, warn};

use bloodhound_common::*;

use crate::btf_offsets;
use crate::{cli::Cli, deserializer::BehaviorEvent, usdt};

/// Loader-owned outcomes, not inferred from program presence or bitmap state.
#[derive(Debug, Default)]
pub struct AttachReport {
    pub probes: u32,
    pub keys: std::collections::BTreeMap<String, bool>,
}

impl AttachReport {
    pub(crate) fn record_tty_attach(
        &mut self,
        key: &str,
        attached: bool,
        tty_offsets: Option<&[u32; 3]>,
    ) {
        // Attached hooks cannot emit TTY events without classification offsets.
        self.keys
            .insert(key.into(), attached && tty_offsets.is_some());
    }
}

/// Capacity of the kernel ring buffer as created, in bytes.
pub fn ring_buffer_size(bpf: &aya::Ebpf) -> Result<u32> {
    match bpf.map("EVENTS") {
        Some(aya::maps::Map::RingBuf(data)) => Ok(data.info()?.max_entries()),
        _ => anyhow::bail!("EVENTS ring buffer not found in BPF object"),
    }
}

pub fn load_and_attach(
    args: &Cli,
    usdt_selections: &[usdt::Selection],
) -> Result<(
    aya::Ebpf,
    Vec<BehaviorEvent>,
    usdt::AttachmentLinks,
    AttachReport,
)> {
    usdt::validate_selections(usdt_selections)?;
    let mut report = AttachReport::default();
    // Resolve task_struct field offsets from the *running* kernel's BTF
    // and inject them as globals before load. Baking compile-time offsets
    // silently breaks tracing on any kernel build but the one the eBPF
    // object was compiled against (issue #37).
    let offsets = btf_offsets::resolve()?;

    // Load BPF programs with global variables set BEFORE loading
    let view_offsets = offsets.exec_view.unwrap_or([0; 14]);
    let view_supported = u32::from(offsets.exec_view.is_some());
    let fd_offsets = offsets.fd_ident.unwrap_or([0; 8]);
    let fd_supported = u32::from(offsets.fd_ident.is_some());
    let tty_offsets = offsets.tty.unwrap_or([0; 3]);
    let tty_supported = u32::from(offsets.tty.is_some());
    let mut bpf = EbpfLoader::new()
        .set_max_entries("EVENTS", args.ring_buffer_size)
        .set_global("OFF_FD_IDENT", &fd_offsets, true)
        .set_global("FD_IDENT_SUPPORTED", &fd_supported, true)
        .set_global("OFF_TTY", &tty_offsets, true)
        .set_global("TTY_SUPPORTED", &tty_supported, true)
        .set_global("OFF_EXEC_VIEW", &view_offsets, true)
        .set_global("EXEC_VIEW_SUPPORTED", &view_supported, true)
        .set_global("OFF_NS", &offsets.namespaces.offsets, true)
        .set_global("NS_SUPPORTED", &offsets.namespaces.supported, true)
        .set_global("TARGET_AUID", &args.uid, true)
        .set_global("DAEMON_PID", &std::process::id(), true)
        .set_global("OFF_LOGINUID", &offsets.loginuid, true)
        .set_global("OFF_SESSIONID", &offsets.sessionid, true)
        .set_global("OFF_TGID", &offsets.tgid, true)
        .set_global("OFF_PID", &offsets.pid, true)
        .set_global("OFF_GROUP_LEADER", &offsets.group_leader, true)
        .set_global("OFF_START_BOOTTIME", &offsets.start_boottime, true)
        .set_global("OFF_SIGNAL", &offsets.signal, true)
        .set_global("OFF_EXIT_CODE", &offsets.exit_code, true)
        .set_global("OFF_COMM", &offsets.comm, true)
        .set_global("OFF_SIGNAL_LIVE", &offsets.signal_live, true)
        .set_global(
            "OFF_SIGNAL_GROUP_EXIT_CODE",
            &offsets.signal_group_exit_code,
            true,
        )
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/bloodhound-ebpf/bpfel-unknown-none/release/bloodhound-ebpf"
        )))?;

    let actual_size = ring_buffer_size(&bpf)?;
    anyhow::ensure!(
        actual_size == args.ring_buffer_size,
        "EVENTS ring buffer size mismatch: configured {} bytes, kernel created {actual_size} bytes",
        args.ring_buffer_size
    );

    info!("BPF object loaded, setting up maps...");

    // Populate exclusion bitmap
    populate_exclusion_bitmap(&mut bpf)?;

    // Lifecycle identity is authoritative for every behavior event. Attach it
    // first so startup cannot enqueue clone/exec observations before the
    // corresponding process_fork edge is observable.
    info!("Attaching kernel process lifecycle hooks...");
    // Cleanup must be installed before any exit claim can be created.
    required(&mut report, "lifecycle", |report| {
        attach_raw_tracepoint(&mut bpf, "sched_process_free", "sched_process_free", report)?;
        attach_raw_tracepoint(&mut bpf, "sched_process_fork", "sched_process_fork", report)?;
        attach_raw_tracepoint(&mut bpf, "sched_process_exit", "sched_process_exit", report)
    })?;

    info!("Attaching non-enforcing signal observation...");
    required(&mut report, "signal", |report| {
        attach_raw_tracepoint(&mut bpf, "signal_generate", "signal_generate", report)
    })?;

    info!("Attaching Layer 2: execve tracepoints...");
    required(&mut report, "exec.execve", |report| {
        attach_syscall_pair(&mut bpf, "execve", "execve", report)
    })?;
    try_attach_syscall_pair(
        &mut bpf,
        "execveat",
        "execveat",
        "exec.execveat",
        &mut report,
    );

    info!("Attaching Layer 3 Tier 1: raw syscalls...");
    required(&mut report, "raw_syscalls", |report| {
        attach_tracepoint_pair(
            &mut bpf,
            "raw_syscalls",
            ("raw_sys_enter", "sys_enter"),
            ("raw_sys_exit", "sys_exit"),
            report,
        )
    })?;

    info!("Attaching Layer 3 Tier 2: rich syscalls...");
    let selected_tier2: Vec<_> = TIER2
        .iter()
        .filter(|syscall| syscall.dedup != Dedup::OptIn || args.enable_rich_sendfile)
        .collect();
    // Report the plan independently of attachment outcomes so readiness can be
    // checked for missing keys without maintaining another syscall list.
    let selected_keys: Vec<_> = selected_tier2
        .iter()
        .map(|syscall| format!("tier2.{}", syscall.name))
        .collect();
    eprintln!(
        "BPF Tier-2 selection: {}",
        serde_json::to_string(&selected_keys)?
    );
    for syscall in selected_tier2 {
        let name = syscall.name;
        if try_attach_syscall_pair(
            &mut bpf,
            name,
            syscall.tracepoint,
            &format!("tier2.{name}"),
            &mut report,
        ) {
            info!("  Attached: {}", name);
        }
    }

    let mut tier2_bitmap: Array<_, u32> = Array::try_from(bpf.map_mut("TIER2_BITMAP").unwrap())?;

    for nr in dedup_syscalls(&report) {
        tier2_bitmap.set(nr, 1, 0)?;
    }

    info!("Attaching Layer 1: TTY kprobes...");
    // ⚠️  Kernel 6.8+ changed `tty_write` to VFS `.write_iter` signature:
    //     tty_write(struct kiocb *iocb, struct iov_iter *from)
    //   The BPF code expects the old signature:
    //     (struct tty_struct *tty, const u8 *buf, size_t count)
    //   `pty_write` retains the old signature and is called for PTY writes,
    //   which is what SSH sessions use. For serial consoles, consider
    //   hooking `n_tty_write` instead.
    //   Similarly, `tty_read` → `n_tty_read` for the read path.
    let ok = try_attach_kprobe(&mut bpf, "tty_write_probe", "pty_write", &mut report);
    report.record_tty_attach("tty.write", ok, offsets.tty.as_ref());
    // A kretprobe registers returns only for calls entering after attachment.
    // Install it first so startup cannot create entries with no possible return;
    // if it fails, leave entry capture disabled rather than accumulate orphans.
    // Why leave the default: Aya 0.13.1 leaves maxactive at zero; Linux 6.8
    // register_kretprobe defaults to max(10, 2 * num_possible_cpus()) instances.
    // Blocked n_tty_read calls consume instances: excess concurrent reads miss
    // returns, and their saved entries later count as invocation_interrupted.
    // Aya's KProbe API exposes no maxactive override; do not imply full coverage.
    if let Err(e) = attach_tty_read_pair(
        &mut bpf,
        &mut report,
        offsets.tty.as_ref(),
        |bpf, report| attach_kprobe(bpf, "tty_read_ret_probe", "n_tty_read", report),
        |bpf, report| attach_kprobe(bpf, "tty_read_probe", "n_tty_read", report).map(|_| ()),
        |bpf, link| {
            let program: &mut KProbe = bpf.program_mut("tty_read_ret_probe").unwrap().try_into()?;
            program.detach(link)?;
            Ok(())
        },
    ) {
        warn!("Failed to attach TTY read pair: {e:#}");
    }

    if args.enable_lsm {
        info!("Attaching opt-in LSM hooks...");
        let btf = Btf::from_sys_fs();
        let lsm_hooks = [
            ("task_kill", "task_kill"),
            ("bpf_hook", "bpf"),
            ("ptrace_access_check", "ptrace_access_check"),
            ("file_open", "file_open"),
            ("inode_unlink", "inode_unlink"),
            ("inode_rename", "inode_rename"),
            ("task_fix_setuid", "task_fix_setuid"),
        ];
        for (prog_name, hook_name) in &lsm_hooks {
            let result = match &btf {
                Ok(btf) => attach_lsm(&mut bpf, prog_name, hook_name, btf, &mut report),
                Err(e) => Err(anyhow::anyhow!("LSM BTF unavailable: {e}")),
            };
            report
                .keys
                .insert(format!("lsm.{hook_name}"), result.is_ok());
            if let Err(e) = result {
                warn!("Failed to attach LSM hook {}: {}", hook_name, e);
            } else {
                info!("  Attached LSM: {}", hook_name);
            }
        }
    }

    let mut usdt_links = usdt::AttachmentLinks::default();
    let usdt_diagnostics = usdt_selections
        .iter()
        .flat_map(|selection| {
            usdt::attach_selected(&mut bpf, selection, &mut usdt_links, &mut report)
        })
        .collect();
    info!("BPF attachment attempts complete");
    Ok((bpf, usdt_diagnostics, usdt_links, report))
}

/// Only complete rich collectors may suppress raw capture. Layer 2 covers
/// exec successes and failures too; the kernel bitmap is the sole dedup owner.
fn dedup_syscalls(report: &AttachReport) -> Vec<u32> {
    TIER2
        .iter()
        .filter(|syscall| syscall.dedup != Dedup::NoDedup)
        .filter(|syscall| report.keys.get(&format!("tier2.{}", syscall.name)) == Some(&true))
        .map(|syscall| syscall.nr)
        .chain(
            EXEC_DEDUP
                .iter()
                .copied()
                .filter(|(_, key)| report.keys.get(*key) == Some(&true))
                .map(|(nr, _)| nr),
        )
        .map(|nr| u32::try_from(nr).expect("syscall number fits u32"))
        .collect()
}

fn required(
    report: &mut AttachReport,
    key: &str,
    attach: impl FnOnce(&mut AttachReport) -> Result<()>,
) -> Result<()> {
    attach(report).with_context(|| format!("required collector {key}"))?;
    report.keys.insert(key.into(), true);
    Ok(())
}

fn attach_raw_tracepoint(
    bpf: &mut aya::Ebpf,
    prog_name: &str,
    name: &str,
    report: &mut AttachReport,
) -> Result<()> {
    let program: &mut RawTracePoint = bpf
        .program_mut(prog_name)
        .context(format!("program {prog_name} not found"))?
        .try_into()?;
    program.load()?;
    program.attach(name)?;
    report.probes += 1;
    Ok(())
}

fn populate_exclusion_bitmap(bpf: &mut aya::Ebpf) -> Result<()> {
    let mut bitmap: Array<_, u32> = Array::try_from(bpf.map_mut("EXCLUSION_BITMAP").unwrap())?;
    for nr in EXCLUDED_SYSCALLS {
        if (*nr as u32) < BITMAP_SIZE as u32 {
            bitmap.set(*nr as u32, 1, 0)?;
        }
    }
    Ok(())
}

fn attach_tracepoint_pair(
    bpf: &mut aya::Ebpf,
    category: &str,
    enter: (&str, &str),
    exit: (&str, &str),
    report: &mut AttachReport,
) -> Result<()> {
    // Install the consumer before the producer: an enter captured before its
    // exit hook exists can survive until task exit and falsely report an
    // invocation_interrupted collection loss (notably for openat).
    attach_pair(
        bpf,
        report,
        |bpf, report| attach_tracepoint(bpf, exit.0, category, exit.1, report),
        |bpf, report| attach_tracepoint(bpf, enter.0, category, enter.1, report).map(|_| ()),
        |bpf, exit_link| {
            let program: &mut TracePoint = bpf.program_mut(exit.0).unwrap().try_into()?;
            program.detach(exit_link)?;
            Ok(())
        },
    )
}

// Keep the rollback transaction testable without loading BPF or requiring root.
fn attach_pair<B, L>(
    backend: &mut B,
    report: &mut AttachReport,
    attach_exit: impl FnOnce(&mut B, &mut AttachReport) -> Result<L>,
    attach_enter: impl FnOnce(&mut B, &mut AttachReport) -> Result<()>,
    detach_exit: impl FnOnce(&mut B, L) -> Result<()>,
) -> Result<()> {
    let exit_link = attach_exit(backend, report)?;
    if let Err(error) = attach_enter(backend, report) {
        detach_exit(backend, exit_link)
            .context("rolling back exit hook after enter attachment failed")?;
        report.probes -= 1;
        return Err(error);
    }
    Ok(())
}

fn attach_syscall_pair(
    bpf: &mut aya::Ebpf,
    name: &str,
    tracepoint_name: &str,
    report: &mut AttachReport,
) -> Result<()> {
    let enter = format!("sys_enter_{name}");
    let exit = format!("sys_exit_{name}");
    let enter_tp = format!("sys_enter_{tracepoint_name}");
    let exit_tp = format!("sys_exit_{tracepoint_name}");
    attach_tracepoint_pair(
        bpf,
        "syscalls",
        (&enter, &enter_tp),
        (&exit, &exit_tp),
        report,
    )
}

fn attach_tracepoint(
    bpf: &mut aya::Ebpf,
    prog_name: &str,
    category: &str,
    name: &str,
    report: &mut AttachReport,
) -> Result<TracePointLinkId> {
    let program: &mut TracePoint = bpf
        .program_mut(prog_name)
        .context(format!("program {} not found", prog_name))?
        .try_into()?;
    program.load()?;
    let link = program.attach(category, name)?;
    report.probes += 1;
    Ok(link)
}

fn try_attach_syscall_pair(
    bpf: &mut aya::Ebpf,
    name: &str,
    tracepoint_name: &str,
    key: &str,
    report: &mut AttachReport,
) -> bool {
    let complete = match attach_syscall_pair(bpf, name, tracepoint_name, report) {
        Ok(()) => true,
        Err(e) => {
            // Optional collectors must not disappear silently when no log
            // filter is configured; readiness exposes failure, not its cause.
            eprintln!("Failed to attach syscall pair {name}: {e:#}");
            false
        }
    };
    report.keys.insert(key.into(), complete);
    complete
}

fn attach_tty_read_pair<B, L>(
    backend: &mut B,
    report: &mut AttachReport,
    tty_offsets: Option<&[u32; 3]>,
    attach_exit: impl FnOnce(&mut B, &mut AttachReport) -> Result<L>,
    attach_enter: impl FnOnce(&mut B, &mut AttachReport) -> Result<()>,
    detach_exit: impl FnOnce(&mut B, L) -> Result<()>,
) -> Result<()> {
    let result = attach_pair(backend, report, attach_exit, attach_enter, detach_exit);
    for key in ["tty.read_ret", "tty.read"] {
        report.record_tty_attach(key, result.is_ok(), tty_offsets);
    }
    result
}

fn attach_kprobe(
    bpf: &mut aya::Ebpf,
    prog_name: &str,
    fn_name: &str,
    report: &mut AttachReport,
) -> Result<KProbeLinkId> {
    let program: &mut KProbe = bpf
        .program_mut(prog_name)
        .context(format!("program {} not found", prog_name))?
        .try_into()?;
    program.load()?;
    let link = program.attach(fn_name, 0)?;
    report.probes += 1;
    Ok(link)
}

fn try_attach_kprobe(
    bpf: &mut aya::Ebpf,
    prog_name: &str,
    fn_name: &str,
    report: &mut AttachReport,
) -> bool {
    match attach_kprobe(bpf, prog_name, fn_name, report) {
        Ok(_) => {
            info!("  Attached kprobe: {}", fn_name);
            true
        }
        Err(e) => {
            warn!("Failed to attach kprobe {}: {}", fn_name, e);
            false
        }
    }
}

fn attach_lsm(
    bpf: &mut aya::Ebpf,
    prog_name: &str,
    hook_name: &str,
    btf: &Btf,
    report: &mut AttachReport,
) -> Result<()> {
    let program: &mut Lsm = bpf
        .program_mut(prog_name)
        .context(format!("LSM program {} not found", prog_name))?
        .try_into()?;
    program.load(hook_name, btf)?;
    program.attach()?;
    report.probes += 1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unselected_keys_stay_absent() {
        let report = AttachReport::default();
        for unselected in [
            "tier2.sendfile",
            "tier2.splice",
            "lsm.bpf",
            "usdt.unselected",
        ] {
            assert!(!report.keys.contains_key(unselected));
        }
    }

    #[test]
    fn bitmap_follows_complete_collectors_including_layer2_exec() {
        let mut report = AttachReport::default();
        assert!(dedup_syscalls(&report).is_empty());
        for complete in [false, true] {
            for key in ["exec.execve", "exec.execveat"] {
                report.keys.insert(key.into(), complete);
            }
            let numbers = dedup_syscalls(&report);
            assert_eq!(numbers.contains(&(NR_EXECVE as u32)), complete);
            assert!(!numbers.contains(&(NR_EXECVEAT as u32)));
        }
        for syscall in TIER2 {
            let key = format!("tier2.{}", syscall.name);
            report.keys.insert(key.clone(), false);
            assert!(!dedup_syscalls(&report).contains(&(syscall.nr as u32)));
            report.keys.insert(key, true);
            assert_eq!(
                dedup_syscalls(&report).contains(&(syscall.nr as u32)),
                syscall.dedup != Dedup::NoDedup
            );
        }
    }

    #[test]
    fn tty_entry_failure_rolls_back_return_and_both_readiness_keys() {
        let mut report = AttachReport { probes: 2, ..AttachReport::default() };
        let mut return_attached = false;
        let result = attach_tty_read_pair(
            &mut return_attached,
            &mut report,
            Some(&[0; 3]),
            |attached, report| {
                *attached = true;
                report.probes += 1;
                Ok(42)
            },
            |attached, _| {
                assert!(*attached, "return must attach before entry");
                anyhow::bail!("injected entry attach failure")
            },
            |attached, link| {
                assert_eq!(link, 42);
                assert!(*attached);
                *attached = false;
                Ok(())
            },
        );
        assert!(result.unwrap_err().to_string().contains("injected entry"));
        assert!(!return_attached);
        assert_eq!(report.probes, 2);
        assert_eq!(report.keys.get("tty.read_ret"), Some(&false));
        assert_eq!(report.keys.get("tty.read"), Some(&false));
    }

    #[test]
    fn required_failure_aborts_without_claiming_availability() {
        let mut report = AttachReport {
            probes: 2,
            ..AttachReport::default()
        };
        let mut exit_attached = false;
        let startup: Result<()> = (|| {
            required(&mut report, "exec.execve", |report| {
                attach_pair(
                    &mut exit_attached,
                    report,
                    |attached, report| {
                        assert!(!*attached);
                        *attached = true;
                        report.probes += 1;
                        Ok(42)
                    },
                    |attached, _| {
                        assert!(*attached, "exit must attach before enter");
                        anyhow::bail!("injected enter attach failure")
                    },
                    |attached, link| {
                        assert_eq!(link, 42);
                        assert!(*attached);
                        *attached = false;
                        Ok(())
                    },
                )
            })?;
            panic!("failed required collector must abort startup");
        })();
        assert!(startup.unwrap_err().to_string().contains("exec.execve"));
        assert!(!exit_attached, "failed pair must detach its exit hook");
        assert_eq!(report.probes, 2, "rollback restores existing probe count");
        assert!(!report.keys.contains_key("exec.execve"));
        required(&mut report, "signal", |report| {
            report.probes += 1;
            Ok(())
        })
        .unwrap();
        assert!(report.keys["signal"]);
        assert_eq!(report.probes, 3);
    }
}
