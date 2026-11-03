use anyhow::{Context, Result};
use aya::{
    maps::Array,
    programs::{KProbe, Lsm, RawTracePoint, TracePoint},
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
    fn pair(&mut self, key: &str, enter: bool, exit: bool) -> bool {
        let complete = enter && exit;
        self.keys.insert(key.into(), complete);
        complete
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
    let mut report = AttachReport::default();
    // Resolve task_struct field offsets from the *running* kernel's BTF
    // and inject them as globals before load. Baking compile-time offsets
    // silently breaks tracing on any kernel build but the one the eBPF
    // object was compiled against (issue #37).
    let offsets = btf_offsets::resolve()?;

    // Load BPF programs with global variables set BEFORE loading
    let view_offsets = offsets.exec_view.unwrap_or([0; 14]);
    let view_supported = u32::from(offsets.exec_view.is_some());
    let mut bpf = EbpfLoader::new()
        .set_max_entries("EVENTS", args.ring_buffer_size)
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
        attach_tracepoint(
            &mut bpf,
            "sys_enter_execve",
            "syscalls",
            "sys_enter_execve",
            report,
        )?;
        attach_tracepoint(
            &mut bpf,
            "sys_exit_execve",
            "syscalls",
            "sys_exit_execve",
            report,
        )
    })?;
    let execveat_enter = try_attach_tracepoint(
        &mut bpf,
        "sys_enter_execveat",
        "syscalls",
        "sys_enter_execveat",
        &mut report,
    );
    let execveat_exit = try_attach_tracepoint(
        &mut bpf,
        "sys_exit_execveat",
        "syscalls",
        "sys_exit_execveat",
        &mut report,
    );

    report.pair("exec.execveat", execveat_enter, execveat_exit);

    info!("Attaching Layer 3 Tier 1: raw syscalls...");
    required(&mut report, "raw_syscalls", |report| {
        attach_tracepoint(
            &mut bpf,
            "raw_sys_enter",
            "raw_syscalls",
            "sys_enter",
            report,
        )?;
        attach_tracepoint(&mut bpf, "raw_sys_exit", "raw_syscalls", "sys_exit", report)
    })?;

    info!("Attaching Layer 3 Tier 2: rich syscalls...");
    let tier2_syscalls: &[(&str, u64)] = &[
        ("openat", NR_OPENAT),
        ("read", NR_READ),
        ("write", NR_WRITE),
        ("connect", NR_CONNECT),
        ("bind", NR_BIND),
        ("listen", NR_LISTEN),
        ("socket", NR_SOCKET),
        ("clone", NR_CLONE),
        ("clone3", NR_CLONE3),
        ("chdir", NR_CHDIR),
        ("fchdir", NR_FCHDIR),
        ("unlink", NR_UNLINK),
        ("unlinkat", NR_UNLINKAT),
        ("rename", NR_RENAME),
        ("renameat2", NR_RENAMEAT2),
        ("mkdir", NR_MKDIR),
        ("mkdirat", NR_MKDIRAT),
        ("rmdir", NR_RMDIR),
        ("symlink", NR_SYMLINK),
        ("symlinkat", NR_SYMLINKAT),
        ("link", NR_LINK),
        ("linkat", NR_LINKAT),
        ("chmod", NR_CHMOD),
        ("fchmod", NR_FCHMOD),
        ("fchmodat", NR_FCHMODAT),
        ("chown", NR_CHOWN),
        ("fchown", NR_FCHOWN),
        ("fchownat", NR_FCHOWNAT),
        ("truncate", NR_TRUNCATE),
        ("ftruncate", NR_FTRUNCATE),
        ("mount", NR_MOUNT),
        ("umount2", NR_UMOUNT2),
        ("sendto", NR_SENDTO),
        ("recvfrom", NR_RECVFROM),
        ("dup", NR_DUP),
        ("dup2", NR_DUP2),
        ("dup3", NR_DUP3),
        ("pread64", NR_PREAD64),
        ("pwrite64", NR_PWRITE64),
        ("readv", NR_READV),
        ("writev", NR_WRITEV),
        ("mmap", NR_MMAP),
    ];

    let mut successful_syscalls = Vec::new();

    for (name, nr) in tier2_syscalls {
        let enter_prog = format!("sys_enter_{}", name);
        let exit_prog = format!("sys_exit_{}", name);
        let enter_tp = format!("sys_enter_{}", name);
        let exit_tp = format!("sys_exit_{}", name);

        let enter_ok =
            try_attach_tracepoint(&mut bpf, &enter_prog, "syscalls", &enter_tp, &mut report);
        let exit_ok =
            try_attach_tracepoint(&mut bpf, &exit_prog, "syscalls", &exit_tp, &mut report);

        if report.pair(&format!("tier2.{name}"), enter_ok, exit_ok) {
            if (*nr as u32) < BITMAP_SIZE as u32 {
                successful_syscalls.push(*nr as u32);
            }
            info!("  Attached: {}", name);
        }
    }

    // fcntl rich extraction is conditional on cmd ∈ {F_DUPFD, F_DUPFD_CLOEXEC};
    // attach the tracepoints, but DO NOT register fcntl in TIER2_BITMAP, so
    // non-DUPFD fcntl commands remain visible via Tier 1 raw capture.
    let fcntl_enter = try_attach_tracepoint(
        &mut bpf,
        "sys_enter_fcntl",
        "syscalls",
        "sys_enter_fcntl",
        &mut report,
    );
    let fcntl_exit = try_attach_tracepoint(
        &mut bpf,
        "sys_exit_fcntl",
        "syscalls",
        "sys_exit_fcntl",
        &mut report,
    );

    report.pair("tier2.fcntl", fcntl_enter, fcntl_exit);

    // sendfile / splice rich extraction is opt-in (issue #9). When enabled,
    // attach both tracepoint pairs and register the syscall numbers in
    // TIER2_BITMAP so Tier 1 deduplicates. When disabled, the BPF programs
    // remain compiled in but unattached, and Tier 1 raw capture continues.
    if args.enable_rich_sendfile {
        let sf_enter = try_attach_tracepoint(
            &mut bpf,
            "sys_enter_sendfile",
            "syscalls",
            "sys_enter_sendfile",
            &mut report,
        );
        let sf_exit = try_attach_tracepoint(
            &mut bpf,
            "sys_exit_sendfile",
            "syscalls",
            "sys_exit_sendfile",
            &mut report,
        );
        let sf_ok = report.pair("tier2.sendfile", sf_enter, sf_exit);
        if sf_ok && (NR_SENDFILE as u32) < BITMAP_SIZE as u32 {
            successful_syscalls.push(NR_SENDFILE as u32);
            info!("  Attached: sendfile (opt-in via --enable-rich-sendfile)");
        }
        let sp_enter = try_attach_tracepoint(
            &mut bpf,
            "sys_enter_splice",
            "syscalls",
            "sys_enter_splice",
            &mut report,
        );
        let sp_exit = try_attach_tracepoint(
            &mut bpf,
            "sys_exit_splice",
            "syscalls",
            "sys_exit_splice",
            &mut report,
        );
        let sp_ok = report.pair("tier2.splice", sp_enter, sp_exit);
        if sp_ok && (NR_SPLICE as u32) < BITMAP_SIZE as u32 {
            successful_syscalls.push(NR_SPLICE as u32);
            info!("  Attached: splice (opt-in via --enable-rich-sendfile)");
        }
    }

    let mut tier2_bitmap: Array<_, u32> = Array::try_from(bpf.map_mut("TIER2_BITMAP").unwrap())?;

    for nr in successful_syscalls {
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
    report.keys.insert("tty.write".into(), ok);
    let ok = try_attach_kprobe(&mut bpf, "tty_read_probe", "n_tty_read", &mut report);
    report.keys.insert("tty.read".into(), ok);
    // kretprobe on n_tty_read: captures the bytes that were actually
    // written into the userspace buffer during the call. Without this
    // attach, only metadata (no `data` field) is emitted for tty_read.
    // Aya's KProbe wrapper handles both kprobe and kretprobe via the
    // `kind` discriminator set by the `#[kretprobe]` macro.
    let ok = try_attach_kprobe(&mut bpf, "tty_read_ret_probe", "n_tty_read", &mut report);
    report.keys.insert("tty.read_ret".into(), ok);

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
            let before = report.probes;
            let diagnostics =
                usdt::attach_selected(&mut bpf, selection, &mut usdt_links, &mut report);
            if selection.enabled {
                report.keys.insert(
                    format!("usdt.{}", selection.collector_id),
                    report.probes > before,
                );
            }
            diagnostics
        })
        .collect();
    info!("BPF attachment attempts complete");
    Ok((bpf, usdt_diagnostics, usdt_links, report))
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

fn attach_tracepoint(
    bpf: &mut aya::Ebpf,
    prog_name: &str,
    category: &str,
    name: &str,
    report: &mut AttachReport,
) -> Result<()> {
    let program: &mut TracePoint = bpf
        .program_mut(prog_name)
        .context(format!("program {} not found", prog_name))?
        .try_into()?;
    program.load()?;
    program.attach(category, name)?;
    report.probes += 1;
    Ok(())
}

fn try_attach_tracepoint(
    bpf: &mut aya::Ebpf,
    prog_name: &str,
    category: &str,
    name: &str,
    report: &mut AttachReport,
) -> bool {
    match attach_tracepoint(bpf, prog_name, category, name, report) {
        Ok(()) => true,
        Err(e) => {
            warn!("Failed to attach tracepoint {}/{}: {}", category, name, e);
            false
        }
    }
}

fn try_attach_kprobe(
    bpf: &mut aya::Ebpf,
    prog_name: &str,
    fn_name: &str,
    report: &mut AttachReport,
) -> bool {
    let result: Result<()> = (|| {
        let program: &mut KProbe = bpf
            .program_mut(prog_name)
            .context(format!("program {} not found", prog_name))?
            .try_into()?;
        program.load()?;
        program.attach(fn_name, 0)?;
        report.probes += 1;
        Ok(())
    })();
    match result {
        Ok(()) => {
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
    fn pairs_require_both_halves_and_unselected_keys_stay_absent() {
        let mut report = AttachReport::default();
        for (enter, exit, complete) in [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (true, true, true),
        ] {
            assert_eq!(report.pair("tier2.openat", enter, exit), complete);
            assert_eq!(report.keys["tier2.openat"], complete);
        }
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
    fn required_failure_aborts_without_claiming_availability() {
        let mut report = AttachReport::default();
        let startup: Result<()> = (|| {
            required(&mut report, "exec.execve", |report| {
                report.probes += 1; // A successful enter does not complete the pair.
                anyhow::bail!("injected exit attach failure")
            })?;
            panic!("failed required collector must abort startup");
        })();
        assert!(startup.is_err());
        assert_eq!(report.probes, 1);
        assert!(!report.keys.contains_key("exec.execve"));
        required(&mut report, "signal", |report| {
            report.probes += 1;
            Ok(())
        })
        .unwrap();
        assert!(report.keys["signal"]);
        assert_eq!(report.probes, 2);
    }
}
