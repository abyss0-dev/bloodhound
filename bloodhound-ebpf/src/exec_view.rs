use aya_ebpf::helpers::{bpf_get_current_task, bpf_probe_read_kernel};
use bloodhound_common::{EventHeader, EventKind, ExecViewPayload};

enum CaptureError {
    Read,
    Changed,
}
impl From<i64> for CaptureError {
    fn from(_: i64) -> Self {
        Self::Read
    }
}

unsafe fn offset(index: usize) -> usize {
    core::ptr::read_volatile(
        core::ptr::addr_of!(crate::OFF_EXEC_VIEW)
            .cast::<u32>()
            .add(index),
    ) as usize
}
unsafe fn read<T: Copy>(base: usize, index: usize) -> Result<T, i64> {
    bpf_probe_read_kernel((base + offset(index)) as *const T)
}
unsafe fn pointer(base: usize, index: usize) -> Result<usize, i64> {
    let value: usize = read(base, index)?;
    if value == 0 {
        return Err(-1);
    }
    Ok(value)
}

// Offsets follow EXEC_VIEW_FIELDS in bloodhound-common. Every read must succeed;
// pointer endpoints are rechecked, without claiming continuous kernel stability.
unsafe fn capture() -> Result<ExecViewPayload, CaptureError> {
    let task = bpf_get_current_task() as usize;
    let fs = pointer(task, 0)?;
    let nsproxy = pointer(task, 1)?;
    let root = fs + offset(2);
    let mnt = pointer(root, 3)?;
    let dentry = pointer(root, 4)?;
    let inode = pointer(dentry, 5)?;
    let sb = pointer(inode, 7)?;
    let ns = pointer(nsproxy, 9)?;
    let mount = mnt.checked_sub(offset(12)).ok_or(-1i64)?;
    let payload = ExecViewPayload {
        root_inode: read(inode, 6)?,
        root_dev: read(sb, 8)?,
        mount_namespace: read(ns + offset(10), 11)?,
        root_mount_id: read(mount, 13)?,
        version: 1,
        status: 1,
        _pad: [0; 2],
    };
    if payload.mount_namespace == 0 || payload.root_mount_id == 0 {
        return Err(CaptureError::Read);
    }
    if pointer(task, 0)? != fs
        || pointer(task, 1)? != nsproxy
        || pointer(root, 3)? != mnt
        || pointer(root, 4)? != dentry
        || pointer(nsproxy, 9)? != ns
    {
        return Err(CaptureError::Changed);
    }
    Ok(payload)
}

pub unsafe fn emit(exec_header: &EventHeader) {
    let mut header = *exec_header;
    header.kind = EventKind::ExecView as u8;
    header._pad = [0; 3];
    let payload = if core::ptr::read_volatile(&raw const crate::EXEC_VIEW_SUPPORTED) == 0 {
        ExecViewPayload {
            version: 1,
            status: 0,
            ..ExecViewPayload::default()
        }
    } else {
        match capture() {
            Ok(payload) => payload,
            Err(error) => ExecViewPayload {
                version: 1,
                status: match error {
                    CaptureError::Read => 2,
                    CaptureError::Changed => 3,
                },
                ..ExecViewPayload::default()
            },
        }
    };
    crate::helpers::emit_fixed(&header, Some(&payload));
}
