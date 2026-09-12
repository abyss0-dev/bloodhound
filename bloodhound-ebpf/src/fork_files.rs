use bloodhound_common::{EventHeader, EventKind, ForkFilesPayload, FORK_FILES_MAX_SLOTS};

use crate::exec_stdio::{descriptor, kind, pointer, read};

unsafe fn capture(task: usize) -> Result<ForkFilesPayload, i64> {
    let files = pointer(task, 0)?;
    let fdt = pointer(files, 1)?;
    let max: u32 = read(fdt, 2)?;
    if max == 0 || max > FORK_FILES_MAX_SLOTS {
        return Ok(ForkFilesPayload {
            version: 1,
            status: 4,
            ..Default::default()
        });
    }
    let table = pointer(fdt, 3)?;
    let mut has_pipe = 0;
    // The scheduler hook runs before this child can execute redirections.
    // A bounded full table scan is required even after finding a pipe.
    for fd in 0..FORK_FILES_MAX_SLOTS {
        if fd >= max {
            break;
        }
        let file = descriptor(table, fd as usize)?;
        if kind(file)? == 6 {
            has_pipe = 1;
        }
        if descriptor(table, fd as usize)? != file {
            return Ok(ForkFilesPayload {
                version: 1,
                status: 3,
                ..Default::default()
            });
        }
    }
    if pointer(task, 0)? != files
        || pointer(files, 1)? != fdt
        || pointer(fdt, 3)? != table
        || read::<u32>(fdt, 2)? != max
    {
        return Ok(ForkFilesPayload {
            version: 1,
            status: 3,
            ..Default::default()
        });
    }
    Ok(ForkFilesPayload {
        version: 1,
        status: 1,
        has_pipe,
        scanned_slots: max,
        ..Default::default()
    })
}

pub unsafe fn emit(child_header: &EventHeader, child: usize) {
    let mut header = *child_header;
    header.kind = EventKind::ForkFiles as u8;
    header._pad = [0; 3];
    let payload = if core::ptr::read_volatile(&raw const crate::EXEC_STDIO_SUPPORTED) == 0 {
        ForkFilesPayload {
            version: 1,
            status: 0,
            ..Default::default()
        }
    } else {
        capture(child).unwrap_or(ForkFilesPayload {
            version: 1,
            status: 2,
            ..Default::default()
        })
    };
    crate::helpers::emit_fixed(&header, Some(&payload));
}
