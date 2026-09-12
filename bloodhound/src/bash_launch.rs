//! Opt-in scalar launch observations for one measured Bash image.
use anyhow::{bail, Context, Result};
use aya::{programs::UProbe, Ebpf};
use bloodhound_common::BashLaunchPayload;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

const MAX_IMAGE_BYTES: u64 = 4 * 1024 * 1024;
const IMAGE_SHA256: &str = "bc5945feb8bd26203ebfafea5ce1878bb2e32cb8fb50ab7ae395cfb1e1aaaef1";
const EXECUTE_COMMAND_OFFSET: u64 = 0x4a280;

pub fn verify_image(path: &Path) -> Result<File> {
    if !path.is_absolute() {
        bail!("Bash launch image path must be absolute");
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .context("opening Bash launch image")?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > MAX_IMAGE_BYTES {
        bail!("Bash launch image is not a bounded regular file");
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_IMAGE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || after.len() != before.len()
        || after.mtime() != before.mtime()
        || after.mtime_nsec() != before.mtime_nsec()
        || after.ctime() != before.ctime()
        || after.ctime_nsec() != before.ctime_nsec()
    {
        bail!("Bash launch image changed during verification");
    }
    verify_bytes(&bytes)?;
    Ok(file)
}

fn verify_bytes(bytes: &[u8]) -> Result<()> {
    if bytes.len() as u64 > MAX_IMAGE_BYTES
        || format!("{:x}", Sha256::digest(bytes)) != IMAGE_SHA256
    {
        bail!("unsupported Bash launch image digest");
    }
    Ok(())
}

pub fn attach(bpf: &mut Ebpf, image: &File) -> Result<()> {
    // Resolve the pinned inode, not a path that could have been replaced after verification.
    let path = format!("/proc/self/fd/{}", image.as_raw_fd());
    for name in ["bash_command_entry", "bash_command_return"] {
        let program: &mut UProbe = bpf
            .program_mut(name)
            .context("missing Bash launch program")?
            .try_into()?;
        program.load()?;
        program.attach(None, EXECUTE_COMMAND_OFFSET, &path, None)?;
    }
    Ok(())
}

pub fn decode_payload(
    payload: &[u8],
) -> Result<(
    String,
    String,
    String,
    Option<serde_json::Value>,
    Option<i64>,
)> {
    if payload.len() != BashLaunchPayload::SIZE {
        bail!("invalid Bash launch payload size");
    }
    let value = unsafe { core::ptr::read_unaligned(payload.as_ptr().cast::<BashLaunchPayload>()) };
    let name = match value.phase {
        1 => "bash_command_entry",
        2 => "bash_command_return",
        _ => bail!("invalid Bash launch phase"),
    };
    let status = if value.version != 1 {
        "unknown"
    } else {
        match value.status {
            1 => "complete",
            2 => "unavailable",
            _ => bail!("invalid Bash launch status"),
        }
    };
    let mut args =
        serde_json::json!({"launch_capture_version": value.version, "launch_status": status});
    if value.version == 1 {
        if value.status != 1 || value.phase == 2 {
            if value.command_type != 0
                || value.command_flags != 0
                || value.asynchronous != 0
                || value.pipe_in != 0
                || value.pipe_out != 0
            {
                bail!("partial or return-only Bash launch arguments");
            }
        } else {
            args["command_type"] = value.command_type.into();
            args["command_flags"] = value.command_flags.into();
            args["asynchronous"] = value.asynchronous.into();
            args["pipe_in"] = value.pipe_in.into();
            args["pipe_out"] = value.pipe_out.into();
        }
    }
    Ok((
        "UPROBE".into(),
        name.into(),
        "behavior".into(),
        Some(args),
        None,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn bytes(value: &BashLaunchPayload) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                (value as *const BashLaunchPayload).cast::<u8>(),
                BashLaunchPayload::SIZE,
            )
        }
    }

    #[test]
    fn fixed_capture_preserves_pipeline_arguments_without_interpreting_grammar() {
        assert_eq!(BashLaunchPayload::SIZE, 24);
        for (input, output) in [(-1, -1), (-1, 4), (3, -1)] {
            let value = BashLaunchPayload {
                version: 1,
                status: 1,
                phase: 1,
                command_type: 4,
                pipe_in: input,
                pipe_out: output,
                ..Default::default()
            };
            let event = decode_payload(bytes(&value)).unwrap();
            assert_eq!(event.0, "UPROBE");
            let args = event.3.unwrap();
            assert_eq!(args["pipe_in"], input);
            assert_eq!(args["pipe_out"], output);
        }
    }

    #[test]
    fn absent_unknown_and_partial_arguments_never_become_complete_entries() {
        let mut value = BashLaunchPayload {
            version: 1,
            status: 2,
            phase: 1,
            ..Default::default()
        };
        let args = decode_payload(bytes(&value)).unwrap().3.unwrap();
        assert_eq!(args["launch_status"], "unavailable");
        assert!(args.get("pipe_in").is_none());
        value.pipe_in = -1;
        assert!(decode_payload(bytes(&value)).is_err());
        value.version = 2;
        let args = decode_payload(bytes(&value)).unwrap().3.unwrap();
        assert_eq!(args["launch_status"], "unknown");
        assert!(args.get("pipe_in").is_none());
        value = BashLaunchPayload {
            version: 1,
            status: 1,
            phase: 2,
            ..Default::default()
        };
        let event = decode_payload(bytes(&value)).unwrap();
        assert_eq!(event.1, "bash_command_return");
        assert!(event.3.unwrap().get("command_type").is_none());
        value.command_type = 4;
        assert!(decode_payload(bytes(&value)).is_err());
        assert!(decode_payload(&[0; 23]).is_err());
        assert!(decode_payload(&[0; 25]).is_err());
    }

    #[test]
    fn image_selection_is_opt_in_and_rejects_unverified_inputs() {
        assert!(
            crate::cli::Cli::try_parse_from(["bloodhound", "--uid", "5"])
                .unwrap()
                .bash_launch
                .is_none()
        );
        assert!(verify_image(Path::new("relative/bash")).is_err());
        assert!(verify_image(Path::new("/dev/null")).is_err());
        assert!(verify_bytes(b"not a measured image").is_err());
    }
}
