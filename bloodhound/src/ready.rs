//! `META bloodhound_ready` (tracer contract §2.3) and the startup nsfs check
//! that makes header namespace inodes comparable with `stat` (§2.8.1).
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;

use serde_json::json;

use crate::clock::monotonic_now_ns;
use crate::deserializer::{BehaviorEvent, EventHeaderJson, EventTypeJson};

const NSFS_MAGIC: i64 = 0x6e73_6673;
const NAMESPACE_FILE: &str = "/proc/self/ns/net";

/// Device number of nsfs, read from a namespace file this process opened
/// after verifying that the file lives on nsfs. `None` when the check fails.
pub fn nsfs_dev() -> Option<u64> {
    nsfs_dev_of(NAMESPACE_FILE)
}

fn nsfs_dev_of(path: &str) -> Option<u64> {
    let file = std::fs::File::open(path).ok()?;
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut fs) } != 0 || fs.f_type as i64 != NSFS_MAGIC {
        return None;
    }
    file.metadata().ok().map(|metadata| metadata.dev())
}

pub fn ready_event(probes_attached: u32, ring_buffer_size: u32, nsfs_dev: Option<u64>) -> BehaviorEvent {
    BehaviorEvent {
        header: EventHeaderJson {
            timestamp: monotonic_now_ns(),
            auid: 0,
            sessionid: 0,
            pid: 0,
            ppid: None,
            comm: String::new(),
            process_ref: None,
            tid: None,
            ns: None,
        },
        event: EventTypeJson {
            event_type: "META".into(),
            name: "bloodhound_ready".into(),
            layer: "behavior".into(),
        },
        proc: None,
        args: Some(json!({
            "probes_attached": probes_attached,
            "ring_buffer_size": ring_buffer_size,
            "nsfs_dev": nsfs_dev,
        })),
        return_code: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_file_dev_matches_stat() {
        let dev = nsfs_dev().expect("/proc/self/ns/net is on nsfs");
        assert_eq!(dev, std::fs::metadata(NAMESPACE_FILE).unwrap().dev());
    }

    #[test]
    fn non_nsfs_file_is_not_verified() {
        assert_eq!(nsfs_dev_of("/proc/self/stat"), None);
        assert_eq!(nsfs_dev_of("/nonexistent"), None);
    }

    #[test]
    fn ready_event_carries_contract_fields_without_task_context() {
        let json = serde_json::to_value(ready_event(42, 4 << 20, None)).unwrap();
        assert_eq!(json["event"]["type"], "META");
        assert_eq!(json["event"]["name"], "bloodhound_ready");
        assert_eq!(json["args"], json!({"probes_attached": 42, "ring_buffer_size": 4 << 20, "nsfs_dev": null}));
        assert!(json["header"].get("tid").is_none() && json["header"].get("ns").is_none());
        let json = serde_json::to_value(ready_event(1, 1, Some(4))).unwrap();
        assert_eq!(json["args"]["nsfs_dev"], 4);
    }
}
