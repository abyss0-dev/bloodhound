use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "bloodhound")]
#[command(about = "eBPF-based behavioral tracing daemon")]
pub struct Cli {
    /// Target user UID to trace (audit login UID)
    #[arg(long)]
    pub uid: u32,

    /// Attach optional LSM hooks, including daemon-protection enforcement.
    #[arg(long, default_value_t = false)]
    pub enable_lsm: bool,

    /// Ring buffer size in bytes (power of two, at least the system page size)
    #[arg(long, default_value_t = 4 * 1024 * 1024)]
    pub ring_buffer_size: u32,

    /// Enable opt-in rich extraction for `sendfile` and `splice`.
    ///
    /// These syscalls dominate event volume on file-serving workloads
    /// (10K+/sec is common). Disabled by default. When enabled, pair with
    /// `--ring-buffer-size` of at least 32 MiB to avoid drops under load.
    #[arg(long, default_value_t = false)]
    pub enable_rich_sendfile: bool,

    /// Interval in seconds between synthesised `HEARTBEAT` events.
    ///
    /// Each heartbeat carries drop deltas and events-emitted deltas so
    /// downstream consumers can mark intervals as `undecidable` when
    /// ring-buffer drops occur within them. Set to `0` to disable
    /// heartbeat emission entirely (consumers that do not expect
    /// `HEARTBEAT` events can opt out).
    #[arg(long, default_value_t = 1.0)]
    pub heartbeat_interval: f64,

    /// Trusted USDT collector selection file. When omitted, no USDT collector
    /// attaches (deny by default). The file can only choose a compiled ID and
    /// set enabled=true/false; it cannot supply BPF, offsets, probes, or ABI.
    #[arg(long)]
    pub usdt_config: Vec<PathBuf>,
}

/// Validate before creating output or loading any BPF resources.
pub fn validate_ring_buffer_size(size: u32, page_size: u64) -> anyhow::Result<()> {
    anyhow::ensure!(
        size.is_power_of_two() && u64::from(size) >= page_size,
        "invalid --ring-buffer-size {size}: must be a power of two and at least the system page size ({page_size} bytes)"
    );
    Ok(())
}

/// Quantize once; readiness and the timer must use the same cadence.
pub fn heartbeat_interval_ms(seconds: f64) -> anyhow::Result<u32> {
    let millis = (seconds * 1000.0).round();
    anyhow::ensure!(
        seconds.is_finite() && seconds >= 0.0 && millis <= u32::MAX as f64
            && (seconds == 0.0 || millis >= 1.0),
        "invalid --heartbeat-interval: expected zero or a finite nonnegative cadence rounding to 1..=u32::MAX milliseconds"
    );
    Ok(millis as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cadence_is_validated_and_quantized() {
        for (seconds, expected) in [
            (0.0, 0),
            (0.0005, 1),
            (0.0006, 1),
            (1.0, 1000),
            (u32::MAX as f64 / 1000.0, u32::MAX),
        ] {
            assert_eq!(heartbeat_interval_ms(seconds).unwrap(), expected);
        }
        for seconds in [
            0.0004,
            -0.001,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::MAX,
            (u32::MAX as f64 + 1.0) / 1000.0,
        ] {
            assert!(heartbeat_interval_ms(seconds).is_err(), "{seconds}");
        }
    }

    #[test]
    fn lsm_is_opt_in_and_packet_flag_is_retired() {
        assert!(
            !Cli::try_parse_from(["bloodhound", "--uid", "1000"])
                .unwrap()
                .enable_lsm
        );
        assert!(
            Cli::try_parse_from(["bloodhound", "--uid", "1000", "--enable-lsm"])
                .unwrap()
                .enable_lsm
        );
        assert!(
            Cli::try_parse_from(["bloodhound", "--uid", "1000", "--exclude-ports", "22"]).is_err()
        );
    }

    #[test]
    fn ring_buffer_sizes_on_4k_pages() {
        for size in [4096, 4 * 1024 * 1024, 32 * 1024 * 1024] {
            assert!(validate_ring_buffer_size(size, 4096).is_ok(), "{size}");
        }
        for size in [0, 2048, 3_000_000, 4097] {
            let error = validate_ring_buffer_size(size, 4096).unwrap_err();
            assert!(error.to_string().contains("invalid --ring-buffer-size"));
        }
    }

    #[test]
    fn ring_buffer_size_respects_injected_page_size() {
        assert!(validate_ring_buffer_size(4096, 65536).is_err());
        assert!(validate_ring_buffer_size(65536, 65536).is_ok());
        assert!(validate_ring_buffer_size(4 * 1024 * 1024, 65536).is_ok());
    }
}
