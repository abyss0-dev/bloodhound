use anyhow::Result;
use aya::maps::ring_buf::RingBuf;
use std::os::fd::AsRawFd;
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, oneshot};

/// Consume events from the BPF ring buffer asynchronously.
/// Sends raw event bytes to the processing channel.
pub async fn consume_ring_buffer(
    mut ring_buf: RingBuf<aya::maps::MapData>,
    tx: mpsc::Sender<Vec<u8>>,
    ready: oneshot::Sender<()>,
) -> Result<()> {
    let fd = ring_buf.as_raw_fd();
    let async_fd = AsyncFd::new(fd)?;
    // The loader readiness marker must not become observable until the ring
    // buffer fd is registered with Tokio's reactor. Otherwise a fixture can
    // emit in the gap between BPF attachment and consumer initialization.
    let _ = ready.send(());

    loop {
        // Drain before waiting. A record can arrive between observing an
        // empty ring and clearing a previous readiness notification. Starting
        // each iteration with a drain makes that race harmless, including for
        // collectors that emit only one event.
        while let Some(item) = ring_buf.next() {
            let data = item.to_vec();
            if tx.send(data).await.is_err() {
                // Receiver dropped, shutting down
                return Ok(());
            }
        }

        // No records remain. Wait for the kernel notification, then clear the
        // readiness token and return to the unconditional drain above.
        let mut guard = async_fd.readable().await?;
        guard.clear_ready();
    }
}
