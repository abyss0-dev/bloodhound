use crate::deserializer::BehaviorEvent;
use std::io::{self, LineWriter, Write};

/// Line-buffered NDJSON writer.
///
/// Wraps the underlying writer in a `LineWriter` so the buffer is
/// flushed at every `\n`, i.e. once per event. Low-rate synthesised
/// events (`HEARTBEAT` every 1s, sporadic `LIFECYCLE`) were otherwise
/// trapped in an 8 KiB `BufWriter` and never reached downstream
/// consumers until hundreds of such events accumulated — which for
/// `HEARTBEAT` meant ~10 minutes of invisibility in quiet sessions.
pub struct Serializer<W: Write> {
    writer: LineWriter<W>,
}

impl Serializer<io::Stdout> {
    pub fn new() -> Self {
        Self {
            writer: LineWriter::new(io::stdout()),
        }
    }
}

impl<W: Write> Serializer<W> {
    /// Create a serializer writing to an arbitrary writer. Test-only:
    /// production wires `Serializer::new()` to `io::stdout()`.
    #[cfg(test)]
    pub(crate) fn with_writer(writer: W) -> Self {
        Self {
            writer: LineWriter::new(writer),
        }
    }

    /// Serialize a BehaviorEvent as NDJSON and write to the output.
    pub fn write_event(&mut self, event: &BehaviorEvent) -> io::Result<()> {
        serde_json::to_writer(&mut self.writer, event)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        self.writer.write_all(b"\n")?;
        Ok(())
    }

    /// Flush the output buffer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}
