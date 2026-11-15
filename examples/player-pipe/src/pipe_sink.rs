//! A [`Sink`] that writes raw samples to standard output.
//!
//! The example has no decoder: an encoded stream stops the session with an error that names what
//! is missing, instead of writing compressed bytes into the pipe. Because stdout is a pipe and not
//! a scheduled audio device, playout deadlines are ignored and frames are written as they arrive.

use std::io::{self, Write};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use syncspin_client::{AudioFormat, AudioFrame, Sink};

/// Forwards PCM frames to stdout and reports the format of the stream it was opened for.
#[derive(Debug, Default)]
pub struct PipeSink {
    format: Option<AudioFormat>,
}

impl PipeSink {
    /// Creates a sink that has not been opened for a stream yet.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Sink for PipeSink {
    fn open(&mut self, format: AudioFormat) -> Result<()> {
        self.format = Some(format);
        Ok(())
    }

    fn write(&mut self, frame: AudioFrame<'_>, _due: Instant) -> Result<()> {
        match frame {
            AudioFrame::Pcm(samples) => io::stdout()
                .lock()
                .write_all(samples)
                .context("failed to write audio to stdout"),
            AudioFrame::Encoded { codec, data } => {
                let stream = match &self.format {
                    Some(format) => format!("the stream announced as `{}`", format.codec),
                    None => "an unannounced stream".to_owned(),
                };
                bail!(
                    "{stream} delivered a {}-byte `{codec}` frame, but this example carries no \
                     decoder feature; run it without --passthrough to receive raw PCM",
                    data.len()
                )
            }
        }
    }

    fn flush(&mut self) -> Result<()> {
        io::stdout()
            .lock()
            .flush()
            .context("failed to flush stdout")
    }

    fn latency(&self) -> Option<Duration> {
        // A pipe reports no additional delay; the samples are already written when the sink
        // returns.
        None
    }
}
