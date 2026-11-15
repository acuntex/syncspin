//! Audio output abstraction.
//!
//! The session owns the connection and the clock; the host owns the speakers. Everything that
//! touches an audio device sits behind [`Sink`], which keeps this crate free of platform
//! dependencies and lets a test record the frames instead of playing them.
//!
//! The session calls the sink from its own task. Calls are strictly ordered: [`Sink::open`] once
//! per stream, then [`Sink::write`] for every audio chunk, and [`Sink::flush`] at a stream
//! boundary. A sink may block only as long as it takes to enqueue the frame: a write that never
//! returns stalls the session, because the trait is synchronous and the session has no second
//! thread to read the connection.

use std::fmt;
use std::time::Duration;

/// One audio frame handed to a [`Sink`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudioFrame<'a> {
    /// Raw PCM samples in the layout announced by [`AudioFormat`].
    Pcm(&'a [u8]),
    /// One encoded frame, to be decoded or passed to an audio pipeline unchanged.
    Encoded {
        /// Codec the frame is encoded with.
        codec: Codec,
        /// Encoded bytes, one frame of the codec's stream.
        data: &'a [u8],
    },
}

/// Audio codec of a stream.
///
/// The protocol names three codecs; [`Codec::Other`] preserves one this revision does not know, so
/// a passthrough sink can still forward it. A sink that decodes must reject the values it cannot
/// handle instead of guessing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Codec {
    /// Raw samples, layout given by [`AudioFormat`].
    Pcm,
    /// FLAC.
    Flac,
    /// Opus.
    Opus,
    /// A codec identifier this revision does not name, unchanged from the wire.
    Other(String),
}

impl Codec {
    /// Returns the identifier as it appears on the wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Pcm => "pcm",
            Self::Flac => "flac",
            Self::Opus => "opus",
            Self::Other(name) => name,
        }
    }
}

impl fmt::Display for Codec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl From<&str> for Codec {
    fn from(value: &str) -> Self {
        match value {
            "pcm" => Self::Pcm,
            "flac" => Self::Flac,
            "opus" => Self::Opus,
            other => Self::Other(other.to_owned()),
        }
    }
}

impl From<String> for Codec {
    fn from(value: String) -> Self {
        match value.as_str() {
            "pcm" => Self::Pcm,
            "flac" => Self::Flac,
            "opus" => Self::Opus,
            _ => Self::Other(value),
        }
    }
}

/// The audio format a stream announces.
///
/// The fields are the wire values of the stream announcement, unchanged. For [`Codec::Pcm`] the
/// samples are signed 16-bit little-endian when `bit_depth` is 16, interleaved by channel; other
/// depths keep the same convention scaled to the announced width.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioFormat {
    /// Codec of the stream.
    pub codec: Codec,
    /// Sample rate in hertz.
    pub sample_rate: u32,
    /// Number of interleaved channels.
    pub channels: u8,
    /// Bits per sample; meaningful for [`Codec::Pcm`] and [`Codec::Flac`].
    pub bit_depth: u8,
}

/// Audio output owned by the host application.
///
/// A sink is moved into the session and lives as long as the connection. Dropping it must stop
/// playback: the session drops the sink when the connection ends.
pub trait Sink: Send + 'static {
    /// Prepares the output for `format`.
    ///
    /// The session calls this once per announced stream, after flushing the previous one, and
    /// before it hands over the first chunk. A format the sink cannot play is an error, which ends
    /// the session.
    fn open(&mut self, format: AudioFormat) -> anyhow::Result<()>;

    /// Writes one frame.
    ///
    /// `due` is the local instant at which the first sample of the frame should reach the
    /// speakers. It is a playout deadline, not a wake-up call: a sink that buffers ahead compares
    /// it with its own clock, and a deadline that is already past means "play as soon as
    /// possible". The session reports [`std::time::Instant::now`] while its clock estimate is not
    /// ready, so the deadline carries no guarantee in that state.
    ///
    /// An error ends the session: the host cannot recover a broken output from here.
    fn write(&mut self, frame: AudioFrame<'_>, due: std::time::Instant) -> anyhow::Result<()>;

    /// Drops audio that is buffered but not audible yet.
    ///
    /// The session calls this before opening a new stream. It must succeed when no stream is
    /// open, so a sink can treat it as "discard everything, keep the output device".
    fn flush(&mut self) -> anyhow::Result<()>;

    /// Reports the output delay the sink adds beyond the audio port.
    ///
    /// The session uses it when it reports its timing to the server. `None` means the sink does
    /// not know, which the session treats as no additional delay.
    fn latency(&self) -> Option<Duration> {
        None
    }

    /// Reports how many times the output ran empty since it was opened.
    ///
    /// This is diagnostic only; the session never changes its behaviour because of it.
    fn underruns(&self) -> u64 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_names_roundtrip_through_the_wire_identifier() {
        for (name, codec) in [
            ("pcm", Codec::Pcm),
            ("flac", Codec::Flac),
            ("opus", Codec::Opus),
            ("future", Codec::Other("future".to_owned())),
        ] {
            assert_eq!(Codec::from(name), codec);
            assert_eq!(codec.as_str(), name);
            assert_eq!(codec.to_string(), name);
            assert_eq!(Codec::from(name.to_owned()), codec);
        }
    }
}
