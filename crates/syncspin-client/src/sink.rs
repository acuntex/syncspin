//! Audio output abstraction.
//!
//! The client owns the connection and the clock; the host owns the speakers. Everything that
//! touches an audio device sits behind [`Sink`], which keeps this crate free of platform
//! dependencies and lets a test record the frames instead of playing them.
//!
//! A sink is moved into [`connect`](crate::connect) once and reused for every connection attempt
//! the client makes, so a reconnect does not need the host to build another one. Calls are strictly
//! ordered and come from the client's task: a flush and then [`Sink::open`] when a stream starts,
//! [`Sink::write`] for every audio chunk, and a flush at each boundary listed on
//! [`Sink::flush`]. A sink may block only as long as it takes to enqueue the frame: a write that
//! never returns stalls the connection, because the trait is synchronous and the client has no
//! second thread to read the socket.
//!
//! An error from [`Sink::open`], [`Sink::write`] or [`Sink::flush`] is fatal for the connection:
//! the client reports it and stops instead of retrying a broken output, so the host has to build a
//! new sink and call [`connect`](crate::connect) again.

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
///
/// The struct is non-exhaustive so a later protocol revision can add a field without breaking a
/// sink implementation. A sink only receives it from [`Sink::open`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AudioFormat {
    /// Codec of the stream.
    pub codec: Codec,
    /// Sample rate in hertz.
    pub sample_rate: u32,
    /// Number of interleaved channels.
    pub channels: u8,
    /// Bits per sample; meaningful for [`Codec::Pcm`] and [`Codec::Flac`].
    pub bit_depth: u8,
    /// Codec header carried by the stream announcement, decoded from its base64 form.
    ///
    /// For FLAC this is the `fLaC` marker followed by `STREAMINFO`; a decoder needs it before the
    /// first frame. Absent for PCM and Opus. The bytes are exactly what the server sent.
    pub codec_header: Option<Vec<u8>>,
}

/// Audio output owned by the host application.
///
/// A sink is moved into the connection and reused across reconnects, so its output device may stay
/// open for the whole lifetime of the connection rather than per session. Dropping it must stop
/// playback: the client drops the sink when the connection ends.
pub trait Sink: Send + 'static {
    /// Prepares the output for `format`.
    ///
    /// The client calls this once per announced stream, after flushing the previous one, and
    /// before it hands over the first chunk. The same sink sees the streams of every connection
    /// attempt, and a new attempt announces its own format, so an implementation must not assume
    /// that the format it last saw is still current. A format the sink cannot play is an error,
    /// which ends the connection: the client does not retry a sink that failed.
    fn open(&mut self, format: AudioFormat) -> anyhow::Result<()>;

    /// Writes one frame.
    ///
    /// `due` is the local instant at which the first sample of the frame should reach the
    /// speakers. It is a playout deadline, not a wake-up call: a sink that buffers ahead compares
    /// it with its own clock, and a deadline that is already past means "play as soon as
    /// possible". The client reports [`std::time::Instant::now`] while its clock estimate is not
    /// ready, so the deadline carries no guarantee in that state.
    ///
    /// An error ends the connection: the host cannot recover a broken output from here, and the
    /// client does not retry a sink that failed.
    fn write(&mut self, frame: AudioFrame<'_>, due: std::time::Instant) -> anyhow::Result<()>;

    /// Drops audio that is buffered but not audible yet.
    ///
    /// Called:
    ///
    /// - on `stream/start`, after the previous stream and before [`Sink::open`] for the new one,
    /// - on `stream/end`, after [`Event::StreamEnd`](crate::Event::StreamEnd),
    /// - on `stream/clear`, which seeks or restarts the stream without ending it, after
    ///   [`Event::StreamClear`](crate::Event::StreamClear),
    /// - when the server removes the `player@v1` role, after an
    ///   [`Event::StreamEnd`](crate::Event::StreamEnd) with
    ///   [`StreamEndReason::RoleRemoved`](crate::StreamEndReason::RoleRemoved), and
    /// - after a connection attempt ends, before the client reconnects, so audio buffered for the
    ///   session that ended cannot become audible on the next one.
    ///
    /// It must succeed when no stream is open, so a sink can treat it as "discard everything, keep
    /// the output device". An error ends the connection.
    fn flush(&mut self) -> anyhow::Result<()>;

    /// Reports the output delay the sink adds beyond the audio port.
    ///
    /// The client uses it when it reports its timing to the server. `None` means the sink does not
    /// know, which the client treats as no additional delay.
    fn latency(&self) -> Option<Duration> {
        None
    }

    /// Reports how many times the output ran empty since it was opened.
    ///
    /// This is diagnostic only; the client never changes its behaviour because of it.
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
