//! Audio output abstraction.
//!
//! The client owns the connection and the clock; the host owns the speakers. Everything that
//! touches an audio device sits behind [`Sink`], which keeps this crate free of platform
//! dependencies and lets a test record the frames instead of playing them.
//!
//! A sink is moved into [`connect`](crate::connect) once and reused for every connection attempt
//! the client makes, so a reconnect does not need the host to build another one. Calls are strictly
//! ordered and come from the client's task: a flush and then [`Sink::open`] when a stream starts,
//! [`Sink::write`] when a frame is due, and a discard or a flush at each boundary listed on
//! [`Sink::discard_from`] and [`Sink::flush`]. The client owns the playout clock: it schedules each
//! frame from its server timestamp and calls [`Sink::write`] when the frame's pre-port write time
//! has arrived, so a sink writes on call instead of scheduling again. A sink may block only as long
//! as it takes to enqueue the frame: a write that never returns stalls the connection, because the
//! trait is synchronous and the client has no second thread to read the socket.
//!
//! An error from [`Sink::open`], [`Sink::write`], [`Sink::discard_from`] or [`Sink::flush`] is
//! fatal for the connection: the client reports it and stops instead of retrying a broken output,
//! so the host has to build a new sink and call [`connect`](crate::connect) again.

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

impl AudioFormat {
    /// Builds a PCM format.
    ///
    /// Samples are interleaved by channel and encoded as signed little-endian integers of
    /// `bit_depth` bits, which is what the specification's PCM convention describes; 24-bit samples
    /// are packed as three bytes.
    ///
    /// The values are not validated. A server must support PCM at 16 bit, one or two channels and
    /// 44.1 or 48 kHz, and may support others, so a format outside that is for the host to judge: a
    /// zero channel count or a bit depth that is not a whole number of bytes describes no stream.
    pub fn pcm(sample_rate: u32, channels: u8, bit_depth: u8) -> AudioFormat {
        AudioFormat {
            codec: Codec::Pcm,
            sample_rate,
            channels,
            bit_depth,
            codec_header: None,
        }
    }
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
    /// The client schedules playout and calls this at the frame's wake time, so the sink writes it
    /// now and must not schedule it again - otherwise a frame whose sink buffers internally is
    /// delayed twice. The call is already early enough to fill the sink's
    /// [`Sink::pre_port_delay`].
    ///
    /// `due` is the local instant at which the first sample of the frame should reach the audio
    /// port, with the sink's [`Sink::output_delay`] already subtracted. The sink's pre-port delay
    /// is compensated by the instant of this call, not by this value. `due` is informational: a
    /// sink that forwards the frame to its pipeline ignores it, one that buffers ahead may compare
    /// it with its own clock, and a deadline that is already past means "write as soon as
    /// possible". The client reports [`std::time::Instant::now`] while its clock estimate is not
    /// ready, so the value carries no guarantee in that state.
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
    /// - on a `stream/clear` that carries no timestamp, after
    ///   [`Event::StreamClear`](crate::Event::StreamClear); a clear that carries one is a
    ///   [`Sink::discard_from`] instead,
    /// - when the server removes the `player@v1` role, after an
    ///   [`Event::StreamEnd`](crate::Event::StreamEnd) with
    ///   [`StreamEndReason::RoleRemoved`](crate::StreamEndReason::RoleRemoved), and
    /// - after a connection attempt ends, before the client reconnects, so audio buffered for the
    ///   session that ended cannot become audible on the next one.
    ///
    /// It must succeed when no stream is open, so a sink can treat it as "discard everything, keep
    /// the output device". An error ends the connection.
    fn flush(&mut self) -> anyhow::Result<()>;

    /// Drops the buffered audio that is due at or after `due`, keeping what plays earlier.
    ///
    /// Called on a `stream/clear` that carries a `from_timestamp`, after
    /// [`Event::StreamClear`](crate::Event::StreamClear). The client already dropped its own queued
    /// frames at or after that server timestamp; this call is for the audio the sink holds itself.
    /// `due` is the server timestamp mapped through the client's clock estimate, with the sink's
    /// [`Sink::output_delay`] subtracted: the local deadline the sink would have been given for that
    /// server time. It is [`std::time::Instant::now`] while no estimate is ready, for a timestamp
    /// that already lies in the past, and when the mapping would overflow — each of which drops
    /// everything buffered and matches [`Sink::flush`].
    ///
    /// It must succeed when no stream is open or no queue exists: an empty queue discards nothing.
    /// A clear can arrive before `stream/start` or after `stream/end`, and the client does not
    /// withhold it.
    ///
    /// The default drops everything, so a sink with no timestamped queue keeps the flush
    /// behaviour without implementing this. An error ends the connection.
    fn discard_from(&mut self, due: std::time::Instant) -> anyhow::Result<()> {
        let _ = due;
        self.flush()
    }

    /// Reports the delay between [`Sink::write`] and the audio port: decoder, pipeline, driver and
    /// device buffers inside the sink. Not the post-port delay reported to the server; that is
    /// [`Sink::output_delay`].
    ///
    /// The client calls [`Sink::write`] this much before the frame's playout deadline, so the frame
    /// reaches the port at `due`. A sink that forwards frames straight to its pipeline leaves this
    /// at zero; one whose output buffers internally reports the buffer here so the client can fill
    /// it. A value that belongs on the post-port side raises the lead the server sends ahead
    /// instead of compensating it, because the server factors `output_delay` into that lead.
    ///
    /// The client polls this when a stream opens, after every `client/state` report, after every
    /// clock burst, once about half a second after an accepted `set_output_delay`, and when the host
    /// calls `ControlHandle::output_delay_applied`; a change moves the timer, and because the
    /// reported lead is at least the pre-port delay, a change that moves that lead in either
    /// direction sends an updated `required_lead_time_ms`. The default is zero.
    fn pre_port_delay(&self) -> Duration {
        Duration::ZERO
    }

    /// Reports the delay the output adds **after** the audio port: external speakers, amplifiers, a
    /// chain after the DAC. Decoder, pipeline and device-internal buffer latency belong in the host's
    /// playout scheduling, not here. A conformant server factors this value into its send-ahead, so
    /// reporting a buffer here raises the lead instead of compensating it; the server in this
    /// workspace ignores the reported timing until `docs/spec-deviations.md` #17 closes.
    ///
    /// The host restores the same value across restarts and reconnections: the protocol requires
    /// `output_delay_ms` to persist, and this trait is the only place the client learns it. The
    /// client polls it at the same points as [`Sink::pre_port_delay`] (stream open, after every
    /// `client/state` report, after every clock burst, the fallback read after `set_output_delay`
    /// and `ControlHandle::output_delay_applied`); a change re-maps the queued
    /// deadlines and sends a new `client/state`, because `output_delay_ms` is a player field.
    ///
    /// `None` means the sink does not know, which the client treats as no additional delay.
    fn output_delay(&self) -> Option<Duration> {
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;

    /// A sink that implements only the required methods and counts its flushes.
    struct FlushingSink {
        flushes: Arc<AtomicUsize>,
    }

    impl Sink for FlushingSink {
        fn open(&mut self, _format: AudioFormat) -> anyhow::Result<()> {
            Ok(())
        }

        fn write(
            &mut self,
            _frame: AudioFrame<'_>,
            _due: std::time::Instant,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        fn flush(&mut self) -> anyhow::Result<()> {
            self.flushes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn a_sink_without_its_own_discard_flushes_everything() {
        let flushes = Arc::new(AtomicUsize::new(0));
        let mut sink = FlushingSink {
            flushes: Arc::clone(&flushes),
        };
        sink.discard_from(std::time::Instant::now())
            .expect("the default discard must flush");
        assert_eq!(
            flushes.load(Ordering::SeqCst),
            1,
            "a sink without its own discard must receive one flush"
        );
    }

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

    #[test]
    fn a_pcm_format_carries_its_parameters() {
        let format = AudioFormat::pcm(48_000, 2, 16);
        assert_eq!(format.codec, Codec::Pcm);
        assert_eq!(format.sample_rate, 48_000);
        assert_eq!(format.channels, 2);
        assert_eq!(format.bit_depth, 16);
        assert!(format.codec_header.is_none(), "PCM carries no codec header");
    }
}
