//! The push data plane: the audio format, the track description and [`StreamWriter`].
//!
//! The host owns the queue and the decoder, the server owns the clock and the wire. A host calls
//! [`ServerHandle::open_stream`](crate::ServerHandle::open_stream), pushes bytes with
//! [`StreamWriter::write`] and the server stamps every chunk with the server-clock timestamp of its
//! first sample and fans it out to the players of the group.
//!
//! Nothing here decodes. Bytes arrive exactly as the host produced them and leave the same way, so
//! the format is the host's statement about what those bytes are, not something the server checks.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use syncspin_core::messages::{PlayerSupport, StreamStartPlayer};

use crate::group::Group;

/// One codec the protocol names, or one this revision does not.
///
/// The enum exists so [`AudioFormat::supported_by`] can apply the specification's rule that
/// `bit_depth` is ignored for `opus`; [`Codec::Other`] preserves an identifier a later revision
/// introduces instead of rejecting the format outright.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Codec {
    /// Raw samples, interleaved by channel, signed little-endian two's complement.
    Pcm,
    /// FLAC, one or more complete frames per chunk.
    Flac,
    /// Opus, exactly one packet per chunk.
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

/// The audio format this server streams.
///
/// The fields are the wire values of `stream/start`: the host states the format once in
/// [`ServerConfig`](crate::ServerConfig) and every stream the server starts announces it. A client
/// is activated as a player only when its `player@v1_support` lists this exact format, so the
/// server never sends a stream a client cannot decode.
///
/// [`AudioFormat::pcm`] is the format a server can serve without knowing anything about a codec;
/// [`AudioFormat::flac`] additionally needs the `fLaC` marker and `STREAMINFO` block the decoder
/// requires before the first frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioFormat {
    /// Codec of the stream.
    pub codec: Codec,
    /// Sample rate in hertz.
    pub sample_rate: u32,
    /// Number of interleaved channels.
    pub channels: u8,
    /// Bits per sample; ignored for [`Codec::Opus`].
    pub bit_depth: u8,
    /// Codec header as raw bytes; required for [`Codec::Flac`] and absent for the other codecs.
    pub codec_header: Option<Vec<u8>>,
}

impl AudioFormat {
    /// Builds a PCM format.
    ///
    /// Samples are interleaved by channel and encoded as signed little-endian integers of
    /// `bit_depth` bits, which is what the specification's PCM convention describes.
    pub fn pcm(sample_rate: u32, channels: u8, bit_depth: u8) -> AudioFormat {
        AudioFormat {
            codec: Codec::Pcm,
            sample_rate,
            channels,
            bit_depth,
            codec_header: None,
        }
    }

    /// Builds a FLAC format from its `fLaC` marker and `STREAMINFO` block.
    pub fn flac(
        sample_rate: u32,
        channels: u8,
        bit_depth: u8,
        codec_header: Vec<u8>,
    ) -> AudioFormat {
        AudioFormat {
            codec: Codec::Flac,
            sample_rate,
            channels,
            bit_depth,
            codec_header: Some(codec_header),
        }
    }

    /// Builds an Opus format. One chunk carries one packet; the decoder is configured from the
    /// sample rate and channel count, so there is no codec header.
    pub fn opus(sample_rate: u32, channels: u8) -> AudioFormat {
        AudioFormat {
            codec: Codec::Opus,
            sample_rate,
            channels,
            bit_depth: 0,
            codec_header: None,
        }
    }

    /// Reports whether a client's `player@v1_support` lists this format.
    ///
    /// The comparison is exact for the fields that describe the stream - codec, sample rate and
    /// channel count - and includes `bit_depth` for the codecs that have one. The specification
    /// ignores `bit_depth` for `opus`, so a client that lists `16` there still accepts the stream.
    #[must_use]
    pub fn supported_by(&self, support: &PlayerSupport) -> bool {
        support.supported_formats.iter().any(|offered| {
            offered.codec == self.codec.as_str()
                && offered.sample_rate == self.sample_rate
                && offered.channels == self.channels
                && (self.codec == Codec::Opus || offered.bit_depth == self.bit_depth)
        })
    }

    /// Returns the `player` object `stream/start` carries.
    #[must_use]
    pub(crate) fn stream_start(&self) -> StreamStartPlayer {
        StreamStartPlayer {
            codec: self.codec.as_str().to_owned(),
            sample_rate: self.sample_rate,
            channels: self.channels,
            bit_depth: self.bit_depth,
            codec_header: self
                .codec_header
                .as_ref()
                .map(|header| STANDARD.encode(header)),
        }
    }

    /// Returns the playtime of `bytes` of this format.
    ///
    /// For [`Codec::Pcm`] the value is exact: whole interleaved frames at the announced width and
    /// rate, with a trailing partial frame counting as nothing. The server does not decode, so a
    /// compressed codec reuses the same map over the announced sample rate, channel count and bit
    /// depth; a host streaming one must therefore keep its chunks at the nominal byte rate this
    /// implies, which holds for a constant-bitrate codec and not for `opus` or a variable-rate
    /// FLAC stream. A duration hint on [`StreamWriter::write`] is the fix when a host needs one.
    pub(crate) fn duration(&self, bytes: usize) -> Duration {
        let sample_bytes = usize::from(self.channels) * usize::from(self.bit_depth / 8).max(1);
        let frames = bytes / sample_bytes;
        if self.sample_rate == 0 {
            return Duration::ZERO;
        }
        let micros = (frames as u64).saturating_mul(1_000_000) / u64::from(self.sample_rate);
        Duration::from_micros(micros)
    }

    /// Rejects a format the server cannot schedule a stream for.
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        use anyhow::bail;
        if self.sample_rate == 0 {
            bail!("the stream format has a sample rate of 0 Hz");
        }
        if self.channels == 0 {
            bail!("the stream format has no channels");
        }
        match &self.codec {
            Codec::Pcm | Codec::Flac => {
                if self.bit_depth == 0 || self.bit_depth % 8 != 0 {
                    bail!(
                        "the {} stream format has a bit depth of {}, which is not a whole number of \
                         bytes",
                        self.codec,
                        self.bit_depth
                    );
                }
            }
            Codec::Opus | Codec::Other(_) => {}
        }
        if self.codec == Codec::Flac && self.codec_header.is_none() {
            bail!("a FLAC stream needs its `fLaC` marker and STREAMINFO block as `codec_header`");
        }
        Ok(())
    }
}

impl fmt::Display for AudioFormat {
    /// Formats the format for an event or an error message, never for the wire.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}, {} Hz, {} channel(s), {} bit",
            self.codec, self.sample_rate, self.channels, self.bit_depth
        )
    }
}

/// The track a stream carries.
///
/// Every field is optional: the server forwards what the host knows and leaves the rest absent,
/// so a client shows what exists instead of an empty string. `duration` of `None` means the
/// length is unknown, which a live stream reports as `0` in the metadata state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrackInfo {
    /// Track title.
    pub title: Option<String>,
    /// Primary artist or artists.
    pub artist: Option<String>,
    /// Album artist, where it differs from the track artist.
    pub album_artist: Option<String>,
    /// Album or release the track belongs to.
    pub album: Option<String>,
    /// Length of the track; `None` when it is unknown.
    pub duration: Option<Duration>,
}

/// The host's handle on one stream.
///
/// [`ServerHandle::open_stream`](crate::ServerHandle::open_stream) returns it; every call applies to
/// the whole group at once, because one server streams one format to every player. The writer
/// stamps nothing itself: [`StreamWriter::write`] hands the bytes to the group, which owns the
/// timeline and the playout timestamps.
///
/// Calls are synchronous and never wait for a client. A write only queues the chunk for the
/// connection tasks, so a client that has stopped reading cannot hold the host up; the price is that
/// its queue grows, which is the backpressure question the next milestone answers.
///
/// Dropping the writer without [`StreamWriter::end`] ends the stream, so a host that returns early
/// does not leave a stream running that it can no longer feed.
#[derive(Debug)]
pub struct StreamWriter {
    group: Arc<Group>,
    ended: bool,
}

impl StreamWriter {
    /// Creates a writer for a stream the group has already announced.
    pub(crate) fn new(group: Arc<Group>) -> StreamWriter {
        StreamWriter {
            group,
            ended: false,
        }
    }

    /// Sends one chunk of audio.
    ///
    /// The chunk must carry whole codec units as the negotiated format defines them: for `pcm`
    /// any whole number of interleaved frames, for `flac` one or more complete FLAC frames, for
    /// `opus` exactly one packet. The server derives the playtime of the chunk from the format, so
    /// a chunk that crosses a codec boundary shifts every later timestamp.
    ///
    /// Bytes are dropped, without an error the host could act on, while the group is paused or the
    /// stream has ended: there is no timeline to put them on until playback resumes, and resending
    /// audio is worse than losing it.
    pub fn write(&mut self, bytes: &[u8]) {
        self.group.write_audio(bytes);
    }

    /// Moves the stream to `position` and drops everything the clients have buffered for it.
    ///
    /// The next chunk plays `START_LEAD` after the seek, which is long enough for a player that is
    /// already running to refill. A position beyond the track's known duration is clamped to the
    /// end; an unknown duration is not clamped at all.
    pub fn seek(&mut self, position: Duration) {
        self.group.seek(position);
    }

    /// Ends the stream for every player.
    ///
    /// Calling it twice sends one `stream/end`, as does dropping the writer.
    pub fn end(&mut self) {
        if !self.ended {
            self.ended = true;
            self.group.end_stream();
        }
    }
}

impl Drop for StreamWriter {
    /// Ends the stream the writer still owns.
    fn drop(&mut self) {
        self.end();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syncspin_core::messages::SupportedFormat;

    /// Builds the `player@v1_support` a client would send for `formats`.
    fn support(formats: &[(&str, u32, u8, u8)]) -> PlayerSupport {
        PlayerSupport {
            supported_formats: formats
                .iter()
                .map(
                    |(codec, sample_rate, channels, bit_depth)| SupportedFormat {
                        codec: (*codec).to_owned(),
                        sample_rate: *sample_rate,
                        channels: *channels,
                        bit_depth: *bit_depth,
                    },
                )
                .collect(),
            buffer_capacity: 1 << 20,
        }
    }

    #[test]
    fn pcm_playtime_is_exact_for_whole_frames() {
        let format = AudioFormat::pcm(48_000, 2, 16);
        // 480 frames of stereo 16-bit is 10 ms at 48 kHz.
        assert_eq!(format.duration(480 * 4), Duration::from_millis(10));
        assert_eq!(format.duration(0), Duration::ZERO);
        assert_eq!(
            format.duration(3),
            Duration::ZERO,
            "a partial frame has no playtime"
        );
    }

    #[test]
    fn a_compressed_format_uses_the_nominal_byte_rate() {
        let format = AudioFormat::flac(48_000, 2, 16, b"fLaC".to_vec());
        assert_eq!(
            format.duration(480 * 2 * 2),
            Duration::from_millis(10),
            "the nominal rate is what the server can derive without decoding"
        );
    }

    #[test]
    fn the_format_gate_compares_what_the_client_listed() {
        let pcm = AudioFormat::pcm(48_000, 2, 16);
        assert!(pcm.supported_by(&support(&[("pcm", 48_000, 2, 16)])));
        assert!(!pcm.supported_by(&support(&[("pcm", 44_100, 2, 16)])));
        assert!(!pcm.supported_by(&support(&[("pcm", 48_000, 1, 16)])));
        assert!(
            !pcm.supported_by(&support(&[("pcm", 48_000, 2, 24)])),
            "PCM has a bit depth and the comparison includes it"
        );
        assert!(!pcm.supported_by(&support(&[])));
    }

    #[test]
    fn opus_is_compared_without_its_bit_depth() {
        let opus = AudioFormat::opus(48_000, 2);
        assert!(opus.supported_by(&support(&[("opus", 48_000, 2, 16)])));
        assert!(opus.supported_by(&support(&[("opus", 48_000, 2, 0)])));
    }

    #[test]
    fn the_stream_start_carries_the_header_as_standard_base64() {
        let format = AudioFormat::flac(44_100, 2, 16, b"fLaC".to_vec());
        let player = format.stream_start();
        assert_eq!(player.codec, "flac");
        assert_eq!(player.sample_rate, 44_100);
        assert_eq!(player.channels, 2);
        assert_eq!(player.bit_depth, 16);
        assert_eq!(player.codec_header.as_deref(), Some("ZkxhQw=="));

        assert_eq!(
            AudioFormat::pcm(48_000, 2, 16).stream_start().codec_header,
            None
        );
    }

    #[test]
    fn an_impossible_format_is_rejected() {
        assert!(AudioFormat::pcm(0, 2, 16).validate().is_err());
        assert!(AudioFormat::pcm(48_000, 0, 16).validate().is_err());
        assert!(AudioFormat::pcm(48_000, 2, 12).validate().is_err());
        assert!(
            AudioFormat::flac(48_000, 2, 16, Vec::new())
                .validate()
                .is_ok(),
            "an empty header is still a header the host chose to send"
        );
        let no_header = AudioFormat {
            codec: Codec::Flac,
            sample_rate: 48_000,
            channels: 2,
            bit_depth: 16,
            codec_header: None,
        };
        assert!(no_header.validate().is_err());
        assert!(AudioFormat::opus(48_000, 2).validate().is_ok());
    }

    #[test]
    fn the_format_reads_back_the_way_it_was_configured() {
        let format = AudioFormat::pcm(48_000, 2, 16);
        assert_eq!(format.to_string(), "pcm, 48000 Hz, 2 channel(s), 16 bit");
        assert_eq!(Codec::from("opus"), Codec::Opus);
        assert_eq!(
            Codec::from("vorbis".to_owned()),
            Codec::Other("vorbis".to_owned())
        );
    }
}
