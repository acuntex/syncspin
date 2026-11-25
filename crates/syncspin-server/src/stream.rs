//! The push data plane: the audio format, the track description and [`StreamWriter`].
//!
//! The host owns the queue and the decoder, the server owns the clock and the wire. A host calls
//! [`ServerHandle::open_stream`](crate::ServerHandle::open_stream), pushes bytes with
//! [`StreamWriter::write`] for PCM or [`StreamWriter::write_encoded`] for a format whose playtime
//! only the decoder knows, and the server stamps every chunk with the server-clock timestamp of
//! its first sample and fans it out to the players of the group.
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

    /// Returns the playtime of `bytes` of this format at the nominal byte rate.
    ///
    /// For [`Codec::Pcm`] the value is exact: whole interleaved frames at the announced width and
    /// rate. [`StreamWriter::write`] refuses a trailing partial frame, so only whole frames reach
    /// this map from that path. The server does not decode, so a compressed codec reuses the same
    /// map over the announced sample rate, channel count and bit depth, which is wrong for the
    /// shorter byte stream of `opus` or a variable-rate FLAC. A host streaming one calls
    /// [`StreamWriter::write_encoded`] with the playtime its decoder reports.
    ///
    /// The writer path uses [`AudioFormat::duration_carrying`], which keeps the remainder this
    /// per-chunk map floors away; this one states the nominal map the tests compare against.
    #[cfg(test)]
    pub(crate) fn duration(&self, bytes: usize) -> Duration {
        let frames = bytes / self.frame_bytes();
        if self.sample_rate == 0 {
            return Duration::ZERO;
        }
        let micros = (frames as u64).saturating_mul(1_000_000) / u64::from(self.sample_rate);
        Duration::from_micros(micros)
    }

    /// Returns the playtime of PCM `bytes`, carrying the sub-microsecond remainder from chunk to
    /// chunk.
    ///
    /// [`AudioFormat::duration`] floors every chunk to whole microseconds, which at 44.1 kHz drops
    /// about a third of a microsecond per 10 ms chunk and lets the timeline fall behind the sample
    /// count by roughly 115 ms an hour. `carry` holds the remainder in units of `1 / sample_rate`
    /// microseconds, so the sum of the returned durations never trails the exact playtime of the
    /// frames written by more than one microsecond.
    pub(crate) fn duration_carrying(&self, bytes: usize, carry: &mut u64) -> Duration {
        if self.sample_rate == 0 {
            return Duration::ZERO;
        }
        let frames = (bytes / self.frame_bytes()) as u64;
        let rate = u64::from(self.sample_rate);
        let total = u128::from(frames) * 1_000_000 + u128::from(*carry);
        let micros = total / u128::from(rate);
        *carry = u64::try_from(total % u128::from(rate)).unwrap_or(0);
        Duration::from_micros(u64::try_from(micros).unwrap_or(u64::MAX))
    }

    /// Returns the bytes of one interleaved frame at the nominal sample width.
    ///
    /// The width is at least one byte per sample, and [`AudioFormat::validate`] rejects a format
    /// with no channels, so this is never zero for a format a stream may announce.
    pub(crate) fn frame_bytes(&self) -> usize {
        usize::from(self.channels) * usize::from(self.bit_depth / 8).max(1)
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

/// The longest title, artist, album artist or album the metadata role allows, in UTF-8 bytes.
pub(crate) const MAX_METADATA_TEXT_BYTES: usize = 255;

/// The track a stream carries.
///
/// Every field is optional: the server forwards what the host knows and leaves the rest absent,
/// so a client shows what exists instead of an empty string. `duration` of `None` means the
/// length is unknown, which a live stream reports as `0` in the metadata state. The metadata role
/// allows at most 255 UTF-8 bytes per text field, so a longer one is cut at the last character
/// boundary that fits.
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

impl TrackInfo {
    /// Returns the track with every text field cut to the metadata role's byte limit.
    pub(crate) fn limited(mut self) -> TrackInfo {
        for text in [
            &mut self.title,
            &mut self.artist,
            &mut self.album_artist,
            &mut self.album,
        ]
        .into_iter()
        .flatten()
        {
            truncate_utf8(text, MAX_METADATA_TEXT_BYTES);
        }
        self
    }
}

/// Cuts `text` to at most `max` bytes at the last character boundary that fits.
fn truncate_utf8(text: &mut String, max: usize) {
    if text.len() <= max {
        return;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
}

/// What became of one chunk a host wrote.
///
/// A host that treats every write as accepted loses audio without noticing: the server refuses a
/// chunk it cannot schedule, holds one whose stream is not anchored yet and skips a player that
/// has no room. The outcome says which happened, and a [`WriteOutcome::Dropped`] chunk is not
/// retried, because resending audio is worse than losing it.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteOutcome {
    /// The chunk was assigned a timestamp and handed to every player that streams, or no player
    /// was streaming to hand it to.
    Written,
    /// The chunk was assigned a timestamp, but at least one streaming player did not get it:
    /// `skipped` of them are gated on their own start, still ahead of this chunk, or out of
    /// `buffer_capacity`. Those players hear a hole while the group timeline moves on. The count
    /// does not say why: a late joiner's start gate passes by itself, while a full buffer is the
    /// case a host that decodes faster than real time can act on by pacing its writes.
    Partial {
        /// How many streaming players were skipped for this chunk.
        skipped: usize,
    },
    /// The chunk is held until the group has anchored the start of the stream. A held chunk can
    /// still be lost: a seek, pause, stop, end or restart before the anchor flushes discards it,
    /// and a player that cannot take it at the flush (it joined with less room, or was gated at
    /// the deadline) is skipped; [`crate::Event::HeldAudioSkipped`] reports that. A chunk lost to a
    /// supersede is not reported again.
    Held,
    /// The chunk was refused; the error names the reason. The server never retries a
    /// refused chunk. None of them moved the timeline, but only [`WriteError::Backpressure`] is
    /// transient: the host may write the same chunk again once the anchor has flushed.
    Dropped(WriteError),
}

/// Why the server refused a chunk.
///
/// The variants describe the chunk and the stream, never its audio: a host may log one without
/// exposing what it was playing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteError {
    /// The chunk is empty or has no playtime.
    Empty,
    /// A PCM chunk does not contain a whole number of interleaved frames.
    Incomplete,
    /// The chunk is longer than the 150 ms a player must be able to buffer.
    TooLong,
    /// The queue of audio held for an anchor is full, either of one second of audio or of the
    /// framed bytes the smallest ready player can buffer, so the new chunk was dropped.
    Backpressure,
    /// The stream is open but not running: the group paused, stopped or ended it.
    Paused,
    /// The stream has ended, or none was open when the chunk was written.
    Ended,
    /// The chunk was written with the method its format does not use.
    WrongMethod,
}

impl fmt::Display for WriteError {
    /// Names the reason without exposing the audio.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "the chunk is empty or has no playtime",
            Self::Incomplete => "a PCM chunk must contain whole interleaved frames",
            Self::TooLong => "the chunk is longer than the 150 ms a player must buffer",
            Self::Backpressure => "the queue of held audio is full",
            Self::Paused => "the stream is paused",
            Self::Ended => "the stream has ended",
            Self::WrongMethod => "the chunk was written with the wrong method for its format",
        })
    }
}

impl std::error::Error for WriteError {}

/// The host's handle on one stream.
///
/// [`ServerHandle::open_stream`](crate::ServerHandle::open_stream) returns it; every call applies to
/// the whole group at once, because one server streams one format to every player. The writer
/// stamps nothing itself: [`StreamWriter::write`] hands the bytes to the group, which owns the
/// timeline and the playout timestamps.
///
/// Calls are synchronous and never wait for a client. A write only queues the chunk for the
/// connection tasks, so a client that has stopped reading cannot hold the host up; the audio
/// outstanding to a member is bounded by the `buffer_capacity` it announced, and a chunk that
/// would overrun it is skipped rather than queued.
///
/// Dropping the writer without [`StreamWriter::end`] ends the stream, so a host that returns early
/// does not leave a stream running that it can no longer feed.
///
/// The writer must not outlive the Tokio runtime that started the server either: a restart that
/// anchors a ready member arms a deadline timer on that runtime, and a timer spawned after the
/// runtime has shut down never runs. The anchor then waits for the next write or report to flush it.
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

    /// Sends one chunk of PCM audio.
    ///
    /// The chunk must carry a whole number of interleaved frames, as the negotiated format defines
    /// them; a partial frame is refused instead of shifting every later timestamp by the playtime
    /// of a frame the client cannot decode. [`StreamWriter::write_encoded`] is the call for a
    /// compressed format, where the server cannot derive the playtime from the byte count.
    ///
    /// The returned [`WriteOutcome`] says what happened: `Written` when the chunk got a timestamp
    /// and reached every streaming player, `Partial` when some were skipped, `Held` while the
    /// group anchors the start of the stream, `Dropped` with the reason otherwise.
    /// A dropped chunk is not queued for retry: bytes written to a paused or ended stream have no
    /// timeline to land on, and resending audio is worse than losing it.
    pub fn write(&mut self, bytes: &[u8]) -> WriteOutcome {
        if self.ended {
            return WriteOutcome::Dropped(WriteError::Ended);
        }
        self.group.write_audio(bytes, None)
    }

    /// Sends one chunk of encoded audio with the playtime the host decoded.
    ///
    /// The server cannot derive the playtime of a compressed chunk from its byte count, so the host
    /// supplies it; the timeline and the player buffering follow that value. The chunk must be one
    /// whole codec unit - one FLAC frame or one Opus packet, as the format states - which the server
    /// cannot check and therefore trusts. A PCM format uses [`StreamWriter::write`] instead, and the
    /// outcome is the same [`WriteOutcome`].
    pub fn write_encoded(&mut self, bytes: &[u8], duration: Duration) -> WriteOutcome {
        if self.ended {
            return WriteOutcome::Dropped(WriteError::Ended);
        }
        self.group.write_audio(bytes, Some(duration))
    }

    /// Moves the stream to `position` and drops everything the clients have buffered for it.
    ///
    /// An active group clears the players, and the next chunk is scheduled the largest reported
    /// `min_buffer_ms` + `output_delay_ms` after that `stream/clear` was transmitted, so a player
    /// that is already running can refill; a report that arrives after that instant re-leads from
    /// the current time. A seek while the group is paused sends no clear: the next `play` restarts
    /// the stream a lead ahead from the new position. A position beyond the track's known duration
    /// is clamped to the end; an unknown duration is not clamped at all.
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
    fn metadata_text_is_cut_at_a_character_boundary_within_255_bytes() {
        let track = TrackInfo {
            title: Some("a".repeat(300)),
            // 128 two-byte characters are 256 bytes: the last one does not fit.
            artist: Some("\u{e9}".repeat(128)),
            album: Some("short".to_owned()),
            ..TrackInfo::default()
        }
        .limited();
        assert_eq!(track.title.as_deref().map(str::len), Some(255));
        assert_eq!(
            track.artist.as_deref().map(str::len),
            Some(254),
            "a character that would cross the limit is dropped whole"
        );
        assert_eq!(track.album.as_deref(), Some("short"));
        assert_eq!(track.album_artist, None);
    }

    #[test]
    fn the_metadata_limit_holds_at_its_edges() {
        let mut exact = "a".repeat(255);
        truncate_utf8(&mut exact, 255);
        assert_eq!(exact.len(), 255, "exactly 255 bytes stay as they are");

        // 63 four-byte characters are 252 bytes; one more would cross the limit.
        let mut wide = "\u{1f3b5}".repeat(64);
        truncate_utf8(&mut wide, 255);
        assert_eq!(
            wide.len(),
            252,
            "a 4-byte character that crosses is dropped whole"
        );

        let mut none = "abc".to_owned();
        truncate_utf8(&mut none, 0);
        assert!(none.is_empty(), "a limit of zero leaves nothing");
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
    fn the_carried_playtime_does_not_drift_from_the_sample_count() {
        // 480 frames at 44.1 kHz are 10 884.35... us: flooring each chunk loses 0.35 us.
        let format = AudioFormat::pcm(44_100, 2, 16);
        let mut carry = 0;
        let mut total = Duration::ZERO;
        for _ in 0..1_000 {
            total += format.duration_carrying(480 * 4, &mut carry);
        }
        let exact_us = 480_000u64 * 1_000_000 / 44_100;
        assert_eq!(
            total,
            Duration::from_micros(exact_us),
            "a thousand chunks add up to the exact playtime of their frames"
        );
        let floored: Duration = (0..1_000).map(|_| format.duration(480 * 4)).sum();
        assert!(
            floored < total - Duration::from_micros(300),
            "the per-chunk floor the carry replaces falls behind"
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
