//! The artwork role's state machine.
//!
//! The server pushes an image as an announce followed by parts, one transfer in flight at a time
//! across the four channels. Per channel the client keeps the **current image** (what the host
//! shows) and at most one **pending image**: the most recently announced one, from its announce
//! until it becomes current. An announce discards the channel's pending image, a cancel discards it
//! as well, and a complete pending image becomes current when its server timestamp is reached. An
//! empty image (`total_size` 0) clears the channel and follows the same rules.
//!
//! The machine owns no socket and no event stream: it consumes parsed messages and reports what the
//! host must be told as [`Change`] values. Errors are the protocol errors the specification says
//! close the connection.
//!
//! Memory is bounded by the host's `max_artwork_bytes`: a transfer announced as larger is followed
//! in a discard mode that counts bytes and enforces the sequence rules but buffers nothing, and a
//! buffer is never sized from the announced total.

use std::time::Instant;

use anyhow::{bail, Result};
use syncspin_core::clock::ClockFilter;
use syncspin_core::messages::{ArtworkChannelState, ArtworkMessage, MAX_ARTWORK_CHANNELS};

use super::sched::Pending;
use crate::config::{ArtworkChannel, ArtworkSource, ImageFormat};

/// A decoded artwork image handed to the host.
#[derive(Clone, PartialEq, Eq)]
pub struct ArtworkImage {
    /// The encoding of `data`.
    pub format: ImageFormat,
    /// The encoded image, exactly as the server sent it.
    pub data: Vec<u8>,
}

impl std::fmt::Debug for ArtworkImage {
    /// Prints the format and the length, never the bytes.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ArtworkImage")
            .field("format", &self.format)
            .field("bytes", &self.data.len())
            .finish()
    }
}

/// What the host has to be told after a message or a deadline.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Change {
    /// `channel` now shows `image`.
    Show(u8, ArtworkImage),
    /// `channel` no longer shows an image.
    Clear(u8),
}

/// The transfer in flight.
struct InFlight {
    channel: usize,
    total: u64,
    received: u64,
    timestamp_us: i64,
    /// The bytes so far, or `None` in discard mode.
    data: Option<Vec<u8>>,
}

pub(crate) struct Artwork {
    declared: [Option<ArtworkChannel>; MAX_ARTWORK_CHANNELS],
    max_bytes: usize,
    stream_active: bool,
    in_flight: Option<InFlight>,
    pending: [Pending<Vec<u8>>; MAX_ARTWORK_CHANNELS],
    shown: [bool; MAX_ARTWORK_CHANNELS],
}

impl Artwork {
    pub(crate) fn new(channels: &[Option<ArtworkChannel>], max_bytes: usize) -> Self {
        let mut declared = [None; MAX_ARTWORK_CHANNELS];
        for (slot, channel) in declared.iter_mut().zip(channels) {
            *slot = *channel;
        }
        Self {
            declared,
            max_bytes,
            stream_active: false,
            in_flight: None,
            pending: [const { Pending::new() }; MAX_ARTWORK_CHANNELS],
            shown: [false; MAX_ARTWORK_CHANNELS],
        }
    }

    /// Whether an artwork stream is active: binary data outside one is discarded.
    pub(crate) fn stream_active(&self) -> bool {
        self.stream_active
    }

    /// The `channels` array of the client's `client/state`: trimmed after the last configured
    /// channel, keeping at least one entry, with explicit `none` holes in between.
    pub(crate) fn state_channels(&self) -> Vec<ArtworkChannelState> {
        let used = self
            .declared
            .iter()
            .rposition(Option::is_some)
            .map_or(1, |last| last + 1);
        self.declared[..used]
            .iter()
            .map(|channel| match channel {
                None => ArtworkChannelState::none(),
                Some(channel) => ArtworkChannelState {
                    source: match channel.source {
                        ArtworkSource::Album => "album",
                        ArtworkSource::Artist => "artist",
                    }
                    .to_owned(),
                    format: Some(
                        match channel.format {
                            ImageFormat::Jpeg => "jpeg",
                            ImageFormat::Png => "png",
                        }
                        .to_owned(),
                    ),
                    width: Some(channel.width),
                    height: Some(channel.height),
                },
            })
            .collect()
    }

    /// Handles the artwork object of a `stream/start`.
    ///
    /// The server's channels must match the declaration, with both sides padded with `none` to four
    /// entries: a truncated array is equal to one with trailing `none`s. A mismatch leaves the state
    /// alone and returns `false`.
    pub(crate) fn stream_start(&mut self, channels: &[ArtworkChannelState]) -> bool {
        if channels.len() > MAX_ARTWORK_CHANNELS {
            return false;
        }
        let wire = self.state_channels();
        for index in 0..MAX_ARTWORK_CHANNELS {
            let ours = wire
                .get(index)
                .cloned()
                .unwrap_or_else(ArtworkChannelState::none);
            let theirs = channels
                .get(index)
                .cloned()
                .unwrap_or_else(ArtworkChannelState::none);
            if ours != theirs {
                return false;
            }
        }
        self.stream_active = true;
        true
    }

    /// Ends the artwork stream: clears every channel, discards pending images and the transfer in
    /// flight, and stops accepting data until the next `stream/start`. Also the cleanup for a
    /// removed role.
    pub(crate) fn stream_end(&mut self) -> Vec<Change> {
        self.stream_active = false;
        self.in_flight = None;
        let mut changes = Vec::new();
        for (index, pending) in self.pending.iter_mut().enumerate() {
            pending.clear();
            if std::mem::take(&mut self.shown[index]) {
                changes.push(Change::Clear(index as u8));
            }
        }
        changes
    }

    /// Handles one well-formed artwork message of an active stream.
    ///
    /// # Errors
    /// The malformed sequences the specification lists: an announce while a transfer is in flight, a
    /// part with no transfer or on another channel, and a part past `total_size`.
    pub(crate) fn handle(
        &mut self,
        message: ArtworkMessage<'_>,
        clock: &ClockFilter,
        local_now_us: i64,
    ) -> Result<Vec<Change>> {
        match message {
            ArtworkMessage::Cancel { channel } => {
                let channel = usize::from(channel);
                self.pending[channel].clear();
                if self
                    .in_flight
                    .as_ref()
                    .is_some_and(|f| f.channel == channel)
                {
                    self.in_flight = None;
                }
                Ok(Vec::new())
            }
            ArtworkMessage::Announce {
                channel,
                timestamp_us,
                total_size,
            } => {
                if self.in_flight.is_some() {
                    bail!("artwork announce while a transfer is in flight");
                }
                let channel = usize::from(channel);
                self.pending[channel].clear();
                let total = u64::from(total_size);
                let keep = self.declared[channel].is_some()
                    && total <= u64::try_from(self.max_bytes).unwrap_or(u64::MAX);
                self.in_flight = Some(InFlight {
                    channel,
                    total,
                    received: 0,
                    timestamp_us,
                    data: keep.then(Vec::new),
                });
                if total == 0 {
                    return Ok(self.finish(clock, local_now_us));
                }
                Ok(Vec::new())
            }
            ArtworkMessage::Part { channel, data } => {
                let Some(flight) = self.in_flight.as_mut() else {
                    bail!("artwork part with no transfer in flight");
                };
                if flight.channel != usize::from(channel) {
                    bail!("artwork part on a channel other than the transfer in flight");
                }
                flight.received += data.len() as u64;
                if flight.received > flight.total {
                    bail!("artwork part past the announced total size");
                }
                if let Some(buffer) = flight.data.as_mut() {
                    buffer.extend_from_slice(data);
                }
                if flight.received == flight.total {
                    return Ok(self.finish(clock, local_now_us));
                }
                Ok(Vec::new())
            }
        }
    }

    /// Completes the transfer in flight: the image is offered to its channel's schedule. A
    /// transfer in discard mode completes without an image.
    fn finish(&mut self, clock: &ClockFilter, local_now_us: i64) -> Vec<Change> {
        let Some(flight) = self.in_flight.take() else {
            return Vec::new();
        };
        let Some(mut data) = flight.data else {
            return Vec::new();
        };
        // The buffer grew by appending, so it may hold up to twice its length; a pending image can
        // wait up to 20 s, so give the slack back.
        data.shrink_to_fit();
        match self.pending[flight.channel].offer(flight.timestamp_us, data, clock, local_now_us) {
            Some(data) => self.apply(flight.channel, data).into_iter().collect(),
            None => Vec::new(),
        }
    }

    /// Makes `data` the channel's current image; empty data clears it.
    fn apply(&mut self, channel: usize, data: Vec<u8>) -> Option<Change> {
        if data.is_empty() {
            return std::mem::take(&mut self.shown[channel])
                .then_some(Change::Clear(channel as u8));
        }
        let format = self.declared[channel]?.format;
        self.shown[channel] = true;
        Some(Change::Show(channel as u8, ArtworkImage { format, data }))
    }

    /// The earliest local instant a pending image is due.
    pub(crate) fn next_deadline(
        &self,
        clock: &ClockFilter,
        local_now_us: i64,
        now: Instant,
    ) -> Option<Instant> {
        self.pending
            .iter()
            .filter_map(|pending| pending.next_deadline(clock, local_now_us, now))
            .min()
    }

    /// Applies every pending image whose moment has been reached.
    pub(crate) fn fire_due(&mut self, clock: &ClockFilter, local_now_us: i64) -> Vec<Change> {
        let mut changes = Vec::new();
        for channel in 0..MAX_ARTWORK_CHANNELS {
            if let Some(data) = self.pending[channel].fire_due(clock, local_now_us) {
                changes.extend(self.apply(channel, data));
            }
        }
        changes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel(format: ImageFormat) -> Option<ArtworkChannel> {
        Some(ArtworkChannel {
            source: ArtworkSource::Album,
            format,
            width: 8,
            height: 8,
        })
    }

    fn machine(max: usize) -> Artwork {
        let mut artwork = Artwork::new(
            &[channel(ImageFormat::Png), None, channel(ImageFormat::Jpeg)],
            max,
        );
        assert!(artwork.stream_start(&artwork.state_channels()));
        artwork
    }

    fn announce(channel: u8, total_size: u32) -> ArtworkMessage<'static> {
        ArtworkMessage::Announce {
            channel,
            timestamp_us: 0,
            total_size,
        }
    }

    fn part(channel: u8, data: &[u8]) -> ArtworkMessage<'_> {
        ArtworkMessage::Part { channel, data }
    }

    fn run(artwork: &mut Artwork, message: ArtworkMessage<'_>) -> Result<Vec<Change>> {
        artwork.handle(message, &ClockFilter::new(), 0)
    }

    #[test]
    fn the_state_array_is_trimmed_and_keeps_its_holes() {
        let artwork = machine(100);
        let channels = artwork.state_channels();
        assert_eq!(channels.len(), 3);
        assert_eq!(channels[1], ArtworkChannelState::none());
        assert_eq!(channels[2].format.as_deref(), Some("jpeg"));
    }

    #[test]
    fn a_truncated_stream_start_equals_the_declaration() {
        let mut artwork = Artwork::new(&[channel(ImageFormat::Png)], 100);
        let mut wire = artwork.state_channels();
        wire.extend([ArtworkChannelState::none(), ArtworkChannelState::none()]);
        assert!(
            artwork.stream_start(&wire),
            "trailing none entries are the same as none"
        );
        let mut other = Artwork::new(&[channel(ImageFormat::Png)], 100);
        let mut wrong = other.state_channels();
        wrong[0].width = Some(9);
        assert!(
            !other.stream_start(&wrong),
            "a different size is a mismatch"
        );
        assert!(!other.stream_active());
        let mut streamed_hole = Artwork::new(&[channel(ImageFormat::Png)], 100);
        let mut extra = streamed_hole.state_channels();
        extra.push(extra[0].clone());
        assert!(
            !streamed_hole.stream_start(&extra),
            "a channel we declared none must not stream"
        );
    }

    #[test]
    fn an_image_becomes_current_when_complete() {
        let mut artwork = machine(100);
        assert!(run(&mut artwork, announce(0, 4)).unwrap().is_empty());
        assert!(run(&mut artwork, part(0, &[1, 2])).unwrap().is_empty());
        let changes = run(&mut artwork, part(0, &[3, 4])).unwrap();
        assert_eq!(
            changes,
            vec![Change::Show(
                0,
                ArtworkImage {
                    format: ImageFormat::Png,
                    data: vec![1, 2, 3, 4]
                }
            )]
        );
    }

    #[test]
    fn an_empty_image_clears_only_a_shown_channel() {
        let mut artwork = machine(100);
        assert!(
            run(&mut artwork, announce(0, 0)).unwrap().is_empty(),
            "nothing to clear"
        );
        run(&mut artwork, announce(0, 1)).unwrap();
        run(&mut artwork, part(0, &[9])).unwrap();
        assert_eq!(
            run(&mut artwork, announce(0, 0)).unwrap(),
            vec![Change::Clear(0)]
        );
    }

    #[test]
    fn the_sequence_rules_are_protocol_errors() {
        let mut artwork = machine(100);
        assert!(
            run(&mut artwork, part(0, &[1])).is_err(),
            "no transfer in flight"
        );
        run(&mut artwork, announce(0, 2)).unwrap();
        assert!(
            run(&mut artwork, announce(2, 2)).is_err(),
            "announce while in flight"
        );
        let mut artwork = machine(100);
        run(&mut artwork, announce(0, 2)).unwrap();
        assert!(run(&mut artwork, part(2, &[1])).is_err(), "another channel");
        let mut artwork = machine(100);
        run(&mut artwork, announce(0, 2)).unwrap();
        assert!(
            run(&mut artwork, part(0, &[1, 2, 3])).is_err(),
            "past the total"
        );
    }

    #[test]
    fn a_cancel_aborts_only_its_own_transfer() {
        let mut artwork = machine(100);
        run(&mut artwork, announce(0, 2)).unwrap();
        run(&mut artwork, ArtworkMessage::Cancel { channel: 2 }).unwrap();
        run(&mut artwork, part(0, &[1])).expect("a cancel elsewhere leaves the transfer running");
        run(&mut artwork, ArtworkMessage::Cancel { channel: 0 }).unwrap();
        assert!(
            run(&mut artwork, part(0, &[1])).is_err(),
            "the transfer was aborted"
        );
    }

    #[test]
    fn an_image_over_the_limit_is_counted_but_never_buffered() {
        let mut artwork = machine(3);
        run(&mut artwork, announce(0, 6)).unwrap();
        assert!(run(&mut artwork, part(0, &[0; 3])).unwrap().is_empty());
        assert!(
            run(&mut artwork, part(0, &[0; 3])).unwrap().is_empty(),
            "no event"
        );
        assert!(
            run(&mut artwork, part(0, &[0])).is_err(),
            "the sequence is still enforced"
        );
        assert!(artwork.in_flight.is_none() || artwork.in_flight.as_ref().unwrap().data.is_none());
    }

    #[test]
    fn a_stream_end_clears_everything_and_stops_the_stream() {
        let mut artwork = machine(100);
        run(&mut artwork, announce(0, 1)).unwrap();
        run(&mut artwork, part(0, &[1])).unwrap();
        run(&mut artwork, announce(2, 1)).unwrap();
        assert_eq!(artwork.stream_end(), vec![Change::Clear(0)]);
        assert!(!artwork.stream_active());
        assert!(
            artwork.in_flight.is_none(),
            "the transfer in flight is aborted"
        );
    }

    /// A ready filter whose server clock is the local one, so a stamp maps to itself.
    fn ready_clock() -> ClockFilter {
        use syncspin_core::clock::TimeSample;
        let mut clock = ClockFilter::new();
        for index in 1..=3i64 {
            let sent = index * 1_000_000;
            clock.push(TimeSample {
                client_sent_us: sent,
                server_received_us: sent + 500,
                server_sent_us: sent + 510,
                client_received_us: sent + 1_010,
            });
        }
        clock
    }

    fn timed(channel: u8, timestamp_us: i64, size: u32) -> ArtworkMessage<'static> {
        ArtworkMessage::Announce {
            channel,
            timestamp_us,
            total_size: size,
        }
    }

    #[test]
    fn a_completed_future_image_waits_and_a_cancel_removes_it() {
        let clock = ready_clock();
        let now = 10_000_000;
        let mut artwork = machine(100);
        artwork
            .handle(timed(0, now + 1_000_000, 1), &clock, now)
            .unwrap();
        assert!(
            artwork
                .handle(part(0, &[4]), &clock, now)
                .unwrap()
                .is_empty(),
            "scheduled"
        );
        assert!(artwork.fire_due(&clock, now + 999_999).is_empty());
        assert_eq!(
            artwork.fire_due(&clock, now + 1_000_000).len(),
            1,
            "shown at its time"
        );

        artwork
            .handle(timed(0, now + 5_000_000, 1), &clock, now)
            .unwrap();
        artwork.handle(part(0, &[5]), &clock, now).unwrap();
        artwork
            .handle(ArtworkMessage::Cancel { channel: 0 }, &clock, now)
            .unwrap();
        assert!(
            artwork.fire_due(&clock, now + 9_000_000).is_empty(),
            "a cancel discards it"
        );
    }

    #[test]
    fn an_announce_discards_the_pending_image_at_once() {
        let clock = ready_clock();
        let now = 10_000_000;
        let mut artwork = machine(100);
        artwork
            .handle(timed(0, now + 5_000_000, 1), &clock, now)
            .unwrap();
        artwork.handle(part(0, &[1]), &clock, now).unwrap();
        artwork
            .handle(timed(0, now + 6_000_000, 1), &clock, now)
            .unwrap();
        assert!(
            artwork.fire_due(&clock, now + 5_500_000).is_empty(),
            "the first one is gone"
        );
    }

    #[test]
    fn a_future_empty_image_schedules_its_clear() {
        let clock = ready_clock();
        let now = 10_000_000;
        let mut artwork = machine(100);
        artwork.handle(timed(0, now, 1), &clock, now).unwrap();
        artwork.handle(part(0, &[1]), &clock, now).unwrap();
        artwork
            .handle(timed(0, now + 2_000_000, 0), &clock, now)
            .unwrap();
        assert_eq!(
            artwork.fire_due(&clock, now + 2_000_000),
            vec![Change::Clear(0)]
        );
    }

    #[test]
    fn the_cap_is_inclusive() {
        let mut artwork = machine(4);
        run(&mut artwork, announce(0, 4)).unwrap();
        assert_eq!(
            run(&mut artwork, part(0, &[1; 4])).unwrap().len(),
            1,
            "total == max is kept"
        );
        let mut artwork = machine(4);
        run(&mut artwork, announce(0, 5)).unwrap();
        assert!(
            run(&mut artwork, part(0, &[1; 5])).unwrap().is_empty(),
            "max + 1 is discarded"
        );
    }
}
