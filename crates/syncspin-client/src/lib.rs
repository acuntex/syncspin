//! Client side of Sendspin.
//!
//! This crate owns the session: it connects to a server, runs the Noise handshake, keeps a clock
//! estimate and feeds audio to a sink the host provides. It stays device agnostic - the
//! application that owns the speakers implements [`Sink`] and decides what playout means.
//!
//! A connection always ends in Noise: the client refuses a server that does not complete the
//! handshake and never falls back to cleartext. A successful attempt reports [`Event::Connected`]
//! and then one event per change; an attempt that ends reports [`Event::Disconnected`] with the
//! delay before the next one, and the crate reconnects on its own with the same sink and identity.
//!
//! [`connect`] validates the configuration and spawns the connection; the first attempt and every
//! retry run in that task and reach the caller through the [`EventStream`]. Only an invalid
//! configuration or an address this build cannot use returns an error - an unreachable server is
//! reported as [`Event::Disconnected`]. The [`ClientHandle`] waits for the connection to end and
//! hands out a [`ControlHandle`] for transport commands, the volume level and mute state. The level
//! follows [`ClientConfig::volume_policy`] - see [`clamp_volume_with`], and [`clamp_volume`] for the
//! default - and the value the server receives is the applied one. [`ClientConfig::volume`] and
//! [`ClientConfig::muted`] are the level and mute state the first report carries, so a host passes
//! the values it restored instead of letting the server see a baseline the output is not at.
//! [`ControlHandle::report_volume`] is the other direction: a level the host reads from its own
//! output is recorded and sent unchanged, because the policy limits requests rather than the level
//! the device is at.
//!
//! [`ClientConfig::device_info`] describes the device the client runs on and is announced in
//! `client/hello`; a host without an answer passes `None` and the server sees only the player name.
//!
//! Pairing records and the long-lived pairing PSK belong to the host: it implements
//! [`storage::Storage`] and the client keeps what it restores, so a paired server is recognised
//! across restarts. The crate does no file I/O of its own; `storage::FileStorage` is an optional
//! JSON backend behind the `storage-file` feature for a host that wants one.
//!
//! A host that renders the stream sees its lifecycle as events: [`Event::StreamStart`] for a new
//! format, [`Event::StreamEnd`] when the server pauses or removes the player role, and
//! [`Event::StreamClear`] for a seek, plus [`Event::Track`] for the now-playing metadata with its
//! position, duration and playback speed. The end and clear events arrive before the sink is
//! flushed, so the host can mute, stop or restart its output first.
//!
//! The connection keeps running until the audio sink fails, which the host has to repair, or until
//! the handle or the event stream is dropped.

mod client;
mod config;
mod session;
mod sink;

pub mod storage;

pub use client::{
    clamp_volume, clamp_volume_with, connect, connect_with_psks, next_backoff, Client,
    ClientHandle, ControlHandle, Event, EventStream, PlaybackState, StreamEndReason,
    INITIAL_BACKOFF, NORMAL_PLAYBACK_SPEED,
};
pub use config::{
    AudioMode, ClientConfig, DeviceInfo, PskCategory, StoredPsk, VolumePolicy, MAX_PLAYER_NAME_LEN,
};
pub use sink::{AudioFormat, AudioFrame, Codec, Sink};

// The identity is part of [`ClientConfig`], so a host that builds a configuration needs it. A
// re-export keeps a consumer from having to depend on the protocol crate directly.
pub use syncspin_core::noise::Identity;

/// Returns the version of this crate as recorded in its manifest.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Shared test doubles for the unit tests in this crate.

    use std::time::Instant;

    use crate::sink::{AudioFormat, AudioFrame, Sink};

    /// A sink that accepts every call and keeps the trait's default latency and underrun count.
    pub(crate) struct NullSink;

    impl Sink for NullSink {
        fn open(&mut self, _format: AudioFormat) -> anyhow::Result<()> {
            Ok(())
        }

        fn write(&mut self, _frame: AudioFrame<'_>, _due: Instant) -> anyhow::Result<()> {
            Ok(())
        }

        fn flush(&mut self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn the_test_sink_reports_the_trait_defaults() {
        let mut sink = NullSink;
        sink.open(AudioFormat {
            codec: crate::Codec::Pcm,
            sample_rate: 48_000,
            channels: 2,
            bit_depth: 16,
            codec_header: None,
        })
        .expect("the test sink accepts a format");
        sink.write(AudioFrame::Pcm(&[1, 2]), Instant::now())
            .expect("the test sink accepts a frame");
        sink.flush().expect("the test sink flushes");
        assert_eq!(
            sink.latency(),
            None,
            "a sink that does not report a delay adds none"
        );
        assert_eq!(
            sink.underruns(),
            0,
            "a sink that does not count underruns reports none"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_the_workspace_version() {
        assert_eq!(version(), "0.1.0");
    }
}
