//! The sink the example streams into: it counts frames and bytes and plays nothing.
//!
//! The client schedules playout and hands a frame over at its wake time, so this sink writes it
//! immediately - which, for a counter, means adding it up - and never schedules it again. No
//! audio device is opened anywhere.

// The client flow that uses this sink is added after it; the example has no other consumer of this
// module, so the allowance covers the gap between the two steps and goes away with it.
#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::bail;
use syncspin_client::{AudioFormat, AudioFrame, Codec, Sink};
use tokio::sync::Notify;

/// Sample rate this sink plays, in hertz.
const SAMPLE_RATE: u32 = 48_000;

/// Channel count this sink plays.
const CHANNELS: u8 = 2;

/// Bits per sample this sink plays.
const BIT_DEPTH: u8 = 16;

/// What the sink counted, shared with whoever waits for the stream to arrive.
///
/// Cloning shares the counts: the sink holds one clone and the run loop the other, and both see
/// the same atomic fields.
#[derive(Clone)]
pub struct Counters {
    /// Frames written so far.
    frames: Arc<AtomicUsize>,
    /// Payload bytes written so far.
    bytes: Arc<AtomicUsize>,
    /// Wakes the waiter once the threshold frame has been counted.
    threshold: Arc<Notify>,
    /// Format of the current stream, `None` before the first `open`.
    format: Arc<Mutex<Option<AudioFormat>>>,
}

impl Counters {
    /// Waits until the sink has written the threshold frame.
    ///
    /// `Notify::notify_one` stores a permit when no waiter is registered, so a wait that starts
    /// after the threshold was reached returns at once instead of hanging.
    pub async fn wait(&self) {
        self.threshold.notified().await;
    }

    /// Frames written so far.
    pub fn frames(&self) -> usize {
        self.frames.load(Ordering::SeqCst)
    }

    /// Payload bytes written so far, summed over both frame variants.
    pub fn bytes(&self) -> usize {
        self.bytes.load(Ordering::SeqCst)
    }

    /// The format of the current stream, `None` before the first `open`.
    pub fn format(&self) -> Option<AudioFormat> {
        self.format
            .lock()
            .expect("the format lock is not poisoned")
            .clone()
    }
}

/// A sink that counts what it is handed instead of playing it.
pub struct CountingSink {
    /// Frame number that wakes the waiter.
    threshold: usize,
    /// The shared counts, one clone of which is handed to the caller of [`Self::new`].
    counters: Counters,
}

impl CountingSink {
    /// Creates a sink and the counters that observe it.
    ///
    /// The waiter is woken once, when the sink writes the `threshold`-th frame.
    pub fn new(threshold: usize) -> (CountingSink, Counters) {
        let counters = Counters {
            frames: Arc::new(AtomicUsize::new(0)),
            bytes: Arc::new(AtomicUsize::new(0)),
            threshold: Arc::new(Notify::new()),
            format: Arc::new(Mutex::new(None)),
        };
        (
            CountingSink {
                threshold,
                counters: counters.clone(),
            },
            counters,
        )
    }
}

impl Sink for CountingSink {
    fn open(&mut self, format: AudioFormat) -> anyhow::Result<()> {
        if format.codec != Codec::Pcm
            || format.sample_rate != SAMPLE_RATE
            || format.channels != CHANNELS
            || format.bit_depth != BIT_DEPTH
        {
            bail!(
                "this sink plays {SAMPLE_RATE} Hz, {CHANNELS} channels, {BIT_DEPTH}-bit `pcm`, \
                 but the stream announced {} Hz, {} channels, {}-bit `{}`",
                format.sample_rate,
                format.channels,
                format.bit_depth,
                format.codec,
            );
        }
        *self
            .counters
            .format
            .lock()
            .expect("the format lock is not poisoned") = Some(format);
        Ok(())
    }

    fn write(&mut self, frame: AudioFrame<'_>, _due: Instant) -> anyhow::Result<()> {
        // The client has already scheduled this frame, so the sink adds it up and returns: a
        // counter that buffered would delay a frame the client timed.
        let payload = match frame {
            AudioFrame::Pcm(data) => data.len(),
            AudioFrame::Encoded { data, .. } => data.len(),
        };
        self.counters.bytes.fetch_add(payload, Ordering::SeqCst);
        let frames = self.counters.frames.fetch_add(1, Ordering::SeqCst) + 1;
        if frames == self.threshold {
            // After the increment, so a waiter woken here sees the count that woke it.
            self.counters.threshold.notify_one();
        }
        Ok(())
    }

    fn flush(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    use syncspin_client::Codec;

    fn format(sample_rate: u32, channels: u8, bit_depth: u8) -> AudioFormat {
        AudioFormat::pcm(sample_rate, channels, bit_depth)
    }

    #[test]
    fn a_foreign_format_is_refused() {
        let (mut sink, _counters) = CountingSink::new(20);
        assert!(sink.open(format(44_100, 2, 16)).is_err());
        assert!(sink.open(format(48_000, 2, 16)).is_ok());
    }

    #[test]
    fn writes_are_counted_and_the_format_is_remembered() {
        let (mut sink, counters) = CountingSink::new(20);
        sink.open(format(48_000, 2, 16)).expect("the format opens");
        let chunk = vec![0u8; 3_840];
        for _ in 0..20 {
            sink.write(AudioFrame::Pcm(&chunk), Instant::now())
                .expect("the frame is accepted");
        }
        assert_eq!(counters.frames(), 20);
        assert_eq!(counters.bytes(), 20 * 3_840);
        assert_eq!(
            counters.format().map(|format| format.sample_rate),
            Some(48_000)
        );
    }

    #[test]
    fn encoded_frames_count_their_payload() {
        let (mut sink, counters) = CountingSink::new(20);
        sink.open(format(48_000, 2, 16)).expect("the format opens");
        sink.write(
            AudioFrame::Encoded {
                codec: Codec::Opus,
                data: &[0u8; 120],
            },
            Instant::now(),
        )
        .expect("the frame is accepted");
        assert_eq!(counters.frames(), 1);
        assert_eq!(counters.bytes(), 120);
    }

    #[tokio::test]
    async fn the_threshold_wakes_the_waiter() {
        let (mut sink, counters) = CountingSink::new(20);
        sink.open(format(48_000, 2, 16)).expect("the format opens");
        let chunk = vec![0u8; 3_840];
        for _ in 0..20 {
            sink.write(AudioFrame::Pcm(&chunk), Instant::now())
                .expect("the frame is accepted");
        }
        tokio::time::timeout(Duration::from_secs(1), counters.wait())
            .await
            .expect("the twentieth write wakes the waiter");
    }
}
