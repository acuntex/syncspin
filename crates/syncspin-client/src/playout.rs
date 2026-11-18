//! The client's playout queue.
//!
//! The session maps a server timestamp to a local deadline and hands the frame to this queue; the
//! queue keeps the frames ordered by that deadline and hands them back when they are due. It owns
//! the bytes - a borrowed [`AudioFrame`] cannot outlive the chunk it was parsed from - and for an
//! encoded frame it keeps the codec too, because a passthrough frame cannot be rebuilt from its
//! bytes alone.
//!
//! The queue is pure: [`Instant`] values and a `now` parameter, no timer, no transport and no
//! session state. The rows in the test module therefore use fixed instants and never sleep.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::sink::{AudioFrame, Codec};

/// Bytes the server advertises as its buffer capacity, and the bound this queue holds itself to.
pub(crate) const BUFFER_CAPACITY: u64 = 131_072;

/// Bytes every chunk costs before its payload: the fixed header of a player audio chunk, one
/// message-id byte, an 8-byte timestamp and a 4-byte send-ahead (`AudioChunkHeader::LEN`).
const CHUNK_HEADER_BYTES: u64 = 13;

/// One audio frame owned by the queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OwnedFrame {
    /// Raw PCM samples, in the layout the open stream announced.
    Pcm(Vec<u8>),
    /// One encoded frame; the codec travels with it because a passthrough sink needs the name.
    Encoded {
        /// Codec the data is encoded with.
        codec: Codec,
        /// Encoded bytes.
        data: Vec<u8>,
    },
}

impl OwnedFrame {
    /// Borrows the frame for a [`crate::Sink::write`] call.
    pub(crate) fn as_frame(&self) -> AudioFrame<'_> {
        match self {
            Self::Pcm(data) => AudioFrame::Pcm(data),
            Self::Encoded { codec, data } => AudioFrame::Encoded {
                codec: codec.clone(),
                data,
            },
        }
    }

    /// Bytes this frame costs in the queue: the chunk header plus the payload.
    fn bytes(&self) -> u64 {
        let payload = match self {
            Self::Pcm(data) => data.len(),
            Self::Encoded { data, .. } => data.len(),
        };
        CHUNK_HEADER_BYTES + u64::try_from(payload).unwrap_or(u64::MAX)
    }
}

/// One frame waiting for its deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Queued {
    /// Server timestamp the frame was mapped from, unchanged.
    ///
    /// The cut of [`PlayoutQueue::discard_from`] uses it: a clock update moves deadlines, so only
    /// the stamp says what a `stream/clear` asked to discard.
    pub(crate) server_us: i64,
    /// Local instant at which the first sample should reach the audio port.
    pub(crate) due: Instant,
    /// The frame itself.
    pub(crate) frame: OwnedFrame,
}

/// Frames one [`PlayoutQueue::push`] dropped, and how late they were.
///
/// A push reports at most two entries: one for a late frame and one for the frames a capacity
/// overrun evicted. The caller sums `count` and takes the largest `late_by`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Dropped {
    /// How far past its deadline the frame was; zero for a capacity eviction.
    pub(crate) late_by: Duration,
    /// Number of frames this entry accounts for.
    pub(crate) count: u64,
}

/// Frames ordered by playout deadline, bounded in bytes.
pub(crate) struct PlayoutQueue {
    /// Frames ordered by [`Queued::due`], earliest first.
    frames: VecDeque<Queued>,
    /// Bytes in use, each frame costing its header plus payload.
    len_bytes: u64,
    /// Bound in bytes.
    capacity_bytes: u64,
    /// Lateness the queue tolerates before it drops a frame.
    late: Duration,
}

impl PlayoutQueue {
    /// Creates an empty queue bounded to `capacity_bytes` and tolerating `late` of lateness.
    pub(crate) fn new(capacity_bytes: u64, late: Duration) -> Self {
        Self {
            frames: VecDeque::new(),
            len_bytes: 0,
            capacity_bytes,
            late,
        }
    }

    /// Queues a frame, reading the clock once for the lateness check.
    ///
    /// Returns the frames this call dropped: the frame itself when it is already at or beyond the
    /// lateness tolerance, and the oldest queued frames a capacity overrun evicted to make room.
    pub(crate) fn push(&mut self, server_us: i64, due: Instant, frame: OwnedFrame) -> Vec<Dropped> {
        self.push_at(Instant::now(), server_us, due, frame)
    }

    /// Queues a frame as of `now`, the injectable-clock form of [`Self::push`].
    ///
    /// A frame is late when its deadline is at or before `now - late`; it is dropped, never moved
    /// forward, because playing it late would break the sync it was scheduled for. A chunk larger
    /// than the whole bound is dropped on its own. Otherwise the oldest frames go until the new
    /// frame fits. Frames with equal deadlines keep their arrival order.
    ///
    /// The tolerance is compared with the port deadline alone. The sink's pre-port delay lives in
    /// the session, which applies the stricter `due - pre_port` cut before it enqueues; this check
    /// stays as the queue's own guard.
    fn push_at(
        &mut self,
        now: Instant,
        server_us: i64,
        due: Instant,
        frame: OwnedFrame,
    ) -> Vec<Dropped> {
        let bytes = frame.bytes();
        let mut dropped = Vec::new();

        if let Some(lateness) = now.checked_duration_since(due) {
            if lateness >= self.late {
                dropped.push(Dropped {
                    late_by: lateness,
                    count: 1,
                });
                return dropped;
            }
        }

        // The oversize check comes before the drain: a frame that can never fit must not cost the
        // queue a healthy frame.
        if bytes > self.capacity_bytes {
            dropped.push(Dropped {
                late_by: Duration::ZERO,
                count: 1,
            });
            return dropped;
        }

        let mut evicted = 0u64;
        while self.len_bytes > self.capacity_bytes - bytes {
            let Some(front) = self.frames.pop_front() else {
                break;
            };
            self.len_bytes = self.len_bytes.saturating_sub(front.frame.bytes());
            evicted += 1;
        }
        if evicted > 0 {
            dropped.push(Dropped {
                late_by: Duration::ZERO,
                count: evicted,
            });
        }

        let index = self.frames.partition_point(|queued| queued.due <= due);
        self.frames.insert(
            index,
            Queued {
                server_us,
                due,
                frame,
            },
        );
        self.len_bytes += bytes;
        dropped
    }

    /// Removes and returns every frame due at or before `now`, in deadline order.
    ///
    /// Lateness is not judged here and nothing is counted: a frame that is merely due is handed
    /// over with the deadline it was queued with, and the caller decides what to write.
    pub(crate) fn pop_due(&mut self, now: Instant) -> Vec<Queued> {
        let mut popped = Vec::new();
        while self.frames.front().is_some_and(|front| front.due <= now) {
            let Some(queued) = self.frames.pop_front() else {
                break;
            };
            self.len_bytes = self.len_bytes.saturating_sub(queued.frame.bytes());
            popped.push(queued);
        }
        popped
    }

    /// Drops every frame whose server timestamp is at or after `server_us`, returning how many.
    ///
    /// The cut is by server timestamp, not by local deadline: a clock update moves deadlines, so
    /// only the stamp identifies what a `stream/clear` asked to discard.
    pub(crate) fn discard_from(&mut self, server_us: i64) -> usize {
        let mut removed = 0usize;
        let mut removed_bytes = 0u64;
        self.frames.retain(|queued| {
            if queued.server_us < server_us {
                return true;
            }
            removed += 1;
            removed_bytes += queued.frame.bytes();
            false
        });
        self.len_bytes = self.len_bytes.saturating_sub(removed_bytes);
        removed
    }

    /// Drops every frame and returns how many there were.
    pub(crate) fn clear(&mut self) -> usize {
        let count = self.frames.len();
        self.frames.clear();
        self.len_bytes = 0;
        count
    }

    /// Bytes in use, each frame costing its 13-byte chunk header plus its payload.
    pub(crate) fn len_bytes(&self) -> u64 {
        self.len_bytes
    }

    /// The earliest deadline in the queue.
    pub(crate) fn next_due(&self) -> Option<Instant> {
        self.frames.front().map(|queued| queued.due)
    }

    /// Recomputes every deadline from its server timestamp with `mapper`, then re-sorts.
    ///
    /// The mapper the session passes is monotonic, so the order normally survives; the sort keeps
    /// the queue ordered even when it does not.
    pub(crate) fn remap<F>(&mut self, mut mapper: F)
    where
        F: FnMut(i64) -> Instant,
    {
        for queued in &mut self.frames {
            queued.due = mapper(queued.server_us);
        }
        // `VecDeque` has no stable sort of its own; the contiguous slice does, and the queue is
        // small enough that the rotation it may cost is irrelevant.
        self.frames
            .make_contiguous()
            .sort_by_key(|queued| queued.due);
    }

    /// Whether the queue holds no frame.
    pub(crate) fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lateness tolerance the session passes.
    const LATE: Duration = Duration::from_millis(10);

    /// Bytes a chunk with `payload` bytes costs in the queue.
    ///
    /// The `13` is the wire header spelled out on purpose: the rows pin the accounting the protocol
    /// defines, not whatever constant the queue happens to hold.
    fn chunk_bytes(payload: usize) -> u64 {
        13 + u64::try_from(payload).expect("a test payload fits in a u64")
    }

    fn pcm_frame(payload: usize) -> OwnedFrame {
        OwnedFrame::Pcm(vec![0; payload])
    }

    fn new_queue() -> PlayoutQueue {
        PlayoutQueue::new(BUFFER_CAPACITY, LATE)
    }

    fn stamps(queued: &[Queued]) -> Vec<i64> {
        queued.iter().map(|queued| queued.server_us).collect()
    }

    fn dues(queued: &[Queued]) -> Vec<Instant> {
        queued.iter().map(|queued| queued.due).collect()
    }

    #[test]
    fn frames_are_ordered_by_deadline() {
        let base = Instant::now();
        let mut queue = new_queue();
        for (server_us, millis) in [(1, 30), (2, 10), (3, 20)] {
            let dropped = queue.push_at(
                base,
                server_us,
                base + Duration::from_millis(millis),
                pcm_frame(4),
            );
            assert!(dropped.is_empty(), "a future frame is queued, not dropped");
        }
        assert_eq!(queue.len_bytes(), 3 * chunk_bytes(4));

        let queued = queue.pop_due(base + Duration::from_millis(100));
        assert_eq!(
            stamps(&queued),
            [2, 3, 1],
            "frames leave in deadline order, not arrival order"
        );
        assert_eq!(
            dues(&queued),
            [
                base + Duration::from_millis(10),
                base + Duration::from_millis(20),
                base + Duration::from_millis(30),
            ]
        );
        assert_eq!(queue.len_bytes(), 0, "a popped frame releases its bytes");
        assert!(queue.is_empty());
    }

    #[test]
    fn a_frame_before_the_tolerance_is_due() {
        let now = Instant::now();
        let mut queue = new_queue();
        let due = now - Duration::from_millis(9);

        let dropped = queue.push_at(now, 1, due, pcm_frame(4));
        assert!(
            dropped.is_empty(),
            "9 ms of lateness is inside the 10 ms tolerance"
        );

        let queued = queue.pop_due(now);
        assert_eq!(queued.len(), 1, "a frame inside the tolerance is due now");
        assert_eq!(queued[0].due, due, "the deadline is kept, never advanced");
        assert_eq!(queue.len_bytes(), 0);
    }

    #[test]
    fn a_frame_after_the_tolerance_is_dropped() {
        let now = Instant::now();
        let mut queue = new_queue();
        for millis in [10, 250] {
            let dropped = queue.push_at(now, 1, now - Duration::from_millis(millis), pcm_frame(4));
            assert_eq!(
                dropped,
                [Dropped {
                    late_by: Duration::from_millis(millis),
                    count: 1
                }],
                "{millis} ms past the deadline is at or beyond the tolerance"
            );
        }
        assert!(queue.is_empty(), "a late frame must not be queued");
        assert_eq!(queue.len_bytes(), 0);

        // The shipped entry point reads the clock itself.
        let dropped = queue.push(1, Instant::now() - Duration::from_secs(1), pcm_frame(4));
        assert_eq!(dropped.len(), 1, "a stale frame is reported once");
        assert_eq!(dropped[0].count, 1);
        assert!(
            dropped[0].late_by >= Duration::from_secs(1),
            "the report carries how late the frame was"
        );
        assert!(queue.is_empty());
    }

    #[test]
    fn an_oversize_chunk_is_dropped_alone() {
        let base = Instant::now();
        let mut queue = PlayoutQueue::new(chunk_bytes(40), LATE);
        assert!(queue
            .push_at(base, 1, base + Duration::from_millis(10), pcm_frame(40))
            .is_empty());

        let dropped = queue.push_at(base, 2, base + Duration::from_millis(20), pcm_frame(41));
        assert_eq!(
            dropped,
            [Dropped {
                late_by: Duration::ZERO,
                count: 1
            }],
            "a chunk larger than the whole bound is dropped on its own"
        );
        assert_eq!(
            queue.len_bytes(),
            chunk_bytes(40),
            "the oversize chunk must not drain the healthy queue"
        );
        assert_eq!(stamps(&queue.pop_due(base + Duration::from_secs(1))), [1]);
    }

    #[test]
    fn an_overrun_drops_oldest_until_it_fits() {
        let base = Instant::now();
        let capacity = 3 * chunk_bytes(10);
        let mut queue = PlayoutQueue::new(capacity, LATE);
        for (server_us, millis) in [(1, 10), (2, 20), (3, 30)] {
            assert!(queue
                .push_at(
                    base,
                    server_us,
                    base + Duration::from_millis(millis),
                    pcm_frame(10)
                )
                .is_empty());
        }

        // The fourth frame fits only after the oldest one goes.
        let dropped = queue.push_at(base, 4, base + Duration::from_millis(40), pcm_frame(10));
        assert_eq!(
            dropped,
            [Dropped {
                late_by: Duration::ZERO,
                count: 1
            }]
        );
        assert_eq!(queue.len_bytes(), capacity);
        assert_eq!(
            queue.next_due(),
            Some(base + Duration::from_millis(20)),
            "the oldest frame went first"
        );

        // A frame that needs room for two evicts two.
        let dropped = queue.push_at(base, 5, base + Duration::from_millis(50), pcm_frame(30));
        assert_eq!(
            dropped,
            [Dropped {
                late_by: Duration::ZERO,
                count: 2
            }]
        );
        assert_eq!(
            queue.len_bytes(),
            chunk_bytes(10) + chunk_bytes(30),
            "the surviving frames and the new one fill the bound"
        );
        assert_eq!(
            stamps(&queue.pop_due(base + Duration::from_secs(1))),
            [4, 5],
            "the remaining frames keep their order"
        );
    }

    #[test]
    fn discard_from_keeps_the_prefix_by_server_stamp() {
        let base = Instant::now();
        let mut queue = new_queue();
        // The deadlines deliberately do not follow the server stamps: the cut is by stamp.
        for (server_us, millis) in [(10, 30), (20, 10), (30, 20)] {
            assert!(queue
                .push_at(
                    base,
                    server_us,
                    base + Duration::from_millis(millis),
                    pcm_frame(10)
                )
                .is_empty());
        }

        assert_eq!(
            queue.discard_from(20),
            2,
            "the frames at or after the cut go"
        );
        assert_eq!(queue.len_bytes(), chunk_bytes(10));
        assert_eq!(
            queue.discard_from(11),
            0,
            "a cut after the only remaining stamp keeps it"
        );

        let queued = queue.pop_due(base + Duration::from_secs(1));
        assert_eq!(
            stamps(&queued),
            [10],
            "the prefix before the cut stays, even though it has the latest deadline"
        );

        let mut queue = new_queue();
        assert!(queue
            .push_at(base, 10, base + Duration::from_millis(10), pcm_frame(10))
            .is_empty());
        assert_eq!(
            queue.discard_from(10),
            1,
            "a stamp exactly at the cut is discarded"
        );
        assert!(queue.is_empty());
    }

    #[test]
    fn clear_returns_the_count() {
        let base = Instant::now();
        let mut queue = new_queue();
        assert_eq!(queue.clear(), 0, "an empty queue clears nothing");

        for (server_us, millis) in [(1, 10), (2, 20), (3, 30)] {
            assert!(queue
                .push_at(
                    base,
                    server_us,
                    base + Duration::from_millis(millis),
                    pcm_frame(4)
                )
                .is_empty());
        }
        assert_eq!(queue.clear(), 3);
        assert!(queue.is_empty());
        assert_eq!(queue.len_bytes(), 0);
        assert_eq!(queue.next_due(), None);
    }

    #[test]
    fn remap_moves_every_deadline() {
        let base = Instant::now();
        let mut queue = new_queue();
        for (server_us, seconds) in [(1_000, 1), (2_000, 2)] {
            assert!(queue
                .push_at(
                    base,
                    server_us,
                    base + Duration::from_secs(seconds),
                    pcm_frame(2)
                )
                .is_empty());
        }
        let before = queue.len_bytes();

        // The session's map is monotonic: a new clock estimate moves a later stamp no earlier.
        queue.remap(|server_us| {
            base + Duration::from_millis(u64::try_from(server_us / 100).unwrap_or_default())
        });

        assert_eq!(queue.len_bytes(), before, "remap moves no bytes");
        assert_eq!(queue.next_due(), Some(base + Duration::from_millis(10)));
        let queued = queue.pop_due(base + Duration::from_secs(3));
        assert_eq!(
            dues(&queued),
            [
                base + Duration::from_millis(10),
                base + Duration::from_millis(20),
            ],
            "every deadline comes from the mapper"
        );
        assert_eq!(
            stamps(&queued),
            [1_000, 2_000],
            "the server stamp the cut uses is unchanged"
        );
    }

    #[test]
    fn next_due_is_the_earliest() {
        let base = Instant::now();
        let mut queue = new_queue();
        assert_eq!(queue.next_due(), None, "an empty queue has no deadline");

        queue.push_at(base, 1, base + Duration::from_millis(30), pcm_frame(2));
        queue.push_at(base, 2, base + Duration::from_millis(10), pcm_frame(2));
        assert_eq!(queue.next_due(), Some(base + Duration::from_millis(10)));

        assert_eq!(
            stamps(&queue.pop_due(base + Duration::from_millis(10))),
            [2],
            "only the due frame is handed over"
        );
        assert_eq!(
            queue.next_due(),
            Some(base + Duration::from_millis(30)),
            "the remaining frame is next"
        );

        assert_eq!(queue.pop_due(base + Duration::from_millis(30)).len(), 1);
        assert_eq!(queue.next_due(), None);
    }

    #[test]
    fn a_zero_capacity_drops_everything() {
        let base = Instant::now();
        let mut queue = PlayoutQueue::new(0, LATE);
        let dropped = queue.push_at(base, 1, base + Duration::from_millis(10), pcm_frame(0));
        assert_eq!(
            dropped,
            [Dropped {
                late_by: Duration::ZERO,
                count: 1
            }],
            "not even an empty payload fits a zero-byte bound"
        );
        assert!(queue.is_empty());
        assert_eq!(queue.len_bytes(), 0);
        assert_eq!(queue.next_due(), None);
    }

    #[test]
    fn an_encoded_frame_keeps_its_codec() {
        let base = Instant::now();
        let mut queue = new_queue();
        let codec = Codec::Other("future".to_owned());
        queue.push_at(
            base,
            1,
            base + Duration::from_millis(10),
            OwnedFrame::Encoded {
                codec: codec.clone(),
                data: vec![1, 2, 3],
            },
        );

        let queued = queue.pop_due(base + Duration::from_millis(10));
        assert_eq!(
            queued[0].frame.as_frame(),
            AudioFrame::Encoded {
                codec,
                data: &[1, 2, 3],
            },
            "a passthrough frame needs the codec it arrived with"
        );

        queue.push_at(
            base,
            2,
            base + Duration::from_millis(20),
            OwnedFrame::Pcm(vec![9, 8]),
        );
        let queued = queue.pop_due(base + Duration::from_millis(20));
        assert_eq!(queued[0].frame.as_frame(), AudioFrame::Pcm(&[9, 8]));
    }
}
