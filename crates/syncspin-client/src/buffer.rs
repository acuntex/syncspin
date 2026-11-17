//! Derives the player's `min_buffer_ms` from measured arrival delay.
//!
//! The spec asks the requested minimum buffer to be sized from the upper tail of the distribution
//! of arrival delay, with measurements debounced so that only a sustained shift applies. This
//! module holds that estimator on its own: no clock, no transport and no sink, so its tests are
//! pure arithmetic.

use std::time::Duration;

/// Samples the estimator keeps in its window.
///
/// At 15-150 ms chunks this spans roughly 4-38 s of audio, the window "long enough to include
/// intermittent interference" the spec asks for.
pub(crate) const RING: usize = 256;

/// Samples the estimator needs before it derives a candidate at all.
pub(crate) const MIN_SAMPLES: usize = 128;

/// Samples between two evaluations once the window holds [`MIN_SAMPLES`].
pub(crate) const STEP: usize = 32;

/// How long after `stream/start` samples are discarded.
///
/// A start-from-empty burst is transmitted back-to-back within milliseconds, so a one-second
/// wall-clock warmup excludes it with margin. A fixed chunk count does not: a burst is tens to
/// hundreds of chunks depending on the chunk length. This is a tuning choice, not a protocol rule.
pub(crate) const WARMUP: Duration = Duration::from_secs(1);

/// Largest delay the estimator treats as a measurement, in microseconds.
///
/// A delay outside `0..=PLAUSIBLE_US` is a clock anomaly, not a buffer requirement; discarding it
/// keeps one bad mapping from pinning the estimate at its clamp. The bound is an implementation
/// guard, not a protocol rule.
pub(crate) const PLAUSIBLE_US: i64 = 60_000_000;

/// Smallest difference from the current value that counts as a change, in milliseconds.
///
/// A candidate inside this band leaves the value where it is and breaks any pending streak, so
/// measurements that flap around the current value emit nothing.
pub(crate) const HYSTERESIS_MS: u32 = 20;

/// Buffer duration a session starts with when the configuration does not pin one, in milliseconds.
///
/// The first `client/state` goes out after one clock sample, before the arrival-delay window holds
/// enough samples to derive a value, so the session reports this until it can derive one.
pub(crate) const MIN_BUFFER_MS: u32 = 250;

/// Largest buffer duration the protocol's range admits, in milliseconds.
pub(crate) const MAX_BUFFER_MS: u32 = 5_000;

/// Rolling estimate of the buffer a session should request from the server.
///
/// [`BufferEstimator::sample`] feeds one arrival-delay measurement, [`BufferEstimator::evaluate`]
/// turns the current window into a candidate when one is due, and [`BufferEstimator::value`]
/// reports the value in force.
pub(crate) struct BufferEstimator {
    /// Whether the host pinned the value, in which case every sample is discarded.
    pinned: bool,
    /// Accepted samples, oldest overwritten once the ring is full.
    samples: [i64; RING],
    /// Ring slot the next sample goes into.
    next: usize,
    /// Number of slots in use, never above [`RING`].
    len: usize,
    /// Accepted samples in total, saturating; the evaluation cadence counts on it.
    received: usize,
    /// The `received` count of the last evaluation, so a repeated call evaluates nothing new.
    last_evaluated: usize,
    /// The value in force, in milliseconds.
    current: u32,
    /// Direction of the pending streak: `1` up, `-1` down, `0` none.
    streak: i64,
}

impl BufferEstimator {
    /// Creates an estimator at the pinned value, or at [`MIN_BUFFER_MS`] when the host pinned none.
    pub(crate) fn new(pin: Option<u32>) -> Self {
        Self {
            pinned: pin.is_some(),
            samples: [0; RING],
            next: 0,
            len: 0,
            received: 0,
            last_evaluated: 0,
            current: pin.unwrap_or(MIN_BUFFER_MS),
            streak: 0,
        }
    }

    /// Feeds one arrival-delay measurement, in microseconds.
    ///
    /// A negative or implausible delay is discarded as a clock anomaly, and a pinned estimator
    /// discards every sample: the host's value is final.
    pub(crate) fn sample(&mut self, delay_us: i64) {
        if self.pinned || !(0..=PLAUSIBLE_US).contains(&delay_us) {
            return;
        }
        self.samples[self.next] = delay_us;
        self.next = (self.next + 1) % RING;
        self.len = (self.len + 1).min(RING);
        self.received = self.received.saturating_add(1);
    }

    /// Derives a candidate when one is due and applies it through the hysteresis.
    ///
    /// An evaluation is due once the window holds [`MIN_SAMPLES`] and then every [`STEP`] accepted
    /// samples. Returns the newly applied value, or `None` when nothing changes. A pinned estimator
    /// always returns `None`.
    pub(crate) fn evaluate(&mut self) -> Option<u32> {
        if self.pinned || self.received < MIN_SAMPLES || self.received == self.last_evaluated {
            return None;
        }
        if (self.received - MIN_SAMPLES) % STEP != 0 {
            return None;
        }
        self.last_evaluated = self.received;
        let candidate = candidate_ms(&self.samples[..self.len]);
        self.consider(candidate)
    }

    /// The value in force, in milliseconds.
    pub(crate) fn value(&self) -> u32 {
        self.current
    }

    /// Runs one candidate through the hysteresis, returning it when it is applied.
    ///
    /// A candidate inside [`HYSTERESIS_MS`] of the current value leaves it alone and breaks the
    /// streak. Otherwise the candidate enters a direction; the second consecutive evaluation in
    /// the same direction applies it, a direction change discards the streak.
    fn consider(&mut self, candidate: u32) -> Option<u32> {
        let delta = i64::from(candidate) - i64::from(self.current);
        if delta.abs() < i64::from(HYSTERESIS_MS) {
            self.streak = 0;
            return None;
        }
        let direction = delta.signum();
        if self.streak == direction {
            self.current = candidate;
            self.streak = 0;
            return Some(candidate);
        }
        self.streak = direction;
        None
    }
}

/// Turns a window of delays into the value it would request, clamped to the protocol's range.
fn candidate_ms(samples: &[i64]) -> u32 {
    // Samples are filtered non-negative by `sample`, so the cast and the round-up cannot wrap.
    let us = u64::try_from(p95_us(samples)).unwrap_or(u64::MAX);
    let ms = us.saturating_add(9_999) / 10_000 * 10;
    u32::try_from(ms)
        .unwrap_or(MAX_BUFFER_MS)
        .min(MAX_BUFFER_MS)
}

/// The nearest-rank 95th percentile of `samples`, in microseconds.
///
/// Nearest rank is `ceil(0.95 * n)`, the index the spec's percentile definition names; the
/// estimator keeps at least [`MIN_SAMPLES`], so the index is always inside the window.
fn p95_us(samples: &[i64]) -> i64 {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = (95 * sorted.len()).div_ceil(100);
    sorted[rank - 1]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feeds `count` samples of one delay and collects the values the evaluations applied.
    fn feed(estimator: &mut BufferEstimator, count: usize, delay_us: i64) -> Vec<u32> {
        let mut applied = Vec::new();
        for _ in 0..count {
            estimator.sample(delay_us);
            if let Some(value) = estimator.evaluate() {
                applied.push(value);
            }
        }
        applied
    }

    #[test]
    fn the_percentile_is_the_nearest_rank() {
        let values: Vec<i64> = (1..=100).collect();
        assert_eq!(p95_us(&values), 95);

        let values: Vec<i64> = (1..=20).collect();
        assert_eq!(p95_us(&values), 19);

        // ceil(0.95 * 128) - 1 = 121, so the 122nd smallest value is the percentile.
        let values: Vec<i64> = (1..=128).collect();
        assert_eq!(p95_us(&values), 122);
    }

    #[test]
    fn no_candidate_appears_before_the_minimum_sample_count() {
        let mut estimator = BufferEstimator::new(None);
        assert_eq!(
            feed(&mut estimator, MIN_SAMPLES - 1, 300_000),
            Vec::<u32>::new(),
            "a window short of its minimum must derive nothing"
        );
        assert_eq!(estimator.value(), MIN_BUFFER_MS);

        assert_eq!(
            feed(&mut estimator, 1, 300_000),
            Vec::<u32>::new(),
            "the first evaluation only enters a streak, it does not apply"
        );
        assert_eq!(estimator.value(), MIN_BUFFER_MS);

        assert_eq!(
            feed(&mut estimator, STEP, 300_000),
            [300],
            "the second same-direction evaluation applies the candidate"
        );
        assert_eq!(estimator.value(), 300);
    }

    #[test]
    fn a_pinned_estimator_never_derives() {
        let mut estimator = BufferEstimator::new(Some(400));
        assert_eq!(estimator.value(), 400);
        assert_eq!(
            feed(&mut estimator, MIN_SAMPLES + 2 * STEP, 300_000),
            Vec::<u32>::new(),
            "a pinned value must survive any number of samples"
        );
        assert_eq!(estimator.value(), 400);
    }

    #[test]
    fn a_candidate_rounds_up_to_ten_milliseconds() {
        let mut estimator = BufferEstimator::new(None);
        assert_eq!(
            feed(&mut estimator, MIN_SAMPLES + STEP, 20_001),
            [30],
            "20.001 ms rounds up to 30 ms"
        );
        assert_eq!(estimator.value(), 30);
    }

    #[test]
    fn a_candidate_is_clamped_to_the_protocol_range() {
        let mut estimator = BufferEstimator::new(None);
        assert_eq!(
            feed(&mut estimator, MIN_SAMPLES + STEP, PLAUSIBLE_US),
            [MAX_BUFFER_MS],
            "the upper plausibility bound maps to 6000 ms, which the protocol range clamps to 5000"
        );
        assert_eq!(estimator.value(), MAX_BUFFER_MS);
    }

    #[test]
    fn a_negative_or_implausible_delay_is_discarded() {
        for delay_us in [-1, PLAUSIBLE_US + 1] {
            let mut estimator = BufferEstimator::new(None);
            assert_eq!(
                feed(&mut estimator, MIN_SAMPLES + STEP, delay_us),
                Vec::<u32>::new(),
                "a delay of {delay_us} us is a clock anomaly, not a buffer requirement"
            );
            assert_eq!(estimator.value(), MIN_BUFFER_MS);
        }
    }

    #[test]
    fn an_evaluation_without_new_samples_changes_nothing() {
        let mut estimator = BufferEstimator::new(None);
        assert_eq!(
            feed(&mut estimator, MIN_SAMPLES, 300_000),
            Vec::<u32>::new()
        );
        assert_eq!(
            estimator.evaluate(),
            None,
            "a repeated evaluation must not count as a second same-direction one"
        );
        assert_eq!(estimator.value(), MIN_BUFFER_MS);
    }

    #[test]
    fn a_direction_change_discards_the_streak() {
        let mut estimator = BufferEstimator::new(None);
        assert_eq!(
            estimator.consider(300),
            None,
            "the first upward evaluation only starts a streak"
        );
        assert_eq!(
            estimator.consider(200),
            None,
            "a downward evaluation discards the upward streak"
        );
        assert_eq!(
            estimator.consider(300),
            None,
            "the discarded streak must not count towards a change"
        );
        assert_eq!(
            estimator.consider(300),
            Some(300),
            "two consecutive same-direction evaluations apply the candidate"
        );
        assert_eq!(estimator.value(), 300);
    }

    #[test]
    fn a_candidate_inside_the_hysteresis_never_applies() {
        let mut estimator = BufferEstimator::new(None);
        for candidate in [269, 269, 269, 231, 231, 231, 250, 250] {
            assert_eq!(
                estimator.consider(candidate),
                None,
                "a difference below {HYSTERESIS_MS} ms must not apply"
            );
        }
        assert_eq!(estimator.value(), MIN_BUFFER_MS);

        // Exactly the hysteresis width is a change: two evaluations apply it.
        assert_eq!(estimator.consider(270), None);
        assert_eq!(estimator.consider(270), Some(270));
        assert_eq!(estimator.value(), 270);
    }
}
