//! Scheduling of role state that carries a server timestamp.
//!
//! Metadata (and later artwork and color) arrives stamped with the server time at which it takes
//! effect. A stamp in the past or present applies at once; a stamp in the future is held until its
//! moment, and a newer one replaces the held one instead of queueing behind it. The held value keeps
//! the **server** timestamp, never a local deadline: the clock filter resynchronises every few
//! seconds and may step, so the local instant is recomputed from the current estimate whenever it
//! is asked for.
//!
//! The functions take the local wall clock reading as a parameter instead of reading it, so a test
//! can place "now" exactly.

use std::time::{Duration, Instant};

use syncspin_core::clock::ClockFilter;

/// At most one value waiting for its server timestamp.
pub(crate) struct Pending<T> {
    held: Option<(i64, T)>,
}

/// Whether `timestamp_us` is still in the future for the local clock `local_now_us`.
///
/// Without a clock estimate nothing is in the future: the specification converts "without waiting
/// for convergence", and a client that has no estimate yet shows the state at once.
fn is_future(clock: &ClockFilter, timestamp_us: i64, local_now_us: i64) -> bool {
    clock
        .client_time_us(timestamp_us)
        .is_some_and(|local_us| local_us > local_now_us)
}

impl<T> Pending<T> {
    /// An empty schedule.
    pub(crate) const fn new() -> Self {
        Self { held: None }
    }

    /// Offers `value` stamped `timestamp_us`.
    ///
    /// Returns the value when it applies now, which also discards a held update: a past or present
    /// message is how a server cancels a scheduled one. A future value replaces the held one and
    /// returns `None`.
    pub(crate) fn offer(
        &mut self,
        timestamp_us: i64,
        value: T,
        clock: &ClockFilter,
        local_now_us: i64,
    ) -> Option<T> {
        if is_future(clock, timestamp_us, local_now_us) {
            self.held = Some((timestamp_us, value));
            None
        } else {
            self.held = None;
            Some(value)
        }
    }

    /// The local instant the held value is due, from the current clock estimate, or `None` when
    /// nothing is held. A value that is already due is due `now`.
    pub(crate) fn next_deadline(
        &self,
        clock: &ClockFilter,
        local_now_us: i64,
        now: Instant,
    ) -> Option<Instant> {
        let (timestamp_us, _) = self.held.as_ref()?;
        let local_us = clock.client_time_us(*timestamp_us)?;
        let wait_us = u64::try_from(local_us.saturating_sub(local_now_us)).unwrap_or(0);
        Some(
            now.checked_add(Duration::from_micros(wait_us))
                .unwrap_or(now),
        )
    }

    /// Takes the held value if the current estimate says its moment has been reached.
    ///
    /// The check is repeated here, against the estimate as it is now, because the deadline the
    /// caller slept on was computed from an earlier one.
    pub(crate) fn fire_due(&mut self, clock: &ClockFilter, local_now_us: i64) -> Option<T> {
        let (timestamp_us, _) = self.held.as_ref()?;
        if is_future(clock, *timestamp_us, local_now_us) {
            return None;
        }
        self.held.take().map(|(_, value)| value)
    }

    /// Drops the held value, for a role that was removed or a connection that was reset.
    #[cfg(test)]
    pub(crate) fn clear(&mut self) {
        self.held = None;
    }
}

#[cfg(test)]
mod tests {
    use syncspin_core::clock::TimeSample;

    use super::*;

    /// A ready filter whose server clock is `offset_us` ahead of the local one, with symmetric
    /// 1 ms paths, so the estimate is exact.
    fn ready_clock(offset_us: i64) -> ClockFilter {
        let mut clock = ClockFilter::new();
        for index in 1..=3i64 {
            let client_sent_us = index * 1_000_000;
            let server_received_us = client_sent_us + offset_us + 500;
            let server_sent_us = server_received_us + 10;
            clock.push(TimeSample {
                client_sent_us,
                server_received_us,
                server_sent_us,
                client_received_us: server_sent_us - offset_us + 500,
            });
        }
        assert!(clock.is_ready(), "three samples make the filter ready");
        clock
    }

    const LOCAL_NOW: i64 = 10_000_000;

    #[test]
    fn a_past_or_present_stamp_applies_at_once() {
        let clock = ready_clock(0);
        let mut pending = Pending::new();
        assert_eq!(
            pending.offer(LOCAL_NOW - 1, "past", &clock, LOCAL_NOW),
            Some("past")
        );
        assert_eq!(
            pending.offer(LOCAL_NOW, "present", &clock, LOCAL_NOW),
            Some("present")
        );
    }

    #[test]
    fn a_future_stamp_waits_until_its_deadline() {
        let clock = ready_clock(0);
        let mut pending = Pending::new();
        assert_eq!(
            pending.offer(LOCAL_NOW + 2_000_000, "next", &clock, LOCAL_NOW),
            None
        );
        let now = Instant::now();
        assert_eq!(
            pending.next_deadline(&clock, LOCAL_NOW, now),
            Some(now + Duration::from_secs(2)),
            "the deadline is the stamp mapped to the local clock"
        );
        assert_eq!(
            pending.fire_due(&clock, LOCAL_NOW + 1_999_999),
            None,
            "not yet"
        );
        assert_eq!(
            pending.fire_due(&clock, LOCAL_NOW + 2_000_000),
            Some("next")
        );
        assert_eq!(
            pending.fire_due(&clock, LOCAL_NOW + 3_000_000),
            None,
            "fires once"
        );
    }

    #[test]
    fn a_newer_future_stamp_replaces_the_held_one() {
        let clock = ready_clock(0);
        let mut pending = Pending::new();
        pending.offer(LOCAL_NOW + 5_000_000, "first", &clock, LOCAL_NOW);
        pending.offer(LOCAL_NOW + 1_000_000, "second", &clock, LOCAL_NOW);
        assert_eq!(
            pending.fire_due(&clock, LOCAL_NOW + 6_000_000),
            Some("second")
        );
        assert_eq!(pending.fire_due(&clock, LOCAL_NOW + 6_000_000), None);
    }

    #[test]
    fn a_past_stamp_cancels_the_held_one() {
        let clock = ready_clock(0);
        let mut pending = Pending::new();
        pending.offer(LOCAL_NOW + 5_000_000, "scheduled", &clock, LOCAL_NOW);
        assert_eq!(
            pending.offer(LOCAL_NOW - 5, "current", &clock, LOCAL_NOW),
            Some("current")
        );
        assert_eq!(
            pending.fire_due(&clock, LOCAL_NOW + 9_000_000),
            None,
            "the schedule is gone"
        );
        assert_eq!(
            pending.next_deadline(&clock, LOCAL_NOW, Instant::now()),
            None
        );
    }

    #[test]
    fn without_a_clock_estimate_everything_applies_at_once() {
        let clock = ClockFilter::new();
        let mut pending = Pending::new();
        assert_eq!(
            pending.offer(i64::MAX, "far future", &clock, LOCAL_NOW),
            Some("far future")
        );
    }

    #[test]
    fn the_deadline_follows_a_step_of_the_clock_estimate() {
        let mut pending = Pending::new();
        let server_stamp = LOCAL_NOW + 2_000_000;
        pending.offer(server_stamp, "next", &ready_clock(0), LOCAL_NOW);
        let now = Instant::now();
        // The server clock turns out to be 1 s ahead: the same server stamp is 1 s sooner.
        let stepped = ready_clock(1_000_000);
        assert_eq!(
            pending.next_deadline(&stepped, LOCAL_NOW, now),
            Some(now + Duration::from_secs(1))
        );
        // And a step the other way moves it later, so a value is not fired early on the old one.
        let back = ready_clock(-1_000_000);
        assert_eq!(pending.fire_due(&back, LOCAL_NOW + 2_000_000), None);
        assert_eq!(pending.fire_due(&back, LOCAL_NOW + 3_000_000), Some("next"));
    }

    #[test]
    fn clear_drops_the_held_value() {
        let clock = ready_clock(0);
        let mut pending = Pending::new();
        pending.offer(LOCAL_NOW + 1_000_000, "held", &clock, LOCAL_NOW);
        pending.clear();
        assert_eq!(pending.fire_due(&clock, LOCAL_NOW + 9_000_000), None);
    }
}
