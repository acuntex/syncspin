//! Clock-filter behaviour: convergence, the readiness threshold, outlier weighting, the
//! server/local round trip and reset.

use syncspin_core::clock::{ClockFilter, TimeSample, READY_AFTER_SAMPLES};

/// Synthetic offset of the server clock relative to the local clock, in microseconds.
const OFFSET_US: i64 = 250_000;

/// Base one-way delay of a round trip, in microseconds.
const BASE_DELAY_US: i64 = 1_000;

/// Amplitude of the delay jitter, in microseconds; the two legs move in opposite directions.
const JITTER_US: i64 = 500;

/// Server processing time between receiving a request and sending the answer.
const PROCESSING_US: i64 = 200;

/// Time between two samples, in microseconds.
const SPACING_US: i64 = 250_000;

/// Local start time of the synthetic run, chosen well above zero like a monotonic clock.
const START_US: i64 = 1_000_000_000;

/// Drift of the synthetic server clock, in microseconds per microsecond (1000 ppm).
///
/// Large for a real crystal and deliberate: a filter that ignores the drift is off by a
/// millisecond per second, which no tolerance below can hide.
const DRIFT_PER_US: f64 = 1e-3;

/// A drift the filter cannot yet separate from its own uncertainty, in µs per µs.
///
/// Three samples leave the drift variance around 8e-6, so the significance threshold sits near
/// 2.8e-3 and 4e-3 falls below twice that. The protocol applies drift only while it is
/// significant, so the conversion must leave it out and accept the growing error instead.
const UNPROVEN_DRIFT_PER_US: f64 = 4e-3;

/// Builds one round trip against a server clock `offset_us` ahead of the local clock.
///
/// `up_us` and `down_us` are the delays of the two legs, so the measurement the filter derives
/// from this sample is `offset_us + (up_us - down_us) / 2` and its error bound is
/// `(up_us + down_us) / 2`.
fn sample(local_sent_us: i64, offset_us: i64, up_us: i64, down_us: i64) -> TimeSample {
    let server_received_us = local_sent_us + offset_us + up_us;
    let server_sent_us = server_received_us + PROCESSING_US;
    TimeSample {
        client_sent_us: local_sent_us,
        server_received_us,
        server_sent_us,
        client_received_us: server_sent_us - offset_us + down_us,
    }
}

/// Builds the `index`th sample of a run whose legs alternate by [`JITTER_US`].
fn jittered_sample(index: i64, local_sent_us: i64) -> TimeSample {
    let (up_us, down_us) = if index % 2 == 0 {
        (BASE_DELAY_US + JITTER_US, BASE_DELAY_US - JITTER_US)
    } else {
        (BASE_DELAY_US - JITTER_US, BASE_DELAY_US + JITTER_US)
    };
    sample(local_sent_us, OFFSET_US, up_us, down_us)
}

/// Builds a round trip against a server clock whose offset grows by `drift_per_us` per
/// microsecond.
///
/// Both legs carry the same delay, so the measurement is exactly the offset at `local_sent_us`
/// and its error bound is [`BASE_DELAY_US`].
fn drifting_sample(local_sent_us: i64, drift_per_us: f64) -> TimeSample {
    sample(
        local_sent_us,
        offset_at(local_sent_us, drift_per_us),
        BASE_DELAY_US,
        BASE_DELAY_US,
    )
}

/// Returns the offset a drifting server clock has at a local reading.
fn offset_at(local_us: i64, drift_per_us: f64) -> i64 {
    OFFSET_US + (drift_per_us * (local_us - START_US) as f64) as i64
}

/// Returns the server reading a drifting server clock shows at a local reading.
fn true_server_us(local_us: i64, drift_per_us: f64) -> i64 {
    local_us + offset_at(local_us, drift_per_us)
}

/// Feeds `count` jittered samples spaced [`SPACING_US`] apart into a fresh filter.
///
/// Returns the filter and the local time at which the last sample arrived.
fn converged_filter(count: usize) -> (ClockFilter, i64) {
    let mut filter = ClockFilter::new();
    let mut local_sent_us = START_US;
    let mut last_received_us = 0;
    for index in 0..count {
        let sample = jittered_sample(index as i64, local_sent_us);
        last_received_us = sample.client_received_us;
        filter.push(sample);
        local_sent_us += SPACING_US;
    }
    (filter, last_received_us)
}

#[test]
fn eight_samples_with_jitter_converge_within_two_milliseconds() {
    let (filter, last_received_us) = converged_filter(8);

    assert_eq!(filter.sample_count(), 8);
    assert!(filter.is_ready());

    let estimate = filter
        .now_us(last_received_us)
        .expect("a ready filter reports an estimate");
    assert!(
        (estimate - (last_received_us + OFFSET_US)).abs() < 2_000,
        "estimate {estimate} is not within 2 ms of {}",
        last_received_us + OFFSET_US
    );

    // The filter has to beat a single raw sample, whose measurement is off by up to the jitter.
    let error = (estimate - (last_received_us + OFFSET_US)).abs();
    assert!(
        error < JITTER_US,
        "estimate {estimate} is {error} µs off, no better than one raw sample ({JITTER_US} µs)"
    );

    let offset = filter
        .offset_us()
        .expect("a ready filter reports an offset");
    assert!(
        (offset - OFFSET_US).abs() < 2_000,
        "offset {offset} is not within 2 ms of {OFFSET_US}"
    );
}

#[test]
fn fewer_than_the_minimum_yields_no_estimate() {
    // Pin the constant: a loop that derives its bound from it passes for any value.
    assert_eq!(READY_AFTER_SAMPLES, 3);

    let mut filter = ClockFilter::new();
    let mut local_sent_us = START_US;

    for index in 0..READY_AFTER_SAMPLES {
        assert!(!filter.is_ready(), "ready after {index} samples");
        assert_eq!(filter.now_us(local_sent_us), None);
        assert_eq!(filter.offset_us(), None);

        let sample = jittered_sample(index as i64, local_sent_us);
        let received_us = sample.client_received_us;
        filter.push(sample);
        assert_eq!(filter.sample_count(), index + 1);
        local_sent_us += SPACING_US;

        if index + 1 == READY_AFTER_SAMPLES {
            assert!(
                filter.is_ready(),
                "not ready after {READY_AFTER_SAMPLES} samples"
            );
            assert!(filter.now_us(received_us).is_some());
            assert!(filter.client_time_us(received_us).is_some());
        }
    }
}

#[test]
fn an_outlier_sample_does_not_move_the_estimate_more_than_two_milliseconds() {
    let (mut filter, last_received_us) = converged_filter(8);
    let before = filter
        .now_us(last_received_us)
        .expect("a ready filter reports an estimate");

    // A 5 s stall on the answer leg: accepted, but with a huge error bound, so the filter must
    // barely weigh it.
    let outlier = sample(
        last_received_us + 1,
        OFFSET_US,
        BASE_DELAY_US,
        BASE_DELAY_US + 5_000_000,
    );
    filter.push(outlier);

    assert_eq!(
        filter.sample_count(),
        9,
        "the outlier must reach the filter, not the discard path"
    );
    let after = filter
        .now_us(last_received_us)
        .expect("a ready filter reports an estimate");
    assert!(
        (after - before).abs() < 2_000,
        "outlier moved the estimate by {} µs ({before} -> {after})",
        after - before
    );
}

#[test]
fn client_time_is_the_inverse_of_now_us() {
    let (filter, last_received_us) = converged_filter(8);
    assert!(filter.is_ready());

    for local_us in [
        last_received_us - SPACING_US,
        last_received_us,
        last_received_us + 1,
        last_received_us + 1_000_000,
        last_received_us + 60_000_000,
    ] {
        let server_us = filter
            .now_us(local_us)
            .expect("a ready filter maps local time to server time");
        let back = filter
            .client_time_us(server_us)
            .expect("a ready filter maps server time to local time");
        assert!(
            (back - local_us).abs() <= 1,
            "round trip of {local_us} µs came back as {back} µs"
        );
    }

    let not_ready = ClockFilter::new();
    assert_eq!(not_ready.client_time_us(0), None);
}

#[test]
fn reset_clears_the_estimate() {
    let (mut filter, last_received_us) = converged_filter(8);
    assert!(filter.is_ready());

    filter.reset();

    assert_eq!(filter.sample_count(), 0);
    assert!(!filter.is_ready());
    assert_eq!(filter.now_us(last_received_us), None);
    assert_eq!(filter.client_time_us(last_received_us), None);
    assert_eq!(filter.offset_us(), None);
    assert_eq!(filter.last_sample_us(), 0);
}

#[test]
fn an_out_of_order_or_impossible_sample_is_discarded() {
    let mut filter = ClockFilter::new();
    let sample = jittered_sample(0, START_US);
    filter.push(sample);
    assert_eq!(filter.sample_count(), 1);
    let accepted_at = filter.last_sample_us();
    let estimate = filter.now_us(accepted_at);

    // The same instant again does not advance the filter; it has to be later.
    filter.push(sample);
    assert_eq!(
        filter.sample_count(),
        1,
        "a sample that does not advance the local clock must be discarded"
    );
    assert_eq!(filter.last_sample_us(), accepted_at);
    assert_eq!(
        filter.now_us(accepted_at),
        estimate,
        "a discarded sample must not move the estimate"
    );

    // A round trip that claims more server processing time than it spent on the wire cannot be
    // true: its error bound is not positive, so it carries no information.
    let impossible = TimeSample {
        client_sent_us: START_US + 10_000,
        server_received_us: START_US + 10_000,
        server_sent_us: START_US + 11_000,
        client_received_us: START_US + 10_500,
    };
    assert!(filter.sample_count() >= 1);
    filter.push(impossible);
    assert_eq!(
        filter.sample_count(),
        1,
        "a non-positive error bound must not be folded in"
    );
}

#[test]
fn default_starts_from_the_same_empty_state_as_new() {
    let default = ClockFilter::default();
    let new = ClockFilter::new();
    assert_eq!(default.sample_count(), new.sample_count());
    assert_eq!(default.last_sample_us(), new.last_sample_us());
    assert_eq!(default.is_ready(), new.is_ready());
    assert_eq!(default.now_us(START_US), None);
    assert_eq!(default.client_time_us(START_US), None);
    assert_eq!(default.offset_us(), None);

    // Both accept the same first sample and derive the same estimate from it.
    let mut default = default;
    let mut new = new;
    let sample = jittered_sample(0, START_US);
    default.push(sample);
    new.push(sample);
    assert_eq!(default.sample_count(), new.sample_count());
    assert_eq!(
        default.now_us(sample.client_received_us),
        new.now_us(sample.client_received_us)
    );
}

#[test]
fn an_unproven_drift_is_not_applied_to_a_conversion() {
    // Three samples produce a drift estimate with a variance this large; the protocol applies
    // drift only while it stands out from that uncertainty. The estimate below is real - four
    // milliseconds per second - but the filter must not trust it yet: the conversion stays at the
    // last offset and trails the truth by a quarter of a second over the minute. A filter that
    // applied the drift anyway would land on the truth and hide the choice.
    let mut filter = ClockFilter::new();
    let mut local_sent_us = START_US;
    let mut last_sample = drifting_sample(local_sent_us, UNPROVEN_DRIFT_PER_US);
    for _ in 0..3 {
        last_sample = drifting_sample(local_sent_us, UNPROVEN_DRIFT_PER_US);
        filter.push(last_sample);
        local_sent_us += SPACING_US;
    }
    assert_eq!(filter.sample_count(), 3);
    assert!(filter.is_ready());

    let later = last_sample.client_received_us + 60_000_000;
    let estimate = filter
        .now_us(later)
        .expect("a ready filter reports an estimate");
    let error = estimate - true_server_us(later, UNPROVEN_DRIFT_PER_US);
    assert!(
        error < -10_000,
        "an unproven drift must not be extrapolated: the estimate should trail the truth by \
         milliseconds, it was off by {error} µs"
    );
}

#[test]
fn adaptive_forgetting_needs_the_residual_to_beat_the_error_bound() {
    // The cutoff is `ADAPTIVE_CUTOFF` times the error bound, not an absolute value: with a 100 µs
    // bound the residual has to exceed 300 µs. A step just below it stays damped, one just above
    // it is followed, so a cutoff that ignored the error bound would treat both alike.
    let below = estimate_after_a_step_of(250, 100, 3);
    let above = estimate_after_a_step_of(350, 100, 3);

    assert!(
        above > below * 3,
        "a 350 µs residual must be followed further than a 250 µs one ({above} vs {below} µs)"
    );
}

#[test]
fn a_drifting_clock_is_extrapolated_with_its_drift() {
    // A server clock that runs [`DRIFT_PER_US`] fast. Every sample is accepted, the offset grows
    // with the run, and a filter that treated the drift as noise would be 60 ms off a minute after
    // the last sample - the estimate's whole accuracy budget at that distance.
    let mut filter = ClockFilter::new();
    let mut local_sent_us = START_US;
    let mut last_sample = drifting_sample(local_sent_us, DRIFT_PER_US);
    for _ in 0..60 {
        last_sample = drifting_sample(local_sent_us, DRIFT_PER_US);
        filter.push(last_sample);
        local_sent_us += SPACING_US;
    }
    assert_eq!(filter.sample_count(), 60);
    assert!(filter.is_ready());
    // Against the sample's own timestamp, not against the accessor: a `last_sample_us` that
    // returned zero would otherwise agree with itself.
    assert_eq!(filter.last_sample_us(), last_sample.client_received_us);

    // At the last sample the estimate may be off by the wire delay, never by the drift.
    let at_sample = filter
        .now_us(last_sample.client_received_us)
        .expect("a ready filter reports an estimate");
    let expected_at_sample = true_server_us(last_sample.client_received_us, DRIFT_PER_US);
    assert!(
        (at_sample - expected_at_sample).abs() < 1_000,
        "estimate {at_sample} is more than a delay away from {expected_at_sample}"
    );

    // A minute later only the drift term carries the estimate: 60 s at 1000 ppm is 60 ms.
    let later = last_sample.client_received_us + 60_000_000;
    let extrapolated = filter
        .now_us(later)
        .expect("a ready filter keeps reporting an estimate");
    let expected_later = true_server_us(later, DRIFT_PER_US);
    assert!(
        (extrapolated - expected_later).abs() < 2_000,
        "estimate {extrapolated} missed the drifting clock at {expected_later} by {} µs",
        extrapolated - expected_later
    );

    // The inverse mapping has to return the same local reading, drift and rounding included.
    for local_us in [last_sample.client_received_us, later, later + 3_600_000_000] {
        let server_us = filter
            .now_us(local_us)
            .expect("a ready filter maps local time to server time");
        let back = filter
            .client_time_us(server_us)
            .expect("a ready filter maps server time back");
        assert!(
            (back - local_us).abs() <= 2,
            "round trip of {local_us} µs came back as {back} µs"
        );
    }
}

/// Feeds `prior` offset-zero samples, then `steps` samples whose server clock is one second
/// ahead, and returns the resulting offset estimate.
///
/// Every sample has an error bound of 100 µs and they are spaced [`SPACING_US`] apart.
fn estimate_after_a_step(prior: usize, steps: usize) -> i64 {
    estimate_after_a_step_of(1_000_000, prior, steps)
}

/// Feeds `prior` offset-zero samples, then `steps` samples whose server clock is `step_us` ahead,
/// and returns the resulting offset estimate.
///
/// Every sample has an error bound of 100 µs and they are spaced [`SPACING_US`] apart.
fn estimate_after_a_step_of(step_us: i64, prior: usize, steps: usize) -> i64 {
    let mut filter = ClockFilter::new();
    let mut local_sent_us = START_US;
    for _ in 0..prior {
        filter.push(sample(local_sent_us, 0, 100, 100));
        local_sent_us += SPACING_US;
    }
    assert_eq!(filter.sample_count(), prior);
    for _ in 0..steps {
        filter.push(sample(local_sent_us, step_us, 100, 100));
        local_sent_us += SPACING_US;
    }
    filter
        .offset_us()
        .unwrap_or_else(|| panic!("{prior} accepted samples must make the filter ready"))
}

#[test]
fn adaptive_forgetting_follows_a_step_once_enough_samples_are_in() {
    // The published cutoff is 100 accepted samples. Below it the filter treats a one-second offset
    // step as an outlier and barely moves; at the cutoff it inflates its covariance and catches up.
    // Comparing the two runs proves the branch is what makes the difference, not the step size.
    let before_cutoff = estimate_after_a_step(99, 3);
    let at_cutoff = estimate_after_a_step(100, 3);

    assert!(
        at_cutoff > 700_000,
        "after the cutoff the estimate must follow the 1 s step, got {at_cutoff} µs"
    );
    assert!(
        before_cutoff < 600_000,
        "below the cutoff the same step must still be damped, got {before_cutoff} µs"
    );
    assert!(
        at_cutoff > before_cutoff,
        "adaptive forgetting must move the estimate further than the damped path \
         ({at_cutoff} vs {before_cutoff})"
    );
}
