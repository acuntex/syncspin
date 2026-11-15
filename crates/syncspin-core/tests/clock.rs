//! Clock-filter behaviour: convergence, the readiness threshold, outlier weighting and reset.

use syncspin_core::clock::{ClockFilter, TimeSample, MIN_SAMPLES};

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
    let mut filter = ClockFilter::new();
    let mut local_sent_us = START_US;

    for index in 0..MIN_SAMPLES {
        assert!(!filter.is_ready(), "ready after {index} samples");
        assert_eq!(filter.now_us(local_sent_us), None);
        assert_eq!(filter.offset_us(), None);

        let sample = jittered_sample(index as i64, local_sent_us);
        let received_us = sample.client_received_us;
        filter.push(sample);
        assert_eq!(filter.sample_count(), index + 1);
        local_sent_us += SPACING_US;

        if index + 1 == MIN_SAMPLES {
            assert!(filter.is_ready(), "not ready after {MIN_SAMPLES} samples");
            assert!(filter.now_us(received_us).is_some());
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
fn reset_clears_the_estimate() {
    let (mut filter, last_received_us) = converged_filter(8);
    assert!(filter.is_ready());

    filter.reset();

    assert_eq!(filter.sample_count(), 0);
    assert!(!filter.is_ready());
    assert_eq!(filter.now_us(last_received_us), None);
    assert_eq!(filter.offset_us(), None);
}
