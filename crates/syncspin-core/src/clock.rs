//! Clock synchronisation: a two-dimensional Kalman filter over clock offset and drift.
//!
//! The filter turns `server/time` round trips into a mapping from the local monotonic clock to
//! the server clock. One exchange is a [`TimeSample`] with four timestamps, all in microseconds:
//!
//! ```text
//! client_sent_us     T1  local time when the request left
//! server_received_us T2  server time when the request arrived
//! server_sent_us     T3  server time when the answer left
//! client_received_us T4  local time when the answer arrived
//! ```
//!
//! Each sample yields one offset measurement (server clock minus local clock) and one error
//! bound for it, both in microseconds:
//!
//! ```text
//! measurement = ((T2 - T1) + (T3 - T4)) / 2
//! max_error   = ((T4 - T1) - (T3 - T2)) / 2
//! ```
//!
//! The integer arithmetic divides with truncation toward zero, as the protocol specifies. The
//! measurement enters a Kalman filter whose state is the offset and the drift (the rate at which
//! the offset changes, in microseconds per microsecond):
//!
//! * the offset performs a random walk with diffusion `PROCESS_STD_DEV` and the drift one with
//!   `DRIFT_PROCESS_STD_DEV`;
//! * the measurement variance grows with `max_error`, so a sample that crossed a stalled queue
//!   moves the estimate far less than a quick one - that is the outlier handling, and it needs no
//!   special case;
//! * once `ADAPTIVE_FORGETTING_AFTER` samples are in, a residual larger than `ADAPTIVE_CUTOFF`
//!   times the error bound inflates the covariance by `FORGET_FACTOR`², so the filter can follow a
//!   genuine step instead of treating it as noise;
//! * drift is applied to a conversion only while it is statistically significant.
//!
//! The module is pure computation: no I/O, no clock reads, no blocking. The caller owns time.

/// Offset random-walk diffusion, in µs per √µs.
const PROCESS_STD_DEV: f64 = 0.0;

/// Drift random-walk diffusion, in 1 per √µs.
const DRIFT_PROCESS_STD_DEV: f64 = 1e-11;

/// Value greater than 1 whose square scales the covariances on a large residual.
const FORGET_FACTOR: f64 = 2.0;

/// Multiple of `max_error` above which a residual counts as large.
const ADAPTIVE_CUTOFF: f64 = 3.0;

/// Scale from `max_error` to the measurement standard deviation.
const MAX_ERROR_SCALE: f64 = 0.5;

/// Ratio of `drift` to its standard deviation above which drift is applied to conversions.
const DRIFT_SIGNIFICANCE_THRESHOLD: f64 = 2.0;

/// Number of accepted samples after which adaptive forgetting may apply.
const ADAPTIVE_FORGETTING_AFTER: usize = 100;

/// Number of accepted samples [`ClockFilter`] needs before it reports an estimate.
///
/// Three is the smallest count for which every stage of the filter has run: the first sample seeds
/// the offset, the second seeds the drift, and the third performs the first full predict/correct
/// cycle. Until then the estimate is withheld rather than reported as if it were measured.
pub const MIN_SAMPLES: usize = 3;

/// The four timestamps of one round trip, in microseconds.
///
/// The two `client_*` fields come from the local monotonic clock and the two `server_*` fields
/// from the server clock; they need not share an epoch or a rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeSample {
    /// Local time when the request was sent.
    pub client_sent_us: i64,
    /// Server time when the request arrived.
    pub server_received_us: i64,
    /// Server time when the answer was sent.
    pub server_sent_us: i64,
    /// Local time when the answer arrived.
    pub client_received_us: i64,
}

/// Two-dimensional Kalman filter over clock offset and drift.
///
/// Feed it every `server/time` reply with [`ClockFilter::push`] and ask it for the matching server
/// timestamp with [`ClockFilter::now_us`]. Clone it to snapshot an estimate; the clone is
/// independent.
#[derive(Debug, Clone)]
pub struct ClockFilter {
    /// Estimated server clock minus local clock, in microseconds.
    offset: f64,
    /// Estimated rate of change of the offset, in microseconds per microsecond.
    drift: f64,
    /// Offset variance.
    p_oo: f64,
    /// Offset-drift covariance.
    p_od: f64,
    /// Drift variance.
    p_dd: f64,
    /// `client_received_us` of the last accepted sample.
    last_sample_us: i64,
    /// Accepted samples, saturating at `usize::MAX`.
    count: usize,
    /// Whether `drift` is significant enough to apply during a conversion.
    use_drift: bool,
}

impl Default for ClockFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl ClockFilter {
    /// Creates a filter with an infinite offset variance and no samples.
    pub fn new() -> Self {
        Self {
            offset: 0.0,
            drift: 0.0,
            p_oo: f64::INFINITY,
            p_od: 0.0,
            p_dd: 0.0,
            last_sample_us: 0,
            count: 0,
            use_drift: false,
        }
    }

    /// Folds one round trip into the estimate.
    ///
    /// A sample is discarded, leaving the estimate and [`ClockFilter::sample_count`] untouched,
    /// when its error bound is not positive or when it would not advance the filter in time -
    /// that is, when `client_received_us` is not later than the last accepted sample's.
    pub fn push(&mut self, sample: TimeSample) {
        let t1 = sample.client_sent_us as i128;
        let t2 = sample.server_received_us as i128;
        let t3 = sample.server_sent_us as i128;
        let t4 = sample.client_received_us as i128;

        // Integer division truncates toward zero, matching the protocol's `/ 2`.
        let measurement_i = ((t2 - t1) + (t3 - t4)) / 2;
        let max_error_i = ((t4 - t1) - (t3 - t2)) / 2;

        if sample.client_received_us <= self.last_sample_us || max_error_i <= 0 {
            return;
        }

        let measurement = measurement_i as f64;
        let max_error = max_error_i as f64;
        let dt = (sample.client_received_us - self.last_sample_us) as f64;
        self.last_sample_us = sample.client_received_us;

        // Measurement variance.
        let r = (MAX_ERROR_SCALE * max_error).powi(2);

        if self.count == 0 {
            self.offset = measurement;
            self.p_oo = r;
            self.drift = 0.0;
            self.count = 1;
            return;
        }

        if self.count == 1 {
            self.drift = (measurement - self.offset) / dt;
            self.p_dd = (self.p_oo + r) / (dt * dt);
            self.offset = measurement;
            self.p_oo = r;
            self.count = 2;
            return;
        }

        // Predict.
        let offset_p = self.offset + self.drift * dt;
        let mut p_oo_p =
            self.p_oo + 2.0 * self.p_od * dt + self.p_dd * dt * dt + PROCESS_STD_DEV.powi(2) * dt;
        let mut p_od_p = self.p_od + self.p_dd * dt;
        let mut p_dd_p = self.p_dd + DRIFT_PROCESS_STD_DEV.powi(2) * dt;

        let residual = measurement - offset_p;
        // Adaptive forgetting only starts once enough samples are behind the filter: a large
        // residual then means the offset really stepped rather than that one packet was slow.
        if self.count >= ADAPTIVE_FORGETTING_AFTER && residual.abs() > ADAPTIVE_CUTOFF * max_error {
            let scale = FORGET_FACTOR.powi(2);
            p_oo_p *= scale;
            p_od_p *= scale;
            p_dd_p *= scale;
        }

        // Correct.
        let s = p_oo_p + r;
        let k_o = p_oo_p / s;
        let k_d = p_od_p / s;
        self.offset = offset_p + k_o * residual;
        self.drift += k_d * residual;
        self.p_oo = p_oo_p - k_o * p_oo_p;
        self.p_od = p_od_p - k_d * p_oo_p;
        self.p_dd = p_dd_p - k_d * p_od_p;
        self.count = self.count.saturating_add(1);
        self.use_drift = self.drift * self.drift > DRIFT_SIGNIFICANCE_THRESHOLD.powi(2) * self.p_dd;
    }

    /// Reports whether the filter has enough samples for an estimate.
    ///
    /// True once [`MIN_SAMPLES`] samples have been accepted; the estimate it guards is
    /// [`ClockFilter::now_us`] and [`ClockFilter::offset_us`].
    pub fn is_ready(&self) -> bool {
        self.count >= MIN_SAMPLES
    }

    /// Returns the server clock reading that corresponds to the local reading `local_us`.
    ///
    /// Drift is applied only while it is statistically significant, matching the protocol.
    /// Returns `None` until the filter is ready.
    pub fn now_us(&self, local_us: i64) -> Option<i64> {
        if !self.is_ready() {
            return None;
        }
        let d = if self.use_drift { self.drift } else { 0.0 };
        Some(round_away_from_zero(
            local_us as f64 + self.offset + d * (local_us as f64 - self.last_sample_us as f64),
        ))
    }

    /// Returns the current offset estimate, server clock minus local clock, in microseconds.
    ///
    /// Rounded to the nearest microsecond, with halves away from zero. Returns `None` until the
    /// filter is ready.
    pub fn offset_us(&self) -> Option<i64> {
        if !self.is_ready() {
            return None;
        }
        Some(round_away_from_zero(self.offset))
    }

    /// Returns the number of accepted samples.
    ///
    /// Discarded samples do not count. The value saturates at `usize::MAX`.
    pub fn sample_count(&self) -> usize {
        self.count
    }

    /// Drops every sample and returns the filter to its [`ClockFilter::new`] state.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

/// Rounds to the nearest integer, with halves rounded away from zero (like the protocol).
fn round_away_from_zero(value: f64) -> i64 {
    value.round() as i64
}
