//! Converting Quinn connection telemetry into the FEC layer's [`LinkState`].
//!
//! The FEC crate is intentionally transport-agnostic: it consumes a plain
//! [`raptun_fec::LinkState`] and never touches Quinn. This module is the bridge,
//! and it owns the one piece of state the FEC layer cannot compute on its own —
//! the **cross-tick congestion-window history** needed to tell a congestion cut
//! (window shrinking) from steady-state random loss (window stable/growing).

use raptun_fec::link::{LinkState, LossRegime};

/// Tracks QUIC's cumulative sent/lost packet counters across telemetry samples
/// to derive a *windowed* loss rate — loss over the interval since the last
/// sample, not over the whole connection lifetime.
///
/// The raw `lost_packets / sent_packets` ratio is cumulative and monotonic in
/// spirit: an early burst of loss permanently inflates it, so a connection that
/// long ago recovered still reports a high loss rate (a live test saw it climb
/// to ~85–92% under only ~4% real loss, and even 0% injected loss). Feeding
/// that stale figure to the adaptive FEC controller makes it read a healthy
/// link as catastrophic and pin repair at its ceiling. A per-interval delta
/// reflects what the link is doing *now*.
#[derive(Debug, Default)]
pub struct LossTracker {
    prev: Option<(u64, u64)>, // (sent, lost) at the previous sample
    /// Wall-clock time the loss-source diagnostic was last emitted. Throttles
    /// the log added to `read_telemetry`: that fn is called from a 20ms
    /// downstream tick *and* a 1s heartbeat, so a sustained high-loss run
    /// would flood the log without a per-tracker rate limit.
    last_diag: Option<std::time::Instant>,
}

impl LossTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold in the latest cumulative counters and return the loss rate over the
    /// interval since the previous call. Returns 0.0 on the first call (only
    /// establishes a baseline) or any interval with no newly-sent packets.
    pub fn window_loss(&mut self, sent: u64, lost: u64) -> f64 {
        let rate = match self.prev {
            None => 0.0,
            Some((ps, pl)) => {
                // Counters are monotonic; guard against wraparound/reset.
                let d_sent = sent.saturating_sub(ps);
                let d_lost = lost.saturating_sub(pl);
                if d_sent == 0 {
                    0.0
                } else {
                    (d_lost as f64 / d_sent as f64).clamp(0.0, 1.0)
                }
            }
        };
        self.prev = Some((sent, lost));
        rate
    }

    /// Return `true` at most once per `DIAG_INTERVAL` so the loss-source
    /// diagnostic in `read_telemetry` doesn't fire on every 20ms tick. Returns
    /// `true` (and stamps the clock) when enough time has elapsed.
    pub(crate) fn allow_diag(&mut self) -> bool {
        const DIAG_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
        let now = std::time::Instant::now();
        match self.last_diag {
            Some(t) if now.duration_since(t) < DIAG_INTERVAL => false,
            _ => {
                self.last_diag = Some(now);
                true
            }
        }
    }
}

/// Rolling classifier that turns successive telemetry samples into a
/// [`LossRegime`]. One instance per connection.
#[derive(Debug, Default)]
pub struct RegimeClassifier {
    /// Congestion window observed on the previous tick, to detect a cut.
    prev_cwnd: Option<u64>,
    /// Small EWMA of the loss rate to avoid classifying on a single noisy sample.
    smoothed_loss: f64,
}

impl RegimeClassifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one sample and get the classified regime.
    ///
    /// Rules (see design doc §"random vs congestion"):
    /// * cwnd fell meaningfully since last tick ⇒ [`LossRegime::Congestion`]
    ///   (the transport is reacting to a full link; do **not** add FEC).
    /// * negligible loss ⇒ [`LossRegime::Quiescent`].
    /// * otherwise (loss present, cwnd stable/growing) ⇒ [`LossRegime::Random`]
    ///   (FEC helps).
    pub fn classify(&mut self, cwnd_bytes: u64, loss_rate: f64) -> LossRegime {
        // EWMA the loss so a single lost packet doesn't flip the regime.
        self.smoothed_loss = self.smoothed_loss * 0.7 + loss_rate.clamp(0.0, 1.0) * 0.3;

        let regime = match self.prev_cwnd {
            // A >12.5% drop in cwnd is treated as a congestion reaction.
            Some(prev) if cwnd_bytes < prev - prev / 8 => LossRegime::Congestion,
            _ if self.smoothed_loss < 0.005 => LossRegime::Quiescent,
            _ => LossRegime::Random,
        };
        self.prev_cwnd = Some(cwnd_bytes);
        regime
    }
}

/// Snapshot of the transport, as would be read from `quinn::Connection`.
///
/// Kept as a plain struct so this module is unit-testable without a live
/// connection. `raptun-core`'s session loop fills it each tick from
/// `conn.rtt()` and `conn.stats()`.
#[derive(Debug, Clone, Copy)]
pub struct TransportSample {
    pub smoothed_rtt: std::time::Duration,
    pub rtt_var: std::time::Duration,
    pub cwnd_bytes: u64,
    pub loss_rate: f64,
}

impl RegimeClassifier {
    /// Convenience: classify a sample and package it as a [`LinkState`] ready
    /// for the FEC layer.
    pub fn to_link_state(&mut self, sample: TransportSample) -> LinkState {
        let regime = self.classify(sample.cwnd_bytes, sample.loss_rate);
        LinkState::new(
            sample.smoothed_rtt,
            sample.rtt_var,
            sample.loss_rate,
            sample.cwnd_bytes,
            regime,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cwnd_cut_is_congestion() {
        let mut c = RegimeClassifier::new();
        assert_eq!(c.classify(100_000, 0.1), LossRegime::Random);
        // cwnd cut by ~50% ⇒ congestion regardless of loss.
        assert_eq!(c.classify(50_000, 0.1), LossRegime::Congestion);
    }

    #[test]
    fn stable_cwnd_with_loss_is_random() {
        let mut c = RegimeClassifier::new();
        c.classify(100_000, 0.15);
        assert_eq!(c.classify(101_000, 0.15), LossRegime::Random);
    }

    #[test]
    fn no_loss_is_quiescent() {
        let mut c = RegimeClassifier::new();
        c.classify(100_000, 0.0);
        assert_eq!(c.classify(100_000, 0.0), LossRegime::Quiescent);
    }

    #[test]
    fn loss_tracker_is_windowed_not_cumulative() {
        let mut t = LossTracker::new();
        // First call has no prior baseline → 0.
        assert_eq!(t.window_loss(1000, 500), 0.0);
        // Next interval: 100 more sent, 4 more lost ⇒ 4% for THIS window,
        // even though the cumulative ratio is 504/1100 ≈ 46%.
        let w = t.window_loss(1100, 504);
        assert!(
            (w - 0.04).abs() < 1e-9,
            "windowed loss should be 4%, got {w}"
        );
        // A clean interval reports ~0 regardless of the ugly cumulative history.
        let w2 = t.window_loss(1200, 504);
        assert_eq!(
            w2, 0.0,
            "a loss-free window must read 0, not the cumulative rate"
        );
    }

    #[test]
    fn loss_tracker_handles_no_new_packets_and_reset() {
        let mut t = LossTracker::new();
        t.window_loss(500, 10);
        // No new packets sent this interval ⇒ 0 (avoid div-by-zero).
        assert_eq!(t.window_loss(500, 10), 0.0);
        // Counter reset (e.g. reconnect) must not panic or go negative.
        assert_eq!(t.window_loss(5, 1), 0.0);
    }
}
