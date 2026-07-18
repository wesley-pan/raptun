//! Converting Quinn connection telemetry into the FEC layer's [`LinkState`].
//!
//! The FEC crate is intentionally transport-agnostic: it consumes a plain
//! [`raptun_fec::LinkState`] and never touches Quinn. This module is the bridge,
//! and it owns the one piece of state the FEC layer cannot compute on its own —
//! the **cross-tick congestion-window history** needed to tell a congestion cut
//! (window shrinking) from steady-state random loss (window stable/growing).

use raptun_fec::link::{LinkState, LossRegime};

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
}
