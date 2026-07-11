//! [`LinkState`] — a snapshot of live transport telemetry, plus the loss-regime
//! classifier that drives every adaptive decision in the FEC layer.
//!
//! In production these fields are populated from Quinn's `Connection::stats()`
//! and `Connection::rtt()` once per control tick. The struct is deliberately
//! plain data (no Quinn types) so the FEC crate stays transport-agnostic and
//! trivially testable — `raptun-core` does the translation from Quinn into this
//! shape.

use std::time::Duration;

/// Which loss regime the link is currently in. This classification decides
/// whether the [`crate::strategy::FecStrategy`] adds or removes redundancy, and
/// whether the [`crate::decoder`] is allowed to request repair at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossRegime {
    /// Losses are occurring but the congestion window is stable or growing:
    /// the loss is (probabilistically) random, not the link being full. FEC
    /// helps here.
    Random,
    /// The congestion window is being cut — the transport is reacting to
    /// congestion. Adding FEC redundancy now makes things worse.
    Congestion,
    /// Effectively no loss. Coast at the minimum standing redundancy.
    Quiescent,
}

/// A point-in-time view of the transport, refreshed each control tick.
#[derive(Debug, Clone)]
pub struct LinkState {
    /// Smoothed RTT estimate (Quinn's `rtt()`).
    smoothed_rtt: Duration,
    /// RTT variance ("rttvar"). Large values mean high jitter and force the
    /// decoder's stall grace period to widen so late symbols are not mistaken
    /// for lost ones.
    rtt_var: Duration,
    /// Recent loss rate in `[0, 1]`, computed as lost/sent over a sliding window.
    loss_rate: f64,
    /// Current congestion window in bytes (Quinn path stats), used both to
    /// classify the regime and to size the [`crate::budget::RepairBudget`].
    cwnd_bytes: u64,
    /// Precomputed regime (the classifier runs in `raptun-core` where the cwnd
    /// *trend* is known across ticks; here we just carry the verdict).
    regime: LossRegime,
    /// Highest block id seen making forward progress per stream is tracked in
    /// the decoder, not here; see [`LinkState::stall_grace`].
    _priv: (),
}

impl LinkState {
    /// Build a snapshot. `regime` is classified by the caller (`raptun-core`),
    /// which owns the cross-tick cwnd history needed to detect a *cut*.
    pub fn new(
        smoothed_rtt: Duration,
        rtt_var: Duration,
        loss_rate: f64,
        cwnd_bytes: u64,
        regime: LossRegime,
    ) -> Self {
        Self {
            smoothed_rtt,
            rtt_var,
            loss_rate: loss_rate.clamp(0.0, 1.0),
            cwnd_bytes,
            regime,
            _priv: (),
        }
    }

    pub fn smoothed_rtt(&self) -> Duration {
        self.smoothed_rtt
    }

    pub fn loss_rate(&self) -> f64 {
        self.loss_rate
    }

    pub fn cwnd_bytes(&self) -> u64 {
        self.cwnd_bytes
    }

    pub fn regime(&self) -> LossRegime {
        self.regime
    }

    /// The grace period a block may sit unfilled before the decoder is allowed
    /// to consider it *stalled* (rather than merely reordered/jittered).
    ///
    /// Uses the classic TCP-RTO shape `srtt + 4·rttvar`: under high jitter,
    /// `rttvar` is large, so the grace period automatically widens. This is the
    /// primary defense against the "late symbol misread as loss ⇒ spurious
    /// NACK storm" failure mode.
    pub fn stall_grace(&self) -> Duration {
        self.smoothed_rtt + 4 * self.rtt_var
    }

    /// True when the transport is congestion-limited and the FEC layer must not
    /// inject additional repair traffic.
    pub fn is_congested(&self) -> bool {
        self.regime == LossRegime::Congestion
    }

    /// Test constructor with sensible defaults for the fields the unit tests
    /// under `strategy`/`decoder` don't exercise.
    #[cfg(test)]
    pub fn for_test(rtt: Duration, loss_rate: f64, regime: LossRegime) -> Self {
        Self::new(rtt, rtt / 2, loss_rate, 64 * 1024, regime)
    }
}
