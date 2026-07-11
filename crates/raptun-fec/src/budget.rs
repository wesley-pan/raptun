//! [`RepairBudget`] — the global cap on in-flight repair symbols.
//!
//! # The convergence guarantee, in one struct
//!
//! Raptun's fallback converges under extreme loss **iff** the rate at which it
//! injects repair symbols stays below the link's spare capacity. Two control
//! loops want to inject repair (the slow adaptive ratio and the fast per-block
//! NACK); left unbounded they can resonate and drive a redundancy → congestion
//! → loss → more-redundancy avalanche.
//!
//! This budget is the physical brake that makes the injection rate provably
//! bounded regardless of what either loop *wants*: repair symbols in flight may
//! never exceed a fixed fraction of the congestion window. When the budget is
//! exhausted, the decoder is denied new repair and must fall back to reliable
//! retransmit (a bounded, terminating path) instead. Because QUIC datagrams are
//! themselves congestion-controlled, this is a *second* line of defense on top
//! of the transport's own backpressure.

use std::sync::atomic::{AtomicU64, Ordering};

/// Tracks how many repair symbols are currently "in flight" (requested/sent but
/// not yet known to have arrived) against a ceiling derived from the cwnd.
///
/// Cheap to share across tasks: it is just an atomic counter plus a ceiling
/// that `raptun-core` refreshes when the cwnd changes.
#[derive(Debug)]
pub struct RepairBudget {
    /// Symbols currently reserved (in flight).
    in_flight: AtomicU64,
    /// Maximum symbols allowed in flight. Recomputed from cwnd each control tick.
    ceiling: AtomicU64,
    /// Symbol size in bytes, to convert the byte-denominated cwnd into a symbol
    /// count.
    symbol_size: u64,
    /// Fraction of cwnd (parts-per-million) that repair traffic may occupy.
    /// e.g. 400_000 = 40%. The design's headline "≤ 40% of cwnd" rule.
    cwnd_fraction_ppm: u64,
}

impl RepairBudget {
    /// Create a budget allowing repair to occupy up to `cwnd_fraction` of the
    /// congestion window. `symbol_size` must match the negotiated FEC symbol
    /// size.
    pub fn new(symbol_size: u16, cwnd_fraction: f64) -> Self {
        Self {
            in_flight: AtomicU64::new(0),
            ceiling: AtomicU64::new(0),
            symbol_size: u64::from(symbol_size).max(1),
            cwnd_fraction_ppm: (cwnd_fraction.clamp(0.0, 1.0) * 1_000_000.0) as u64,
        }
    }

    /// Recompute the ceiling from the current congestion window. Call this from
    /// the control tick whenever fresh cwnd telemetry arrives.
    pub fn refresh_ceiling(&self, cwnd_bytes: u64) {
        let repair_bytes = cwnd_bytes.saturating_mul(self.cwnd_fraction_ppm) / 1_000_000;
        let symbols = repair_bytes / self.symbol_size;
        self.ceiling.store(symbols, Ordering::Relaxed);
    }

    /// Try to reserve `n` repair symbols. Returns `true` and reserves them if
    /// they fit under the ceiling; returns `false` and reserves nothing if they
    /// would overflow it (all-or-nothing so a NACK either gets fully satisfied
    /// or cleanly falls through to the degraded path).
    pub fn try_reserve(&self, n: u32) -> bool {
        let n = u64::from(n);
        let ceiling = self.ceiling.load(Ordering::Relaxed);
        // Compare-and-swap loop to keep the reservation atomic under contention.
        let mut current = self.in_flight.load(Ordering::Relaxed);
        loop {
            if current + n > ceiling {
                return false;
            }
            match self.in_flight.compare_exchange_weak(
                current,
                current + n,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    /// Release `n` previously-reserved symbols (e.g. when the block decodes or
    /// the repair symbols are confirmed delivered).
    pub fn release(&self, n: u32) {
        self.in_flight.fetch_sub(u64::from(n), Ordering::AcqRel);
    }

    /// Current in-flight count, for metrics.
    pub fn in_flight(&self) -> u64 {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// Current ceiling, for metrics.
    pub fn ceiling(&self) -> u64 {
        self.ceiling.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservation_respects_ceiling() {
        // 1200-byte symbols, repair may use 40% of cwnd.
        let budget = RepairBudget::new(1200, 0.40);
        // cwnd = 120_000 bytes ⇒ 48_000 bytes for repair ⇒ 40 symbols.
        budget.refresh_ceiling(120_000);
        assert_eq!(budget.ceiling(), 40);

        assert!(budget.try_reserve(30));
        assert_eq!(budget.in_flight(), 30);
        // 30 + 15 = 45 > 40 ⇒ denied, nothing reserved.
        assert!(!budget.try_reserve(15));
        assert_eq!(budget.in_flight(), 30);
        // 30 + 10 = 40 ⇒ exactly fits.
        assert!(budget.try_reserve(10));
        assert_eq!(budget.in_flight(), 40);

        budget.release(40);
        assert_eq!(budget.in_flight(), 0);
    }

    #[test]
    fn shrinking_cwnd_shrinks_ceiling() {
        let budget = RepairBudget::new(1000, 0.40);
        budget.refresh_ceiling(100_000); // 40_000 / 1000 = 40
        assert_eq!(budget.ceiling(), 40);
        budget.refresh_ceiling(10_000); // congestion cut: 4_000 / 1000 = 4
        assert_eq!(budget.ceiling(), 4);
    }
}
