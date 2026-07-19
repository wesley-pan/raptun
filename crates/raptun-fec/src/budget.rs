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

/// Connection-wide flow-control window over in-flight *data* blocks, shared by
/// every tunnel on one QUIC connection.
///
/// The per-tunnel credit gate alone is not enough: N tunnels each allowed a
/// fixed window still sum to N× the connection's capacity, so a few dozen
/// tunnels re-create the very congestion overshoot the window exists to stop
/// (measured: windowed loss ~70% under zero injected loss even *with* a
/// per-tunnel window). This ceiling is connection-wide and cwnd-derived — the
/// aggregate in-flight blocks across all tunnels may not exceed it — so adding
/// tunnels shares one budget rather than multiplying it. Same shape and sharing
/// (`Arc`) as [`RepairBudget`].
#[derive(Debug)]
pub struct SendWindow {
    /// Aggregate blocks in flight (sent but not yet delivered) across all
    /// tunnels on the connection.
    in_flight: AtomicU64,
    /// Maximum in-flight blocks, recomputed from cwnd each control tick.
    ceiling: AtomicU64,
    /// Block size in bytes, to convert the byte-denominated cwnd into a block
    /// count.
    block_bytes: u64,
    /// Minimum ceiling in blocks, so a tiny/cold cwnd still lets each tunnel
    /// keep at least a little data in flight rather than stalling to a crawl.
    floor_blocks: u64,
}

impl SendWindow {
    /// `block_bytes` is one block's on-wire size (K × symbol_size). `floor` is
    /// the smallest ceiling to allow even when cwnd is tiny.
    pub fn new(block_bytes: u64, floor_blocks: u64) -> Self {
        Self {
            in_flight: AtomicU64::new(0),
            ceiling: AtomicU64::new(floor_blocks.max(1)),
            block_bytes: block_bytes.max(1),
            floor_blocks: floor_blocks.max(1),
        }
    }

    /// Recompute the ceiling from the current congestion window (bytes). The
    /// window tracks *data*, so it may use the whole cwnd (unlike the repair
    /// budget's fraction). Never drops below `floor_blocks`.
    pub fn refresh_ceiling(&self, cwnd_bytes: u64) {
        let blocks = (cwnd_bytes / self.block_bytes).max(self.floor_blocks);
        self.ceiling.store(blocks, Ordering::Relaxed);
    }

    /// Whether the connection can accept another in-flight block right now.
    pub fn has_room(&self) -> bool {
        self.in_flight.load(Ordering::Relaxed) < self.ceiling.load(Ordering::Relaxed)
    }

    /// Account one freshly-sent block against the connection window.
    pub fn add_sent(&self) {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
    }

    /// Reconcile this tunnel's delivered progress: `newly_delivered` blocks have
    /// left the in-flight set. Saturating so a reset or reordering can't wrap.
    pub fn settle(&self, newly_delivered: u64) {
        if newly_delivered == 0 {
            return;
        }
        let mut cur = self.in_flight.load(Ordering::Relaxed);
        loop {
            let next = cur.saturating_sub(newly_delivered);
            match self.in_flight.compare_exchange_weak(
                cur,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => cur = observed,
            }
        }
    }

    /// Current aggregate in-flight blocks, for metrics.
    pub fn in_flight(&self) -> u64 {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// Current ceiling in blocks, for metrics.
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

    #[test]
    fn send_window_ceiling_from_cwnd_with_floor() {
        // 10 KB blocks, floor of 4 blocks.
        let w = SendWindow::new(10_000, 4);
        assert_eq!(w.ceiling(), 4, "starts at the floor");
        w.refresh_ceiling(100_000); // 100_000 / 10_000 = 10 blocks
        assert_eq!(w.ceiling(), 10);
        w.refresh_ceiling(20_000); // 2 blocks < floor ⇒ clamped to 4
        assert_eq!(w.ceiling(), 4, "tiny cwnd is clamped up to the floor");
    }

    #[test]
    fn send_window_has_room_and_settle() {
        let w = SendWindow::new(1000, 1);
        w.refresh_ceiling(3000); // 3 blocks
        assert!(w.has_room());
        w.add_sent();
        w.add_sent();
        w.add_sent();
        assert!(!w.has_room(), "3 in flight == ceiling 3, full");
        w.settle(2); // 2 delivered
        assert_eq!(w.in_flight(), 1);
        assert!(w.has_room());
        // Over-settle saturates at 0, never wraps.
        w.settle(10);
        assert_eq!(w.in_flight(), 0);
    }
}
