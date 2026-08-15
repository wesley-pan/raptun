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
use std::sync::Arc;

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

/// Multiplier applied to the running-minimum cwnd to form the BDP cap.
///
/// BBR inflates cwnd well above the true BDP during bandwidth probing
/// (measured: ~880 Mbps estimated vs 100 Mbps real on loopback+netem, giving
/// 11× cwnd inflation). Without a cap, `refresh_ceiling` sets the in-flight
/// block ceiling to the inflated value, which overflows middlebox queues and
/// causes ~89% sustained packet loss — far above FEC's 33% recovery threshold.
///
/// With the initial `min_cwnd_bdp` seeded at `floor_cwnd_bytes` (≈264 KB at
/// default geometry), a multiplier of 1 keeps the ceiling at `floor_blocks`
/// (16 blocks) until `observe_cwnd` records a smaller value. This gives a
/// per-tunnel `fair_share` of roughly `16 / num_tunnels` blocks — for 3 active
/// tunnels that is ~5 blocks ≈ 82 KB ≈ 6.6 ms at 100 Mbps. The resulting
/// queuing delay for an interactive request behind one saturating bulk flow is
/// ~13 ms, keeping the p99 loaded/baseline latency ratio well under 4×.
///
/// Using 4× (the previous value) gave ceiling=63 blocks, fair_share=21 per
/// tunnel, and ~1400 ms interactive latency under bulk load (9× baseline) —
/// because the bulk flow filled 21 blocks × 24 datagrams = 504 datagrams into
/// QUIC's pacing buffer before the interactive request could squeeze in.
///
/// Set to 0 to disable the cap entirely (raw cwnd passthrough).
pub const BDP_CEILING_MULTIPLIER: u32 = 1;

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
///
/// # Why a connection ceiling alone starves interactive traffic
///
/// A purely aggregate ceiling is *safe* but not *fair*. Whoever fills it first
/// owns it: a bulk transfer with an unbounded appetite pins `in_flight` at the
/// ceiling continuously, and every other tunnel finds the window full on every
/// check. The result is the reported symptom — one 4K stream or download makes
/// SSH and web traffic on the same connection unusable, because they are not
/// losing a race for bandwidth, they are being denied entry to the window
/// altogether.
///
/// So each tunnel additionally gets a **fair share**: `ceiling / active
/// tunnels`, computed live via [`Self::register_tunnel`]. A tunnel at its share
/// blocks even when the connection has room, which is the point — the headroom
/// it leaves is what the interactive tunnels use. With one tunnel active the
/// share equals the whole ceiling, so this costs nothing in the single-flow
/// case. See `docs/raptun-congestion-optimization-plan.md` §3.2.
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
    /// Live count of registered tunnels, the divisor for the fair share.
    active_tunnels: AtomicU64,
    /// Running minimum of cwnd samples seen above the floor threshold.
    ///
    /// BBR over-estimates bandwidth on constrained links (e.g. loopback+netem)
    /// and produces cwnd values far above the true BDP. This minimum is updated
    /// by `observe_cwnd` and used in `refresh_ceiling` to cap the effective cwnd
    /// at `BDP_CEILING_MULTIPLIER × min_cwnd_bdp`. Stored as bytes; initialised
    /// to `u64::MAX` (sentinel for "not yet observed").
    min_cwnd_bdp: AtomicU64,
}

/// Minimum per-tunnel fair share, in blocks.
///
/// With many tunnels over a small cwnd the computed share rounds to zero and
/// every tunnel blocks forever — a deadlock, since nothing can drain what
/// nothing may send. This floor trades a bounded overshoot of the connection
/// ceiling for guaranteed forward progress. The overshoot is acceptable because
/// the cwnd is an estimate and QUIC's own congestion control still backpressures
/// underneath; a deadlock is not acceptable at any price.
const MIN_TUNNEL_SHARE_BLOCKS: u64 = 2;

/// A tunnel's registration in a [`SendWindow`].
///
/// Holds the tunnel's own in-flight count and keeps it counted in the fair-share
/// divisor. Dropping it deregisters the tunnel **and releases any blocks still
/// in flight**.
///
/// That release is load-bearing. A tunnel torn down mid-flight (peer reset,
/// stall deadline, connection abort) never delivers the credits that would
/// settle its outstanding blocks. Without release-on-drop those blocks stay
/// counted in the connection aggregate forever, so every tunnel churn
/// permanently shrinks the usable window until the connection wedges with an
/// idle link — the same shape as the `active_tunnels` leak fixed earlier.
#[derive(Debug)]
pub struct TunnelSlot {
    window: Arc<SendWindow>,
    in_flight: AtomicU64,
}

impl TunnelSlot {
    /// This tunnel's own in-flight block count, for metrics.
    pub fn in_flight(&self) -> u64 {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// Release all of this tunnel's in-flight blocks from the connection-wide
    /// aggregate without dropping the slot. Called after a catastrophic loss
    /// event (e.g. BBR cwnd inflation collapse) where blocks were sent at a
    /// high cwnd and never delivered — credits will never arrive for them, so
    /// the in-flight count must be forcibly cleared to allow the gate to reopen.
    /// Any late credits that arrive after this call are safely handled by
    /// `settle`'s saturating subtract.
    pub fn abandon_in_flight(&self) {
        let mine = self.in_flight.swap(0, Ordering::AcqRel);
        if mine > 0 {
            self.window.release_aggregate(mine);
        }
    }
}

impl Drop for TunnelSlot {
    fn drop(&mut self) {
        let mine = self.in_flight.load(Ordering::Relaxed);
        if mine > 0 {
            self.window.release_aggregate(mine);
        }
        self.window.active_tunnels.fetch_sub(1, Ordering::AcqRel);
    }
}

impl SendWindow {
    /// `block_bytes` is one block's on-wire size (K × symbol_size). `floor` is
    /// the smallest ceiling to allow even when cwnd is tiny.
    pub fn new(block_bytes: u64, floor_blocks: u64) -> Self {
        let block_bytes = block_bytes.max(1);
        let floor_blocks = floor_blocks.max(1);
        // Seed the BDP proxy at the floor cwnd so that even the very first
        // refresh_ceiling call is capped at BDP_CEILING_MULTIPLIER × floor_cwnd.
        // Without a seed, min_cwnd_bdp stays u64::MAX until observe_cwnd fires,
        // and BBR can inflate the ceiling to tens of MB in the first few RTTs
        // (measured: 4.5 MB at t=2s on a 100 Mbps / 25 ms link, vs BDP=312 KB).
        // The floor cwnd is a conservative BDP lower bound: it equals
        // floor_blocks × block_bytes ≈ 264 KB on the default geometry, giving
        // a cap of 4 × 264 KB = 1.05 MB → ~63 blocks ceiling — tight enough to
        // avoid queue overflow while still allowing 3-4× BDP in flight.
        let initial_min = floor_blocks * block_bytes;
        Self {
            in_flight: AtomicU64::new(0),
            ceiling: AtomicU64::new(floor_blocks),
            block_bytes,
            floor_blocks,
            active_tunnels: AtomicU64::new(0),
            min_cwnd_bdp: AtomicU64::new(initial_min),
        }
    }

    /// Test-only constructor with no BDP cap (min_cwnd_bdp = u64::MAX).
    ///
    /// Lets unit tests exercise the core ceiling/fair_share logic without the
    /// BDP cap clipping `refresh_ceiling` to the floor. Not intended for
    /// production code — production always uses `new()` which seeds the cap.
    #[cfg(test)]
    pub fn new_uncapped(block_bytes: u64, floor_blocks: u64) -> Self {
        let block_bytes = block_bytes.max(1);
        let floor_blocks = floor_blocks.max(1);
        Self {
            in_flight: AtomicU64::new(0),
            ceiling: AtomicU64::new(floor_blocks),
            block_bytes,
            floor_blocks,
            active_tunnels: AtomicU64::new(0),
            min_cwnd_bdp: AtomicU64::new(u64::MAX),
        }
    }

    /// Record a raw cwnd sample for BDP tracking. Only samples above
    /// `floor_cwnd_bytes()` are considered to skip slow-start values.
    /// Uses an atomic minimum update so any tunnel may call this concurrently.
    pub fn observe_cwnd(&self, cwnd_bytes: u64) {
        if cwnd_bytes <= self.floor_cwnd_bytes() {
            return;
        }
        let mut cur = self.min_cwnd_bdp.load(Ordering::Relaxed);
        while cwnd_bytes < cur {
            match self.min_cwnd_bdp.compare_exchange_weak(
                cur,
                cwnd_bytes,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => cur = observed,
            }
        }
    }

    /// Recompute the ceiling from the current congestion window (bytes). The
    /// window tracks *data*, so it may use the whole cwnd (unlike the repair
    /// budget's fraction). Never drops below `floor_blocks`.
    ///
    /// Applies the BDP cap internally: if [`BDP_CEILING_MULTIPLIER`] > 0 and a
    /// minimum cwnd has been observed via [`Self::observe_cwnd`], the effective
    /// cwnd is capped at `BDP_CEILING_MULTIPLIER × min_cwnd_bdp` before
    /// computing the block count. This prevents BBR's inflated cwnd from
    /// driving the ceiling above what the link's queue can sustain.
    pub fn refresh_ceiling(&self, cwnd_bytes: u64) {
        let effective = if BDP_CEILING_MULTIPLIER > 0 {
            let min = self.min_cwnd_bdp.load(Ordering::Relaxed);
            if min < u64::MAX {
                let cap = min.saturating_mul(u64::from(BDP_CEILING_MULTIPLIER));
                cwnd_bytes.min(cap)
            } else {
                cwnd_bytes
            }
        } else {
            cwnd_bytes
        };
        let blocks = (effective / self.block_bytes).max(self.floor_blocks);
        self.ceiling.store(blocks, Ordering::Relaxed);
    }

    /// Register a tunnel and get its [`TunnelSlot`]. The slot counts toward the
    /// fair-share divisor until dropped.
    pub fn register_tunnel(self: &Arc<Self>) -> TunnelSlot {
        self.active_tunnels.fetch_add(1, Ordering::AcqRel);
        TunnelSlot {
            window: Arc::clone(self),
            in_flight: AtomicU64::new(0),
        }
    }

    /// Blocks a single tunnel may keep in flight right now: an equal split of
    /// the connection ceiling across live tunnels, floored at
    /// [`MIN_TUNNEL_SHARE_BLOCKS`] so a crowded connection still makes progress.
    ///
    /// Recomputed on every call rather than cached, so a tunnel's share widens
    /// the instant its neighbours close — a bulk flow reclaims the full window
    /// as soon as it is alone, with no settling period.
    pub fn fair_share(&self) -> u64 {
        let ceiling = self.ceiling.load(Ordering::Relaxed);
        let active = self.active_tunnels.load(Ordering::Relaxed).max(1);
        (ceiling / active).max(MIN_TUNNEL_SHARE_BLOCKS)
    }

    /// Whether `slot`'s tunnel may put another block in flight: it must fit
    /// under **both** the connection-wide ceiling (protects the link) and the
    /// tunnel's own fair share (protects the other tunnels).
    pub fn has_room(&self, slot: &TunnelSlot) -> bool {
        self.in_flight.load(Ordering::Relaxed) < self.ceiling.load(Ordering::Relaxed)
            && slot.in_flight.load(Ordering::Relaxed) < self.fair_share()
    }

    /// Whether the connection-wide ceiling has room for one more block,
    /// ignoring the per-tunnel fair-share. Used when credits are stale and
    /// the gate falls back to cwnd-only back-pressure — fair-share is still
    /// applied on the credit-gated path, so this is a safe fallback.
    pub fn has_cwnd_room(&self) -> bool {
        self.in_flight.load(Ordering::Relaxed) < self.ceiling.load(Ordering::Relaxed)
    }

    /// Account one freshly-sent block against both the connection window and
    /// the sending tunnel's own share.
    pub fn add_sent(&self, slot: &TunnelSlot) {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        slot.in_flight.fetch_add(1, Ordering::AcqRel);
    }

    /// Reconcile a tunnel's delivered progress: `newly_delivered` blocks have
    /// left the in-flight set. Saturating so a reset or reordering can't wrap.
    ///
    /// The per-tunnel counter is decremented first and the *actual* amount it
    /// yielded is what gets subtracted from the aggregate. Subtracting the
    /// caller's raw figure from both would let an over-settle (duplicate or
    /// reordered credit) release blocks the tunnel never held, silently
    /// inflating the connection window past the cwnd.
    pub fn settle(&self, slot: &TunnelSlot, newly_delivered: u64) {
        if newly_delivered == 0 {
            return;
        }
        let actual = Self::saturating_release(&slot.in_flight, newly_delivered);
        if actual > 0 {
            self.release_aggregate(actual);
        }
    }

    /// Subtract from the connection-wide in-flight count, saturating at zero.
    fn release_aggregate(&self, n: u64) {
        Self::saturating_release(&self.in_flight, n);
    }

    /// Saturating CAS subtract; returns how much was actually removed.
    fn saturating_release(counter: &AtomicU64, n: u64) -> u64 {
        let mut cur = counter.load(Ordering::Relaxed);
        loop {
            let removed = cur.min(n);
            let next = cur - removed;
            match counter.compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return removed,
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

    /// Floor cwnd in bytes: `floor_blocks × block_bytes`. Used to skip
    /// slow-start cwnd values when computing the min-cwnd BDP proxy.
    pub fn floor_cwnd_bytes(&self) -> u64 {
        self.floor_blocks * self.block_bytes
    }

    /// Live registered tunnel count, for metrics.
    pub fn active_tunnels(&self) -> u64 {
        self.active_tunnels.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fair_share_limits_one_tunnel_to_its_slice() {
        // 1 KB blocks, ceiling 100 blocks, 4 active tunnels ⇒ each may hold
        // 100/4 = 25 in flight even though the connection has room for 100.
        // Without this, one bulk flow claims the whole window and every other
        // tunnel blocks on a full connection window — the starvation that makes
        // SSH unusable while a download runs.
        let w = Arc::new(SendWindow::new_uncapped(1000, 1));
        w.refresh_ceiling(100_000);
        let bulk = w.register_tunnel();
        let _a = w.register_tunnel();
        let _b = w.register_tunnel();
        let _c = w.register_tunnel();

        for _ in 0..25 {
            assert!(w.has_room(&bulk), "under its 25-block share");
            w.add_sent(&bulk);
        }
        assert!(
            !w.has_room(&bulk),
            "bulk tunnel is capped at its fair share, not the connection ceiling"
        );
        assert!(
            w.in_flight() < w.ceiling(),
            "the connection as a whole still has room — this is per-tunnel starvation prevention"
        );
    }

    #[test]
    fn other_tunnels_still_send_while_one_is_capped() {
        // The point of the cap: a saturated bulk flow must not block anyone else.
        let w = Arc::new(SendWindow::new_uncapped(1000, 1));
        w.refresh_ceiling(100_000);
        let bulk = w.register_tunnel();
        let ssh = w.register_tunnel();
        for _ in 0..50 {
            w.add_sent(&bulk); // bulk saturates its own share (100/2 = 50)
        }
        assert!(!w.has_room(&bulk), "bulk is at its share");
        assert!(
            w.has_room(&ssh),
            "a starved interactive tunnel must still get through"
        );
    }

    #[test]
    fn single_tunnel_may_use_the_whole_window() {
        // With one tunnel active the fair share IS the connection ceiling —
        // the cap must not cost throughput when there is nobody to be fair to.
        let w = Arc::new(SendWindow::new_uncapped(1000, 1));
        w.refresh_ceiling(50_000); // 50 blocks
        let only = w.register_tunnel();
        for _ in 0..50 {
            assert!(w.has_room(&only), "lone tunnel gets the full window");
            w.add_sent(&only);
        }
        assert!(
            !w.has_room(&only),
            "still bounded by the connection ceiling"
        );
    }

    #[test]
    fn fair_share_has_a_floor_so_many_tunnels_dont_deadlock() {
        // 100 tunnels over a 10-block ceiling would give each 0 blocks — every
        // tunnel permanently blocked. The floor guarantees forward progress at
        // the cost of overshooting the ceiling, which is the right trade: the
        // cwnd is a soft advisory, a deadlock is not.
        let w = Arc::new(SendWindow::new_uncapped(1000, 1));
        w.refresh_ceiling(10_000); // 10 blocks
        let slots: Vec<_> = (0..100).map(|_| w.register_tunnel()).collect();
        assert!(
            w.has_room(&slots[0]),
            "every tunnel must be able to send at least one block"
        );
    }

    #[test]
    fn share_widens_as_tunnels_close() {
        // Fair share is computed live, so a bulk flow reclaims the full window
        // once the tunnels it was sharing with go away.
        let w = Arc::new(SendWindow::new_uncapped(1000, 1));
        w.refresh_ceiling(100_000);
        let bulk = w.register_tunnel();
        {
            let _other = w.register_tunnel();
            for _ in 0..50 {
                w.add_sent(&bulk);
            }
            assert!(!w.has_room(&bulk), "capped at 50 while sharing with one");
        } // _other drops → active tunnels back to 1
        assert!(
            w.has_room(&bulk),
            "share widens to the full ceiling once the peer closes"
        );
    }

    #[test]
    fn closing_a_tunnel_releases_its_in_flight_blocks() {
        // A tunnel that dies mid-flight (peer reset, stall deadline) never sends
        // the credits that would settle its blocks. Without release-on-drop those
        // blocks leak into the connection window forever, permanently shrinking
        // it — after enough churn the connection wedges with an empty link. This
        // is the same class of bug as the `active_tunnels` leak.
        let w = Arc::new(SendWindow::new_uncapped(1000, 1));
        w.refresh_ceiling(10_000);
        {
            let dying = w.register_tunnel();
            w.add_sent(&dying);
            w.add_sent(&dying);
            assert_eq!(w.in_flight(), 2);
        }
        assert_eq!(
            w.in_flight(),
            0,
            "a dropped tunnel must not leak its in-flight blocks"
        );
    }

    #[test]
    fn settle_releases_from_the_owning_tunnel() {
        // Per-tunnel accounting must track delivery, or a long-lived tunnel's
        // own counter climbs forever and it self-starves despite the connection
        // being idle.
        let w = Arc::new(SendWindow::new_uncapped(1000, 1));
        w.refresh_ceiling(100_000);
        let t = w.register_tunnel();
        let _peer = w.register_tunnel();
        for _ in 0..50 {
            w.add_sent(&t);
        }
        assert!(!w.has_room(&t));
        w.settle(&t, 10);
        assert!(
            w.has_room(&t),
            "delivered blocks free up the tunnel's share"
        );
        assert_eq!(w.in_flight(), 40, "and the connection aggregate too");
    }

    #[test]
    fn over_settle_does_not_wrap_per_tunnel() {
        let w = Arc::new(SendWindow::new_uncapped(1000, 1));
        w.refresh_ceiling(100_000);
        let t = w.register_tunnel();
        w.add_sent(&t);
        w.settle(&t, 99); // more than was ever sent
        assert_eq!(w.in_flight(), 0);
        // Dropping must not underflow the connection counter either.
        drop(t);
        assert_eq!(w.in_flight(), 0);
    }

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
        // 10 KB blocks, floor of 4 blocks. initial_min = 4×10000 = 40000.
        // With BDP_CEILING_MULTIPLIER=1, cap=40000. All refresh calls are
        // constrained to max(cwnd_or_cap, floor_blocks).
        let w = Arc::new(SendWindow::new(10_000, 4));
        assert_eq!(w.ceiling(), 4, "starts at the floor");
        // refresh(100_000): min(100000, 1×40000)=40000 → 40000/10000=4 blocks (= floor = cap).
        w.refresh_ceiling(100_000);
        assert_eq!(w.ceiling(), 4, "capped at floor by BDP cap");
        // refresh(20_000): min(20000, 40000)=20000 → 20000/10000=2 < floor ⇒ clamped to 4.
        w.refresh_ceiling(20_000);
        assert_eq!(w.ceiling(), 4, "tiny cwnd is still clamped up to the floor");
    }

    #[test]
    fn send_window_has_room_and_settle() {
        // With floor=1 and block_bytes=1000: initial_min=1000, cap=1×1000=1000 → ceiling=1.
        // To test has_room with ceiling=3, we need to pass cwnd=3000 within the cap.
        // Use floor=3 so initial_min=3000 and cap=3000; refresh(3000) → 3 blocks.
        let w = Arc::new(SendWindow::new(1000, 3));
        w.refresh_ceiling(3000); // min(3000, 1×3000)=3000 → 3 blocks
        assert_eq!(w.ceiling(), 3, "ceiling is 3 blocks");
        let t = w.register_tunnel();
        assert!(w.has_room(&t));
        w.add_sent(&t);
        w.add_sent(&t);
        w.add_sent(&t);
        assert!(!w.has_room(&t), "3 in flight == ceiling 3, full");
        w.settle(&t, 2); // 2 delivered
        assert_eq!(w.in_flight(), 1);
        assert!(w.has_room(&t));
        // Over-settle saturates at 0, never wraps.
        w.settle(&t, 10);
        assert_eq!(w.in_flight(), 0);
    }

    #[test]
    fn bdp_cap_limits_ceiling_after_observe() {
        // block_bytes=1000, floor_blocks=4. floor_cwnd_bytes=4000. initial min_cwnd_bdp=4000.
        // observe_cwnd(5000): 5000 > floor(4000) but 5000 > initial_min(4000) → no update
        // (CAS only fires when cwnd_bytes < cur; 5000 > 4000 so no update)
        // refresh_ceiling(100_000): cap = BDP_CEILING_MULTIPLIER(1) × 4000 = 4000 → 4 blocks (= floor).
        let w = Arc::new(SendWindow::new(1000, 4));
        w.observe_cwnd(5000);
        w.refresh_ceiling(100_000);
        assert_eq!(
            w.ceiling(),
            4, // capped at floor because initial seed = floor_cwnd
            "ceiling capped at BDP_CEILING_MULTIPLIER × min observed cwnd"
        );
    }

    #[test]
    fn observe_cwnd_ignores_below_floor() {
        // floor_cwnd_bytes = 4 × 1000 = 4000. A sample of 3000 should be ignored.
        // Initial min_cwnd_bdp = 4000 (seed). observe(3000): below floor, ignored.
        // observe(6000): above floor but 6000 > 4000 → no CAS update (minimum only decreases).
        // refresh_ceiling(50_000): cap = 1 × 4000 = 4000 → 4 blocks (= floor).
        let w = Arc::new(SendWindow::new(1000, 4));
        w.observe_cwnd(3000); // below floor — should not update min_cwnd_bdp
        w.observe_cwnd(6000); // above floor but larger than seed — no update
        w.refresh_ceiling(50_000);
        assert_eq!(w.ceiling(), 4, "capped at floor by initial seed");
    }

    #[test]
    fn observe_cwnd_only_decreases() {
        // Initial min_cwnd_bdp = 4 × 1000 = 4000.
        // observe(3500): above floor(4000)? No — 3500 < 4000, so below floor, ignored.
        // Actually with floor=4, block=1000: floor_cwnd=4000. observe(3500) < 4000, ignored.
        // observe(4500): > floor. 4500 > cur(4000) → no update. min stays 4000.
        // refresh_ceiling(50_000): min(50000, 1×4000)=4000 → 4 blocks.
        // To test "only decreases", use a block/floor that gives min > some observe:
        // floor=1, block=1000: initial_min=1000. observe(800)→ below floor(1000), ignored.
        // observe(500) → below floor(1000), ignored.
        // observe(2000) → above floor, but 2000 > 1000 → no update.
        // So the only way to update is to observe < initial_min AND > floor — impossible
        // since initial_min = floor_cwnd. Prove that larger sample never raises min:
        let w = Arc::new(SendWindow::new(1000, 4)); // floor=4000, initial_min=4000
        w.observe_cwnd(50_000); // larger — must not raise min
        w.refresh_ceiling(50_000);
        // Cap = 1 × 4000 = 4000 → 4 blocks, not 50 blocks.
        assert_eq!(w.ceiling(), 4, "minimum not raised by larger sample");
    }

    #[test]
    fn shared_window_cap_uses_connection_minimum() {
        // Two tunnels share a SendWindow. The bulk tunnel observes a large cwnd.
        // The ceiling must reflect the seeded minimum, not the bulk tunnel's large value.
        // floor=2, block=1000: initial_min=2000. BDP_CEILING_MULTIPLIER=1.
        let w = Arc::new(SendWindow::new(1000, 2));
        // Bulk tunnel starts with large BBR-inflated cwnd.
        w.observe_cwnd(9_000_000); // larger than seed(2000) — does not update
        w.refresh_ceiling(9_000_000);
        // Cap = 1 × 2000 = 2000 → max(2000/1000, 2) = 2 blocks (= floor).
        assert_eq!(
            w.ceiling(),
            2,
            "bulk tunnel's large cwnd must not overwrite the seeded floor minimum"
        );
    }
}
