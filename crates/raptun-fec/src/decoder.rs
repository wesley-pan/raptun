//! The receiver-side per-block state machine — the concrete answer to
//! "does the FEC fallback converge under high loss, jitter, and reordering?"
//!
//! Each source block is tracked by one [`BlockManager`]. Its lifecycle:
//!
//! ```text
//!                    symbol arrives
//!        ┌─────────────────────────────────┐
//!        │                                 ▼
//!   ┌─────────┐  collected K   ┌──────────┐
//!   │ Filling │──────────────▶│ Decoded  │ ──▶ deliver, release budget
//!   └────┬────┘  (zero RTT)    └──────────┘
//!        │
//!        │ enter Stalled only if ALL hold (so jitter/reorder don't misfire):
//!        │   1. later blocks are already progressing   (sequence oracle)
//!        │   2. elapsed > srtt + 4·rttvar              (jitter grace)
//!        │   3. still short of K
//!        ▼
//!   ┌─────────┐   congested?  ──yes──▶ Degraded (reliable retransmit)
//!   │ Stalled │───────────────┐
//!   └────┬────┘               │no + budget available
//!        │ budget full         ▼
//!        └────▶ Degraded   ┌──────────┐
//!                          │ NackSent │  (idempotent: reports `have`)
//!                          └────┬─────┘
//!                repair arrives │  ─▶ back to Filling
//!                NACK lost/timeout ─▶ back to Stalled (re-arbitrate)
//! ```
//!
//! The three-way AND for entering `Stalled` is what separates *reordering* from
//! *loss*: a late symbol under jitter does not trip it, because condition 1
//! (later blocks progressing) plus condition 2 (a jitter-scaled grace period)
//! must also hold. That is the mechanism that prevents the NACK-storm avalanche
//! the naive "one-RTT timer" design would suffer.

use std::time::Instant;

use raptun_proto::BlockId;

use crate::budget::RepairBudget;
use crate::link::LinkState;

/// What the caller (`raptun-core`) should do after feeding an event to a
/// [`BlockManager`]. The manager never performs I/O itself — it only decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecoderAction {
    /// Nothing to do yet.
    Idle,
    /// Send a `BlockNack` on the control stream requesting `need` fresh repair
    /// symbols; `have` is reported for idempotency.
    SendNack { have: u32, need: u32 },
    /// Give up on FEC for this block: ask the sender to retransmit the block's
    /// remaining bytes over the reliable control/stream path. Terminating.
    RequestReliableRetransmit,
    /// The block is complete; `bytes` is the reconstructed source data, ready to
    /// hand to the tunnelled connection.
    Deliver { bytes: Vec<u8> },
}

/// Terminal outcome of a block, for metrics/telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockOutcome {
    /// Reconstructed purely from received symbols (the happy path).
    DecodedFromFec,
    /// Completed only after a reliable retransmit fallback.
    DecodedAfterFallback,
}

/// Internal state of the block state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Filling,
    Stalled { since: Instant },
    NackSent { requested: u32, at: Instant },
    Done,
    Degraded,
}

/// Everything the manager needs to know about the transport at decision time,
/// passed in per-tick so the manager stays a pure decision function.
pub struct TickCtx<'a> {
    pub now: Instant,
    pub link: &'a LinkState,
    pub budget: &'a RepairBudget,
    /// Sequence-progress oracle: has the stream made progress *past* this block
    /// by at least `lookahead` blocks? True ⇒ this block is genuinely behind,
    /// not merely reordered. Implemented in `raptun-core` from the highest
    /// contiguous block delivered.
    pub later_blocks_progressing: bool,
}

/// Per-block reassembly + fallback state machine.
///
/// The actual RaptorQ symbol accumulation is delegated to a decoder handle
/// (`RaptorQBlockDecoder`) which this type owns; see [`BlockManager::on_symbol`].
pub struct BlockManager {
    block_id: BlockId,
    /// Source block size (symbols needed to decode). Learned from the first
    /// symbol's negotiated geometry.
    k: u32,
    /// Distinct symbols received so far.
    received: u32,
    /// When the first symbol for this block arrived (start of the grace clock).
    first_symbol_at: Option<Instant>,
    state: State,
    /// The underlying RaptorQ decoder for this block. Boxed behind our own
    /// trait so the state machine is testable without the real codec.
    codec: Box<dyn RaptorQBlockDecoder + Send>,
}

/// Abstraction over the `raptorq` per-block decoder, so this state machine can
/// be unit-tested with a fake and so we can swap RaptorQ internals without
/// touching the convergence logic.
///
/// The real implementation wraps `raptorq::SourceBlockDecoder`.
pub trait RaptorQBlockDecoder {
    /// Feed one encoding symbol (source or repair). Returns the fully decoded
    /// block bytes once enough symbols have been collected, else `None`.
    fn add_symbol(&mut self, esi: u32, payload: &[u8]) -> Option<Vec<u8>>;
}

impl BlockManager {
    pub fn new(block_id: BlockId, k: u32, codec: Box<dyn RaptorQBlockDecoder + Send>) -> Self {
        Self {
            block_id,
            k,
            received: 0,
            first_symbol_at: None,
            state: State::Filling,
            codec,
        }
    }

    pub fn block_id(&self) -> BlockId {
        self.block_id
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self.state, State::Done | State::Degraded)
    }

    /// Feed a received symbol. If it completes the block, transitions to `Done`
    /// and returns [`DecoderAction::Deliver`].
    pub fn on_symbol(&mut self, now: Instant, esi: u32, payload: &[u8]) -> DecoderAction {
        if self.is_terminal() {
            return DecoderAction::Idle;
        }
        self.first_symbol_at.get_or_insert(now);
        self.received += 1;

        if let Some(bytes) = self.codec.add_symbol(esi, payload) {
            self.state = State::Done;
            return DecoderAction::Deliver { bytes };
        }

        // A repair symbol arriving while we were waiting on a NACK returns us to
        // plain filling — the arbitration in `tick` will re-run if we stall again.
        if let State::NackSent { .. } = self.state {
            self.state = State::Filling;
        }
        DecoderAction::Idle
    }

    /// Periodic arbitration. Call on a timer (e.g. every few ms) for every
    /// non-terminal block. This is where the three-condition stall test, the
    /// congestion arbitration, and the budget check live.
    pub fn tick(&mut self, ctx: &TickCtx<'_>) -> DecoderAction {
        match self.state {
            State::Filling => self.tick_filling(ctx),
            State::Stalled { .. } => self.tick_stalled(ctx),
            State::NackSent { at, .. } => self.tick_nack_sent(ctx, at),
            State::Done | State::Degraded => DecoderAction::Idle,
        }
    }

    fn tick_filling(&mut self, ctx: &TickCtx<'_>) -> DecoderAction {
        let Some(first) = self.first_symbol_at else {
            // No symbol has arrived yet; nothing to time out.
            return DecoderAction::Idle;
        };
        let elapsed = ctx.now.saturating_duration_since(first);
        let grace = ctx.link.stall_grace();

        // The three-way AND. All must hold to declare the block stalled.
        let genuinely_behind = ctx.later_blocks_progressing; // (1) not just reordered
        let past_grace = elapsed > grace; // (2) jitter-scaled patience exhausted
        let still_short = self.received < self.k; // (3) actually missing symbols

        // Hard-deadline escape: after a large multiple of the grace period (with
        // an absolute floor), a block that is still short is declared stalled
        // *regardless* of the sequence-progress oracle. This covers the case
        // where no higher block ever arrives (e.g. a short stream whose tail
        // block, or whole single block, suffers heavy loss) — reordering is no
        // longer a plausible explanation after this long, and without this the
        // block would strand forever with no progress signal to trip condition
        // (1).
        let hard_deadline = (grace * 8).max(std::time::Duration::from_millis(500));
        let past_hard_deadline = elapsed > hard_deadline;

        if still_short && (past_hard_deadline || (genuinely_behind && past_grace)) {
            self.state = State::Stalled { since: ctx.now };
            // Fall through and immediately arbitrate this tick.
            return self.tick_stalled(ctx);
        }
        DecoderAction::Idle
    }

    fn tick_stalled(&mut self, ctx: &TickCtx<'_>) -> DecoderAction {
        // Congestion arbitration: if the link is congestion-limited, injecting
        // repair would deepen it. Skip straight to the reliable fallback.
        if ctx.link.is_congested() {
            self.state = State::Degraded;
            return DecoderAction::RequestReliableRetransmit;
        }

        let need = self.k.saturating_sub(self.received);
        if need == 0 {
            // Raced with a symbol arrival; nothing to request.
            self.state = State::Filling;
            return DecoderAction::Idle;
        }

        // Budget is the hard brake. If the repair we'd request doesn't fit under
        // the in-flight ceiling, fall back rather than pile on more redundancy.
        if ctx.budget.try_reserve(need) {
            self.state = State::NackSent {
                requested: need,
                at: ctx.now,
            };
            DecoderAction::SendNack {
                have: self.received,
                need,
            }
        } else {
            self.state = State::Degraded;
            DecoderAction::RequestReliableRetransmit
        }
    }

    fn tick_nack_sent(&mut self, ctx: &TickCtx<'_>, sent_at: Instant) -> DecoderAction {
        // The NACK (or its repair reply) may have been lost. If a feedback RTT
        // passes with no progress, release the reservation and re-arbitrate.
        // Re-arbitration (not blind resend) is what keeps this idempotent and
        // bounded: on the second pass we may find the link now congested and
        // degrade, rather than requesting yet more repair.
        let waited = ctx.now.saturating_duration_since(sent_at);
        if waited > ctx.link.smoothed_rtt() && self.received < self.k {
            if let State::NackSent { requested, .. } = self.state {
                ctx.budget.release(requested);
            }
            self.state = State::Stalled { since: sent_at };
            return self.tick_stalled(ctx);
        }
        DecoderAction::Idle
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::LossRegime;
    use std::time::Duration;

    /// A fake block decoder that "decodes" once it has seen `k` symbols.
    struct FakeCodec {
        k: u32,
        seen: u32,
    }
    impl RaptorQBlockDecoder for FakeCodec {
        fn add_symbol(&mut self, _esi: u32, _payload: &[u8]) -> Option<Vec<u8>> {
            self.seen += 1;
            if self.seen >= self.k {
                Some(vec![0xAB; 8])
            } else {
                None
            }
        }
    }

    fn mgr(k: u32) -> BlockManager {
        BlockManager::new(1, k, Box::new(FakeCodec { k, seen: 0 }))
    }

    #[test]
    fn happy_path_decodes_without_nack() {
        let mut m = mgr(3);
        let t0 = Instant::now();
        assert_eq!(m.on_symbol(t0, 0, b"a"), DecoderAction::Idle);
        assert_eq!(m.on_symbol(t0, 1, b"b"), DecoderAction::Idle);
        assert!(matches!(
            m.on_symbol(t0, 2, b"c"),
            DecoderAction::Deliver { .. }
        ));
        assert!(m.is_terminal());
    }

    #[test]
    fn reordering_does_not_trigger_nack() {
        // Past the jitter grace but well within the hard deadline: if later
        // blocks are NOT progressing, the symbol may merely be reordered/late,
        // so we must not stall yet.
        let mut m = mgr(5);
        let t0 = Instant::now();
        m.on_symbol(t0, 0, b"a");
        let budget = RepairBudget::new(1200, 0.4);
        budget.refresh_ceiling(1_000_000);
        let link = LinkState::for_test(Duration::from_millis(50), 0.1, LossRegime::Random);

        let ctx = TickCtx {
            // grace ≈ 150ms; hard deadline ≈ 1.2s. 300ms is past grace but
            // far short of the hard deadline, so reorder protection applies.
            now: t0 + Duration::from_millis(300),
            link: &link,
            budget: &budget,
            later_blocks_progressing: false, // <-- nothing ahead ⇒ just reordered
        };
        let mut m2 = m;
        assert_eq!(m2.tick(&ctx), DecoderAction::Idle);
    }

    #[test]
    fn genuine_stall_sends_nack_then_budget_exhaustion_degrades() {
        let mut m = mgr(10);
        let t0 = Instant::now();
        m.on_symbol(t0, 0, b"a"); // received = 1, need = 9

        let budget = RepairBudget::new(1200, 0.4);
        budget.refresh_ceiling(1_000_000); // plenty
        let link = LinkState::for_test(Duration::from_millis(50), 0.2, LossRegime::Random);
        let ctx = TickCtx {
            now: t0 + Duration::from_secs(1),
            link: &link,
            budget: &budget,
            later_blocks_progressing: true,
        };
        assert_eq!(m.tick(&ctx), DecoderAction::SendNack { have: 1, need: 9 });

        // A fresh block that stalls when the budget is empty must degrade.
        let mut m2 = mgr(10);
        m2.on_symbol(t0, 0, b"a");
        let tight = RepairBudget::new(1200, 0.4);
        tight.refresh_ceiling(0); // ceiling 0 ⇒ nothing fits
        let ctx2 = TickCtx {
            now: t0 + Duration::from_secs(1),
            link: &link,
            budget: &tight,
            later_blocks_progressing: true,
        };
        assert_eq!(m2.tick(&ctx2), DecoderAction::RequestReliableRetransmit);
    }

    #[test]
    fn congestion_regime_degrades_without_nack() {
        let mut m = mgr(10);
        let t0 = Instant::now();
        m.on_symbol(t0, 0, b"a");
        let budget = RepairBudget::new(1200, 0.4);
        budget.refresh_ceiling(1_000_000);
        let congested = LinkState::for_test(Duration::from_millis(50), 0.2, LossRegime::Congestion);
        let ctx = TickCtx {
            now: t0 + Duration::from_secs(1),
            link: &congested,
            budget: &budget,
            later_blocks_progressing: true,
        };
        // Even with budget available, congestion ⇒ no NACK, straight to fallback.
        assert_eq!(m.tick(&ctx), DecoderAction::RequestReliableRetransmit);
    }

    #[test]
    fn hard_deadline_stalls_head_block_without_progress_signal() {
        // A block that never sees a higher block (no progress oracle) must still
        // stall once the absolute hard deadline passes — otherwise a lone/tail
        // block lost heavily would strand forever. With budget available it
        // NACKs; the point is that it no longer waits indefinitely.
        let mut m = mgr(10);
        let t0 = Instant::now();
        m.on_symbol(t0, 0, b"a"); // 1 of 10, far from decodable
        let budget = RepairBudget::new(1200, 0.4);
        budget.refresh_ceiling(1_000_000);
        let link = LinkState::for_test(Duration::from_millis(50), 0.2, LossRegime::Random);

        // Just past the jitter grace but with no later block: must NOT stall.
        let early = TickCtx {
            now: t0 + Duration::from_millis(300),
            link: &link,
            budget: &budget,
            later_blocks_progressing: false,
        };
        assert_eq!(m.tick(&early), DecoderAction::Idle);

        // Well past the hard deadline: must act despite no progress signal.
        let late = TickCtx {
            now: t0 + Duration::from_secs(5),
            link: &link,
            budget: &budget,
            later_blocks_progressing: false,
        };
        assert_eq!(m.tick(&late), DecoderAction::SendNack { have: 1, need: 9 });
    }
}
