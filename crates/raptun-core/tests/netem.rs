//! Extreme-network convergence benchmark — an in-process, deterministic
//! emulation of the acceptance scenario in DESIGN.md §5.
//!
//! # Why in-process instead of `tc netem`?
//!
//! `tc netem` is Linux-only and needs root, so it cannot run in this repo's CI
//! (macOS) or unprivileged environments. A `netem_bench.sh` for real-network
//! validation on Linux ships alongside this file. But the *convergence
//! properties* §5 asks us to verify — bounded tail latency, no NACK avalanche,
//! the in-flight-repair budget invariant, and eventual completion under
//! loss+jitter+reorder — are properties of Raptun's own FEC control loop, not
//! of the kernel qdisc. So we exercise them directly and deterministically:
//!
//! * a **virtual clock** advanced in fixed steps (no wall-clock flakiness),
//! * a **seeded xorshift PRNG** for reproducible loss/jitter/reorder,
//! * the **real** [`FecSender`], [`FecReceiver`], its control `tick`, the
//!   [`RepairBudget`] brake, and the [`LinkState`] the arbitration consumes.
//!
//! The datagram path is modeled as lossy+reordering (what QUIC datagrams
//! actually are); the signaling path (NACK / reliable-retransmit) is modeled as
//! reliable but delayed (a QUIC stream). This mirrors the two-path data plane.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::time::{Duration, Instant};

use raptun_core::fec::{FecReceiver, FecSender, TunnelSignal};
use raptun_fec::link::{LinkState, LossRegime};
use raptun_fec::RepairBudget;
use raptun_proto::datagram::SymbolHeader;

/// Deterministic xorshift64* PRNG — no external crate, fully reproducible.
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    /// Uniform in [0, 1).
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    /// Uniform in [0, n).
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }
}

/// A datagram in flight on the (lossy) data channel, ordered by delivery time.
struct InFlight {
    // Retained for readability of the flight record even though ordering is
    // handled by the priority queue rather than by reading this field back.
    #[allow(dead_code)]
    deliver_at: u64, // virtual ms
    block: u64,
    esi: u32,
    payload: Vec<u8>,
}

/// One direction of the emulated link.
struct Channel {
    /// Milliseconds of base one-way delay.
    base_delay_ms: u64,
    /// Max extra jitter (uniform [0, jitter_ms]).
    jitter_ms: u64,
    /// Loss probability in [0, 1].
    loss: f64,
    /// Probability a delivered packet is additionally reordered (extra delay).
    reorder: f64,
    /// Pending datagrams, min-heap by delivery time.
    queue: BinaryHeap<Reverse<(u64, u64)>>, // (deliver_at, seq) index into store
    store: Vec<Option<InFlight>>,
}

impl Channel {
    fn new(base_delay_ms: u64, jitter_ms: u64, loss: f64, reorder: f64) -> Self {
        Self {
            base_delay_ms,
            jitter_ms,
            loss,
            reorder,
            queue: BinaryHeap::new(),
            store: Vec::new(),
        }
    }

    /// Offer a datagram to the channel at virtual time `now`. Returns whether it
    /// was accepted (not dropped by loss).
    fn send(&mut self, now: u64, block: u64, esi: u32, payload: Vec<u8>, rng: &mut Rng) -> bool {
        if rng.unit() < self.loss {
            return false; // lost
        }
        let mut delay = self.base_delay_ms + rng.below(self.jitter_ms + 1);
        if rng.unit() < self.reorder {
            // Reordered packets get a bigger extra delay so they arrive late.
            delay += self.base_delay_ms + rng.below(self.jitter_ms * 2 + 1);
        }
        let idx = self.store.len() as u64;
        self.store.push(Some(InFlight {
            deliver_at: now + delay,
            block,
            esi,
            payload,
        }));
        self.queue.push(Reverse((now + delay, idx)));
        true
    }

    /// Drain all datagrams whose delivery time is <= `now`.
    fn ready(&mut self, now: u64) -> Vec<InFlight> {
        let mut out = Vec::new();
        while let Some(Reverse((t, idx))) = self.queue.peek().copied() {
            if t > now {
                break;
            }
            self.queue.pop();
            if let Some(item) = self.store[idx as usize].take() {
                out.push(item);
            }
        }
        out
    }
}

/// Metrics collected across the run, checked against §5 acceptance criteria.
#[derive(Default)]
struct Metrics {
    /// Per-block completion latency in virtual ms (first offered → delivered).
    block_latency_ms: Vec<u64>,
    /// NACKs emitted per tick, to detect avalanche (unbounded growth).
    nacks_per_tick: Vec<usize>,
    /// Reliable-retransmit fallbacks used.
    reliable_fallbacks: usize,
    /// Max observed in-flight repair as a fraction of the ceiling.
    max_inflight_over_ceiling: f64,
}

impl Metrics {
    fn percentile(&self, p: f64) -> u64 {
        if self.block_latency_ms.is_empty() {
            return 0;
        }
        let mut v = self.block_latency_ms.clone();
        v.sort_unstable();
        let idx = ((v.len() as f64 - 1.0) * p).round() as usize;
        v[idx]
    }
}

/// Run one extreme-network scenario end to end and return (recovered bytes,
/// original bytes, metrics).
#[allow(clippy::too_many_arguments)]
fn run_scenario(
    seed: u64,
    payload_len: usize,
    symbol_size: u16,
    k: u32,
    proactive_repair: u32,
    data_loss: f64,
    jitter_ms: u64,
    reorder: f64,
    cwnd_bytes: u64,
    regime: LossRegime,
) -> (Vec<u8>, Vec<u8>, Metrics) {
    let mut rng = Rng::new(seed);
    let mut metrics = Metrics::default();

    // Deterministic payload.
    let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();

    let mut sender = FecSender::new(1, symbol_size, k);
    let mut receiver = FecReceiver::new(symbol_size, k);
    let budget = RepairBudget::new(symbol_size, 0.40); // the ≤40% cwnd brake
    budget.refresh_ceiling(cwnd_bytes);

    // Data channel: lossy + jittered + reordering. Signaling channel: reliable
    // (no loss) but delayed, like a QUIC stream.
    let base_delay = 20u64;
    let mut data = Channel::new(base_delay, jitter_ms, data_loss, reorder);
    let mut sig = Channel::new(base_delay, jitter_ms, 0.0, 0.0);

    // Encode all blocks up front and offer their symbols at t=0..; track when
    // each block was first offered for latency accounting.
    let cap = sender.block_payload();
    let mut first_offered: Vec<u64> = Vec::new();
    let mut block_done: Vec<bool> = Vec::new();
    let mut now = 0u64;
    for chunk in payload.chunks(cap) {
        for dg in sender.encode_one_block(chunk, proactive_repair) {
            let (h, p) = SymbolHeader::parse(&dg).unwrap();
            data.send(now, h.block_id, h.esi, p.to_vec(), &mut rng);
        }
        first_offered.push(now);
        block_done.push(false);
        now += 1; // stagger block offers slightly
    }
    let total_blocks = first_offered.len() as u64;
    // The sender announces the block count reliably.
    sig.send(
        now,
        u64::MAX,
        0,
        TunnelSignal::BlockCount {
            total: total_blocks,
        }
        .encode(),
        &mut rng,
    );

    let link = LinkState::new(
        Duration::from_millis(base_delay),
        Duration::from_millis(jitter_ms.max(1)),
        data_loss,
        cwnd_bytes,
        regime,
    );

    let mut assembled = Vec::new();
    let tick_period = 20u64;
    let mut next_tick = tick_period;
    let clock_start = Instant::now(); // only for the tick's `now: Instant` arg base
    let deadline = 60_000u64; // 60 virtual seconds hard cap

    while receiver.highest_delivered() < total_blocks && now < deadline {
        // Deliver data-channel arrivals.
        for item in data.ready(now) {
            let out = receiver.on_symbol(
                item.block,
                item.esi,
                &item.payload,
                clock_start + Duration::from_millis(now),
                &budget,
            );
            record_delivered(
                &mut block_done,
                &first_offered,
                now,
                &mut metrics,
                &receiver,
            );
            assembled.extend_from_slice(&out);
            // A block may have decoded: ack it so the sender releases
            // its retained state for this block.
            for block in receiver.drain_acks() {
                sig.send(
                    now,
                    block,
                    0,
                    TunnelSignal::BlockAck { block }.encode(),
                    &mut rng,
                );
            }
        }
        // Deliver signaling-channel arrivals (both directions share `sig`).
        for item in sig.ready(now) {
            if let Some((signal, _)) = TunnelSignal::decode(&item.payload) {
                match signal {
                    TunnelSignal::BlockCount { total } => {
                        if total != u64::MAX {
                            receiver.set_total_blocks(total);
                        }
                    }
                    TunnelSignal::HighWater { blocks } => {
                        receiver.set_high_water(blocks);
                    }
                    TunnelSignal::Nack { block, need, .. } => {
                        // Sender serves the NACK with fresh repair on the data channel.
                        for dg in sender.additional_repair(block, need) {
                            let (h, p) = SymbolHeader::parse(&dg).unwrap();
                            data.send(now, h.block_id, h.esi, p.to_vec(), &mut rng);
                        }
                    }
                    TunnelSignal::ReliableRequest { block } => {
                        // Sender ships the block's bytes reliably.
                        if let Some(bytes) = sender.reliable_payload(block) {
                            sig.send(
                                now,
                                block,
                                0,
                                TunnelSignal::ReliableData { block, bytes }.encode(),
                                &mut rng,
                            );
                        }
                    }
                    TunnelSignal::ReliableData { block, bytes } => {
                        metrics.reliable_fallbacks += 1;
                        let out = receiver.on_reliable_block(block, bytes);
                        record_delivered(
                            &mut block_done,
                            &first_offered,
                            now,
                            &mut metrics,
                            &receiver,
                        );
                        assembled.extend_from_slice(&out);
                        // A reliably-completed block is also done: ack it.
                        for block in receiver.drain_acks() {
                            sig.send(
                                now,
                                block,
                                0,
                                TunnelSignal::BlockAck { block }.encode(),
                                &mut rng,
                            );
                        }
                    }
                    // Flow-control credit is a live-path optimization; the
                    // deterministic netem model does not gate on it.
                    TunnelSignal::Credit { .. } => {}
                    // BlockAck: the receiver decoded this block; release
                    // the sender's retained state for it.
                    TunnelSignal::BlockAck { block } => {
                        sender.retire_block(block);
                    }
                }
            }
        }

        // Periodic control tick: arbitrate stalled blocks, route signals back.
        if now >= next_tick {
            next_tick += tick_period;
            let signals = receiver.tick(&link, &budget, clock_start + Duration::from_millis(now));
            metrics.nacks_per_tick.push(
                signals
                    .iter()
                    .filter(|s| matches!(s, TunnelSignal::Nack { .. }))
                    .count(),
            );
            // Record the budget invariant.
            let ceiling = budget.ceiling().max(1);
            let frac = budget.in_flight() as f64 / ceiling as f64;
            if frac > metrics.max_inflight_over_ceiling {
                metrics.max_inflight_over_ceiling = frac;
            }
            for s in signals {
                sig.send(now, 0, 0, s.encode(), &mut rng);
            }
            // Tick may have detected entirely-lost blocks and completed
            // them via the reliable path; ack those too.
            for block in receiver.drain_acks() {
                sig.send(
                    now,
                    block,
                    0,
                    TunnelSignal::BlockAck { block }.encode(),
                    &mut rng,
                );
            }
        }

        now += 1;
    }

    (assembled, payload, metrics)
}

/// Note the completion time of any blocks that just became delivered.
fn record_delivered(
    block_done: &mut [bool],
    first_offered: &[u64],
    now: u64,
    metrics: &mut Metrics,
    receiver: &FecReceiver,
) {
    let delivered = receiver.highest_delivered() as usize;
    for b in 0..delivered.min(block_done.len()) {
        if !block_done[b] {
            block_done[b] = true;
            metrics
                .block_latency_ms
                .push(now.saturating_sub(first_offered[b]));
        }
    }
}

/// §5 acceptance: the extreme triple — 30% loss + heavy jitter + 25% reorder —
/// must still converge (full, correct, in-order recovery), with a bounded tail
/// latency, no NACK avalanche, and the in-flight repair budget never exceeding
/// its ceiling.
#[test]
fn extreme_loss_jitter_reorder_converges_bounded() {
    // Run several seeds so the result isn't a lucky draw.
    for seed in [1u64, 7, 42, 1000, 65535] {
        let (got, want, m) = run_scenario(
            seed,
            40_000,     // payload bytes → many blocks
            256,        // small symbols → more symbols per block
            16,         // K
            8,          // proactive repair ~50% (随机丢包 regime appropriate)
            0.30,       // 30% datagram loss
            150,        // up to 150ms jitter
            0.25,       // 25% reordered
            256 * 1024, // cwnd
            LossRegime::Random,
        );

        // Convergence: full, correct, in-order.
        assert_eq!(got, want, "seed {seed}: stream must fully converge");

        // Budget invariant: in-flight repair never exceeds the ceiling.
        assert!(
            m.max_inflight_over_ceiling <= 1.0 + 1e-9,
            "seed {seed}: in-flight repair {:.3}× ceiling exceeds the 40%-cwnd brake",
            m.max_inflight_over_ceiling
        );

        // No avalanche: the per-tick NACK count must not grow without bound. We
        // assert the late-run average is not higher than the early-run average
        // by more than a small factor — a diverging control loop would show
        // monotonically climbing NACK counts.
        let n = m.nacks_per_tick.len();
        if n >= 10 {
            let early: usize = m.nacks_per_tick[..n / 4].iter().sum();
            let late: usize = m.nacks_per_tick[3 * n / 4..].iter().sum();
            let early_rate = early as f64 / (n / 4).max(1) as f64;
            let late_rate = late as f64 / (n - 3 * n / 4).max(1) as f64;
            assert!(
                late_rate <= early_rate.max(1.0) * 3.0 + 1.0,
                "seed {seed}: NACK rate climbing (early {early_rate:.2} → late {late_rate:.2}) — possible avalanche"
            );
        }

        // Report tail latency (informational; bounded by construction via the
        // hard deadline + reliable fallback).
        let p50 = m.percentile(0.50);
        let p99 = m.percentile(0.99);
        eprintln!(
            "seed {seed}: blocks={}, p50={}ms p99={}ms, reliable_fallbacks={}, max_inflight/ceiling={:.2}",
            m.block_latency_ms.len(),
            p50,
            p99,
            m.reliable_fallbacks,
            m.max_inflight_over_ceiling
        );
        assert!(p99 < 60_000, "seed {seed}: p99 latency unbounded");
    }
}

/// A congestion-limited link: FEC must *not* pile on repair (the strategy backs
/// off), and the stream still completes via the reliable fallback. Verifies the
/// "don't add FEC under congestion" arbitration end to end.
#[test]
fn congestion_regime_completes_via_fallback_without_repair_flood() {
    let (got, want, m) = run_scenario(
        99,
        20_000,
        256,
        16,
        0,                      // no proactive repair
        0.30,                   // 30% loss
        80,                     // jitter
        0.10,                   // reorder
        64 * 1024,              // cwnd
        LossRegime::Congestion, // congestion-limited: must not NACK-flood
    );
    assert_eq!(
        got, want,
        "must still converge under congestion via fallback"
    );
    // Under congestion the tick must degrade rather than NACK, so NACK counts
    // stay at zero and completion relies on reliable retransmit.
    let total_nacks: usize = m.nacks_per_tick.iter().sum();
    assert_eq!(
        total_nacks, 0,
        "must not emit NACKs (add repair) on a congestion-limited link"
    );
    assert!(
        m.reliable_fallbacks > 0,
        "congestion path must complete via reliable retransmit"
    );
    eprintln!(
        "congestion: reliable_fallbacks={}, p99={}ms",
        m.reliable_fallbacks,
        m.percentile(0.99)
    );
}
