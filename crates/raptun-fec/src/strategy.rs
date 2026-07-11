//! [`RepairRatio`] and the adaptive [`FecStrategy`] controller.
//!
//! # Why adaptive at all?
//!
//! FEC is not free and, crucially, it is not always *helpful*:
//!
//! * Against **random loss** (satellite, congested mobile, policy-based packet
//!   drops on international links — kcptun's home turf) FEC is a clear win:
//!   proactively sending redundancy recovers the loss without waiting a round
//!   trip for a retransmit.
//! * Against **congestion loss** (the link is genuinely full) FEC is *harmful*:
//!   every repair symbol steals congestion-window space from real data, so more
//!   redundancy causes more drops — a positive feedback loop toward collapse.
//!
//! Therefore the single most important job of this controller is to tell those
//! two regimes apart and move the repair ratio in *opposite directions* for
//! each. kcptun cannot do this — running over KCP it has no view of the true
//! congestion state. Raptun reads it directly from Quinn.

use crate::link::{LinkState, LossRegime};

/// A repair overhead ratio: repair symbols per source symbol, as a fraction.
///
/// Stored as parts-per-million internally for exact arithmetic on the wire
/// (`raptun_proto` carries parts-per-thousand; we keep more precision here and
/// round when announcing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RepairRatio(u32);

impl RepairRatio {
    /// Construct from a floating fraction (e.g. `0.15` = 15% overhead),
    /// clamped to `[0, 4.0]` — beyond 400% overhead is never sensible.
    pub fn from_fraction(f: f64) -> Self {
        let clamped = f.clamp(0.0, 4.0);
        RepairRatio((clamped * 1_000_000.0) as u32)
    }

    /// The fraction as an `f64`.
    pub fn as_fraction(self) -> f64 {
        self.0 as f64 / 1_000_000.0
    }

    /// Parts-per-thousand, for the [`raptun_proto::control::FecParams`] wire field.
    pub fn as_ppm_thousandths(self) -> u16 {
        (self.0 / 1000).min(u16::MAX as u32) as u16
    }

    /// How many repair symbols to generate for a block of `k` source symbols.
    /// Always at least 1 when the ratio is non-zero, so a tiny block still gets
    /// *some* protection.
    pub fn repair_count_for(self, k: u32) -> u32 {
        if self.0 == 0 {
            return 0;
        }
        let raw = (u64::from(k) * u64::from(self.0) / 1_000_000) as u32;
        raw.max(1)
    }
}

/// Tunable bounds and gains for the adaptive controller. Sourced from CLI /
/// config; see the design doc parameter table.
#[derive(Debug, Clone, Copy)]
pub struct StrategyConfig {
    /// Never drop below this ratio, even on a clean link — a small standing
    /// redundancy absorbs the first surprise loss without a NACK round trip.
    pub min: RepairRatio,
    /// Never exceed this ratio. Bounds worst-case bandwidth amplification and
    /// is independently enforced by the server (`--fec-max`).
    pub max: RepairRatio,
    /// Multiplier applied to observed loss to set the target in the random-loss
    /// regime. `1.3` means "provision 30% above the measured loss rate" as a
    /// safety margin for loss-rate estimation error.
    pub safety_margin: f64,
    /// Fraction of the gap to the target closed per update tick (EWMA-style
    /// smoothing). Small = sluggish but stable; large = twitchy. `0.25` is a
    /// reasonable default.
    pub gain: f64,
}

impl Default for StrategyConfig {
    fn default() -> Self {
        Self {
            min: RepairRatio::from_fraction(0.02),
            max: RepairRatio::from_fraction(0.50),
            safety_margin: 1.3,
            gain: 0.25,
        }
    }
}

/// The adaptive FEC controller. One instance per tunnelled stream (or per
/// connection, if repair ratio is managed connection-wide).
///
/// It is a slow control loop: call [`FecStrategy::update`] periodically (e.g.
/// once per RTT) with a fresh [`LinkState`] snapshot. The fast loop — the
/// per-block NACK — lives in [`crate::decoder`] and is deliberately *separate*;
/// see [`FecStrategy::update`] for how the two are kept from fighting.
#[derive(Debug)]
pub struct FecStrategy {
    config: StrategyConfig,
    current: RepairRatio,
}

impl FecStrategy {
    pub fn new(config: StrategyConfig, initial: RepairRatio) -> Self {
        let current = initial.clamp(config.min, config.max);
        Self { config, current }
    }

    /// The ratio to use for the next block encoded.
    pub fn current(&self) -> RepairRatio {
        self.current
    }

    /// Fold a new telemetry snapshot into the repair ratio.
    ///
    /// The regime classification is the crux:
    ///
    /// * [`LossRegime::Random`] — move the ratio *toward* `loss * safety_margin`.
    ///   More loss ⇒ more redundancy, so most blocks self-heal without a NACK.
    /// * [`LossRegime::Congestion`] — move the ratio *down* toward `min`.
    ///   Adding redundancy now would deepen the congestion; back off and let the
    ///   [`crate::decoder`] fall back to reliable retransmit for the few blocks
    ///   that actually strand.
    /// * [`LossRegime::Quiescent`] — decay gently toward `min`.
    ///
    /// Returns `true` if the ratio changed enough to be worth announcing to the
    /// peer via a `FecReconfig` control message.
    pub fn update(&mut self, link: &LinkState) -> bool {
        let target = match link.regime() {
            LossRegime::Random => {
                RepairRatio::from_fraction(link.loss_rate() * self.config.safety_margin)
            }
            LossRegime::Congestion => self.config.min,
            LossRegime::Quiescent => self.config.min,
        };
        let target = target.clamp(self.config.min, self.config.max);

        // EWMA step toward the target so the ratio never jumps discontinuously.
        let now = self.current.as_fraction();
        let stepped = now + (target.as_fraction() - now) * self.config.gain;
        let next = RepairRatio::from_fraction(stepped).clamp(self.config.min, self.config.max);

        // Only report a change if it crosses a meaningful threshold (1%), to
        // avoid a chatty stream of FecReconfig messages.
        let changed = (next.as_fraction() - self.current.as_fraction()).abs() > 0.01;
        self.current = next;
        changed
    }
}

impl RepairRatio {
    fn clamp(self, lo: RepairRatio, hi: RepairRatio) -> RepairRatio {
        RepairRatio(self.0.clamp(lo.0, hi.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::LinkState;
    use std::time::Duration;

    #[test]
    fn repair_count_rounds_and_floors_at_one() {
        let r = RepairRatio::from_fraction(0.15);
        assert_eq!(r.repair_count_for(100), 15);
        // Non-zero ratio always yields at least one repair symbol.
        assert_eq!(RepairRatio::from_fraction(0.001).repair_count_for(10), 1);
        assert_eq!(RepairRatio::from_fraction(0.0).repair_count_for(100), 0);
    }

    #[test]
    fn random_loss_raises_ratio_congestion_lowers_it() {
        let cfg = StrategyConfig::default();
        let mut strat = FecStrategy::new(cfg, RepairRatio::from_fraction(0.05));

        // Random-loss link at 20% loss: ratio should climb over several ticks.
        let random = LinkState::for_test(Duration::from_millis(100), 0.20, LossRegime::Random);
        for _ in 0..20 {
            strat.update(&random);
        }
        assert!(
            strat.current().as_fraction() > 0.15,
            "expected ratio to rise toward ~0.26, got {}",
            strat.current().as_fraction()
        );

        // Now the link becomes congested: ratio must fall back toward min.
        let congested =
            LinkState::for_test(Duration::from_millis(100), 0.20, LossRegime::Congestion);
        for _ in 0..50 {
            strat.update(&congested);
        }
        assert!(
            strat.current().as_fraction() < 0.05,
            "expected ratio to collapse toward min under congestion, got {}",
            strat.current().as_fraction()
        );
    }
}
