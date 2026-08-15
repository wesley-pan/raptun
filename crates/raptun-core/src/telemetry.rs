//! Converting Quinn connection telemetry into the FEC layer's [`LinkState`].
//!
//! The FEC crate is intentionally transport-agnostic: it consumes a plain
//! [`raptun_fec::LinkState`] and never touches Quinn. This module is the bridge,
//! and it owns the one piece of state the FEC layer cannot compute on its own —
//! the **cross-tick congestion-window history** needed to tell a congestion cut
//! (window shrinking) from steady-state random loss (window stable/growing).

use std::sync::atomic::{AtomicU64, Ordering};

use raptun_fec::link::{LinkState, LossRegime};

/// Global throttle for the loss-source diagnostic log.
///
/// `LossTracker::allow_diag` is per-tunnel (500 ms), but a single QUIC connection
/// can carry many tunnels that all see the same path stats.  Without a global
/// gate, every tunnel fires the diagnostic simultaneously the first time loss
/// crosses 5 %, producing a burst of identical log lines.  This atomic records
/// the last wall-clock millisecond the diagnostic was emitted by *any* tunnel and
/// enforces a connection-wide minimum interval.
static LAST_DIAG_MS: AtomicU64 = AtomicU64::new(0);
/// Minimum interval between loss-source diagnostics, connection-wide.
const DIAG_INTERVAL_MS: u64 = 2_000; // 2 s — diagnostic, not a heartbeat

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
    /// Separate baseline advanced only when the loss-source diagnostic actually
    /// fires (~every 2 s), so the logged loss rate covers the whole
    /// diagnostic interval rather than the last 20 ms `read_telemetry` tick.
    /// `read_telemetry` runs every 20 ms, so `prev`-based loss is a
    /// tiny-denominator sample that swings wildly (a single late packet reads as
    /// 100%). Keying the *logged* figure on its own coarse baseline makes the
    /// diagnostic reflect what the link did over the interval it represents.
    diag_prev: Option<(u64, u64)>,
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
    /// interval since the previous call. Returns `None` on the first call (only
    /// establishes a baseline) or any interval with no newly-sent packets.
    ///
    /// Like [`Self::diag_loss`], the baseline case is exposed as `None` so the
    /// caller can distinguish "no measurement yet" from a real 0% reading.
    /// The FEC controller treats a baseline as 0% (assumed no loss until seen),
    /// which matches the pre-Option behaviour; the operator-facing heartbeat
    /// skips the `loss_pct` field on baseline ticks so it doesn't display a
    /// bogus `0.00` that looks like a real reading.
    pub fn window_loss(&mut self, sent: u64, lost: u64) -> Option<f64> {
        let rate = match self.prev {
            None => None,
            Some((ps, pl)) => {
                // Counters are monotonic; guard against wraparound/reset.
                let d_sent = sent.saturating_sub(ps);
                let d_lost = lost.saturating_sub(pl);
                if d_sent == 0 {
                    Some(0.0)
                } else {
                    Some((d_lost as f64 / d_sent as f64).clamp(0.0, 1.0))
                }
            }
        };
        self.prev = Some((sent, lost));
        rate
    }

    /// Loss rate over the interval since the last *diagnostic*, and advance the
    /// diagnostic baseline. Call this only when about to emit the loss-source
    /// diagnostic (i.e. right after `allow_diag` returns true): unlike
    /// `window_loss`, whose 20 ms cadence gives a tiny, noisy denominator, this
    /// spans the full ~2 s diagnostic interval, so the logged figure reflects
    /// the link over the window the log line actually represents.
    ///
    /// Returns `None` on the first diagnostic (baseline only — no measurement
    /// yet) or `Some(rate)` otherwise (the rate is 0.0 for an interval with no
    /// newly-sent packets, which is a real "nothing happened" reading, not a
    /// missing baseline). The `Option` exists to make the baseline-vs-measurement
    /// distinction explicit to the caller; logging a baseline 0.0 as a real
    /// `loss_pct` reading misleads operators (regression test: `diag_loss_is_none_on_baseline`).
    pub(crate) fn diag_loss(&mut self, sent: u64, lost: u64) -> Option<f64> {
        let rate = match self.diag_prev {
            None => None,
            Some((ps, pl)) => {
                let d_sent = sent.saturating_sub(ps);
                let d_lost = lost.saturating_sub(pl);
                if d_sent == 0 {
                    Some(0.0)
                } else {
                    Some((d_lost as f64 / d_sent as f64).clamp(0.0, 1.0))
                }
            }
        };
        self.diag_prev = Some((sent, lost));
        rate
    }

    /// Return `true` at most once per `DIAG_INTERVAL` so the loss-source
    /// diagnostic in `read_telemetry` doesn't fire on every 20ms tick.
    ///
    /// The per-tracker timer (500 ms) prevents each tunnel from hammering the
    /// global atomic on every tick; the global atomic (2 s) prevents all
    /// tunnels on a shared connection from firing simultaneously the first
    /// time loss crosses the threshold.
    pub(crate) fn allow_diag(&mut self) -> bool {
        const LOCAL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
        let now = std::time::Instant::now();
        if let Some(t) = self.last_diag {
            if now.duration_since(t) < LOCAL_INTERVAL {
                return false;
            }
        }
        // Global gate: at most one tunnel per connection (really per process,
        // but the log is connection-stats anyway) emits the diagnostic per
        // DIAG_INTERVAL_MS.  If two tunnels race the CAS the loser backs off
        // until its next local window.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let last = LAST_DIAG_MS.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) < DIAG_INTERVAL_MS {
            return false;
        }
        if LAST_DIAG_MS
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        self.last_diag = Some(now);
        true
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
    /// * heavy smoothed loss (>10%) while the cwnd has stopped growing ⇒
    ///   [`LossRegime::Congestion`]. This is the local-buffer-overflow
    ///   tail-drop signature: BBR keeps the cwnd flat-or-high because the
    ///   drops happen in a local/middlebox queue it cannot see, so the
    ///   cwnd-cut rule above never fires — yet piling FEC repair onto the
    ///   overloaded queue only deepens the loss (the flapping feedback loop,
    ///   docs/raptun-congestion-optimization-plan.md §3.3).
    /// * negligible loss ⇒ [`LossRegime::Quiescent`].
    /// * otherwise (loss present, cwnd stable/growing) ⇒ [`LossRegime::Random`]
    ///   (FEC helps).
    pub fn classify(&mut self, cwnd_bytes: u64, loss_rate: f64) -> LossRegime {
        // EWMA the loss so a single lost packet doesn't flip the regime.
        self.smoothed_loss = self.smoothed_loss * 0.7 + loss_rate.clamp(0.0, 1.0) * 0.3;

        let regime = match self.prev_cwnd {
            // A >12.5% drop in cwnd is treated as a congestion reaction.
            Some(prev) if cwnd_bytes < prev - prev / 8 => LossRegime::Congestion,
            // Heavy loss with a non-growing cwnd: tail-drop congestion that
            // the transport's own loss detector failed to classify.
            Some(prev) if self.smoothed_loss > 0.10 && cwnd_bytes <= prev => LossRegime::Congestion,
            _ if self.smoothed_loss < 0.005 => LossRegime::Quiescent,
            _ => LossRegime::Random,
        };
        self.prev_cwnd = Some(cwnd_bytes);
        regime
    }
}

/// Consecutive-bad-tick detector that decides when a connection is stalled
/// badly enough to be worth tearing down and re-dialing.
///
/// # Why kill a connection that is technically still alive
///
/// Under the bufferbloat → tail-drop → repair-storm cycle the QUIC connection
/// does not die: keepalives still get through, so the idle timeout never fires,
/// and Quinn happily keeps a connection that is passing almost no useful data.
/// The user sees a hang that lasts until something else finally breaks. A
/// deliberate close converts that open-ended hang into a bounded one: the
/// supervision loop re-dials on the fast backoff (200 ms, jittered) and the new
/// connection starts with a cold cwnd and an empty local queue — which is
/// exactly the state the stalled connection cannot reach on its own, because
/// its own backlog is what keeps it stalled.
///
/// # Why a streak rather than a duration or an average
///
/// The trip condition must be *sustained* loss. Transient spikes are normal
/// (one bad tick during a route change, a burst of cross traffic) and must
/// never cost a reconnect — a watchdog that fires on noise is worse than no
/// watchdog, since each spurious close drops every live tunnel on the
/// connection. Requiring N consecutive bad ticks, with any single healthy tick
/// clearing the streak, makes recovery strictly cheaper than tripping: the
/// connection only dies if it fails to produce even one good tick in a row.
///
/// The watchdog is deliberately *not* cwnd-aware. The whole point of the
/// tail-drop signature (§3.3 of the optimization plan) is that cwnd stays
/// inflated while the link drowns, so gating on "cwnd is also low" would
/// suppress the watchdog in precisely the scenario it exists for.
#[derive(Debug)]
pub struct StallWatchdog {
    /// Loss rate above which a tick counts as "bad" (strictly greater).
    loss_threshold: f64,
    /// Consecutive bad ticks required to trip. Zero disables the watchdog.
    ticks_to_trip: u32,
    /// Current run of consecutive bad ticks.
    streak: u32,
    /// Latched once tripped, so a slow teardown can't fire a second close.
    fired: bool,
}

impl StallWatchdog {
    pub fn new(loss_threshold: f64, ticks_to_trip: u32) -> Self {
        Self {
            loss_threshold,
            ticks_to_trip,
            streak: 0,
            fired: false,
        }
    }

    /// Fold in one heartbeat sample; returns `true` exactly once, on the tick
    /// that completes the bad streak.
    ///
    /// `loss` is `None` when the sample carries no measurement (the heartbeat's
    /// first tick, before the loss baseline exists). Such a tick is skipped
    /// entirely — it neither advances nor clears the streak — so the watchdog's
    /// timing doesn't depend on when the baseline happened to be established.
    pub fn observe(&mut self, loss: Option<f64>) -> bool {
        if self.ticks_to_trip == 0 || self.fired {
            return false;
        }
        let Some(loss) = loss else { return false };
        if loss > self.loss_threshold {
            self.streak += 1;
            if self.streak >= self.ticks_to_trip {
                self.fired = true;
                return true;
            }
        } else {
            self.streak = 0;
        }
        false
    }

    /// Current consecutive-bad-tick run, for logging.
    pub fn streak(&self) -> u32 {
        self.streak
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
    fn watchdog_trips_only_after_sustained_loss() {
        // Threshold 30%, 3 consecutive ticks required.
        let mut w = StallWatchdog::new(0.30, 3);
        assert!(!w.observe(Some(0.50)), "one bad tick is not a stall");
        assert!(!w.observe(Some(0.50)), "two bad ticks is not a stall yet");
        assert!(w.observe(Some(0.50)), "third consecutive bad tick trips it");
    }

    #[test]
    fn watchdog_resets_on_recovery() {
        // A single healthy tick must clear the streak: transient loss spikes are
        // normal and must never cost the user a reconnect.
        let mut w = StallWatchdog::new(0.30, 3);
        w.observe(Some(0.50));
        w.observe(Some(0.50));
        assert!(!w.observe(Some(0.01)), "recovery clears the streak");
        assert!(!w.observe(Some(0.50)), "streak restarts from zero");
        assert!(!w.observe(Some(0.50)));
        assert!(w.observe(Some(0.50)), "needs 3 fresh consecutive ticks");
    }

    #[test]
    fn watchdog_ignores_baseline_ticks() {
        // `None` is "no measurement" (the heartbeat's first tick), not "0% loss"
        // and not "bad". It must neither advance nor reset the streak — folding
        // a baseline in either direction would make the watchdog's timing
        // depend on when the loss baseline happened to be established.
        let mut w = StallWatchdog::new(0.30, 3);
        assert!(!w.observe(Some(0.50)));
        assert!(!w.observe(None), "baseline is not a bad tick");
        assert!(!w.observe(Some(0.50)));
        assert!(
            w.observe(Some(0.50)),
            "the None tick was skipped, not counted as recovery"
        );
    }

    #[test]
    fn watchdog_trips_at_most_once() {
        // After tripping, the caller closes the connection and the task ends.
        // Latch so a slow teardown can't fire a second close.
        let mut w = StallWatchdog::new(0.30, 2);
        w.observe(Some(0.90));
        assert!(w.observe(Some(0.90)));
        assert!(!w.observe(Some(0.90)), "must not re-trip after firing");
    }

    #[test]
    fn watchdog_loss_exactly_at_threshold_is_not_bad() {
        // Strictly-greater comparison: a link sitting exactly at the configured
        // threshold is at the edge of tolerated, not over it.
        let mut w = StallWatchdog::new(0.30, 2);
        assert!(!w.observe(Some(0.30)));
        assert!(!w.observe(Some(0.30)), "at-threshold loss never trips");
    }

    #[test]
    fn watchdog_disabled_never_trips() {
        // ticks == 0 disables the watchdog entirely (operator escape hatch).
        let mut w = StallWatchdog::new(0.30, 0);
        for _ in 0..100 {
            assert!(!w.observe(Some(0.99)), "disabled watchdog must never trip");
        }
    }

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
    fn high_loss_with_flat_cwnd_is_congestion() {
        // The local-buffer-overflow tail-drop scenario: BBR never cuts the
        // cwnd (loss happens in the local queue, invisible to it), yet the
        // link is drowning. High smoothed loss + a cwnd that has stopped
        // growing must classify as Congestion so FEC backs off instead of
        // amplifying the overload (the flapping root cause,
        // docs/raptun-congestion-optimization-plan.md §3.3).
        let mut c = RegimeClassifier::new();
        // Feed several samples so the EWMA (0.7/0.3) crosses the 10% gate:
        // 0.09 → 0.153 → 0.197 …
        c.classify(100_000, 0.30);
        c.classify(100_000, 0.30);
        assert_eq!(
            c.classify(100_000, 0.30),
            LossRegime::Congestion,
            "sustained 30% loss with a flat cwnd is congestion, not random loss"
        );
    }

    #[test]
    fn moderate_loss_with_growing_cwnd_stays_random() {
        // Below the 10% gate, or with a growing cwnd, the new rule must not
        // fire: genuine random loss on a lossy-but-uncongested link still
        // wants FEC.
        let mut c = RegimeClassifier::new();
        c.classify(100_000, 0.08);
        c.classify(110_000, 0.08);
        assert_eq!(
            c.classify(120_000, 0.08),
            LossRegime::Random,
            "8% loss with a growing cwnd must stay Random (FEC helps here)"
        );
    }

    #[test]
    fn loss_tracker_is_windowed_not_cumulative() {
        let mut t = LossTracker::new();
        // First call has no prior baseline → None.
        assert_eq!(t.window_loss(1000, 500), None);
        // Next interval: 100 more sent, 4 more lost ⇒ 4% for THIS window,
        // even though the cumulative ratio is 504/1100 ≈ 46%.
        let w = t.window_loss(1100, 504);
        assert!(w.is_some(), "second call must produce a rate");
        assert!(
            (w.unwrap() - 0.04).abs() < 1e-9,
            "windowed loss should be 4%, got {w:?}"
        );
        // A clean interval reports Some(0.0) (a real "no loss in this
        // window" reading, NOT a missing-baseline artifact).
        let w2 = t.window_loss(1200, 504);
        assert_eq!(
            w2,
            Some(0.0),
            "a loss-free window must be Some(0.0), not None or the cumulative rate"
        );
    }

    #[test]
    fn loss_tracker_handles_no_new_packets_and_reset() {
        let mut t = LossTracker::new();
        t.window_loss(500, 10);
        // No new packets sent this interval ⇒ Some(0.0) (avoid div-by-zero,
        // distinct from the baseline None case).
        assert_eq!(t.window_loss(500, 10), Some(0.0));
        // Counter reset (e.g. reconnect) must not panic or go negative.
        assert_eq!(t.window_loss(5, 1), Some(0.0));
    }

    #[test]
    fn diag_loss_spans_its_own_interval_not_the_20ms_tick() {
        let mut t = LossTracker::new();
        // 20ms ticks churn `window_loss` many times without a diagnostic.
        t.window_loss(1000, 100);
        t.window_loss(1010, 110); // last tick: 10 lost / 10 sent = 100% (noise)
                                  // First diagnostic only establishes the diag baseline.
        assert_eq!(t.diag_loss(1010, 110), None);
        // More 20ms ticks, then the next diagnostic ~2s later: 1000 sent,
        // 40 lost across the whole interval ⇒ 4%, NOT the 100% a single tick saw.
        t.window_loss(1500, 130);
        t.window_loss(2010, 150);
        let d = t.diag_loss(2010, 150);
        assert!(d.is_some(), "second diagnostic must produce a rate");
        assert!(
            (d.unwrap() - 0.04).abs() < 1e-9,
            "diag loss should be 4%, got {d:?}"
        );
    }

    /// B1 regression: first `diag_loss` is a baseline, not a measurement.
    /// Pre-fix, this returned `Some(0.0)` which the caller logged as a real
    /// `loss_pct=0.00`. With 1000+ per-tunnel trackers each setting their own
    /// baseline, this hid the actual 30-37% loss observed in the 2026-08-02
    /// load test. The fix is to return `None` on the baseline call so the
    /// caller can skip the log.
    #[test]
    fn diag_loss_is_none_on_baseline() {
        let mut t = LossTracker::new();
        // First call: no prior diag_prev → baseline only.
        assert_eq!(
            t.diag_loss(1000, 100),
            None,
            "baseline-only diagnostic must return None, not Some(0.0)"
        );
        // Real reading with 0 newly-lost is Some(0.0), not None.
        assert_eq!(t.diag_loss(1010, 100), Some(0.0));
        // Real loss rate after that.
        let d = t.diag_loss(1110, 110);
        assert!(d.is_some());
        assert!((d.unwrap() - 0.1).abs() < 1e-9, "10/100 = 0.1");
    }
}
