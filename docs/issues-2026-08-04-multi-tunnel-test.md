# 2026-08-04 multi-tunnel test session — known issues

**Test setup**: Windows client (`raptun-client.exe`) connecting to remote server
(`190.92.203.155:29900`, fingerprint pinned) via QUIC + RaptorQ on the unreliable
datagram path. Workload drove 100+ concurrent FEC tunnels through a single QUIC
connection while real link conditions fluctuated between ~0.2% and ~67% loss.

This session surfaced one **open** issue, one issue **fixed in-session**, and one
**working-as-designed** signal. The network observations are recorded for context
only — they are not Raptun bugs.

---

## Issue 1 — FEC symbol-drop warn is not rate-limited (OPEN)

**Files**: `crates/raptun-core/src/fec.rs:316` (docstring) vs `fec.rs:388-396` (code)

**Symptom**: when a single tunnel's downstream task is wedged, the per-stream
route channel fills to `ROUTE_CAPACITY = 1024` and `dispatch` emits one
`WARN ... symbol dropped: route channel full (consumer wedged?)` per dropped
symbol — roughly one warn per incoming datagram, with no rate limit. A wedged
stream can produce thousands of warn lines per second.

**Sample log** (2026-08-04 16:59:26, span ≈ 3 ms, single stream_id=136):
```
WARN raptun_core::fec: symbol dropped: route channel full (consumer wedged?) stream_id=136 cap=1024
WARN raptun_core::fec: symbol dropped: route channel full (consumer wedged?) stream_id=136 cap=1024
[... 33 lines in 3 ms, all stream_id=136 ...]
```

**Root cause**:
- `fec.rs:316` docstring promises *"rate-limited warn so a wedged receiver is
  operator-visible"*, but the implementation in `dispatch` calls `tracing::warn!`
  on every `TrySendError::Full(_)` with no throttling.
- This is purely a doc/code mismatch at the warn level. The drop itself is
  intentional (see `fec.rs:383-387`) — `dispatch` cannot `await` inside the
  `HubInner` mutex, and FEC will surface the missing symbol via the receiver's
  NACK path on its next tick.

**Open questions for deeper analysis (NOT to be fixed in this pass)**:

1. **Is `ROUTE_CAPACITY = 1024` the right cap?** At the negotiated
   `symbol_size=1100` (see Issue 0 from earlier in this session) that's ~1.1 MB
   per stream. Whether that is too small, too large, or just right for typical
   1-block + repair-spurt bursts needs measurement on a stable link, not under
   the noisy conditions of this test.

2. **Is there backpressure to the sender?** When a per-stream channel stays
   full, `dispatch` keeps dropping inbound symbols, but the sender's
   `add_repair(...)` continues to mint fresh repair symbols for the same block
   on each NACK round-trip. Those repair symbols also land in the same full
   channel and are dropped. The sender has no signal that "this stream's
   consumer is saturated, stop emitting". The right shape of that backpressure
   signal (pause the sender? lower the per-stream budget? shed the tunnel?)
   is a design call, not a one-line change.

3. **Why is the consumer wedging in the first place?** The most likely cause
   is the local TCP write back-pressuring the downstream task
   (`run.rs:1374` `tcp_write.write_all(&out).await`), i.e. the local app
   attached to `127.0.0.1:12948` is not draining its socket fast enough. The
   test session did not pin this down — we'd need either
   `(a)` a per-tunnel diagnostic that distinguishes "TCP write blocked" from
   "FEC decoder stalled" from "receiver-budget exhausted", or
   `(b)` a reproduction under controlled load.

**Candidate mitigations to evaluate (not yet chosen)**:
- Per-`(stream_id, last_warn_at)` 1 Hz rate limit on the warn. Cheap,
  matches the docstring, preserves visibility.
- Demote to `debug!` and rely on `RUST_LOG=raptun_core::fec=debug` for
  diagnostics. Cheapest, but loses operator visibility by default.
- Hub-level backpressure to the sender so a wedged stream stops consuming
  repair budget. Large change, requires design discussion.

---

## Issue 2 — "signaling writer failed" on normal EOF (FIXED this session)

**File**: `crates/raptun-core/src/run.rs:971-1009`

**Symptom**: `WARN raptun_core::run: signaling writer failed; closing the
channel error=sending stopped by peer: error 0` fires on every clean tunnel
teardown. At 100+ tunnels this drowns the operator log.

**Root cause**: `quinn::WriteError::Stopped(VarInt(0))` is the peer's graceful
"I'm done reading" signal — the normal end-of-life of a tunnel — but the writer
logged every error variant at `warn!` level.

**Fix applied**: matched on the error type. `Stopped(0)` now logs at `debug!`
with the message *"signaling stream closed by peer (EOF); closing the channel"*;
other variants (`ConnectionLost`, `ClosedStream`, non-zero `Stopped`,
`ZeroRttRejected`) still log at `warn!` with the original message. Tests:
`cargo test -p raptun-core --lib` → 46/46 pass.

**Operator follow-up**: rebuild and redeploy both `raptun-client.exe` and
`raptun-server` (the change is in the shared `raptun-core` crate). After restart,
the `Stopped(0)` warn should disappear from `journalctl -u raptun-server -f`
under normal churn.

---

## Issue 3 — "tunnel stalled: aborting" at 120 s (working as designed)

**File**: `crates/raptun-core/src/run.rs:728` (`TUNNEL_MAX_STALL = 120s`),
fired at `run.rs:1254-1261`

**Symptom**: `WARN raptun_core::run: tunnel stalled: aborting total_blocks=299
delivered=162 stalled_s=120`.

**Why this is not a bug**: the 120-s deadline is the documented lifetime guard
(`run.rs:725-728` comment: *"a tunnel that makes no progress for longer than
this is stuck on any real link"*). Aborting releases the per-tunnel
`FecSender`/`FecReceiver` state and a stream_id. The 162/299 case observed in
this session coincided with a 67% loss window — FEC can't recover that many
blocks and the reliable-retransmit fallback is also stuck in the same loss.
Aborting is the correct outcome.

**Operator reading guide**: a stall warn = *"the link was so bad that the
tunnel gave up"*, not *"the tunnel has a bug"*. No action required; the warn
should be expected during severe-loss windows.

---

## Issue 4 — BBR holds cwnd at 21 MB while loss sits at 39% (working as designed, design call to revisit)

**File**: server-side observation; relevant control loop is `raptun-core/src/telemetry.rs::RegimeClassifier` + the BBR pacing inside Quinn (upstream).

**Symptom**: at 2026-08-04 17:01:29, the server logged
`cwnd_bytes=21422443` (~21 MB) with `loss_pct="39.16"` on the same sample.
That is, QUIC's congestion window was inflated to 21 MB while ~39% of the
link's packets were being dropped. The next minute saw the new
`datagram send failed (rate-limited; link may be dead) error=connection lost`
warn fire, indicating the connection gave up shortly after.

**Why this is not a bug, in isolation**:
- BBR models loss as *noise* rather than as the primary congestion signal —
  its bandwidth probe intentionally keeps growing cwnd until it sees an RTT
  inflation, on the theory that some loss is acceptable as long as the
  bottleneck isn't queuing. Holding 21 MB at 39% loss is a known BBR behaviour
  on lossy / over-buffered paths, not a Quinn bug.
- The design doc §6 "Congestion cuts the fast loop" mechanism
  (`RegimeClassifier` at 12.5% cwnd drop threshold) is a *separate* control
  loop: it only throttles the FEC repair-injection rate, it does not (and
  should not) push back on QUIC's own cwnd. So the FEC fast loop correctly
  attenuates during congestion, even when QUIC cwnd is still inflated.

**Why it is worth flagging**: the two control loops are independent, and on
this particular link the combination produced a tail outcome that neither
loop caught in time:
1. BBR keeps cwnd large because the path's RTT inflation is masked by the
   67%-loss window — there is no RTT growth for BBR to react to.
2. FEC's `RegimeClassifier` only sees a *cwnd drop* (12.5% reduction
   window-over-window). When the previous sample was already at 21 MB and
   the next drops to 5 MB, the threshold trips and the FEC loop attenuates.
   But the *first* sample where loss spikes to 39% may not coincide with a
   cwnd drop — BBR hasn't reacted yet — so FEC briefly runs at full budget
   into a now-congested path.
3. Inflight repair ≤ 40% of cwnd (per `raptun-fec/src/budget.rs`) was
   therefore allowed to be up to ~8 MB of repair on the wire at the moment
   the link went bad, which likely made the loss worse before BBR's
   bandwidth probe contracted.

**This is a design-level tradeoff, not a one-line fix.** Three possible
directions, none of which this session is choosing:
- **Tighter BBR probe schedule** — the QUIC tuning knob lives in
  `raptun-core/src/config.rs` (`TransportConfig` → cc/initial_cwnd/mtu).
  Lowering the BBR probe gain flattens the cwnd ceiling but trades
  throughput on clean links.
- **Feed the FEC layer's *loss* signal (not just cwnd drop) into the
  inflight repair budget** — `raptun-fec/src/budget.rs` currently caps by
  cwnd fraction. Adding a direct `loss_pct > 0.3` ceiling would attenuate
  faster than the cwnd-drop signal alone, but risks oscillation against
  BBR.
- **Cross-loop signal: have FEC publish its observed loss back to the
  transport layer so QUIC's pacing backs off sooner.** This is the
  cleanest answer architecturally but requires a new
  `LossSignal → CongestionSignal` trait, plus a behaviour change in
  Quinn's pacing hook, so it is a multi-day change rather than a tuning
  knob.

**Operator reading guide**: this is recorded so a future operator looking
at the same `cwnd_bytes=21MB / loss_pct=39%` line on a fresh log is not
surprised. It is *not* an action item for the next deploy.

---

## Network observations (context only, not Raptun bugs)

- Server side (`190.92.203.155:29900`):
  - `black_holes: 1282 → 1741 → 2338` — **1056 new paths silently dropping in
    6 s** during the 67% loss window. A black hole is a path that stops ACKing
    without RST/ICMP, i.e. a router mid-path dropping silently.
  - `congestion_events: 7851 → 10796` — 2945 BBR congestion events in 6 s.
    Normal rate is single-digits per hour; 2945/6s is sustained congestion
    detection.
  - `cwnd_bytes` swung 102 KB ↔ 5.4 MB during the loss spike (BBR cycling).
- Client side: `loss_pct` between 0.04% and 52% in observed 5–7 s windows.
- Asymmetric `udp_tx_dgrams=17682 / udp_rx_dgrams=1668` reading at
  2026-08-04 16:51:10 is **not** asymmetric loss — it's a fresh QUIC connection
  that just reconnected after `server connection lost`, so the rx counter
  started from zero while the tx counter was already running for retransmits
  and 0-RTT probes.

**Action**: track the upstream link. The 7 h of telemetry before the spike
shows steady ~0.5% loss with `black_holes` flat at 1282, so the spike is a
single event, not a steady state.

---

## Deploy checklist (operator)

- [ ] Rebuild `raptun-core` (changes are in `run.rs` only — Issue 2 fix)
- [ ] Rebuild `raptun-client.exe` and `raptun-server` (both depend on
      `raptun-core`)
- [ ] `sudo systemctl restart raptun-server`
- [ ] Restart the Windows client
- [ ] Verify `signaling writer failed; ... error 0` is gone from
      `journalctl -u raptun-server -f`
- [ ] Verify `clamp_fec` warn fires on any client asking for
      `symbol_size > 1100` (the warn added in `clamp_fec` earlier this session)
- [ ] `symbol dropped: route channel full` will still flood — **Issue 1 still
      open**, do not block deploy on it
