# Issues: 2026-08-04 Multi-Tunnel Test Session

Tracking document for issues surfaced during the multi-tunnel test session on 2026-08-04.

---

## Issue 1: FecHub symbol-drop warn is not rate-limited

**Status:** OPEN
**Severity:** Medium (log flood risk under backpressure)
**File:** `crates/raptun-core/src/fec.rs:388-396`

### Description

The docstring at `fec.rs:316` promises rate-limiting on the "symbol dropped: route channel full" warning, but the implementation at lines 388-396 does not implement it. Under sustained backpressure (e.g., a slow consumer tunnel while others are active), this warn fires once per dropped symbol — potentially thousands per second.

### Current Code

```rust
// fec.rs:388-396
if sig_tx.send(sig).is_err() {
    tracing::warn!(
        stream_id,
        "symbol dropped: route channel full"
    );
}
```

### Suggested Fix

Add a per-`(stream_id, last_warn_at)` throttle at 1 Hz, or implement hub-level backpressure that pauses the FEC sender when the route channel is full. The former is a one-line fix; the latter is a design change.

### Impact

- No data loss (FEC repair or reliable fallback covers dropped symbols)
- Log noise can mask other warnings during the same window
- Operators may miss genuine failures in the same journal window

---

## Issue 2: clamp_fec silently reducing symbol_size

**Status:** FIXED (this session)
**File:** `crates/raptun-core/src/session.rs:227-268`

### Description

`clamp_fec` silently downgraded the negotiated `symbol_size` from the client's requested value (typically 1200) to the server's configured value capped at `SAFE_MAX_SYMBOL_SIZE` (1100). The `HelloAck` echoed the clamped value so both ends agreed on the wire, but operators had no visibility into the config mismatch.

### Fix

Added `tracing::warn!` for each of the three clamped fields (`symbol_size`, `block_size`, `repair_ppm`) when the effective value differs from what the client requested. No logic change.

---

## Issue 3: signaling writer `error 0` on clean tunnel teardown

**Status:** FIXED (this session)
**File:** `crates/raptun-core/src/run.rs:936-967`

### Description

`quinn::WriteError::Stopped(VarInt(0))` is the peer's graceful "I'm done reading" signal — the normal end-of-life for a signaling stream during clean tunnel teardown. It was logged at `warn!` alongside real failures (`ConnectionLost`, `ClosedStream`, etc.), producing one false-positive per clean disconnect.

### Fix

Pattern-matched on `WriteError` variants. Demoted `Stopped(0)` and graceful `ConnectionLost` (`ApplicationClosed` / `LocallyClosed`) to `debug!`. All other variants remain at `warn!`. Mirrors the existing `is_benign_local_close` pattern (run.rs:253-267).

---

## Issue 4: 120-s tunnel stall abort during 67% loss window

**Status:** Working as designed
**Severity:** None (expected behavior)
**File:** `crates/raptun-core/src/run.rs` (TUNNEL_MAX_STALL constant)

### Description

During the test's 67% loss window, a tunnel made no forward progress for 120 seconds and was aborted with `"tunnel stalled: aborting"`. This is the correct behavior — the stall detector prevents resource leaks from permanently stuck tunnels.

### Observation

The warn is expected during severe loss. No code change needed. The stall timeout (120s) is a reasonable default for the use case (tunnelled TCP streams that should make progress within 2 minutes).

---

## Issue 5: BBR cwnd at 21 MB under 39% loss — independent control loops

**Status:** Working as designed (design call to revisit)
**Severity:** None (no bug; architectural observation)

### Description

During the test, QUIC's BBR congestion controller held `cwnd` at ~21 MB while the FEC `RegimeClassifier` observed 39% loss. BBR did not reduce `cwnd` because it was not seeing congestion signals (no persistent queueing delay, no packet loss from its perspective — FEC was absorbing the loss). The FEC classifier watches for a >12.5% `cwnd` drop to switch to `Congestion` regime, but BBR never dropped `cwnd`.

### Analysis

The two control loops are independent:
- **BBR** (QUIC layer): reacts to RTT inflation and loss as congestion signals. FEC repair masks the loss, so BBR sees a healthy link and keeps `cwnd` high.
- **FEC RegimeClassifier** (application layer): watches `cwnd` changes to distinguish random loss from congestion loss. Since BBR doesn't drop `cwnd`, the classifier stays in `Random` regime and keeps increasing repair.

This is not a bug — it's the designed behavior. But it means under severe random loss, the FEC loop can push repair overhead high while QUIC's `cwnd` stays inflated, potentially over-using bandwidth.

### Design Question (not a one-line fix)

Should there be a cross-loop signal from the FEC loss rate to QUIC's pacing? For example, if FEC observes >30% loss for >5 seconds, signal QUIC to cap `cwnd` or switch CC algorithm. This would couple the two loops and requires careful stability analysis to avoid oscillation.

---

## Network Context

- **Server:** VPS at 190.92.203.155:29900 (self-signed TLS, PSK auth)
- **Client:** local WSL2, connecting over public internet
- **Observed RTT:** ~186-242ms (handshake time)
- **Test scenarios:** clean, mild-loss (5%), heavy-loss (20%), jitter (5%+100ms), reorder (5%+25%), EXTREME-triple (30%+150ms+25%)
- **Loss injection:** simulated via application-level packet drop in the test harness (not `tc netem`)

## Test Results Summary

| Test Suite | Result |
|---|---|
| raptun-fec unit tests | 5/5 passed |
| raptun-proto unit tests | 4/4 passed |
| raptun-core lib tests | 46/46 passed |
| raptun-core fec_e2e integration | 10/12 passed (2 pre-existing flakes on main) |

The 2 failing integration tests (`credit_suppressed_still_completes_via_probe` and `large_payload_survives_send_buffer_pressure`) fail identically on `main` without these changes. Verified by stashing the diff and re-running. They are buffer-pressure flakes under `cargo test`'s default parallel scheduling, not regressions.

---

## Deploy Checklist

- [ ] Rebuild `raptun-core` (changes in `run.rs` and `session.rs`)
- [ ] Rebuild `raptun-client` and `raptun-server` (both depend on `raptun-core`)
- [ ] `sudo systemctl restart raptun-server`
- [ ] Restart Windows client
- [ ] Verify `"signaling writer failed; error 0"` is gone from `journalctl -u raptun-server -f` under normal tunnel churn
- [ ] Verify `"clamp_fec: client symbol_size adjusted"` fires on any client asking for `symbol_size > 1100`
- [ ] Note: `"symbol dropped: route channel full"` will still flood — that is Issue 1 above, do not block deploy on it
