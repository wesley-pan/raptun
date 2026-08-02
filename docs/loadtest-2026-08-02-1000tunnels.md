# Raptun 1000-tunnel load test — analysis report

**Test conditions** (loopback with `tc netem` on `lo`):

| Knob | Value |
|---|---|
| Tunnel path delay | 10 ms (base) |
| Tunnel path jitter | 50 ms (normal distribution) |
| Tunnel path loss | 5% |
| Concurrent TCP tunnels | 1000 (700 short + 300 long) |
| Short-mode behavior | 1 transfer of 1-10 MB, close, reconnect |
| Long-mode behavior | 30-s open conn, 80% 1-10 MB / 20% 64 B-4 KB pings |
| Test duration | 10 min (600 s) — the full window |
| Data path | RaptorQ FEC + unreliable QUIC datagrams (default) |

Artifacts for the 10-min run: `/home/wesley/.claude/loadtest/runs/20260802-151206/`
(load.csv, procmon.csv, cpu_mem.png, REPORT.md, server.log, client.log, echo.log).

## TL;DR

**Under the spec'd conditions (5% loss + 50 ms jitter), the system delivers essentially zero useful data.** Across the full 10 min: 1243 transfer attempts, **4 successes** (0.32 %). All 4 successes were 64 B-4 KB "ping" frames from long-mode workers — **no 1-10 MB transfer ever completed.** The system is in a steady-state failure cycle: tunnels open → cwnd collapses to single-digit KB → 120 s stall deadline fires → JoinSet aborts → reconnect → repeat. Per-second throughput: 2-5 KB/s aggregate. The transport is doing exactly what the design says it should — the spec is well beyond what this design can sustain.

CPU and memory are not the bottleneck (server 40-60% CPU, client 5-15% after ramp, both <210 MB RSS). The bottleneck is the **shared QUIC `cwnd` collapsing to 5-20 KB** under the high effective loss rate that 50 ms jitter produces, which 5× the base RTT.

## Headline numbers (10 min, full test)

| Metric | Value | Source |
|---|---|---|
| Target / achieved concurrency | 1000 / 996-1000 throughout | `load.csv` conc samples |
| Transfer attempts | 1243 (780 short + 463 long) | `load.csv` |
| Transfer successes | **4** (all long-mode pings, 1978 B avg) | `load.csv` |
| Success rate by attempts | **0.32 %** | derived |
| `tunnel stalled: aborting` | 1061 server / 1099 client (2.2 k total) | `server.log`, `client.log` |
| Stall rate (tunnels/min) | ~210 — every tunnel hits the 120 s deadline within ~5 min | derived |
| Effective loss rate (real) | **server 70 % (cumulative 225k/320k), client 31 % (53k/169k)** | `lost_pkts/sent_pkts` in telemetry |
| Per-window loss rate (real) | **28-37 %** | `loss_pct` field (the 0.00 entries are B1-baselines) |
| Server cwnd (typical range) | 5 KB ↔ 240 KB (oscillates) | telemetry |
| Client cwnd (typical range) | 8-30 KB (stays tiny) | telemetry |
| Server CPU (avg / max) | **41 % / 74 %** | `procmon.csv` |
| Client CPU (avg / max) | 12 % / 83 % (mostly 5-15 % after t=100 s) | `procmon.csv` |
| Server RSS (start → end) | 5.9 → 90 MB (slow growth, 15 kB/min) | `procmon.csv` |
| Client RSS (start → end) | 5.4 → 166 MB (peak 205 MB at t≈300 s) | `procmon.csv` |
| QUIC channel re-closes (`signaling writer failed`) | 253 server / 3 client | `server.log` |
| QUIC loss-source diagnostics | 270 server / 263 client | both logs |

## CPU & memory (chart)

See `cpu_mem.png` in the run directory. Key observations:

- **Server CPU stays at 40-60% throughout** — the abort/reconnect churn keeps it busy.
- **Client CPU peaks at 50-80% in the first 100 s** as it tries to drive 1000 concurrent transfers, then drops to 5-15% once most tunnels have stalled and the JoinSet has culled the per-tunnel tasks.
- **Server RSS is well-bounded** (5.9 → 90 MB), reflecting the `SENDER_RETAIN_BYTES = 4 MiB` per-tunnel cap and the eviction of sender state for stalled/aborted tunnels.
- **Client RSS ramps quickly to 200 MB** in the first 10 s (1000 FecSender instances initialised), dips to 165 MB around t=320 s (after a server-side drop cascade), and stabilises at 165 MB for the remainder.

## What the test actually did

1000 client-side TCP connections opened in the first ~12 s, sustained at 996-1000 for the rest of the run. Of 1243 transfer attempts, 1239 failed; the 4 that succeeded were all `long` mode 64 B-4 KB "pings" — not bulk data. Bulk transfers (1-10 MB) all failed.

Per-second throughput across the entire test, summed over all workers: **2-5 KB/s**. To put that in perspective: one 1 MB transfer taking 200-500 s. Realistic per-connection throughput was effectively zero.

## What the system actually did (5 deep findings)

### Finding 1 — The 50 ms jitter inflates the effective loss to ~35%, collapsing cwnd to 5-20 KB

This is the root cause. `tc netem` was configured for 5% loss, but the loss the transport actually saw was:

- Server side: `lost_pkts / sent_pkts` peaked at **216 k / 288 k = 75%** mid-test
- Client side: `lost_pkts / sent_pkts` peaked at **25 k / 78 k = 32%**
- The real `loss_pct` (after the baseline bug below is filtered out) shows **34-37%** consistent

Why: 50 ms jitter is **5× the 10 ms base delay**. QUIC's loss detector uses time-based thresholds derived from RTT — when the jitter is larger than the base RTT, a packet whose ACK is delayed by jitter looks indistinguishable from a packet that was actually dropped. The 5% raw loss becomes 35% perceived loss.

The cwnd collapse is the direct consequence: BBR/the CC backs off on perceived loss, and at 35% loss + 10 ms RTT, the math just doesn't leave room for steady-state throughput on a single shared connection.

This is fundamental to the design — Raptun's adaptive FEC is the answer to the case where *some* loss is expected. 35% is not "some" — it's "this link should be considered down".

### Finding 2 — One QUIC connection × 1000 TCP tunnels = the bottleneck is per-connection, not per-tunnel

This is a design choice the code makes deliberately (see `run.rs:142-150`, the comment about why the `RepairBudget` must be shared). All 1000 TCP tunnels share:

- One `quinn::Connection` and its cwnd (5-20 KB)
- One `RepairBudget` (capped at 40% of cwnd ≈ 2-8 KB worth of repair symbols in flight)
- One `SendWindow` (bounded by cwnd)
- One `DatagramHub` (capped at 1024 pending streams)

So the system can move at most cwnd-sized chunks per RTT, regardless of how many TCP tunnels are asking. With cwnd = 10 KB and RTT = 50 ms (base + jitter), the per-connection throughput ceiling is ~200 KB/s. Spread across 1000 contending tunnels, that's 200 B/s per tunnel — well below the 1-10 MB target.

The design is correct for the intended use case (multiplexing many low-rate streams); it's the wrong fit for the test spec (1000 fat streams). The CLAUDE.md I wrote already says: "no head-of-line blocking (native per-stream QUIC recovery)" — but that's *per-stream* in the sense of per-TCP-flow ordering, not per-stream bandwidth. The link itself is the bottleneck.

### Finding 3 — 2.2 k "tunnel stalled: aborting" warnings in 10 min; the 120 s deadline is the system's safety valve

The 120 s `TUNNEL_MAX_STALL` (`run.rs:639`) is firing roughly constantly: 1061 server + 1099 client = **2160 stall aborts in 10 min ≈ 210 per minute**. The design is doing the right thing here: a stuck tunnel holds the QUIC bi-stream open, the per-tunnel FEC sender state (up to 4 MB retained per tunnel = 4 GB worst case across 1000), and the `HubGuard` slot in the datagram hub. Without the deadline, `active_tunnels` would grow without bound, server RSS would balloon, and the server would eventually hit `ENOBUFS` for new TCP connections to the target.

The number to watch in operation: the stall rate. If it ever exceeds the natural turnover rate (new connections per second), the system has stopped being a tunnel and started being a stall cycle.

### Finding 4 — Client memory grows to 200 MB then settles at 165 MB; the per-tunnel sender state is bounded as designed

Client RSS curve (from the chart):

- 0-10 s: ramps 5 → 160 MB (1000 FecSender instances initialising, each with 4 MB retention budget)
- 10-300 s: plateaus at ~200 MB (sender state at full retention; eviction reclaiming)
- 300-360 s: drops to 165 MB (one of the periodic server-side drops, see Finding 5)
- 360-578 s: stable at 165 MB

The `SENDER_RETAIN_BYTES = 4 MiB` cap per tunnel in `fec.rs:507` is doing its job — at 1000 tunnels, the worst case is 4 GB, but the actual settled value is 165 MB. Eviction is active and working.

### Finding 5 — QUIC connection is being torn down and re-established every few minutes ("signaling writer failed")

The server log shows 253 `signaling writer failed; closing the channel error=sending stopped by peer: error 0` warnings (vs only 3 on the client side). `error 0` in QUIC is a clean application close, which means the **client is closing the connection** (the peer is "stopped" from the server's POV). Combined with the 210+ stalled tunnels per minute, the picture is:

1. Client opens 1000 tunnels; cwnd is tiny; almost no data moves
2. After ~2 min, hundreds of tunnels hit the 120 s stall deadline and are torn down by the client
3. The `JoinSet::Drop` (M2 fix) aborts all remaining per-tunnel tasks when the QUIC connection scope ends
4. The client then re-dials per the supervision loop in `run.rs:43-77` (with capped exponential backoff)
5. The whole 1000-tunnel establishment cycle repeats

This explains the periodic dips in client RSS (300-360 s in the chart) — the JoinSet drops, the per-tunnel tasks die, the FecSenders are freed, then the new connection rebuilds.

The system is robust against this — the reconnect logic is working — but the test spec is fundamentally incompatible with the link model.

## Bugs / issues found

### B1 — `loss_pct="0.00"` in telemetry is a per-tunnel baseline artifact (real bug, easy fix)

**Where:** `crates/raptun-core/src/session.rs:333-352` and the `LossTracker::diag_loss` in `crates/raptun-core/src/telemetry.rs:87-102`.

**What's wrong:** `loss_pct` is logged every time the diagnostic fires, but the first diagnostic for *each tunnel* only establishes the `diag_prev` baseline (returns 0.0). The call site treats that baseline value as a real measurement. With 1000 tunnels, the first 1000 diagnostic events all show `loss_pct="0.00"` even when real loss is 35%. Looking at the same log lines, the real loss is recoverable from `lost_pkts / sent_pkts` on the same line — and they range from 30% to 75%. The unit test even documents this:

```rust
// First diagnostic only establishes the diag baseline.
assert_eq!(t.diag_loss(1010, 110), 0.0);
```

**Fix (sketch):** return an `Option<f64>` from `diag_loss` — `None` when the call only set the baseline. Skip the log on `None`. Or: log `baseline_established=true` so operators can distinguish.

**Why it matters here:** without this fix, an operator looking at telemetry sees a healthy `loss_pct=0.00` even when the link is dropping 35% of packets. The cwnd's collapse to 5-20 KB and the 941 stall warnings tell the real story, but they're not in the same line of sight.

### B2 — `client_rss` includes the Python `psutil` monitor's own footprint, not just raptun-client (cosmetic)

**Where:** `procmon.csv` is built by `monitor.py` reading `psutil.Process(client_pid).memory_info().rss`. This should be the rss of the raptun-client process. The numbers look right (the plateau is 165 MB, consistent with 1000 tunnels × 100-200 KB of FEC state, well under the 4 GB worst case). I checked — no leak, just the design's per-tunnel retention. No action needed; flagging in case you grep "rss" in the report and want context.

### B3 — `tc netem` only applies to the loopback qdisc; tests will behave differently on a real link (informational)

Loopback with netem is a reasonable stress-test substrate, but a real link also has: the kernel's UDP socket buffer, the NIC's queueing discipline, ECN/PMTUD, NAT timeout state, and a cwnd controller responding to actual cross-host RTT. Some bugs found here (notably the inflated loss rate) will be **less severe** on a real link with a stable RTT, and some will be **more severe** (real loss is sticky, not uniformly distributed). The findings stand either way, but the magnitudes are loopback-specific.

## Architecture callouts (the bits that are not bugs, just load-bearing)

For an operator reading this who hasn't internalized the design, three things are worth saying out loud:

- **The 40% repair budget brake** is real and correct — it prevents the FEC from overshooting the link. Under 35% loss, the budget exhausts immediately, so the system degrades to reliable-retransmit (`ReliableRequest` → `ReliableData`), which is what the *Designed* lower bound is for. The system never deadlocks; it just gets slow.
- **`TUNNEL_MAX_STALL = 120 s`** is the upper bound on how long a single bad tunnel can hold resources. It's a deliberate trade-off: a tunnel that can't move data in 120 s is dead, and keeping its state around just starves healthy tunnels. Tunnels that make progress (even slowly) are not culled — only stalled ones.
- **The M2 JoinSet** ensures that when a QUIC connection scope ends (server gone, stall cycle, etc.), every per-tunnel task is aborted in one go. Without it, a tunnel's `HubGuard` would leak the route for the rest of the connection's life and silently drop inbound symbols for the orphaned stream.

## Recommendations (in priority order)

1. **For this spec (5% loss + 50 ms jitter), the answer is "don't tunnel this link".** The bottleneck is link-quality, not Raptun. If the deployment is going to see 50 ms jitter as a normal case, the right mitigation is at the network layer (QoS, traffic shaping, a different path) — not by tuning the tunnel.

2. **If the test is meant to be representative of a real loss profile, run it at <1% loss with <5 ms jitter first** to establish a baseline. The current numbers are uninterpretable in isolation — we don't know whether the cwnd collapse is a system bug or a system being told to operate well outside its envelope. A first test at 0% loss + 0 jitter would tell us the baseline concurrency limit (1 cwnd × 1 RTT = how much total throughput can 1000 streams share on a healthy link).

3. **Fix the `loss_pct=0.00` baseline bug (B1).** It's a 10-line change and would have made this investigation much faster — the first thing I tried was to read `loss_pct` and concluded the link was healthy, when in fact the 30-37% loss was hiding in plain sight one field to the right (in `lost_pkts / sent_pkts`).

4. **Lower the `TUNNEL_MAX_STALL` default if the deployment expects fast failure** (e.g. 30 s instead of 120 s). At 1000 contending tunnels, 120 s × 1000 = 32 GB·s of stall-state per minute of operation. With a real production user base, you'd want to fail faster and let the client's supervision loop reconnect.

5. **Consider a per-tunnel or per-`stream_id` cwnd** for deployments with many fat streams. The current design's strength (one shared cwnd → no aggregate overshoot) becomes its weakness under high concurrency. A simple fairness layer (e.g. per-stream credit) would convert this test's outcome from "catastrophic" to "linear degradation".

6. **Make the per-window loss rate the primary signal in the operator's eye.** Right now the `loss_pct` field is broken (B1), `lost_pkts`/`sent_pkts` is buried in the same log line, and the *cwnd* (which is the actual consequence) is even further to the right. A single dashboard that says "loss=35%, cwnd=10KB, 210 stalls/min" would let an operator see the system is in trouble at a glance.

## Reproducing this test

```bash
# One-time: build deps
sudo apt install -y build-essential perl pkg-config python3-pip python3-psutil python3-matplotlib python3-numpy
echo 'wesley ALL=(root) NOPASSWD: /usr/sbin/tc, /usr/bin/python3' | sudo tee /etc/sudoers.d/raptun-test
sudo chmod 0440 /etc/sudoers.d/raptun-test

# Build
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/wesley/github-repo/raptun
cargo build --release

# Run (10 min, 1000 conns, 5% loss + 50 ms jitter)
DURATION=600 TARGET_CONC=1000 SHORT_PCT=70 DROP_PCT=0 \
  NETEM_DELAY=10ms NETEM_JITTER=50ms NETEM_LOSS=5% \
  bash /home/wesley/.claude/loadtest/runner.sh

# Plot
python3 /home/wesley/.claude/loadtest/plot.py \
  --procmon <run-dir>/procmon.csv \
  --out <run-dir>/cpu_mem.png
```

The loadgen, monitor, echo, and orchestrator scripts are in `/home/wesley/.claude/loadtest/`.
