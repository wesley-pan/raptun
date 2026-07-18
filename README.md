# Raptun

**Raptun = RaptorQ + QUIC Tunnel** — a next-generation kcptun-style tunnel.

Where kcptun stacks `yamux over KCP`, Raptun uses **native QUIC multiplexing**
(via [Quinn](https://github.com/quinn-rs/quinn)) plus **RaptorQ forward error
correction** (via [`raptorq`](https://github.com/cberner/raptorq)) on QUIC's
unreliable-datagram path to cut tail latency on high-loss / high-latency links.

- No head-of-line blocking (native per-stream QUIC recovery, data over datagrams)
- Adaptive FEC that reads real congestion state from Quinn (kcptun cannot)
- Provably-bounded FEC fallback that degrades gracefully to plain reliable QUIC
- TLS 1.3 built in; connection migration for mobile networks

See [`docs/DESIGN.md`](docs/DESIGN.md) for the full design rationale, methods,
convergence analysis, and per-parameter reference.

## Workspace layout

| Crate | Role |
|---|---|
| `raptun-proto` | Wire protocol: control messages + datagram symbol header |
| `raptun-fec` | RaptorQ layer: encoder, receiver block-manager state machine, adaptive strategy, repair budget |
| `raptun-core` | Quinn/TLS setup, telemetry bridge, two-path session manager |
| `raptun-client` | Local TCP/SOCKS5 acceptor + CLI |
| `raptun-server` | Target forwarder + CLI |

## Build & test

Pure Cargo — no `configure`/`make`. Prerequisites: **Rust ≥ 1.75**, a **C
compiler**, and **Perl** (the last two are needed by `ring`, rustls' crypto
backend). Per-OS setup (macOS / Linux / Windows / musl / cross) is in
[`docs/BUILD.md`](docs/BUILD.md).

```bash
cargo build --release            # optimized binaries → target/release/
cargo test                       # 63 tests across proto/fec/core/cli (+real-QUIC e2e + netem)
cargo test --features test-hooks # 66 tests: adds the lossy-link recovery + degrade e2e
cargo clippy --all-targets       # lints
```

Built & tested on `aarch64-apple-darwin`; Linux/Windows/other targets are
portable Rust expected to build once the platform toolchain is present — see the
support matrix in [`docs/BUILD.md`](docs/BUILD.md).

## Status

- **Phase 1 wired & tested (reliable-stream tunnel):** real Quinn endpoints,
  TLS 1.3 with self-signed + fingerprint-pinned trust, the Raptun control-stream
  handshake (with PSK auth), and per-connection bidirectional TCP forwarding
  over native QUIC streams.
- **Phase 2 wired & tested (datagram + RaptorQ FEC path — now the default):**
  TCP bytes are chunked into RaptorQ blocks, sent as unreliable QUIC datagrams,
  demultiplexed per tunnel by a datagram hub (with a startup buffer to close the
  route-registration race), reassembled in order, and forwarded. FEC is on by
  default; `--fec off` or `--datagram false` falls back to the reliable path.
  Proven by:
  - `cargo test` — **63 tests** (66 with `--features test-hooks`), including
    real-QUIC loopback tests and an
    end-to-end FEC tunnel test (`tests/fec_e2e.rs`) that drives the full
    `run_client`/`run_server` loops socket-to-socket over the datagram path.
  - `raptun-fec` / `raptun-core::fec` unit tests prove per-symbol loss recovery
    (drop 1/3 of every block's symbols → full stream still reconstructed in
    order) and NACK-driven repair top-up.
  - `smoke_test.sh` — the real binaries tunnel live TCP over the FEC datagram
    path end to end (log confirms `data path: unreliable datagrams + RaptorQ FEC`).
- **Complete & unit-tested (FEC decision layer):** block-manager state machine,
  repair budget, adaptive strategy, congestion classifier.
- **Phase 3 wired & tested (NACK control loop + convergence):** each FEC tunnel
  runs a periodic control tick that samples live QUIC telemetry, refreshes the
  in-flight repair budget, and arbitrates stalled blocks via the block-manager
  state machine — emitting `BlockNack`s over the tunnel's reliable signaling
  stream, which the sender answers with fresh RaptorQ repair symbols.
- **Convergence lower bound closed (reliable-retransmit degrade):** when FEC
  cannot recover a block — repair budget exhausted, congestion-limited link, an
  entirely-lost block with no symbols, or a stalled head/tail block past a hard
  deadline — the receiver requests the block's bytes over the reliable signaling
  channel (`ReliableRequest`), the sender ships them (`ReliableData`), and the
  block is injected verbatim into the in-order reorder buffer. The stream can
  therefore never deadlock; worst case it degrades to reliable delivery. Proven
  by:
  - a unit test where a zero repair budget forces the reliable path, and
  - `--features test-hooks` end-to-end test
    `reliable_retransmit_completes_under_unrecoverable_loss`: with 1-in-3
    datagram loss, **zero proactive repair, and a zero repair budget** (so FEC
    can make no progress), a multi-block payload still round-trips intact — only
    the reliable-retransmit fallback can carry it.
  - the earlier `fec_recovers_under_datagram_loss` still covers the FEC+NACK
    happy path (~17% loss recovered without degrading).
- **Extreme-network convergence verified (DESIGN §5):** a deterministic
  in-process channel emulator (`tests/netem.rs`, virtual clock + seeded PRNG,
  driving the real sender/receiver/tick/budget) proves that under **30% loss +
  150 ms jitter + 25% reorder** the stream still converges fully and in order,
  with **bounded P99 tail latency**, **no NACK avalanche**, and **in-flight
  repair never exceeding the 40%-cwnd budget**; a congestion-regime scenario
  confirms the loop emits *zero* NACKs (no repair flood) and completes purely
  via reliable fallback. A Linux `netem_bench.sh` runs the same scenarios
  against the real binaries over a real `tc netem` qdisc (root required).
- **Remaining (Phase 4+):** SOCKS5 mode, connection migration polish, PEM/CA
  trust, and abuse hardening. See `docs/DESIGN.md`.

## Try it

```bash
cargo build
bash smoke_test.sh      # end-to-end: TCP echo tunnelled through raptun over FEC
```

## Quick start

```bash
# Server: self-signed cert, prints a fingerprint to pin on the client
raptun-server -l 0.0.0.0:29900 -r 127.0.0.1:8080 --self-signed --psk "$SECRET"

# Client: forward local 12948 -> server -> its target, pinning the fingerprint
raptun-client -l 127.0.0.1:12948 -r vps.example.com:29900 \
    --psk "$SECRET" --fingerprint SHA256:aabbcc...
```

## Configuration

Every setting can be given three ways, in decreasing precedence:

```
CLI flag  >  environment variable  >  config file (-c)  >  built-in default
```

So a `--config` file supplies your baseline and any CLI flag overrides it for a
one-off. `raptun-{client,server} --help` lists every flag; the two annotated
example files — [`raptun-client.example.toml`](raptun-client.example.toml) and
[`raptun-server.example.toml`](raptun-server.example.toml) — document the same
settings in file form. Secrets can be kept out of the file with the `env:`
prefix (`psk = "env:RAPTUN_PSK"` reads `$RAPTUN_PSK`).

**Config-file form** (production: real cert, secret from the environment):

```bash
export RAPTUN_PSK="…"

# server.toml: listen, target, cert/key, client_auth, [fec], [transport] …
raptun-server -c server.toml

# client.toml: remoteaddr, fingerprint or cert, [fec], [transport] …
raptun-client -c client.toml
```

**Full CLI form** (equivalent, everything explicit):

```bash
# ---- Server ----
RAPTUN_PSK="…" raptun-server \
    -l 0.0.0.0:29900 -r 127.0.0.1:8080 \
    --cert /etc/raptun/server.pem --key /etc/raptun/server-key.pem \
    --client-auth psk \
    --fec raptorq --fec-max 0.5 --symbol-size 1200 --mtu 1350 --cc bbr \
    --max-streams 1024 --max-conns 4096 \
    --keepalive 10 --idle-timeout 30 --connect-timeout 10 --log-level info

# ---- Client ----
RAPTUN_PSK="…" raptun-client \
    -l 127.0.0.1:12948 -r vps.example.com:29900 \
    --listen-mode tcp --sni <cert-CN/SAN> \
    --fec raptorq --fec-mode adaptive --fec-min 0.02 --fec-max 0.5 \
    --symbol-size 1200 --mtu 1350 --cc bbr \
    --max-streams 1024 --keepalive 10 --heartbeat 30 --idle-timeout 30 \
    --log-level info
```

**Loopback test** (self-signed, pin the fingerprint the server prints):

```bash
raptun-server -l 127.0.0.1:29900 -r 127.0.0.1:8080 --self-signed --psk secret
# copy the "SHA256:…" fingerprint from the server log, then:
raptun-client -l 127.0.0.1:12948 -r 127.0.0.1:29900 \
    --psk secret --fingerprint SHA256:… --heartbeat 2
```

Settings that **must match on both ends**: `--psk`, `--symbol-size`, `--mtu`,
and the FEC scheme. `--symbol-size` mismatch makes RaptorQ decoding fail
outright. The server's `--fec-max` is a hard ceiling that clamps whatever repair
ratio a client requests.

> **Trust:** `--fingerprint` (trust-on-first-use pinning) and `--insecure`
> (testing only) are wired today; client-side `--cert`/CA-file trust is a
> Phase-4 item.

