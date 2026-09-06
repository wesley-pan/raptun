//! Per-connection session: control-stream framing, handshake, TCP tunnelling,
//! datagram FEC plumbing, and the telemetry-driven control loop.
//!
//! This module is where Raptun's two-path data plane meets real Quinn I/O:
//!
//! * **Control path** — [`ControlChannel`] frames [`raptun_proto::control::Message`]s
//!   over the reliable bi-stream #0 with a `u32` length prefix. The handshake
//!   ([`handshake_client`] / [`handshake_server`]) runs here.
//! * **Tunnel path (Phase-1 baseline)** — [`tunnel_bi`] pumps bytes between a
//!   local [`tokio::net::TcpStream`] and a QUIC bidirectional stream. Native
//!   QUIC multiplexing means one QUIC stream per tunnelled TCP connection with
//!   no head-of-line blocking — this is the direct yamux replacement.
//! * **Datagram/FEC path (Phase-2 seam)** — [`send_symbol`] / [`recv_datagram`]
//!   move framed RaptorQ symbols over unreliable QUIC datagrams.
//! * **Telemetry** — [`read_telemetry`] samples `quinn::Connection` into the
//!   FEC layer's input shape.

use bytes::Bytes;
use quinn::{Connection, RecvStream, SendStream};

use raptun_proto::control::{FecParams, Hello, HelloAck, Message};
use raptun_proto::{Decode, Encode};

use crate::config::RuntimeConfig;
use crate::telemetry::{LossTracker, TransportSample};
use crate::{CoreError, Result};

/// Maximum control message size we will accept, to bound a peer's allocation.
const MAX_CONTROL_MSG: usize = 64 * 1024;

/// A conservative upper bound on the FEC symbol payload size.
///
/// A framed symbol is `symbol_size + SYMBOL_HEADER_LEN` bytes and must fit in
/// one QUIC datagram. QUIC's usable datagram size after overhead is commonly
/// ~1150–1200 bytes even on a 1350-ish path MTU, so we cap the symbol payload
/// well under that. The server clamps the negotiated size to this ceiling so
/// both ends share a geometry that is guaranteed to fit; oversized symbols
/// would otherwise be silently dropped by `send_datagram`.
///
/// The ceiling is reduced from 1100 to 1098 because the symbol header grew by
/// 2 bytes (`actual_k`), keeping the maximum framed symbol size unchanged at
/// ~1120 bytes.
pub const SAFE_MAX_SYMBOL_SIZE: u16 = 1098;

/// Application error code used when closing a connection cleanly.
pub const CLOSE_OK: u32 = 0;

/// Role of this side of the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// Framed reader/writer for control-stream messages.
///
/// Wraps the reliable bi-stream #0. Each message is length-delimited so the two
/// ends can frame a stream of messages without ambiguity, even though QUIC
/// itself preserves order and reliability.
pub struct ControlChannel {
    send: SendStream,
    recv: RecvStream,
}

impl ControlChannel {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }

    /// Encode and send one control message, prefixed with its `u32` length.
    pub async fn send(&mut self, msg: &Message) -> Result<()> {
        let mut body = Vec::new();
        msg.encode(&mut body);
        if body.len() > MAX_CONTROL_MSG {
            return Err(CoreError::Handshake(format!(
                "control message too large: {} bytes",
                body.len()
            )));
        }
        let len = (body.len() as u32).to_be_bytes();
        self.send
            .write_all(&len)
            .await
            .map_err(|e| CoreError::Endpoint(format!("control write len: {e}")))?;
        self.send
            .write_all(&body)
            .await
            .map_err(|e| CoreError::Endpoint(format!("control write body: {e}")))?;
        Ok(())
    }

    /// Receive one control message.
    pub async fn recv(&mut self) -> Result<Message> {
        let mut len_buf = [0u8; 4];
        self.recv
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| CoreError::Endpoint(format!("control read len: {e}")))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_CONTROL_MSG {
            return Err(CoreError::Handshake(format!(
                "peer announced oversized control message: {len} bytes"
            )));
        }
        let mut body = vec![0u8; len];
        self.recv
            .read_exact(&mut body)
            .await
            .map_err(|e| CoreError::Endpoint(format!("control read body: {e}")))?;
        let mut slice = body.as_slice();
        let msg = Message::decode(&mut slice)?;
        Ok(msg)
    }

    /// Gracefully finish the send side.
    pub fn finish(&mut self) -> Result<()> {
        self.send
            .finish()
            .map_err(|e| CoreError::Endpoint(format!("control finish: {e}")))
    }
}

/// Client side of the handshake: open bi-stream #0, send `Hello`, await
/// `HelloAck`, and return the negotiated (possibly clamped) FEC parameters plus
/// the open control channel.
pub async fn handshake_client(
    conn: &Connection,
    config: &RuntimeConfig,
) -> Result<(ControlChannel, FecParams)> {
    let (send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| CoreError::Endpoint(format!("open control bi: {e}")))?;
    let mut ctrl = ControlChannel::new(send, recv);

    let hello = Message::Hello(Hello {
        version: raptun_proto::PROTOCOL_VERSION,
        auth_token: config.psk.clone().unwrap_or_default().into_bytes(),
        fec: config.fec.to_wire_params(),
    });
    ctrl.send(&hello).await?;

    match ctrl.recv().await? {
        Message::HelloAck(HelloAck { version, fec }) => {
            if version != raptun_proto::PROTOCOL_VERSION {
                return Err(CoreError::Handshake(format!(
                    "server protocol version {version} != {}",
                    raptun_proto::PROTOCOL_VERSION
                )));
            }
            Ok((ctrl, fec))
        }
        Message::OpenTargetErr { reason, .. } => Err(CoreError::Handshake(reason)),
        other => Err(CoreError::Handshake(format!(
            "expected HelloAck, got {other:?}"
        ))),
    }
}

/// Server side of the handshake: accept bi-stream #0, read `Hello`, verify the
/// PSK and version, clamp the requested FEC params to policy, and reply with
/// `HelloAck`.
pub async fn handshake_server(
    conn: &Connection,
    config: &RuntimeConfig,
) -> Result<(ControlChannel, FecParams)> {
    let (send, recv) = conn
        .accept_bi()
        .await
        .map_err(|e| CoreError::Endpoint(format!("accept control bi: {e}")))?;
    let mut ctrl = ControlChannel::new(send, recv);

    let hello = match ctrl.recv().await? {
        Message::Hello(h) => h,
        other => {
            return Err(CoreError::Handshake(format!(
                "expected Hello, got {other:?}"
            )))
        }
    };

    if hello.version != raptun_proto::PROTOCOL_VERSION {
        return Err(CoreError::Handshake(format!(
            "client protocol version {} != {}",
            hello.version,
            raptun_proto::PROTOCOL_VERSION
        )));
    }

    // App-level auth. The channel is already TLS-encrypted; this only gates who
    // may consume server resources.
    if !crate::tls::psk_matches(config.psk.as_deref(), &hello.auth_token) {
        let _ = ctrl
            .send(&Message::OpenTargetErr {
                stream_id: 0,
                reason: "authentication failed".into(),
            })
            .await;
        return Err(CoreError::Handshake("authentication failed".into()));
    }

    // Clamp the client's requested repair ratio to the server's ceiling. The
    // server's configured `strategy.max` is the hard cap against amplification.
    let clamped = clamp_fec(&hello.fec, config);
    ctrl.send(&Message::HelloAck(HelloAck {
        version: raptun_proto::PROTOCOL_VERSION,
        fec: clamped.clone(),
    }))
    .await?;

    Ok((ctrl, clamped))
}

/// Upper bound on the per-block geometry K (`block_size`). A client may request
/// any `u16` value here, but a single block is held in memory twice by the
/// sender (encoder + raw payload) and the byte-budget retention cap
/// (`SENDER_RETAIN_BYTES` in raptun-fec) only works when one block is much
/// smaller than the cap. At the default 1200-byte symbol size, K=256 yields
/// ~300 KB/block — well under the 4 MB retention cap so a handful of blocks
/// can be retained; a hostile K=65535 (block ~78 MB) bypasses the cap entirely
/// and the sender keeps a single ~156 MB allocation. Both ends always see the
/// clamped value via the HelloAck echo, so clamping is safe and silent.
const MAX_BLOCK_SIZE: u16 = 256;

/// Clamp client-requested FEC params against server policy: symbol size must
/// match the server's, and the repair ratio may not exceed the server ceiling.
fn clamp_fec(requested: &FecParams, config: &RuntimeConfig) -> FecParams {
    let max_ppm = config.fec.strategy.max.as_ppm_thousandths();
    // Symbol size is fixed by the server so both ends frame identically, and is
    // clamped to a size guaranteed to fit in one QUIC datagram.
    let symbol_size = config.fec.symbol_size.min(SAFE_MAX_SYMBOL_SIZE);
    // Clamp block_size too: a client-requested u16 = 65535 forces the sender
    // to allocate ~78 MB per block and the per-tunnel retention cap stops
    // applying. Capped to MAX_BLOCK_SIZE (the HelloAck echoes the
    // clamped value so both ends agree).
    let block_size = requested.block_size.min(MAX_BLOCK_SIZE);
    let repair_ppm = requested.repair_ppm.min(max_ppm);

    if requested.symbol_size != symbol_size {
        tracing::warn!(
            requested = requested.symbol_size,
            effective = symbol_size,
            ceiling = SAFE_MAX_SYMBOL_SIZE,
            "clamp_fec: client symbol_size adjusted by server"
        );
    }
    if requested.block_size != block_size {
        tracing::warn!(
            requested = requested.block_size,
            effective = block_size,
            ceiling = MAX_BLOCK_SIZE,
            "clamp_fec: client block_size clamped"
        );
    }
    if requested.repair_ppm != repair_ppm {
        tracing::warn!(
            requested = requested.repair_ppm,
            effective = repair_ppm,
            ceiling = max_ppm,
            "clamp_fec: client repair_ppm clamped"
        );
    }

    FecParams {
        symbol_size,
        block_size,
        repair_ppm,
    }
}

/// Pump bytes bidirectionally between a local TCP stream and a QUIC bi-stream.
///
/// This is the Phase-1 tunnel baseline: reliable, no FEC, one QUIC stream per
/// TCP connection. It demonstrates that native QUIC multiplexing replaces yamux
/// with no head-of-line blocking across tunnelled connections.
pub async fn tunnel_bi(
    mut tcp: tokio::net::TcpStream,
    mut quic_send: SendStream,
    mut quic_recv: RecvStream,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut tcp_read, mut tcp_write) = tcp.split();

    // TCP -> QUIC
    let up = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = tcp_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            quic_send
                .write_all(&buf[..n])
                .await
                .map_err(|e| std::io::Error::other(format!("quic write: {e}")))?;
        }
        let _ = quic_send.finish();
        Ok::<(), std::io::Error>(())
    };

    // QUIC -> TCP
    let down = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match quic_recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    tcp_write.write_all(&buf[..n]).await?;
                }
                Ok(None) => break, // stream finished
                Err(e) => return Err(std::io::Error::other(format!("quic read: {e}"))),
            }
        }
        tcp_write.shutdown().await?;
        Ok::<(), std::io::Error>(())
    };

    // Run both directions until both complete or one errors.
    tokio::try_join!(up, down)
        .map(|_| ())
        .map_err(CoreError::Io)
}

/// Send one framed FEC symbol as an unreliable QUIC datagram (Phase-2 path).
///
/// `symbol` is the already-framed header+payload from `raptun_fec`. Returns an
/// error if the datagram exceeds the peer's advertised maximum.
pub fn send_symbol(conn: &Connection, symbol: Bytes) -> Result<()> {
    conn.send_datagram(symbol)
        .map_err(|e| CoreError::Endpoint(format!("send_datagram: {e}")))
}

/// Await the next inbound unreliable datagram.
pub async fn recv_datagram(conn: &Connection) -> Result<Bytes> {
    conn.read_datagram()
        .await
        .map_err(|e| CoreError::Endpoint(format!("read_datagram: {e}")))
}

/// Sample the transport's live telemetry into the FEC layer's input shape.
///
/// Loss rate is the *windowed* loss since the last sample (via `tracker`), not
/// the connection-lifetime cumulative ratio — see [`LossTracker`] for why the
/// raw ratio is misleading. This is the exact signal kcptun cannot see (it runs
/// above KCP, blind to the real path).
pub fn read_telemetry(conn: &Connection, tracker: &mut LossTracker) -> TransportSample {
    let stats = conn.stats();
    let path = stats.path;
    // `window_loss` returns `None` on the first call (only establishes a
    // baseline) or when no new packets have been sent in the window. Treat
    // both as 0% for the sample: the FEC controller's default "no loss seen
    // yet, assume no loss" is the right behaviour for a 0-sent-window, and
    // matches the pre-Option semantics.
    let loss_rate = tracker
        .window_loss(path.sent_packets, path.lost_packets)
        .unwrap_or(0.0);

    // 诊断:当窗口丢包率 > 5% 且通过节流时,打印 Quinn 计数器的来源分解,
    // 用来区分"真实丢包"与"指标误判"。三条判据:
    //   1. 拥塞信号 congestion_events / black_holes_detected 是否随 lost_packets
    //      增长 —— 增长即真拥塞;不动则可能是误判。
    //   2. UDP socket 层:跨端对照 client.udp_tx_dgrams vs server.udp_rx_dgrams。
    //      relay drop=0 时若 server.udp_rx ≪ client.udp_tx,说明包在 relay/内核
    //      丢了(真实丢包,假设 relay 掉队成立);若两端 UDP 计数对得上但
    //      lost_packets 仍高,则是 QUIC 层把包误判为 lost(指标不准)。
    //   3. lost_bytes / lost_packets ≈ 平均丢包大小,接近 MTU 说明丢的是满载数据包。
    if loss_rate > 0.05 && tracker.allow_diag() {
        // Log the loss over the whole diagnostic interval (~2 s), not the 20 ms
        // `loss_rate` tick that tripped the gate: the latter has a tiny
        // denominator and swings to 100% on a single late packet. `loss_rate`
        // still drives the >5% trigger and the FEC controller unchanged.
        //
        // `diag_loss` returns `None` on the very first diagnostic for this
        // tracker (baseline only — no rate to report yet). Skip the log in
        // that case: logging the baseline 0.0 as a real reading misleads
        // operators, and was the B1 issue surfaced by the 2026-08-02 load
        // test. The call still establishes `diag_prev` so subsequent calls
        // produce real rates.
        if let Some(diag_pct) = tracker.diag_loss(path.sent_packets, path.lost_packets) {
            tracing::info!(
                target: "raptun_core::telemetry",
                loss_pct = format!("{:.2}", diag_pct * 100.0),
                sent_pkts = path.sent_packets,
                lost_pkts = path.lost_packets,
                lost_bytes = path.lost_bytes,
                congestion_events = path.congestion_events,
                black_holes = path.black_holes_detected,
                udp_tx_dgrams = stats.udp_tx.datagrams,
                udp_rx_dgrams = stats.udp_rx.datagrams,
                cwnd_bytes = path.cwnd,
                "quinn loss-source breakdown (path vs udp vs congestion)"
            );
        }
    }

    TransportSample {
        smoothed_rtt: conn.rtt(),
        // quinn-proto exposes rtt but not rttvar publicly; approximate the
        // jitter grace with a fraction of RTT until a variance signal is wired.
        rtt_var: conn.rtt() / 2,
        cwnd_bytes: path.cwnd,
        loss_rate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FecConfig, TransportConfig};

    fn test_config(psk: Option<&str>) -> RuntimeConfig {
        RuntimeConfig {
            fec: FecConfig::default(),
            transport: TransportConfig::default(),
            psk: psk.map(str::to_string),
        }
    }

    #[test]
    fn clamp_fec_caps_repair_and_fixes_symbol_size() {
        let cfg = test_config(None);
        let requested = FecParams {
            symbol_size: 9999, // client asks for a different size
            block_size: 32,
            repair_ppm: 900, // 90% — above the 50% default ceiling
        };
        let clamped = clamp_fec(&requested, &cfg);
        // Symbol size is forced to the server's config, further capped to the
        // datagram-safe ceiling.
        let expected_symbol = cfg.fec.symbol_size.min(SAFE_MAX_SYMBOL_SIZE);
        assert_eq!(clamped.symbol_size, expected_symbol, "symbol size forced");
        assert!(
            clamped.symbol_size <= SAFE_MAX_SYMBOL_SIZE,
            "symbol size within datagram-safe bound"
        );
        assert_eq!(clamped.block_size, 32, "block size preserved");
        assert!(
            clamped.repair_ppm <= cfg.fec.strategy.max.as_ppm_thousandths(),
            "repair ratio clamped to ceiling"
        );
    }

    #[test]
    fn clamp_fec_caps_block_size_to_bounded_memory() {
        // A hostile client can request block_size = u16::MAX, which without
        // clamping forces a ~78 MB allocation per block on the sender. Verify
        // the cap is enforced and the value is still well above the default.
        let cfg = test_config(None);
        let hostile = FecParams {
            symbol_size: 1200,
            block_size: u16::MAX,
            repair_ppm: 100,
        };
        let clamped = clamp_fec(&hostile, &cfg);
        assert_eq!(
            clamped.block_size, MAX_BLOCK_SIZE,
            "u16::MAX block_size must be clamped"
        );
        assert!(
            clamped.block_size >= 16,
            "clamp leaves headroom for normal use"
        );
    }
}
