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

use std::sync::Arc;

use bytes::Bytes;
use quinn::{Connection, RecvStream, SendStream};

use raptun_fec::budget::RepairBudget;
use raptun_fec::strategy::FecStrategy;
use raptun_proto::control::{FecParams, Hello, HelloAck, Message};
use raptun_proto::{Decode, Encode};

use crate::config::RuntimeConfig;
use crate::telemetry::{LossTracker, RegimeClassifier, TransportSample};
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
pub const SAFE_MAX_SYMBOL_SIZE: u16 = 1100;

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

/// Clamp client-requested FEC params against server policy: symbol size must
/// match the server's, and the repair ratio may not exceed the server ceiling.
fn clamp_fec(requested: &FecParams, config: &RuntimeConfig) -> FecParams {
    let max_ppm = config.fec.strategy.max.as_ppm_thousandths();
    // Symbol size is fixed by the server so both ends frame identically, and is
    // clamped to a size guaranteed to fit in one QUIC datagram.
    let symbol_size = config.fec.symbol_size.min(SAFE_MAX_SYMBOL_SIZE);
    FecParams {
        symbol_size,
        block_size: requested.block_size,
        repair_ppm: requested.repair_ppm.min(max_ppm),
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
    let loss_rate = tracker.window_loss(path.sent_packets, path.lost_packets);
    TransportSample {
        smoothed_rtt: conn.rtt(),
        // quinn-proto exposes rtt but not rttvar publicly; approximate the
        // jitter grace with a fraction of RTT until a variance signal is wired.
        rtt_var: conn.rtt() / 2,
        cwnd_bytes: path.cwnd,
        loss_rate,
    }
}

/// A live Raptun session over one established QUIC connection.
///
/// Owns the shared FEC state (adaptive strategy + repair budget + congestion
/// classifier). The per-connection run loops (`control_tick`, datagram pump,
/// tunnel accept) drive these; construction wires them together.
pub struct Session {
    role: Role,
    config: RuntimeConfig,
    conn: Connection,
    strategy: FecStrategy,
    budget: Arc<RepairBudget>,
    classifier: RegimeClassifier,
    loss_tracker: LossTracker,
    /// Effective FEC params after handshake negotiation.
    fec: FecParams,
}

impl Session {
    /// Build a session around an established connection and negotiated params.
    pub fn new(role: Role, config: RuntimeConfig, conn: Connection, fec: FecParams) -> Self {
        let strategy = FecStrategy::new(config.fec.strategy, config.fec.initial_ratio);
        let budget = Arc::new(RepairBudget::new(
            config.fec.symbol_size,
            config.fec.repair_cwnd_fraction,
        ));
        Self {
            role,
            config,
            conn,
            strategy,
            budget,
            classifier: RegimeClassifier::new(),
            loss_tracker: LossTracker::new(),
            fec,
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// The resolved runtime configuration this session runs under.
    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn negotiated_fec(&self) -> &FecParams {
        &self.fec
    }

    pub fn repair_budget(&self) -> &Arc<RepairBudget> {
        &self.budget
    }

    /// One iteration of the control loop: sample telemetry, refresh the repair
    /// budget ceiling from the live cwnd, and update the adaptive strategy.
    ///
    /// Returns `true` if the repair ratio changed enough to warrant announcing a
    /// [`Message::FecReconfig`] to the peer.
    pub fn control_tick(&mut self) -> bool {
        let sample = read_telemetry(&self.conn, &mut self.loss_tracker);
        let link = self.classifier.to_link_state(sample);
        self.budget.refresh_ceiling(link.cwnd_bytes());
        self.strategy.update(&link)
    }

    /// Close the connection cleanly.
    pub fn close(&self) {
        self.conn.close(CLOSE_OK.into(), b"bye");
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
}
