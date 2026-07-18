//! Building the Quinn [`quinn::Endpoint`] with Raptun's transport tuning.
//!
//! This maps [`crate::config::TransportConfig`] onto Quinn's
//! `quinn::TransportConfig`: congestion controller, flow-control windows,
//! datagram support, keep-alive, idle timeout, and stream limits. The result is
//! a ready-to-use client or server endpoint.

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::congestion::{BbrConfig, CubicConfig, NewRenoConfig};
use quinn::{Endpoint, IdleTimeout, ServerConfig, TransportConfig as QuinnTransport, VarInt};

use crate::config::{CongestionControl, TransportConfig};
use crate::tls::{self, ServerIdentity, ServerTrust};
use crate::{CoreError, Result};

/// Datagram receive-buffer size when datagrams are enabled. Sized to hold a
/// burst of symbols; a few MiB is plenty for the FEC path.
const DATAGRAM_RECV_BUFFER: usize = 8 * 1024 * 1024;

/// Datagram *send*-buffer size. Quinn's default is only 1 MiB, and its
/// `send_datagram` silently evicts the oldest queued symbol once that fills —
/// so a large burst strands early blocks and stalls the tunnel (see
/// `live_size_sweep.sh`). The sender back-pressures on a full buffer rather
/// than evicting (`send_datagram_paced` in `run.rs`), but a generous buffer,
/// symmetric with the receive side, keeps normal bursts flowing without
/// repeatedly parking the send loop.
const DATAGRAM_SEND_BUFFER: usize = 8 * 1024 * 1024;

/// Translate [`TransportConfig`] into a shared `quinn::TransportConfig`.
///
/// The same transport parameters are used on both client and server so their
/// windows and timeouts agree.
pub fn build_transport(cfg: &TransportConfig) -> Result<Arc<QuinnTransport>> {
    let mut t = QuinnTransport::default();

    // Congestion controller: Raptun defaults to BBR for high bandwidth-delay
    // product links (the tunnel's typical habitat), with CUBIC/NewReno available.
    match cfg.congestion {
        CongestionControl::Bbr => {
            t.congestion_controller_factory(Arc::new(BbrConfig::default()));
        }
        CongestionControl::Cubic => {
            t.congestion_controller_factory(Arc::new(CubicConfig::default()));
        }
        CongestionControl::NewReno => {
            t.congestion_controller_factory(Arc::new(NewRenoConfig::default()));
        }
    }

    // Flow-control windows. These bound per-stream and whole-connection
    // in-flight unacknowledged data; see the parameter reference in DESIGN.md.
    t.stream_receive_window(to_varint(cfg.stream_recv_window)?);
    t.receive_window(to_varint(cfg.conn_recv_window)?);

    // Concurrent bidi-stream cap. Each tunnel holds one bidi stream open for the
    // life of its local TCP connection, so this bounds simultaneous tunnels. The
    // Quinn default is only 100 — far too low for browser traffic — and once it
    // is reached the peer's `open_bi()` blocks until a stream closes, which reads
    // as new connections stalling until an old one times out. Applied on both
    // ends so each side grants the other enough credit.
    t.max_concurrent_bidi_streams(to_varint(u64::from(cfg.max_concurrent_streams))?);

    // Idle timeout and keep-alive. Keep-alive must be well under the idle
    // timeout or an otherwise-healthy connection could still time out.
    let idle = IdleTimeout::try_from(cfg.idle_timeout)
        .map_err(|e| CoreError::Endpoint(format!("idle timeout: {e}")))?;
    t.max_idle_timeout(Some(idle));
    t.keep_alive_interval(cfg.keepalive);

    // Datagrams: enabling a receive buffer is what permits `send_datagram`. When
    // the escape-hatch `--datagram false` is set, we disable them so the whole
    // FEC path is bypassed and business data rides reliable streams instead.
    if cfg.use_datagrams {
        t.datagram_receive_buffer_size(Some(DATAGRAM_RECV_BUFFER));
        t.datagram_send_buffer_size(DATAGRAM_SEND_BUFFER);
    } else {
        t.datagram_receive_buffer_size(None);
    }

    Ok(Arc::new(t))
}

/// Convert a `u64` byte count into a QUIC `VarInt`, rejecting values that exceed
/// the 62-bit varint range.
fn to_varint(v: u64) -> Result<VarInt> {
    VarInt::from_u64(v).map_err(|_| CoreError::Endpoint(format!("value {v} exceeds VarInt range")))
}

/// Build a client-side endpoint bound to an ephemeral local UDP port, with its
/// default client config set from the given [`ServerTrust`] and transport.
pub fn build_client_endpoint(
    trust: &ServerTrust,
    transport: Arc<QuinnTransport>,
) -> Result<Endpoint> {
    // Bind to an unspecified IPv4 address / ephemeral port for outbound use.
    let local: SocketAddr = "0.0.0.0:0".parse().expect("static addr literal is valid");
    let mut endpoint = Endpoint::client(local)?;

    let mut client_cfg = tls::client_config(trust)?;
    client_cfg.transport_config(transport);
    endpoint.set_default_client_config(client_cfg);
    Ok(endpoint)
}

/// Build a server-side endpoint listening on `bind` with the given identity and
/// transport parameters.
pub fn build_server_endpoint(
    bind: SocketAddr,
    identity: &ServerIdentity,
    transport: Arc<QuinnTransport>,
) -> Result<Endpoint> {
    let mut server_cfg: ServerConfig = tls::server_config(identity)?;
    server_cfg.transport_config(transport);
    let endpoint = Endpoint::server(server_cfg, bind)?;
    Ok(endpoint)
}

/// Sanity bound: the largest symbol payload that fits in one datagram given the
/// configured MTU, or `None` if datagrams are disabled. Callers size the FEC
/// symbol to at most this.
pub fn max_symbol_payload(cfg: &TransportConfig) -> Option<u16> {
    if !cfg.use_datagrams {
        return None;
    }
    // The MTU already accounts for UDP/IP; the symbol header is subtracted by
    // the FEC encoder. We just surface the datagram budget here.
    Some(cfg.mtu)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_builds_with_datagrams() {
        let cfg = TransportConfig::default();
        assert!(build_transport(&cfg).is_ok());
        assert_eq!(max_symbol_payload(&cfg), Some(cfg.mtu));
    }

    #[test]
    fn datagram_escape_hatch_disables_symbol_budget() {
        let cfg = TransportConfig {
            use_datagrams: false,
            ..TransportConfig::default()
        };
        assert!(build_transport(&cfg).is_ok());
        assert_eq!(max_symbol_payload(&cfg), None);
    }

    #[test]
    fn each_congestion_controller_builds() {
        for cc in [
            CongestionControl::Bbr,
            CongestionControl::Cubic,
            CongestionControl::NewReno,
        ] {
            let cfg = TransportConfig {
                congestion: cc,
                ..TransportConfig::default()
            };
            assert!(build_transport(&cfg).is_ok(), "cc {cc:?} failed");
        }
    }

    #[tokio::test]
    async fn client_endpoint_builds() {
        let transport = build_transport(&TransportConfig::default()).unwrap();
        // Binding an ephemeral UDP socket should succeed in the test env.
        let ep = build_client_endpoint(&ServerTrust::Insecure, transport);
        assert!(ep.is_ok(), "client endpoint: {:?}", ep.err());
    }

    #[tokio::test]
    async fn server_endpoint_builds() {
        let id = ServerIdentity::generate_self_signed("raptun.test").unwrap();
        let transport = build_transport(&TransportConfig::default()).unwrap();
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let ep = build_server_endpoint(bind, &id, transport);
        assert!(ep.is_ok(), "server endpoint: {:?}", ep.err());
    }
}
