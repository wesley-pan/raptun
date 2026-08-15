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

// Datagram *send*-buffer size comes from `TransportConfig::datagram_send_buffer`
// (default 2 MiB). Quinn's own default is only 1 MiB, and its `send_datagram`
// silently evicts the oldest queued symbol once that fills — so a large burst
// strands early blocks and stalls the tunnel (see `live_size_sweep.sh`). The
// sender back-pressures on a full buffer rather than evicting
// (`send_datagram_paced` in `run.rs`). The buffer must stay *small enough*
// that a bulk flow cannot queue seconds of symbols locally: an oversized
// buffer hides the real link from BBR (everything "sends" successfully into
// the queue), cwnd stays inflated, and the queue eventually tail-drops whole
// blocks in bursts — the bufferbloat → loss-spike → repair-storm flapping
// cycle documented in `docs/raptun-congestion-optimization-plan.md`.

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
        t.datagram_send_buffer_size(cfg.datagram_send_buffer);
    } else {
        t.datagram_receive_buffer_size(None);
    }

    // Loss-detection / reordering tolerance. A shaped link (e.g. the stress
    // relay, or any path with per-packet jitter) can spread adjacent packets
    // across a wide delay window. Quinn's defaults (packet_threshold=3,
    // time_threshold=1.125·RTT) then misread late-but-arriving packets as
    // lost, which trips black-hole detection and collapses the cwnd - the root
    // cause of the spurious high loss_pct and throughput collapse seen under
    // reordering. Raising these lets reordered packets survive so the cwnd
    // stays stable and the FEC path is not drowned in spurious repair. The
    // FEC layer (RaptorQ) is itself order-agnostic; this tuning stops QUIC's
    // loss detector from fighting it.
    t.packet_threshold(cfg.reorder_packet_threshold);
    t.time_threshold(cfg.reorder_time_threshold);
    t.persistent_congestion_threshold(cfg.persistent_congestion_threshold);
    t.min_mtu(cfg.min_mtu);
    t.initial_mtu(cfg.mtu);
    t.pad_to_mtu(true);
    if let Some(rtt) = cfg.initial_rtt {
        t.initial_rtt(rtt);
    }

    Ok(Arc::new(t))
}

/// Convert a `u64` byte count into a QUIC `VarInt`, rejecting values that exceed
/// the 62-bit varint range.
fn to_varint(v: u64) -> Result<VarInt> {
    VarInt::from_u64(v).map_err(|_| CoreError::Endpoint(format!("value {v} exceeds VarInt range")))
}

/// Set `SO_RCVBUF` and `SO_SNDBUF` on a UDP socket via socket2. The OS may
/// silently cap the requested value to a system maximum; we log at debug level
/// if the resulting buffer differs from the request so operators can diagnose
/// a too-low `net.core.rmem_max` / `wmem_max` without the endpoint failing.
fn apply_socket_buffers(socket: &socket2::Socket, requested: u32) {
    let req = requested as usize;
    if let Err(e) = socket.set_recv_buffer_size(req) {
        tracing::warn!(error = %e, requested, "failed to set SO_RCVBUF");
    }
    if let Err(e) = socket.set_send_buffer_size(req) {
        tracing::warn!(error = %e, requested, "failed to set SO_SNDBUF");
    }
    match (socket.recv_buffer_size(), socket.send_buffer_size()) {
        (Ok(rcv), Ok(snd)) if rcv < req || snd < req => {
            tracing::debug!(
                requested,
                actual_rcv = rcv,
                actual_snd = snd,
                "socket buffer smaller than requested (check sysctl rmem_max/wmem_max)"
            );
        }
        _ => {}
    }
}

/// Build a client-side endpoint bound to an ephemeral local UDP port, with its
/// default client config set from the given [`ServerTrust`] and transport.
///
/// The UDP socket's send/receive buffers are sized from `cfg.socket_buffer`
/// (previously a dead config field — now applied via `SO_RCVBUF`/`SO_SNDBUF`).
/// 0-RTT is enabled on the TLS client config when `cfg.allow_0rtt` is set.
pub fn build_client_endpoint(
    trust: &ServerTrust,
    transport: Arc<QuinnTransport>,
    cfg: &TransportConfig,
) -> Result<Endpoint> {
    let local: SocketAddr = "0.0.0.0:0".parse().expect("static addr literal is valid");
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(local),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .map_err(|e| CoreError::Endpoint(format!("create socket: {e}")))?;
    socket
        .bind(&local.into())
        .map_err(|e| CoreError::Endpoint(format!("bind UDP: {e}")))?;
    apply_socket_buffers(&socket, cfg.socket_buffer);

    let mut client_cfg = tls::client_config(trust, cfg.allow_0rtt)?;
    client_cfg.transport_config(transport);

    let std_socket: std::net::UdpSocket = socket.into();
    let runtime = Arc::new(quinn::TokioRuntime);
    let mut endpoint = Endpoint::new(quinn::EndpointConfig::default(), None, std_socket, runtime)
        .map_err(|e| CoreError::Endpoint(format!("client endpoint: {e}")))?;
    endpoint.set_default_client_config(client_cfg);
    Ok(endpoint)
}

/// Build a server-side endpoint listening on `bind` with the given identity and
/// transport parameters.
///
/// The UDP socket's send/receive buffers are sized from `cfg.socket_buffer`.
/// Connection migration is controlled by `cfg.allow_migration`.
pub fn build_server_endpoint(
    bind: SocketAddr,
    identity: &ServerIdentity,
    transport: Arc<QuinnTransport>,
    cfg: &TransportConfig,
) -> Result<Endpoint> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(bind),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .map_err(|e| CoreError::Endpoint(format!("create socket: {e}")))?;
    // Intentionally no SO_REUSEADDR: Quinn's Endpoint::server() doesn't set it
    // either, and enabling it causes the kernel to load-balance incoming packets
    // between the old and new socket during server restarts, breaking reconnection.
    socket
        .bind(&bind.into())
        .map_err(|e| CoreError::Endpoint(format!("bind UDP: {e}")))?;
    apply_socket_buffers(&socket, cfg.socket_buffer);

    let mut server_cfg: ServerConfig = tls::server_config(identity)?;
    server_cfg.transport_config(transport);
    server_cfg.migration(cfg.allow_migration);

    let std_socket: std::net::UdpSocket = socket.into();
    let runtime = Arc::new(quinn::TokioRuntime);
    Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_cfg),
        std_socket,
        runtime,
    )
    .map_err(|e| CoreError::Endpoint(format!("server endpoint: {e}")))
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
    fn reorder_tuning_defaults_are_set() {
        let cfg = TransportConfig::default();
        assert_eq!(cfg.reorder_packet_threshold, 8);
        assert!((cfg.reorder_time_threshold - 2.0).abs() < f32::EPSILON);
        assert_eq!(cfg.persistent_congestion_threshold, 5);
        assert_eq!(cfg.min_mtu, 1200);
        assert!(cfg.initial_rtt.is_none());
    }

    #[test]
    fn transport_applies_custom_reorder_tuning() {
        // Custom loss-detection knobs must be accepted by Quinn. Quinn does not
        // expose getters to read them back, so this asserts acceptance, not
        // values - the real proof is the stress run's loss_pct/cwnd behaviour.
        let cfg = TransportConfig {
            reorder_packet_threshold: 16,
            reorder_time_threshold: 3.0,
            persistent_congestion_threshold: 7,
            min_mtu: 1280,
            initial_rtt: Some(std::time::Duration::from_millis(120)),
            ..TransportConfig::default()
        };
        assert!(build_transport(&cfg).is_ok());
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
        let cfg = TransportConfig::default();
        let transport = build_transport(&cfg).unwrap();
        let ep = build_client_endpoint(&ServerTrust::Insecure, transport, &cfg);
        assert!(ep.is_ok(), "client endpoint: {:?}", ep.err());
    }

    #[tokio::test]
    async fn server_endpoint_builds() {
        let id = ServerIdentity::generate_self_signed("raptun.test").unwrap();
        let cfg = TransportConfig::default();
        let transport = build_transport(&cfg).unwrap();
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let ep = build_server_endpoint(bind, &id, transport, &cfg);
        assert!(ep.is_ok(), "server endpoint: {:?}", ep.err());
    }
}
