//! Top-level run loops for the client and server binaries.
//!
//! Phase-1 scope: tunnel business traffic over reliable QUIC bidirectional
//! streams (one per accepted TCP connection). This is the functional baseline
//! that proves native QUIC multiplexing replaces yamux. The datagram+FEC data
//! path (Phase 2) plugs into [`crate::session`] alongside this without changing
//! the accept/forward structure here.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::RuntimeConfig;
use crate::endpoint::{build_client_endpoint, build_server_endpoint, build_transport};
use crate::fec::{DatagramHub, FecReceiver, FecSender};
use crate::session::{handshake_client, handshake_server, tunnel_bi};
use crate::tls::{ServerIdentity, ServerTrust};
use crate::{CoreError, Result};

use raptun_proto::control::FecParams;
use raptun_proto::StreamId;

/// How the client resolves a tunnelled connection's destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenMode {
    /// Every accepted TCP connection is forwarded to the server's fixed target.
    Tcp,
    /// SOCKS5 — per-connection destinations (Phase-4; not yet implemented).
    Socks5,
}

/// Run the client: listen locally, and for each accepted TCP connection open a
/// QUIC bi-stream to the server and pump bytes both ways.
///
/// The QUIC connection is supervised: if it drops (e.g. the server restarts),
/// the client re-dials with capped exponential backoff and resumes serving,
/// rather than wedging on a dead connection. The local listener is bound once
/// and shared across reconnects so the local port stays stable.
pub async fn run_client(
    config: RuntimeConfig,
    local_addr: SocketAddr,
    server_addr: SocketAddr,
    sni: &str,
    trust: ServerTrust,
    mode: ListenMode,
) -> Result<()> {
    if mode == ListenMode::Socks5 {
        return Err(CoreError::Endpoint(
            "socks5 listen mode is a Phase-4 feature".into(),
        ));
    }

    let transport = build_transport(&config.transport)?;
    let endpoint = build_client_endpoint(&trust, transport)?;

    // Bind the local listener once so the local port is stable across QUIC
    // reconnects. Accepted connections are held until a live server connection
    // exists to serve them.
    let listener = TcpListener::bind(local_addr).await?;
    tracing::info!(%local_addr, "listening for local connections");

    let config = Arc::new(config);

    // Supervision loop: (re)establish the QUIC connection and serve tunnels over
    // it until it drops, then reconnect with capped exponential backoff.
    let mut backoff = Duration::from_millis(500);
    const MAX_BACKOFF: Duration = Duration::from_secs(30);
    loop {
        tracing::info!(%server_addr, %sni, "connecting to raptun server");
        let conn = match connect_and_handshake(&endpoint, server_addr, sni, &config).await {
            Ok(conn) => {
                backoff = Duration::from_millis(500); // reset after a good connection
                conn
            }
            Err(e) => {
                tracing::warn!(error = %e, retry_in = ?backoff, "connect/handshake failed; retrying");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };

        // Serve tunnels over this connection until it closes. On return the
        // connection is dead (server gone, idle timeout, etc.) and we reconnect.
        serve_connection(conn, &listener, &config).await?;
        tracing::warn!(%server_addr, "server connection lost; reconnecting");
    }
}

/// Establish one QUIC connection to the server and run the handshake.
async fn connect_and_handshake(
    endpoint: &quinn::Endpoint,
    server_addr: SocketAddr,
    sni: &str,
    config: &RuntimeConfig,
) -> Result<(Arc<quinn::Connection>, FecParams)> {
    let conn = endpoint
        .connect(server_addr, sni)
        .map_err(|e| CoreError::Endpoint(format!("connect: {e}")))?
        .await
        .map_err(|e| CoreError::Endpoint(format!("connection: {e}")))?;

    let (_ctrl, fec) = handshake_client(&conn, config).await?;
    tracing::info!(
        symbol_size = fec.symbol_size,
        repair_ppm = fec.repair_ppm,
        "handshake ok"
    );
    Ok((Arc::new(conn), fec))
}

/// Accept local TCP connections and tunnel each over the given QUIC connection,
/// returning once the QUIC connection is no longer usable so the caller can
/// reconnect. The local listener persists across calls.
async fn serve_connection(
    conn_fec: (Arc<quinn::Connection>, FecParams),
    listener: &TcpListener,
    config: &Arc<RuntimeConfig>,
) -> Result<()> {
    let (conn, fec) = conn_fec;

    let use_fec = config.transport.use_datagrams && fec_enabled(config);

    // Connection-wide datagram reader for the FEC path.
    let hub = DatagramHub::new();
    if use_fec {
        spawn_datagram_reader(Arc::clone(&conn), hub.clone());
        tracing::info!("data path: unreliable datagrams + RaptorQ FEC");
    } else {
        tracing::info!("data path: reliable QUIC streams (FEC off)");
    }

    loop {
        // Race accepting a local connection against the QUIC connection closing,
        // so a server that goes away while we are idle triggers a reconnect
        // instead of leaving us blocked in `accept()`.
        let (tcp, peer) = tokio::select! {
            accepted = listener.accept() => accepted?,
            closed = conn.closed() => {
                tracing::debug!(reason = %closed, "quic connection closed while idle");
                return Ok(());
            }
        };
        tracing::debug!(%peer, "accepted local connection");
        let conn = Arc::clone(&conn);
        let hub = hub.clone();
        let fec = fec.clone();
        let config = Arc::clone(config);
        tokio::spawn(async move {
            let res = if use_fec {
                handle_client_conn_fec(&conn, &hub, &fec, &config, tcp).await
            } else {
                handle_client_conn(&conn, tcp).await
            };
            if let Err(e) = res {
                tracing::warn!(error = %e, "client tunnel closed with error");
            }
        });
    }
}

/// Open a QUIC bi-stream for one local TCP connection and tunnel it (reliable).
async fn handle_client_conn(conn: &quinn::Connection, tcp: TcpStream) -> Result<()> {
    let (send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| CoreError::Endpoint(format!("open tunnel bi: {e}")))?;
    tunnel_bi(tcp, send, recv).await
}

/// Open a signaling bi-stream and tunnel one local TCP connection over FEC.
async fn handle_client_conn_fec(
    conn: &quinn::Connection,
    hub: &DatagramHub,
    fec: &FecParams,
    config: &RuntimeConfig,
    tcp: TcpStream,
) -> Result<()> {
    let (send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| CoreError::Endpoint(format!("open signaling bi: {e}")))?;
    client_tunnel_fec(conn, hub, fec, config, tcp, send, recv).await
}

/// Run the server: listen for QUIC connections, run the handshake on each, and
/// forward every accepted bi-stream to the configured target.
pub async fn run_server(
    config: RuntimeConfig,
    bind: SocketAddr,
    target: SocketAddr,
    identity: ServerIdentity,
) -> Result<()> {
    tracing::info!(fingerprint = %identity.fingerprint_hex, "pin this fingerprint on clients");

    let transport = build_transport(&config.transport)?;
    let endpoint = build_server_endpoint(bind, &identity, transport)?;
    tracing::info!(%bind, %target, "raptun server listening");

    while let Some(incoming) = endpoint.accept().await {
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_server_conn(incoming, config, target).await {
                tracing::warn!(error = %e, "server connection closed with error");
            }
        });
    }
    Ok(())
}

/// Handle one accepted QUIC connection: handshake, then forward each inbound
/// bi-stream to the target service.
async fn handle_server_conn(
    incoming: quinn::Incoming,
    config: RuntimeConfig,
    target: SocketAddr,
) -> Result<()> {
    let conn = incoming
        .await
        .map_err(|e| CoreError::Endpoint(format!("accept connection: {e}")))?;
    let remote = conn.remote_address();
    tracing::debug!(%remote, "client connected");

    let (_ctrl, fec) = handshake_server(&conn, &config).await?;
    tracing::debug!(%remote, "handshake ok");

    let use_fec = config.transport.use_datagrams && fec_enabled(&config);
    let conn = Arc::new(conn);
    let config = Arc::new(config);

    // When FEC is on, one connection-wide datagram read loop demultiplexes
    // inbound symbols to per-tunnel receivers via the hub.
    let hub = DatagramHub::new();
    if use_fec {
        spawn_datagram_reader(Arc::clone(&conn), hub.clone());
    }

    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::debug!(%remote, error = %e, "connection ended");
                return Ok(());
            }
        };
        let conn = Arc::clone(&conn);
        let hub = hub.clone();
        let fec = fec.clone();
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            match TcpStream::connect(target).await {
                Ok(tcp) => {
                    let res = if use_fec {
                        server_tunnel_fec(&conn, &hub, &fec, &config, tcp, send, recv).await
                    } else {
                        tunnel_bi(tcp, send, recv).await
                    };
                    if let Err(e) = res {
                        tracing::warn!(error = %e, "server tunnel closed with error");
                    }
                }
                Err(e) => tracing::warn!(%target, error = %e, "failed to reach target"),
            }
        });
    }
}

// ----------------------------------------------------------------------------
// FEC data path (Phase 2)
// ----------------------------------------------------------------------------

/// Whether the negotiated config uses the RaptorQ FEC scheme.
fn fec_enabled(config: &RuntimeConfig) -> bool {
    matches!(config.fec.scheme, crate::config::FecScheme::RaptorQ)
}

/// Resolve a concrete source-block symbol count K from negotiated params,
/// defaulting when the peer left it on auto (0).
fn resolve_k(fec: &FecParams) -> u32 {
    if fec.block_size == 0 {
        16
    } else {
        fec.block_size as u32
    }
}

/// Repair symbols to send per block, from the negotiated repair ratio
/// (parts-per-thousand) applied to K, with a floor of 1 when any repair is set.
fn repair_count(fec: &FecParams, k: u32) -> u32 {
    let raw = (u64::from(k) * u64::from(fec.repair_ppm) / 1000) as u32;
    if fec.repair_ppm > 0 {
        raw.max(1)
    } else {
        0
    }
}

/// Client-assigned stream ids for FEC tunnels. Even ids for client-originated
/// tunnels keeps them from colliding with any future server-originated ones.
static NEXT_STREAM_ID: AtomicU64 = AtomicU64::new(2);

/// Spawn the connection-wide datagram read loop that feeds the hub.
fn spawn_datagram_reader(conn: Arc<quinn::Connection>, hub: DatagramHub) {
    tokio::spawn(async move {
        loop {
            match conn.read_datagram().await {
                Ok(dg) => {
                    tracing::trace!(len = dg.len(), "datagram received");
                    hub.dispatch(&dg);
                }
                Err(e) => {
                    tracing::debug!(error = %e, "datagram reader stopped");
                    break;
                }
            }
        }
    });
}

/// Client side of a FEC tunnel: assign a stream id, announce it on the
/// bi-stream, then pump TCP data both ways over FEC datagrams.
async fn client_tunnel_fec(
    conn: &quinn::Connection,
    hub: &DatagramHub,
    fec: &FecParams,
    config: &RuntimeConfig,
    tcp: TcpStream,
    mut sig_send: quinn::SendStream,
    sig_recv: quinn::RecvStream,
) -> Result<()> {
    let stream_id = NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed);
    // Announce the stream id so the server registers the same route.
    sig_send
        .write_all(&stream_id.to_be_bytes())
        .await
        .map_err(|e| CoreError::Endpoint(format!("announce stream id: {e}")))?;

    let inbound = hub.register(stream_id);
    tracing::debug!(stream_id, "client FEC tunnel opened");
    let res = run_fec_tunnel(
        conn, fec, config, stream_id, tcp, sig_send, sig_recv, inbound,
    )
    .await;
    hub.unregister(stream_id);
    res
}

/// Server side of a FEC tunnel: read the client's stream id off the bi-stream,
/// register the route, then pump TCP data both ways.
async fn server_tunnel_fec(
    conn: &quinn::Connection,
    hub: &DatagramHub,
    fec: &FecParams,
    config: &RuntimeConfig,
    tcp: TcpStream,
    sig_send: quinn::SendStream,
    mut sig_recv: quinn::RecvStream,
) -> Result<()> {
    let mut id_buf = [0u8; 8];
    sig_recv
        .read_exact(&mut id_buf)
        .await
        .map_err(|e| CoreError::Endpoint(format!("read stream id: {e}")))?;
    let stream_id = u64::from_be_bytes(id_buf);

    let inbound = hub.register(stream_id);
    tracing::debug!(stream_id, "server FEC tunnel opened");
    let res = run_fec_tunnel(
        conn, fec, config, stream_id, tcp, sig_send, sig_recv, inbound,
    )
    .await;
    hub.unregister(stream_id);
    res
}

/// The symmetric core of a FEC tunnel, run by both ends after the stream id is
/// agreed.
///
/// Four concurrent tasks share the connection:
///
/// * **Upstream** (TCP → datagrams): read the socket, cut into blocks, send each
///   block's source + repair symbols as datagrams. On EOF, announce the total
///   block count on the reliable signaling stream. Also serves inbound NACKs by
///   minting fresh repair symbols for the named block.
/// * **Downstream** (datagrams → TCP): feed inbound symbols to a [`FecReceiver`]
///   and write recovered, in-order bytes to the socket until the peer's
///   announced block count has all been delivered.
/// * **Control tick**: periodically run the convergence arbitration
///   ([`FecReceiver::tick`]) over stalled blocks and emit NACKs.
/// * **Signal reader/writer**: multiplex [`TunnelSignal`]s over the one reliable
///   bi-stream.
async fn run_fec_tunnel(
    conn: &quinn::Connection,
    fec: &FecParams,
    config: &RuntimeConfig,
    stream_id: StreamId,
    tcp: TcpStream,
    sig_send: quinn::SendStream,
    sig_recv: quinn::RecvStream,
    inbound: tokio::sync::mpsc::UnboundedReceiver<crate::fec::InboundSymbol>,
) -> Result<()> {
    use crate::fec::TunnelSignal;
    use tokio::sync::mpsc;

    let k = resolve_k(fec);
    let repair = repair_count(fec, k);
    // The negotiated symbol size must fit inside one QUIC datagram together with
    // the symbol header, or every `send_datagram` would fail and the FEC path
    // would silently stall. Both ends clamp identically against the *negotiated*
    // value, so they agree even if their live `max_datagram_size` differs.
    let symbol_size = effective_symbol_size(conn, fec.symbol_size);
    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    // Signaling fan-in: any task can queue a TunnelSignal to send to the peer.
    let (sig_tx, mut sig_rx) = mpsc::unbounded_channel::<TunnelSignal>();
    // Inbound NACKs routed from the signal reader to the upstream task.
    let (nack_tx, mut nack_rx) = mpsc::unbounded_channel::<(u64, u32)>();
    // Peer's announced total block count, routed to the downstream task.
    let (count_tx, mut count_rx) = mpsc::unbounded_channel::<u64>();
    // Reliable-retransmit requests routed to the upstream task (which owns the
    // sender and its retained block payloads).
    let (rel_req_tx, mut rel_req_rx) = mpsc::unbounded_channel::<u64>();
    // Reliable-retransmit data routed to the downstream task (which owns the
    // receiver and delivers in order).
    let (rel_data_tx, mut rel_data_rx) = mpsc::unbounded_channel::<(u64, Vec<u8>)>();

    // --- Signal writer: owns sig_send, serializes queued signals. ---
    let writer = async move {
        let mut sig_send = sig_send;
        while let Some(sig) = sig_rx.recv().await {
            let bytes = sig.encode();
            if sig_send.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = sig_send.finish();
        Ok::<(), CoreError>(())
    };

    // --- Signal reader: owns sig_recv, demultiplexes inbound signals. ---
    let reader = async move {
        let mut sig_recv = sig_recv;
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 512];
        loop {
            match sig_recv.read(&mut chunk).await {
                Ok(Some(n)) => buf.extend_from_slice(&chunk[..n]),
                Ok(None) | Err(_) => break, // signaling stream finished
            }
            // Drain as many complete signals as the buffer holds.
            while let Some((sig, used)) = TunnelSignal::decode(&buf) {
                buf.drain(..used);
                match sig {
                    TunnelSignal::BlockCount { total } => {
                        let _ = count_tx.send(total);
                    }
                    TunnelSignal::Nack { block, need, .. } => {
                        let _ = nack_tx.send((block, need));
                    }
                    TunnelSignal::ReliableRequest { block } => {
                        let _ = rel_req_tx.send(block);
                    }
                    TunnelSignal::ReliableData { block, bytes } => {
                        let _ = rel_data_tx.send((block, bytes));
                    }
                }
            }
        }
        Ok::<(), CoreError>(())
    };

    // --- Upstream: TCP -> FEC datagrams, plus serving inbound NACKs and
    //     reliable-retransmit requests. ---
    let up_conn = conn.clone();
    let up_sig = sig_tx.clone();
    let up = async move {
        let mut sender = FecSender::new(stream_id, symbol_size, k);
        let cap = sender.block_payload();
        let mut buf = vec![0u8; cap];
        let mut total_blocks: u64 = 0;
        let mut eof = false;

        while !eof {
            tokio::select! {
                // Read application data and emit block symbols.
                read = tcp_read.read(&mut buf) => {
                    let n = read.map_err(CoreError::Io)?;
                    if n == 0 {
                        eof = true;
                        continue;
                    }
                    // Flush each read burst immediately as one or more blocks;
                    // buffering until a full block forms would stall interactive
                    // traffic whose messages are far smaller than a block.
                    for chunk in buf[..n].chunks(cap) {
                        for dg in sender.encode_one_block(chunk, repair) {
                            send_datagram_lossy(&up_conn, dg);
                        }
                        total_blocks += 1;
                    }
                }
                // Serve an inbound NACK: mint fresh repair for the named block.
                Some((block, need)) = nack_rx.recv() => {
                    for dg in sender.additional_repair(block, need) {
                        send_datagram_lossy(&up_conn, dg);
                    }
                }
                // Serve a reliable-retransmit request: ship the block's bytes
                // over the reliable channel (the convergence lower bound).
                Some(block) = rel_req_rx.recv() => {
                    if let Some(bytes) = sender.reliable_payload(block) {
                        let _ = up_sig.send(TunnelSignal::ReliableData { block, bytes });
                    }
                }
            }
        }
        // Announce the count so the receiver knows the stream length, then keep
        // serving late NACKs / reliable requests until the peer finishes. We do
        // NOT return here: a block stranded near EOF may still need a reliable
        // retransmit, and the sender must remain able to answer it.
        let _ = up_sig.send(TunnelSignal::BlockCount {
            total: total_blocks,
        });
        loop {
            tokio::select! {
                Some((block, need)) = nack_rx.recv() => {
                    for dg in sender.additional_repair(block, need) {
                        send_datagram_lossy(&up_conn, dg);
                    }
                }
                Some(block) = rel_req_rx.recv() => {
                    if let Some(bytes) = sender.reliable_payload(block) {
                        let _ = up_sig.send(TunnelSignal::ReliableData { block, bytes });
                    }
                }
                else => break,
            }
        }
        Ok::<(), CoreError>(())
    };

    // --- Downstream: FEC datagrams -> TCP, with periodic convergence tick. ---
    // Repair budget shared by every block's arbitration (the in-flight brake).
    let budget = std::sync::Arc::new(raptun_fec::RepairBudget::new(
        symbol_size,
        config.fec.repair_cwnd_fraction,
    ));
    let down_conn = conn.clone();
    let down_sig = sig_tx.clone();
    let mut classifier = crate::telemetry::RegimeClassifier::new();
    let down = async move {
        let mut inbound = inbound;
        let mut receiver = FecReceiver::new(symbol_size, k);
        let mut expected: Option<u64> = None;
        // Tick cadence for the convergence arbitration.
        let mut ticker = tokio::time::interval(std::time::Duration::from_millis(20));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            if let Some(total) = expected {
                if receiver.highest_delivered() >= total {
                    break;
                }
            }
            tokio::select! {
                sym = inbound.recv() => {
                    match sym {
                        Some((block_id, esi, payload)) => {
                            let out = receiver.on_symbol(block_id, esi, &payload, Instant::now());
                            if !out.is_empty() {
                                tcp_write.write_all(&out).await.map_err(CoreError::Io)?;
                            }
                        }
                        None => break,
                    }
                }
                Some(total) = count_rx.recv() => {
                    expected = Some(total);
                    // Let the receiver detect entirely-lost blocks against the
                    // announced total (blocks with no symbol at all).
                    receiver.set_total_blocks(total);
                }
                // Reliable-retransmit data: inject verbatim, bypassing FEC. This
                // is the convergence lower bound — a block that FEC could not
                // recover is completed here, so the stream can never deadlock.
                Some((block, bytes)) = rel_data_rx.recv() => {
                    let out = receiver.on_reliable_block(block, bytes);
                    if !out.is_empty() {
                        tcp_write.write_all(&out).await.map_err(CoreError::Io)?;
                    }
                }
                _ = ticker.tick() => {
                    // Refresh telemetry-derived link state + budget ceiling, then
                    // arbitrate stalled blocks and emit NACKs / reliable requests.
                    let sample = crate::session::read_telemetry(&down_conn);
                    let link = classifier.to_link_state(sample);
                    budget.refresh_ceiling(link.cwnd_bytes());
                    for sig in receiver.tick(&link, &budget, Instant::now()) {
                        let _ = down_sig.send(sig);
                    }
                }
            }
        }
        let _ = tcp_write.shutdown().await;
        Ok::<(), CoreError>(())
    };

    // Drop the extra sender handle so the writer task can terminate once up/down
    // finish and release their clones.
    drop(sig_tx);

    let (up_r, down_r, _w, _r) = tokio::join!(up, down, writer, reader);
    up_r?;
    down_r?;
    Ok(())
}

/// Test-only datagram loss injection: drop 1-in-N sent datagrams to exercise
/// the FEC recovery / NACK path deterministically. `0` (the default) disables
/// it. Compiled only under the `test-hooks` feature so it never affects a
/// production build. Set via [`set_test_drop_one_in`] from tests.
#[cfg(feature = "test-hooks")]
static TEST_DROP_ONE_IN: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "test-hooks")]
static TEST_DROP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Enable/disable test datagram loss injection (drop every `n`-th datagram).
#[cfg(feature = "test-hooks")]
pub fn set_test_drop_one_in(n: u64) {
    TEST_DROP_ONE_IN.store(n, Ordering::Relaxed);
    TEST_DROP_COUNTER.store(0, Ordering::Relaxed);
}

/// Send a datagram, tolerating "too large" / transient errors by dropping the
/// symbol — FEC on the stream absorbs individual symbol loss, so a dropped
/// datagram is not fatal.
fn send_datagram_lossy(conn: &quinn::Connection, dg: bytes::Bytes) {
    #[cfg(feature = "test-hooks")]
    {
        let n = TEST_DROP_ONE_IN.load(Ordering::Relaxed);
        if n > 0 {
            let c = TEST_DROP_COUNTER.fetch_add(1, Ordering::Relaxed);
            if c % n == 0 {
                // Simulate loss: never hand this symbol to the transport.
                return;
            }
        }
    }
    if let Err(e) = conn.send_datagram(dg) {
        tracing::trace!(error = %e, "datagram dropped (FEC will absorb)");
    }
}

/// The symbol payload size to use for a tunnel.
///
/// The geometry **must be identical on both ends** or RaptorQ decode fails, so
/// this returns the negotiated size verbatim — the server already clamped it to
/// [`crate::session::SAFE_MAX_SYMBOL_SIZE`] during the handshake, which is
/// chosen to fit within a conservative QUIC datagram (well under typical
/// `max_datagram_size`). The `conn` is accepted for a debug assertion only.
fn effective_symbol_size(conn: &quinn::Connection, negotiated: u16) -> u16 {
    let header = raptun_proto::datagram::SYMBOL_HEADER_LEN as u16;
    if let Some(max) = conn.max_datagram_size() {
        debug_assert!(
            (negotiated as usize + header as usize) <= max,
            "negotiated symbol {} + header {} exceeds datagram max {} — handshake clamp is too loose",
            negotiated,
            header,
            max
        );
    }
    negotiated.max(1)
}
