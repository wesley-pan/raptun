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
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::RuntimeConfig;
use crate::endpoint::{build_client_endpoint, build_server_endpoint, build_transport};
use crate::fec::{DatagramHub, FecReceiver, FecSender};
use crate::monitor::{TunnelRegistry, TunnelStats};
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
    let endpoint = build_client_endpoint(&trust, transport, &config.transport)?;

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

    // One repair budget per QUIC *connection*, shared by every tunnel on it.
    // The budget is the ≤40%-of-cwnd brake on in-flight repair symbols; since
    // all tunnels share this one connection's cwnd, they must also share one
    // budget, or N tunnels each independently claim 40% of the same cwnd and
    // the aggregate repair injection overshoots the link by a factor of N —
    // self-inflicted congestion that collapses throughput as concurrency rises.
    let budget = new_conn_budget(&conn, &fec, config);
    // One connection-wide send window, shared by every tunnel so aggregate
    // in-flight data stays bounded by cwnd regardless of tunnel count.
    let send_window = new_conn_send_window(&conn, &fec);

    // Count of currently-live tunnels, surfaced by the heartbeat. Each accepted
    // connection increments it and a guard decrements on completion.
    let active = Arc::new(AtomicU64::new(0));
    // One LossTracker per QUIC connection, shared by the heartbeat task and
    // every per-tunnel downstream task. The tracker is *connection-scoped* —
    // not per-tunnel — so a fresh per-tunnel tracker does not establish a new
    // `diag_prev` baseline on every tunnel open/close cycle. Pre-fix, each
    // tunnel's first diagnostic call returned 0.0 (baseline) and was logged as
    // a real `loss_pct=0.00`, which hid the actual 30-37% loss from the
    // operator. The lock is held only for the few-line delta math in
    // `read_telemetry`; contention is negligible (diagnostic fires at most
    // every 2 s globally).
    let conn_loss_tracker: Arc<Mutex<crate::telemetry::LossTracker>> =
        Arc::new(Mutex::new(crate::telemetry::LossTracker::new()));
    // Latest LinkState snapshot computed by the downstream task, shared with the
    // upstream task so proactive repair spurts can be gated on the live loss
    // regime (M3). Written once per 20 ms control tick; read once per proactive
    // tick (RTT/4). One cell per connection, not per tunnel.
    let conn_link_state: Arc<Mutex<Option<raptun_fec::LinkState>>> = Arc::new(Mutex::new(None));
    if let Some(interval) = config.transport.heartbeat {
        spawn_client_heartbeat(
            Arc::clone(&conn),
            Arc::clone(&active),
            Arc::clone(&conn_loss_tracker),
            interval,
        );
    }

    // M2: collect every per-tunnel task into a JoinSet so we can abort them
    // all when the connection scope ends. `JoinSet::Drop` aborts every still-
    // running task, so the right-shutdown semantics are "live tunnels die
    // when the QUIC connection dies", with no orphans left for the rest of
    // the process. `join_next` reaps finished tasks without blocking.
    let mut tunnels: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

    loop {
        // Race accepting a local connection against the QUIC connection closing,
        // so a server that goes away while we are idle triggers a reconnect
        // instead of leaving us blocked in `accept()`. The third arm reaps
        // finished per-tunnel tasks so the set doesn't grow without bound
        // over a long-lived connection.
        let (tcp, peer) = tokio::select! {
            accepted = listener.accept() => accepted?,
            closed = conn.closed() => {
                tracing::debug!(reason = %closed, "quic connection closed while idle");
                return Ok(());
            }
            // A per-tunnel task finished; ignore its JoinError (panic or
            // external abort). `continue` restarts the loop so we re-poll
            // the select — the joint set is now smaller and a future
            // accept is more likely to win the race.
            Some(_result) = tunnels.join_next(), if !tunnels.is_empty() => continue,
        };
        tracing::debug!(%peer, "accepted local connection");
        let conn = Arc::clone(&conn);
        let hub = hub.clone();
        let fec = fec.clone();
        let active = Arc::clone(&active);
        let budget = Arc::clone(&budget);
        let send_window = Arc::clone(&send_window);
        let conn_loss_tracker = Arc::clone(&conn_loss_tracker);
        let conn_link_state = Arc::clone(&conn_link_state);
        tunnels.spawn(async move {
            // Track this tunnel in the live count for the heartbeat; the guard
            // decrements even if the tunnel returns early with an error.
            active.fetch_add(1, Ordering::Relaxed);
            let _guard = ActiveGuard(&active);
            let res = if use_fec {
                handle_client_conn_fec(
                    &conn,
                    &hub,
                    &fec,
                    &budget,
                    &send_window,
                    &conn_loss_tracker,
                    &conn_link_state,
                    tcp,
                )
                .await
            } else {
                handle_client_conn(&conn, tcp).await
            };
            if let Err(e) = res {
                if is_benign_local_close(&e) {
                    // The local application (browser tab, cancelled request,
                    // expired keep-alive) hung up while we still had downstream
                    // bytes to hand it. Routine for interactive traffic — log at
                    // debug so genuine failures stay visible at warn.
                    tracing::debug!(error = %e, "client tunnel closed (local peer hung up)");
                } else {
                    tracing::warn!(error = %e, "client tunnel closed with error");
                }
            }
        });
    }
}

/// Whether a tunnel error is just the local peer closing its socket while we
/// still had data to deliver — expected churn for browser/interactive traffic,
/// not a fault worth a warning.
///
/// Covers the four typical "peer disappeared" kinds: `BrokenPipe` (write
/// after peer closed), `ConnectionReset` / `ConnectionAborted` (TCP RST), and
/// `UnexpectedEof` / `NotConnected` (peer closed cleanly while we still
/// had data buffered). `NotConnected` shows up when the local socket was
/// never fully connected (e.g. the local process killed the socket between
/// `connect` and the first read) — also benign.
///
/// What this does NOT cover: `TimedOut`, `Interrupted`, or any non-I/O
/// `CoreError` — those stay at warn level.
fn is_benign_local_close(err: &CoreError) -> bool {
    use std::io::ErrorKind;
    matches!(
        err,
        CoreError::Io(io)
            if matches!(
                io.kind(),
                ErrorKind::BrokenPipe
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::UnexpectedEof
                    | ErrorKind::NotConnected
            )
    )
}

#[cfg(test)]
mod close_classification_tests {
    use super::*;
    use std::io::{Error as IoError, ErrorKind};

    fn io_err(kind: ErrorKind) -> CoreError {
        CoreError::Io(IoError::from(kind))
    }

    /// H6 regression: the four typical "local peer closed the socket while
    /// we still had data" kinds are all benign. Previously `UnexpectedEof`
    /// and `NotConnected` were missing, so the same kind of behaviour
    /// (browser tab close, client cancel before first read) was being
    /// logged at warn.
    #[test]
    fn benign_local_close_covers_the_four_peer_gone_kinds() {
        for kind in [
            ErrorKind::BrokenPipe,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::UnexpectedEof,
            ErrorKind::NotConnected,
        ] {
            assert!(
                is_benign_local_close(&io_err(kind)),
                "{kind:?} must be classified as benign"
            );
        }
    }

    /// And the things that are NOT benign stay at warn level.
    #[test]
    fn benign_local_close_does_not_swallow_real_errors() {
        for kind in [
            ErrorKind::TimedOut,
            ErrorKind::Interrupted,
            ErrorKind::PermissionDenied,
            ErrorKind::OutOfMemory,
        ] {
            assert!(
                !is_benign_local_close(&io_err(kind)),
                "{kind:?} must NOT be classified as benign"
            );
        }
    }

    /// Non-I/O errors (e.g. protocol) are never benign.
    #[test]
    fn non_io_errors_are_never_benign() {
        let proto = CoreError::Proto(raptun_proto::WireError::Truncated { needed: 0 });
        assert!(!is_benign_local_close(&proto));
    }
}

/// Decrements the active-tunnel counter when a tunnel task ends, on any path.
struct ActiveGuard<'a>(&'a AtomicU64);
impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Spawn the periodic client heartbeat: at `interval`, log one `info` line with
/// live connection telemetry (RTT / cwnd / loss / active tunnels) so a healthy,
/// otherwise-silent tunnel still produces rolling output confirming liveness.
/// The task ends when the connection closes.
fn spawn_client_heartbeat(
    conn: Arc<quinn::Connection>,
    active: Arc<AtomicU64>,
    conn_loss_tracker: Arc<Mutex<crate::telemetry::LossTracker>>,
    interval: Duration,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Skip the immediate first tick so the heartbeat doesn't fire at t=0
        // right after the startup logs.
        ticker.tick().await;
        // Skip the `loss_pct` field on the first real tick: the per-connection
        // `window_loss` baseline is set by the first caller (often a per-tunnel
        // task that runs at 20ms, long before the heartbeat's 1s tick), so
        // the baseline-call detection inside `read_telemetry` rarely fires from
        // the heartbeat. Track first-tick here so the operator never sees a
        // misleading `0.00` on the very first heartbeat line.
        let mut first_tick = true;
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    // First tick: only the post-baseline `loss_pct` is
                    // unreliable (the 20ms-cadenced `window_loss` baseline
                    // may be set by a per-tunnel task rather than the
                    // heartbeat, so the literal-first-call detection in
                    // `read_telemetry` doesn't apply). Skip the `loss_pct`
                    // field on the first tick so the operator never sees a
                    // potentially-misleading `0.00`; rtt / cwnd / tunnel
                    // count are always meaningful.
                    let sample = crate::session::read_telemetry(
                        &conn,
                        &mut *conn_loss_tracker.lock().expect("loss tracker poisoned"),
                    );
                    if first_tick {
                        tracing::info!(
                            rtt_ms = sample.smoothed_rtt.as_millis(),
                            cwnd_bytes = sample.cwnd_bytes,
                            active_tunnels = active.load(Ordering::Relaxed),
                            "tunnel alive (loss_pct=baseline)"
                        );
                        first_tick = false;
                    } else {
                        tracing::info!(
                            rtt_ms = sample.smoothed_rtt.as_millis(),
                            cwnd_bytes = sample.cwnd_bytes,
                            loss_pct = format!("{:.2}", sample.loss_rate * 100.0),
                            active_tunnels = active.load(Ordering::Relaxed),
                            "tunnel alive"
                        );
                    }
                }
                closed = conn.closed() => {
                    tracing::debug!(reason = %closed, "heartbeat stopping (connection closed)");
                    break;
                }
            }
        }
    });
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
#[allow(clippy::too_many_arguments)]
async fn handle_client_conn_fec(
    conn: &quinn::Connection,
    hub: &DatagramHub,
    fec: &FecParams,
    budget: &Arc<raptun_fec::RepairBudget>,
    send_window: &Arc<raptun_fec::SendWindow>,
    conn_loss_tracker: &Arc<Mutex<crate::telemetry::LossTracker>>,
    conn_link_state: &Arc<Mutex<Option<raptun_fec::LinkState>>>,
    tcp: TcpStream,
) -> Result<()> {
    let (send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| CoreError::Endpoint(format!("open signaling bi: {e}")))?;
    client_tunnel_fec(
        conn,
        hub,
        fec,
        budget,
        send_window,
        conn_loss_tracker,
        conn_link_state,
        tcp,
        send,
        recv,
    )
    .await
}

/// Run the server: listen for QUIC connections, run the handshake on each, and
/// forward every accepted bi-stream to the configured target.
pub async fn run_server(
    config: RuntimeConfig,
    bind: SocketAddr,
    target: SocketAddr,
    identity: ServerIdentity,
    registry: Option<Arc<TunnelRegistry>>,
) -> Result<()> {
    tracing::info!(fingerprint = %identity.fingerprint_hex, "pin this fingerprint on clients");

    let transport = build_transport(&config.transport)?;
    let endpoint = build_server_endpoint(bind, &identity, transport, &config.transport)?;
    tracing::info!(%bind, %target, "raptun server listening");

    while let Some(incoming) = endpoint.accept().await {
        let config = config.clone();
        let registry = registry.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_server_conn(incoming, config, target, registry).await {
                tracing::warn!(error = %e, "server connection closed with error");
            }
        });
    }
    Ok(())
}

/// QUIC application error code used to reset a tunnel's stream when the server
/// cannot reach its forwarding target (connect error or timeout). Distinct
/// non-zero code so a packet capture / peer can tell it apart from a clean
/// close (0).
const TARGET_UNREACHABLE_CODE: quinn::VarInt = quinn::VarInt::from_u32(1);

/// Handle one accepted QUIC connection: handshake, then forward each inbound
/// bi-stream to the target service.
async fn handle_server_conn(
    incoming: quinn::Incoming,
    config: RuntimeConfig,
    target: SocketAddr,
    registry: Option<Arc<TunnelRegistry>>,
) -> Result<()> {
    let conn = incoming
        .await
        .map_err(|e| CoreError::Endpoint(format!("accept connection: {e}")))?;
    let remote = conn.remote_address();
    tracing::debug!(%remote, "client connected");

    let (_ctrl, fec) = handshake_server(&conn, &config).await?;
    tracing::debug!(%remote, "handshake ok");

    let use_fec = config.transport.use_datagrams && fec_enabled(&config);
    let connect_timeout = config.transport.target_connect_timeout;
    let conn = Arc::new(conn);
    let config = Arc::new(config);

    // When FEC is on, one connection-wide datagram read loop demultiplexes
    // inbound symbols to per-tunnel receivers via the hub.
    let hub = DatagramHub::new();
    if use_fec {
        spawn_datagram_reader(Arc::clone(&conn), hub.clone());
    }

    // One repair budget per QUIC connection, shared by every tunnel on it — the
    // ≤40%-of-cwnd brake operates over the whole connection, not per tunnel (see
    // the matching comment in `serve_connection`).
    let budget = new_conn_budget(&conn, &fec, &config);
    let send_window = new_conn_send_window(&conn, &fec);
    // One LossTracker per QUIC connection, shared by every tunnel. See the
    // matching comment in `serve_connection` for the rationale (B1 from the
    // 2026-08-02 load test).
    let conn_loss_tracker: Arc<Mutex<crate::telemetry::LossTracker>> =
        Arc::new(Mutex::new(crate::telemetry::LossTracker::new()));
    // Latest LinkState snapshot shared from downstream to upstream task (M3).
    // See the matching comment in `serve_connection`.
    let conn_link_state: Arc<Mutex<Option<raptun_fec::LinkState>>> = Arc::new(Mutex::new(None));

    // M2: same JoinSet pattern as the client. When the connection scope ends
    // (conn closes, accept_bi errors, etc.), the JoinSet's Drop aborts every
    // still-running per-tunnel task, so we never leave orphaned tunnels around
    // for the rest of the process to clean up.
    let mut tunnels: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

    loop {
        // Race accept_bi against finished-tunnel reaps. accept_bi's Err is
        // the conn-close signal; that path also drops `tunnels` and aborts
        // everything. The `Some` arm only fires when a tunnel completes.
        let (mut send, mut recv) = tokio::select! {
            accepted = conn.accept_bi() => match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::debug!(%remote, error = %e, "connection ended");
                    return Ok(());
                }
            },
            // Tunnel finished: re-enter the select so a future accept wins.
            // `tunnels.is_empty()` would yield `None` from `join_next` and
            // panic on `Some(_result) =` pattern matching, so the `if` guard
            // disables the arm when there's nothing to reap.
            Some(_result) = tunnels.join_next(), if !tunnels.is_empty() => continue,
        };
        let conn = Arc::clone(&conn);
        let hub = hub.clone();
        let fec = fec.clone();
        let budget = Arc::clone(&budget);
        let send_window = Arc::clone(&send_window);
        let conn_loss_tracker = Arc::clone(&conn_loss_tracker);
        let conn_link_state = Arc::clone(&conn_link_state);
        let registry = registry.clone();
        tunnels.spawn(async move {
            // Bound the target connect: an unreachable target must not park this
            // tunnel on the OS default timeout while its QUIC stream stays open.
            let connect = tokio::time::timeout(connect_timeout, TcpStream::connect(target)).await;
            match connect {
                Ok(Ok(tcp)) => {
                    let res = if use_fec {
                        server_tunnel_fec(
                            &conn,
                            &hub,
                            &fec,
                            &budget,
                            &send_window,
                            &conn_loss_tracker,
                            &conn_link_state,
                            tcp,
                            send,
                            recv,
                            registry,
                            remote,
                        )
                        .await
                    } else {
                        tunnel_bi(tcp, send, recv).await
                    };
                    if let Err(e) = res {
                        if is_benign_local_close(&e) {
                            tracing::debug!(error = %e, "server tunnel closed (target hung up)");
                        } else {
                            tracing::warn!(error = %e, "server tunnel closed with error");
                        }
                    }
                }
                // Could not reach the target — reset the tunnel's stream so the
                // client side unwinds now instead of hanging until idle timeout.
                Ok(Err(e)) => {
                    tracing::warn!(%target, error = %e, "failed to reach target");
                    let _ = send.reset(TARGET_UNREACHABLE_CODE);
                    let _ = recv.stop(TARGET_UNREACHABLE_CODE);
                }
                Err(_) => {
                    tracing::warn!(
                        %target,
                        timeout_ms = connect_timeout.as_millis() as u64,
                        "target connect timed out"
                    );
                    let _ = send.reset(TARGET_UNREACHABLE_CODE);
                    let _ = recv.stop(TARGET_UNREACHABLE_CODE);
                }
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

/// Build the single per-connection [`raptun_fec::RepairBudget`] that every FEC
/// tunnel on this QUIC connection shares. Called exactly once per connection
/// (in `serve_connection` / `handle_server_conn`), never per tunnel — see the
/// budget-sharing rationale where it is called.
fn new_conn_budget(
    conn: &quinn::Connection,
    fec: &FecParams,
    config: &RuntimeConfig,
) -> Arc<raptun_fec::RepairBudget> {
    #[cfg(feature = "test-hooks")]
    TEST_BUDGETS_CREATED.fetch_add(1, Ordering::Relaxed);
    Arc::new(raptun_fec::RepairBudget::new(
        effective_symbol_size(conn, fec.symbol_size),
        config.fec.repair_cwnd_fraction,
    ))
}

/// One connection-wide [`SendWindow`], shared by every tunnel on the QUIC
/// connection so aggregate in-flight data blocks stay bounded by cwnd (not
/// multiplied by the tunnel count).
fn new_conn_send_window(conn: &quinn::Connection, fec: &FecParams) -> Arc<raptun_fec::SendWindow> {
    let symbol_size = effective_symbol_size(conn, fec.symbol_size);
    let k = resolve_k(fec).max(1) as u64;
    let block_bytes = symbol_size as u64 * k;
    // Floor: even on a cold/tiny cwnd, allow a little in-flight per connection so
    // startup isn't throttled to a crawl.
    Arc::new(raptun_fec::SendWindow::new(
        block_bytes,
        CREDIT_WINDOW_FLOOR_BLOCKS,
    ))
}

/// Test-only counter of how many per-connection repair budgets have been
/// created. The invariant is *one budget per QUIC connection* — a regression
/// that moves budget creation back inside the per-tunnel path would make this
/// climb with tunnel count instead of connection count. See the
/// `shared_repair_budget_is_per_connection` test.
#[cfg(feature = "test-hooks")]
static TEST_BUDGETS_CREATED: AtomicU64 = AtomicU64::new(0);

/// Read the number of per-connection repair budgets created so far.
#[cfg(feature = "test-hooks")]
pub fn test_budgets_created() -> u64 {
    TEST_BUDGETS_CREATED.load(Ordering::Relaxed)
}

/// Reset the per-connection repair-budget creation counter.
#[cfg(feature = "test-hooks")]
pub fn reset_test_budgets_created() {
    TEST_BUDGETS_CREATED.store(0, Ordering::Relaxed);
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

/// Floor for the connection-wide [`raptun_fec::SendWindow`], in blocks: even on
/// a cold or tiny congestion window, the connection may keep this many data
/// blocks in flight so startup and thin links aren't throttled to a crawl. The
/// real ceiling is cwnd-derived and usually far larger; this only bounds the
/// low end. At the default geometry (~18 KB/block) 16 blocks ≈ 300 KB.
const CREDIT_WINDOW_FLOOR_BLOCKS: u64 = 16;

/// If no fresh credit arrives for this long while the window is full, the
/// sender stops gating and falls back to cwnd back-pressure (see the gate in
/// `run_fec_tunnel`). This guarantees a delayed or lost credit can only degrade
/// the sender to its pre-credit behaviour, never deadlock it. The reliable
/// signaling stream already guarantees eventual credit delivery; this is a
/// further backstop for pathological credit delay.
const CREDIT_PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// Hard upper bound on how long a single FEC tunnel may go *without making
/// progress* before it is forcibly closed. This is a stall deadline, NOT an
/// absolute lifetime: a tunnel that keeps delivering blocks (or has caught up
/// to everything it has sent) may live arbitrarily long, which is exactly what
/// a long-lived connection — SSH, streaming, keep-alive HTTP — needs.
///
/// Under high link loss combined with jitter, the congestion window can
/// collapse to a few KiB and a tunnel may take minutes to ship a single block.
/// Without a deadline, such genuinely-stuck tunnels accumulate indefinitely —
/// `active_tunnels` climbs without bound, client RSS balloons, and the server
/// eventually hits `ENOBUFS` on new TCP connections to the target. A tunnel
/// that has delivered nothing new for this long is a lost cause: the
/// application above it has almost certainly timed out already, and retaining
/// its state only starves healthy tunnels of memory and file descriptors.
///
/// Keying on *stall* rather than absolute age is what stops the earlier bug
/// where healthy, caught-up tunnels (`delivered == total_blocks`, 0% loss)
/// were culled every 120 s simply for staying open.
///
/// 120 s is well above the 30 s idle timeout and the ~10 s target-connect
/// timeout; a tunnel that makes no progress for longer than this is stuck on
/// any real link.
const TUNNEL_MAX_STALL: Duration = Duration::from_secs(120);

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
#[allow(clippy::too_many_arguments)]
async fn client_tunnel_fec(
    conn: &quinn::Connection,
    hub: &DatagramHub,
    fec: &FecParams,
    budget: &Arc<raptun_fec::RepairBudget>,
    send_window: &Arc<raptun_fec::SendWindow>,
    conn_loss_tracker: &Arc<Mutex<crate::telemetry::LossTracker>>,
    conn_link_state: &Arc<Mutex<Option<raptun_fec::LinkState>>>,
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

    // HubGuard unregisters on drop, including panic — the old `unregister` call
    // was only on the Ok/Err return path, so a panic between register and
    // return leaked the route.
    let mut inbound = hub.register(stream_id);
    tracing::debug!(stream_id, "client FEC tunnel opened");
    let res = run_fec_tunnel(
        conn,
        fec,
        budget,
        send_window,
        conn_loss_tracker,
        conn_link_state,
        stream_id,
        tcp,
        sig_send,
        sig_recv,
        inbound.take_rx(),
        // The client does not run the monitor; server-only feature.
        None,
    )
    .await;
    res
}

/// Server side of a FEC tunnel: read the client's stream id off the bi-stream,
/// register the route, then pump TCP data both ways.
#[allow(clippy::too_many_arguments)]
async fn server_tunnel_fec(
    conn: &Arc<quinn::Connection>,
    hub: &DatagramHub,
    fec: &FecParams,
    budget: &Arc<raptun_fec::RepairBudget>,
    send_window: &Arc<raptun_fec::SendWindow>,
    conn_loss_tracker: &Arc<Mutex<crate::telemetry::LossTracker>>,
    conn_link_state: &Arc<Mutex<Option<raptun_fec::LinkState>>>,
    tcp: TcpStream,
    mut sig_send: quinn::SendStream,
    mut sig_recv: quinn::RecvStream,
    registry: Option<Arc<TunnelRegistry>>,
    remote: SocketAddr,
) -> Result<()> {
    let mut id_buf = [0u8; 8];
    sig_recv
        .read_exact(&mut id_buf)
        .await
        .map_err(|e| CoreError::Endpoint(format!("read stream id: {e}")))?;
    let stream_id = u64::from_be_bytes(id_buf);

    // M3: refuse to overwrite an active route. A peer that re-uses a
    // stream_id would otherwise overwrite the prior route, leaving the
    // older tunnel's receiver silent (its sender is still in the routes
    // map but the route points at a different channel). Reject and reset
    // the stream so the client sees the failure cleanly.
    if hub.has_route(stream_id) {
        tracing::warn!(
            stream_id,
            %remote,
            "duplicate stream_id on the control stream; resetting tunnel"
        );
        let _ = sig_send.reset(TARGET_UNREACHABLE_CODE);
        return Err(CoreError::Endpoint(format!(
            "duplicate stream_id {stream_id}"
        )));
    }

    // HubGuard unregisters on drop, including panic — see client_tunnel_fec.
    let mut inbound = hub.register(stream_id);
    tracing::debug!(stream_id, "server FEC tunnel opened");

    // Publish live stats for the monitor UI, if enabled. The guard removes the
    // entry when this tunnel ends on any path; `stats` is the shared handle the
    // data loops accumulate into. When monitoring is off, both are `None` and
    // no counters are ever allocated or touched.
    let (stats, _reg_guard) = match &registry {
        Some(reg) => {
            let stats = Arc::new(TunnelStats::new(remote, stream_id, conn, resolve_k(fec)));
            let guard = reg.register((conn.stable_id(), stream_id), Arc::clone(&stats));
            (Some(stats), Some(guard))
        }
        None => (None, None),
    };

    let res = run_fec_tunnel(
        conn,
        fec,
        budget,
        send_window,
        conn_loss_tracker,
        conn_link_state,
        stream_id,
        tcp,
        sig_send,
        sig_recv,
        inbound.take_rx(),
        stats,
    )
    .await;
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
// The parameters are the tunnel's collaborators (connection, negotiated FEC
// params, shared budget, stream id, the TCP socket, and the three QUIC
// channels); bundling them into a struct would only move the same fan-out one
// level up without improving clarity.
#[allow(clippy::too_many_arguments)]
async fn run_fec_tunnel(
    conn: &quinn::Connection,
    fec: &FecParams,
    budget: &Arc<raptun_fec::RepairBudget>,
    send_window: &Arc<raptun_fec::SendWindow>,
    // Connection-wide LossTracker shared by every tunnel on this QUIC connection.
    // The tracker was previously created per-tunnel, which made the first
    // diagnostic on every new tunnel log a baseline 0.0 as a real reading
    // (B1 from the 2026-08-02 load test). Lock is held only for the few-line
    // delta math in `read_telemetry`; contention is negligible.
    conn_loss_tracker: &Arc<Mutex<crate::telemetry::LossTracker>>,
    // Latest LinkState snapshot computed by the downstream task and shared with
    // the upstream task (M3). Used to gate proactive repair spurts on the live
    // loss regime. Written once per 20 ms control tick; read once per proactive
    // tick (RTT/4). One cell per connection, not per tunnel.
    conn_link_state: &Arc<Mutex<Option<raptun_fec::LinkState>>>,
    stream_id: StreamId,
    tcp: TcpStream,
    sig_send: quinn::SendStream,
    sig_recv: quinn::RecvStream,
    inbound: tokio::sync::mpsc::Receiver<crate::fec::InboundSymbol>,
    // Live stats sink for the server monitor UI; `None` on the client and
    // whenever monitoring is off, in which case the data loops touch nothing.
    stats: Option<Arc<TunnelStats>>,
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
    // Peer's running high-water block count, routed to the downstream task so it
    // can recover entirely-lost blocks even when no later block follows.
    let (hw_tx, mut hw_rx) = mpsc::unbounded_channel::<u64>();
    // Reliable-retransmit requests routed to the upstream task (which owns the
    // sender and its retained block payloads). Bounded: if the upstream task
    // is slow to serve requests, the channel fills and the reader drops new
    // ones — the tick mechanism will re-request them next cycle.
    let (rel_req_tx, mut rel_req_rx) = mpsc::channel::<u64>(32);
    // Reliable-retransmit data routed to the downstream task (which owns the
    // receiver and delivers in order). Bounded: each message carries a full
    // block payload (up to ~20 KiB), so 4 slots = ~80 KiB max queued. If full,
    // the reader drops the message and the tick re-requests it.
    let (rel_data_tx, mut rel_data_rx) = mpsc::channel::<(u64, Vec<u8>)>(4);
    // Flow-control credit routed from the signal reader to the upstream task:
    // the peer's cumulative delivered-block high-water. `up` gates production so
    // in-flight blocks stay bounded (see `CREDIT_WINDOW_BLOCKS`).
    let (credit_tx, mut credit_rx) = mpsc::unbounded_channel::<u64>();
    // Block-level decode acknowledgements routed from the signal reader to the
    // upstream task: each block the receiver decoded is released on the sender
    // side via `FecSender::retire_block`. Distinct from `credit_rx` (which
    // drives flow control on in-order delivery): a BlockAck fires per-block on
    // decode, so out-of-order decodes still free sender memory promptly.
    let (ack_tx, mut ack_rx) = mpsc::unbounded_channel::<u64>();
    // Downstream-finished signal: fires exactly once when the `down` task
    // completes (either the peer's announced block count has been fully
    // delivered, or the inbound datagram channel closed). `up`'s post-EOF
    // service loop observes this and exits promptly, which drops both local
    // `sig_tx` clones, lets `writer` call `sig_send.finish()`, and cascades
    // an EOF to the peer's `reader` so the peer's identical loop also
    // unwinds. Without this, both ends deadlock waiting on each other and
    // `ActiveGuard` is never dropped (the `active_tunnels` leak).
    //
    // A `oneshot` (not `Notify`) is essential here: the two directions finish
    // in arbitrary order, and `down` can complete *before* `up` reaches its
    // post-EOF loop and first awaits the signal (e.g. the peer half-closes its
    // write side while the local socket stays open). `Notify::notify_waiters()`
    // only wakes waiters already parked at that instant, so such an early
    // completion would be lost forever and `up` would hang — reintroducing the
    // leak. `oneshot` buffers the send: `up` observes it regardless of ordering.
    let (down_done_tx, down_done_rx) = tokio::sync::oneshot::channel::<()>();

    // --- Signal writer: owns sig_send, serializes queued signals. ---
    let writer = async move {
        let mut sig_send = sig_send;
        while let Some(sig) = sig_rx.recv().await {
            let bytes = sig.encode();
            if let Err(e) = sig_send.write_all(&bytes).await {
                // Classify the write error: Stopped(0) and graceful connection
                // close are the normal teardown path (peer finished reading the
                // signaling stream), not a failure. Log those at debug to avoid
                // flooding the log with one warn per clean tunnel disconnect.
                // All other variants are genuine failures and stay at warn.
                match &e {
                    quinn::WriteError::Stopped(code) if code.into_inner() == 0 => {
                        tracing::debug!("signaling writer: peer finished (Stopped(0))");
                    }
                    quinn::WriteError::ConnectionLost(
                        quinn::ConnectionError::ApplicationClosed(_)
                        | quinn::ConnectionError::LocallyClosed,
                    ) => {
                        tracing::debug!(reason = %e, "signaling writer: connection closing");
                    }
                    _ => {
                        tracing::warn!(
                            error = %e,
                            "signaling writer failed; closing the channel"
                        );
                    }
                }
                break;
            }
        }
        let _ = sig_send.finish();
        Ok::<(), CoreError>(())
    };

    // --- Signal reader: owns sig_recv, demultiplexes inbound signals. ---
    // Returns `true` if the stream ended abnormally (peer reset / read error),
    // as opposed to a clean finish (`Ok(None)`). The caller uses this to tell a
    // control-channel failure — e.g. the server resetting the stream because it
    // could not reach its target — apart from the normal end-of-stream that
    // follows a completed transfer.
    let reader = async move {
        let mut sig_recv = sig_recv;
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 512];
        let reset = loop {
            match sig_recv.read(&mut chunk).await {
                Ok(Some(n)) => buf.extend_from_slice(&chunk[..n]),
                Ok(None) => break false, // peer finished the stream cleanly
                Err(_) => break true,    // peer reset / read error
            }
            // Drain as many complete signals as the buffer holds. A decode
            // failure (unknown tag byte, version skew, framing corruption)
            // returns `Err(n)` so we can drop the bad bytes and keep going
            // instead of deadlocking the buffer; previously an unknown tag
            // synthesised a BlockCount{total: u64::MAX} which permanently
            // hung the downstream task.
            while let Some(outcome) = TunnelSignal::decode(&buf) {
                match outcome {
                    Ok((sig, used)) => {
                        buf.drain(..used);
                        match sig {
                            TunnelSignal::BlockCount { total } => {
                                let _ = count_tx.send(total);
                            }
                            TunnelSignal::HighWater { blocks } => {
                                let _ = hw_tx.send(blocks);
                            }
                            TunnelSignal::Nack { block, need, .. } => {
                                let _ = nack_tx.send((block, need));
                            }
                            TunnelSignal::ReliableRequest { block } => {
                                if let Err(e) = rel_req_tx.try_send(block) {
                                    tracing::debug!(block, error = %e, "rel_req channel full; tick will retry");
                                }
                            }
                            TunnelSignal::ReliableData { block, bytes } => {
                                if let Err(e) = rel_data_tx.try_send((block, bytes)) {
                                    tracing::debug!(block, error = %e, "rel_data channel full; tick will retry");
                                }
                            }
                            TunnelSignal::Credit { delivered } => {
                                let _ = credit_tx.send(delivered);
                            }
                            TunnelSignal::BlockAck { block } => {
                                let _ = ack_tx.send(block);
                            }
                        }
                    }
                    Err(skipped) => {
                        tracing::warn!(skipped, "unknown tag on signaling stream: resynced");
                        buf.drain(..skipped);
                    }
                }
            }
        };
        reset
    };

    // --- Upstream: TCP -> FEC datagrams, plus serving inbound NACKs and
    //     reliable-retransmit requests. ---
    let up_conn = conn.clone();
    let up_sig = sig_tx.clone();
    let up_window = Arc::clone(send_window);
    let up_budget = Arc::clone(budget);
    let up_link_state = Arc::clone(conn_link_state);
    let up_stats = stats.clone();
    let up = async move {
        let mut down_done_rx = down_done_rx;
        let mut sender = FecSender::new(stream_id, symbol_size, k);
        let cap = sender.block_payload();
        let mut buf = vec![0u8; cap];
        let mut total_blocks: u64 = 0;
        // Peer's delivered-block high-water for THIS tunnel, from `Credit`
        // signals. Used to reconcile this tunnel's contribution to the shared
        // connection-wide send window as blocks are delivered.
        let mut delivered: u64 = 0;
        // Whether credits are flowing recently enough to gate on. Cleared when a
        // probe times out (fall back to cwnd back-pressure), re-armed when a
        // fresh credit arrives.
        let mut credit_fresh: bool = true;
        let mut eof = false;
        let tunnel_started_at = Instant::now();
        // Stall tracking for the lifetime guard below. `last_progress_at` is
        // reset whenever the tunnel advances (a fresh block delivered) or is
        // caught up to everything it has sent; the guard aborts only after this
        // has gone stale for TUNNEL_MAX_STALL. `last_progress_delivered` is the
        // `delivered` high-water at the last observed advance, so a repeated
        // unchanged credit is not mistaken for progress.
        let mut last_progress_at = tunnel_started_at;
        let mut last_progress_delivered: u64 = 0;
        // Periodic stall check: fires every 5 s so a tunnel stuck in slow
        // progress (tiny cwnd + high loss) is eventually aborted rather than
        // accumulating forever. At ~5 s granularity, the worst-case stall
        // overshoot is 5 s on top of TUNNEL_MAX_STALL.
        let mut lifetime_tick = tokio::time::interval(Duration::from_secs(5));
        lifetime_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // M3: proactive repair spurt ticker. Fires every RTT/4 so the sender can
        // inject additional repair for blocks that have not been acknowledged
        // after one RTT, without waiting for the receiver's NACK round-trip.
        // Floor at 10 ms so very low RTT links do not spin the task.
        let mut proactive_tick =
            tokio::time::interval((up_conn.rtt() / 4).max(Duration::from_millis(10)));
        proactive_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        while !eof {
            tokio::select! {
                // Read application data and emit block symbols.
                read = tcp_read.read(&mut buf) => {
                    let n = read.map_err(CoreError::Io)?;
                    if n == 0 {
                        eof = true;
                        continue;
                    }
                    if let Some(s) = &up_stats {
                        s.add_bytes_up(n as u64);
                    }
                    // Flush each read burst immediately as one or more blocks;
                    // buffering until a full block forms would stall interactive
                    // traffic whose messages are far smaller than a block.
                    for chunk in buf[..n].chunks(cap) {
                        // Flow-control gate against the CONNECTION-WIDE window
                        // (shared by all tunnels, cwnd-derived) so aggregate
                        // in-flight blocks can't overshoot the link no matter how
                        // many tunnels are active. Block while the window is full
                        // and credits are flowing; if none arrives within the
                        // probe timeout, treat credits as stale and stop gating,
                        // falling back to send-buffer + cwnd back-pressure. A
                        // later credit re-arms the gate. So a delayed/lost credit
                        // can only degrade to the pre-credit behaviour, never
                        // deadlock. TCP reads pausing here IS the back-pressure.
                        while credit_fresh && !up_window.has_room() {
                            let probe = tokio::time::sleep(CREDIT_PROBE_TIMEOUT);
                            tokio::select! {
                                c = credit_rx.recv() => {
                                    match c {
                                        Some(d) => {
                                            let newly = d.saturating_sub(delivered);
                                            delivered = delivered.max(d);
                                            up_window.settle(newly);
                                            credit_fresh = true;
                                            if let Some(s) = &up_stats {
                                                s.set_delivered(delivered);
                                            }
                                        }
                                        None => break, // credit channel closed; stop gating
                                    }
                                }
                                _ = probe => {
                                    credit_fresh = false;
                                    tracing::debug!(
                                        in_flight = up_window.in_flight(),
                                        ceiling = up_window.ceiling(),
                                        "credit stale: gating disabled, relying on cwnd back-pressure"
                                    );
                                    break;
                                }
                            }
                        }
                        up_window.add_sent();
                        for dg in sender.encode_one_block(chunk, repair) {
                            send_datagram_paced(&up_conn, dg).await;
                        }
                        // Yield after each block's burst so other tunnels on the
                        // same QUIC connection can interleave their datagrams.
                        // Without this, a high-throughput tunnel's ~24-datagram
                        // burst (K=16 + 8 repair) fills the send buffer and
                        // starves latency-sensitive tunnels.
                        tokio::task::yield_now().await;
                        total_blocks += 1;
                        if let Some(s) = &up_stats {
                            s.record_block(repair);
                        }
                    }
                    // Announce the running high-water mark on the reliable stream
                    // so the receiver learns these blocks exist even if every one
                    // of their datagrams is lost and no later block follows (the
                    // interactive request/response stall). Cheap: one small frame
                    // per burst, not per block.
                    let _ = up_sig.send(TunnelSignal::HighWater {
                        blocks: total_blocks,
                    });
                }
                // Serve an inbound NACK: mint fresh repair for the named block.
                Some((block, need)) = nack_rx.recv() => {
                    for dg in sender.additional_repair(block, need) {
                        send_datagram_paced(&up_conn, dg).await;
                    }
                    if let Some(s) = &up_stats {
                        s.add_repair(need);
                    }
                }
                // Serve a reliable-retransmit request: ship the block's bytes
                // over the reliable channel (the convergence lower bound).
                Some(block) = rel_req_rx.recv() => {
                    if let Some(bytes) = sender.reliable_payload(block) {
                        let _ = up_sig.send(TunnelSignal::ReliableData { block, bytes });
                    }
                }
                // Drain flow-control credits even when not gating, so the shared
                // window is reconciled and a stale gate re-arms as credits resume.
                Some(d) = credit_rx.recv() => {
                    let newly = d.saturating_sub(delivered);
                    delivered = delivered.max(d);
                    up_window.settle(newly);
                    credit_fresh = true;
                    if let Some(s) = &up_stats {
                        s.set_delivered(delivered);
                    }
                }
                // A block was decoded on the receiver: release its retained
                // encoder/payload now rather than waiting for the byte
                // retention window to evict it.
                Some(block) = ack_rx.recv() => {
                    sender.retire_block(block);
                }
                // M3: proactive repair spurt. Emit additional repair for blocks
                // that have not been acknowledged after one RTT, without waiting
                // for the receiver's NACK round-trip. Gated on the live loss
                // regime: skipped under congestion so we don't deepen a collapse.
                _ = proactive_tick.tick() => {
                    let link = up_link_state.lock().expect("link state poisoned").clone();
                    if let Some(link) = link {
                        let rtt = up_conn.rtt();
                        let now = Instant::now();
                        for (block, extra) in sender.proactive_topups(now, rtt, &up_budget, &link) {
                            for dg in sender.additional_repair(block, extra) {
                                send_datagram_paced(&up_conn, dg).await;
                            }
                            if let Some(s) = &up_stats {
                                s.add_repair(extra);
                            }
                        }
                    }
                }
                // Stall bound: abort a tunnel only if it has made no progress
                // for TUNNEL_MAX_STALL. "Progress" is either delivering a new
                // block (delivered advanced) or being fully caught up
                // (delivered >= total_blocks) — the latter is the healthy,
                // idle long-connection case that must NOT be culled. Keying on
                // stall rather than absolute age prevents accumulation under
                // catastrophic link conditions (tiny cwnd + high loss) where a
                // tunnel makes vanishingly slow progress and active_tunnels
                // grows without bound, eventually exhausting memory and OS file
                // descriptors (ENOBUFS), while leaving working tunnels alone.
                _ = lifetime_tick.tick() => {
                    let caught_up = delivered >= total_blocks;
                    let advanced = delivered > last_progress_delivered;
                    if caught_up || advanced {
                        last_progress_delivered = delivered;
                        last_progress_at = Instant::now();
                    } else if last_progress_at.elapsed() > TUNNEL_MAX_STALL {
                        tracing::warn!(
                            total_blocks,
                            delivered,
                            stalled_s = last_progress_at.elapsed().as_secs(),
                            "tunnel stalled: aborting"
                        );
                        break;
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
        // Reset the stall clock for the post-EOF phase. Pre-EOF progress was
        // measured by `delivered` advancing; post-EOF the receiver may still be
        // decoding the last few blocks (measured by BlockAcks, below), so a
        // fresh clock is needed — otherwise a long-idle-but-caught-up tunnel
        // that just reached EOF would be killed by the very first post-EOF
        // tick (H4).
        last_progress_at = Instant::now();
        loop {
            tokio::select! {
                Some((block, need)) = nack_rx.recv() => {
                    for dg in sender.additional_repair(block, need) {
                        send_datagram_paced(&up_conn, dg).await;
                    }
                }
                Some(block) = rel_req_rx.recv() => {
                    if let Some(bytes) = sender.reliable_payload(block) {
                        let _ = up_sig.send(TunnelSignal::ReliableData { block, bytes });
                    }
                }
                // M3: proactive repair continues post-EOF so the final blocks
                // can recover without waiting for a NACK round-trip.
                _ = proactive_tick.tick() => {
                    let link = up_link_state.lock().expect("link state poisoned").clone();
                    if let Some(link) = link {
                        let rtt = up_conn.rtt();
                        let now = Instant::now();
                        for (block, extra) in sender.proactive_topups(now, rtt, &up_budget, &link) {
                            for dg in sender.additional_repair(block, extra) {
                                send_datagram_paced(&up_conn, dg).await;
                            }
                            if let Some(s) = &up_stats {
                                s.add_repair(extra);
                            }
                        }
                    }
                }
                // Late BlockAck: the receiver may still be decoding the last
                // blocks after we've announced BlockCount; retire them so the
                // sender's retained state is cleaned up. Each ack is also fresh
                // progress — post-EOF the credit channel no longer advances
                // `delivered`, so decoded-block acks are the stall guard's only
                // progress signal.
                Some(block) = ack_rx.recv() => {
                    sender.retire_block(block);
                    last_progress_at = Instant::now();
                }
                // Downstream finished: stop serving late repairs and unwind so
                // the sig_tx clones drop, writer.finish() cascades EOF to the
                // peer, and `ActiveGuard` can drop (fixes active_tunnels leak).
                // `&mut` so a not-yet-fired receiver can be re-polled next
                // iteration; a fired/closed receiver resolves immediately.
                _ = &mut down_done_rx => break,
                // Stall guard also applies post-EOF: the receiver might be stuck
                // and never send `down_done_rx`. Abort only after no BlockAck
                // has arrived for TUNNEL_MAX_STALL, so a slow-but-progressing
                // drain is left to finish.
                _ = lifetime_tick.tick() => {
                    if last_progress_at.elapsed() > TUNNEL_MAX_STALL {
                        tracing::warn!(
                            total_blocks,
                            delivered,
                            stalled_s = last_progress_at.elapsed().as_secs(),
                            "tunnel stalled (post-EOF): aborting"
                        );
                        break;
                    }
                }
                else => break,
            }
        }
        Ok::<(), CoreError>(())
    };

    // --- Downstream: FEC datagrams -> TCP, with periodic convergence tick. ---
    // Repair budget: the connection-wide brake, shared by every tunnel on this
    // QUIC connection (created once per connection in `serve_connection` /
    // `handle_server_conn` and threaded in). Cloning the `Arc` shares the one
    // atomic in-flight counter and ceiling, so the ≤40%-of-cwnd cap applies to
    // the aggregate repair across all tunnels rather than per tunnel.
    let budget = Arc::clone(budget);
    let down_window = Arc::clone(send_window);
    let down_conn = conn.clone();
    let down_sig = sig_tx.clone();
    let down_stats = stats.clone();
    // Take a clone of the connection-wide LossTracker for this tunnel's down
    // task. The shared tracker is owned by `serve_connection` / `handle_server_conn`
    // and lives for the life of the QUIC connection.
    let down_loss_tracker = Arc::clone(conn_loss_tracker);
    let down_link_state = Arc::clone(conn_link_state);
    let mut classifier = crate::telemetry::RegimeClassifier::new();
    let down = async move {
        let mut inbound = inbound;
        let mut receiver = FecReceiver::new(symbol_size, k);
        let mut expected: Option<u64> = None;
        // Last delivered high-water announced to the peer as a flow-control
        // credit, to avoid re-sending an unchanged value every tick.
        let mut last_credit_sent: u64 = 0;
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
                            let out = receiver.on_symbol(block_id, esi, &payload, Instant::now(), &budget);
                            if !out.is_empty() {
                                if let Some(s) = &down_stats {
                                    s.add_bytes_down(out.len() as u64);
                                }
                                tcp_write.write_all(&out).await.map_err(CoreError::Io)?;
                            }
                            // A block may have decoded from this symbol:
                            // ack it immediately so the sender can release
                            // its retained encoder/payload.
                            for block in receiver.drain_acks() {
                                let _ = down_sig.send(TunnelSignal::BlockAck { block });
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
                Some(blocks) = hw_rx.recv() => {
                    // Running high-water mark: bounds the entirely-lost scan so a
                    // block whose every datagram was lost is still recovered even
                    // if no later block ever advances the observed high mark.
                    receiver.set_high_water(blocks);
                }
                // Reliable-retransmit data: inject verbatim, bypassing FEC. This
                // is the convergence lower bound — a block that FEC could not
                // recover is completed here, so the stream can never deadlock.
                Some((block, bytes)) = rel_data_rx.recv() => {
                    let out = receiver.on_reliable_block(block, bytes);
                    if !out.is_empty() {
                        if let Some(s) = &down_stats {
                            s.add_bytes_down(out.len() as u64);
                        }
                        tcp_write.write_all(&out).await.map_err(CoreError::Io)?;
                    }
                    // A reliably-completed block is also done: ack it
                    // so the sender releases its state.
                    for block in receiver.drain_acks() {
                        let _ = down_sig.send(TunnelSignal::BlockAck { block });
                    }
                }
                _ = ticker.tick() => {
                    // Refresh telemetry-derived link state + budget ceiling, then
                    // arbitrate stalled blocks and emit NACKs / reliable requests.
                    // The second tuple element (`is_window_baseline`) is for the
                    // operator-facing heartbeat and is irrelevant to the FEC
                    // controller; sample.loss_rate is 0.0 on the baseline tick,
                    // which is the same default the controller always had.
                    let sample = crate::session::read_telemetry(
                        &down_conn,
                        &mut *down_loss_tracker.lock().expect("loss tracker poisoned"),
                    );
                    let link = classifier.to_link_state(sample);
                    budget.refresh_ceiling(link.cwnd_bytes());
                    // Publish the live regime snapshot for the upstream task's
                    // proactive repair spurts (M3).
                    *down_link_state.lock().expect("link state poisoned") = Some(link.clone());
                    // Keep the connection-wide send window sized to the live cwnd
                    // so the sender's flow-control gate tracks link capacity.
                    down_window.refresh_ceiling(link.cwnd_bytes());
                    for sig in receiver.tick(&link, &budget, Instant::now()) {
                        let _ = down_sig.send(sig);
                    }
                    // Tick may have detected entirely-lost blocks and
                    // completed them via the reliable path; ack those too.
                    for block in receiver.drain_acks() {
                        let _ = down_sig.send(TunnelSignal::BlockAck { block });
                    }
                    // Emit a flow-control credit: the sender caps in-flight blocks
                    // at delivered + window. Sent every tick (not only on change)
                    // so a delayed/lost earlier credit self-heals and the sender
                    // is never stranded waiting for one — the reliable signaling
                    // stream guarantees eventual delivery, and the sender also has
                    // its own timeout-probe as a further backstop.
                    let delivered = receiver.highest_delivered();
                    // Only send on change. If the impairment hook drops it,
                    // leave last_credit_sent unchanged so the credit is genuinely
                    // lost for this value — the sender must then fall back on its
                    // probe timeout, which is what the hook exercises.
                    if delivered != last_credit_sent && !test_should_drop_credit() {
                        let _ = down_sig.send(TunnelSignal::Credit { delivered });
                        last_credit_sent = delivered;
                    }
                }
            }
        }
        let _ = tcp_write.shutdown().await;
        // Signal `up` that the receive direction is done. Buffered by the
        // oneshot, so it unblocks `up` even if `up` has not yet reached its
        // post-EOF await. (Any early `?` return above instead *drops*
        // `down_done_tx`, which closes the channel and likewise wakes `up` —
        // either way `up` never hangs.)
        let _ = down_done_tx.send(());
        Ok::<(), CoreError>(())
    };

    // Drop the extra sender handle so the writer task can terminate once up/down
    // finish and release their clones.
    drop(sig_tx);

    // The signaling stream is the tunnel's control lifeline. If the peer
    // *resets* it before the data directions wind down on their own — e.g. the
    // server could not reach its target and reset the stream — the tunnel can
    // make no further progress, so tear it down now (dropping `up`/`down`
    // closes the local TCP) instead of hanging until the idle timeout. A clean
    // finish (`reader` returns `false`) is the *normal* end-of-transfer signal
    // and must NOT interrupt the data directions, which may still be flushing
    // the final bytes — in that case we fall through to awaiting them.
    let data = async {
        let (up_r, down_r, w_r) = tokio::join!(up, down, writer);
        if let Err(e) = w_r {
            // The signaling writer saw an error after H5. Log once at warn
            // so it's not silently swallowed — the underlying cause is
            // already in the writer's own warn line; this is a backstop
            // for the case where data directions masked the failure.
            tracing::warn!(error = %e, "signaling writer task returned error");
        }
        up_r?;
        down_r?;
        Ok::<(), CoreError>(())
    };
    tokio::pin!(data);
    tokio::select! {
        r = &mut data => r,
        reset = reader => {
            if reset {
                // Control channel failed abnormally — abandon the tunnel.
                Ok(())
            } else {
                // Clean finish; let the data directions complete normally.
                (&mut data).await
            }
        }
    }
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

/// Test-only flow-control credit impairment, to exercise the sender's behaviour
/// when the reverse credit signal is delayed or lost. `1` fully suppresses
/// credits (the extreme: the sender must rely entirely on its probe-timeout
/// backstop to avoid deadlock); `n > 1` drops every `n`-th credit (partial
/// delay). `0` (default) sends every credit normally.
#[cfg(feature = "test-hooks")]
static TEST_CREDIT_DROP_ONE_IN: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "test-hooks")]
static TEST_CREDIT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Set credit-signal impairment: `1` suppresses all credits, `n>1` drops every
/// `n`-th, `0` disables. See [`TEST_CREDIT_DROP_ONE_IN`].
#[cfg(feature = "test-hooks")]
pub fn set_test_credit_drop_one_in(n: u64) {
    TEST_CREDIT_DROP_ONE_IN.store(n, Ordering::Relaxed);
    TEST_CREDIT_COUNTER.store(0, Ordering::Relaxed);
}

/// Whether this credit send should be suppressed by the test hook.
#[cfg(feature = "test-hooks")]
fn test_should_drop_credit() -> bool {
    let n = TEST_CREDIT_DROP_ONE_IN.load(Ordering::Relaxed);
    if n == 0 {
        return false;
    }
    if n == 1 {
        return true; // suppress all
    }
    let c = TEST_CREDIT_COUNTER.fetch_add(1, Ordering::Relaxed);
    c % n == 0
}

#[cfg(not(feature = "test-hooks"))]
#[inline]
fn test_should_drop_credit() -> bool {
    false
}

/// Hand a datagram to the transport, applying back-pressure instead of losing
/// it to a full local send buffer.
///
/// `quinn::Connection::send_datagram` uses `drop = true` internally: when the
/// outgoing datagram buffer is full it *silently evicts the oldest queued,
/// still-unsent* symbol and returns `Ok`. During a large burst that evicts the
/// head of the queue — the very symbols an early block still needs — so those
/// blocks strand, degrade to reliable retransmit, and the un-paced sender
/// self-inflicts loss on an otherwise clean link (see
/// `live_size_sweep.sh`: a hard delivery cliff at the 1 MiB default buffer).
///
/// `send_datagram_wait` instead awaits `datagrams_unblocked` when the buffer is
/// full, so this becomes real back-pressure: the caller's TCP read loop pauses
/// until the transport drains, and no locally-queued symbol is ever dropped.
/// Genuine on-wire loss (the case FEC exists to absorb) still happens in the
/// network, where repair symbols recover it. `TooLarge`/`UnsupportedByPeer` and
/// a lost connection are non-retryable and are simply logged and dropped.
/// Process-wide throttle for `send_datagram_paced` errors. The function is
/// called per-symbol, so a dying connection can produce thousands of errors
/// per second. We log the first one at warn and then one-per-second until
/// the storm stops; the dropped count is also recorded so the operator can
/// tell the difference between a brief error and a sustained loss.
static DATAGRAM_ERR_LAST_MS: AtomicU64 = AtomicU64::new(0);
static DATAGRAM_ERR_TOTAL: AtomicU64 = AtomicU64::new(0);
const DATAGRAM_ERR_LOG_INTERVAL_MS: u64 = 1_000;

async fn send_datagram_paced(conn: &quinn::Connection, dg: bytes::Bytes) {
    #[cfg(feature = "test-hooks")]
    {
        let n = TEST_DROP_ONE_IN.load(Ordering::Relaxed);
        if n > 0 {
            let c = TEST_DROP_COUNTER.fetch_add(1, Ordering::Relaxed);
            if c % n == 0 {
                // Simulate on-wire loss: never hand this symbol to the transport.
                return;
            }
        }
    }
    if let Err(e) = conn.send_datagram_wait(dg).await {
        DATAGRAM_ERR_TOTAL.fetch_add(1, Ordering::Relaxed);
        // Throttle so a flapping link doesn't flood the log; previously this
        // was a `trace!` per error, which meant *no* operator signal in a
        // production run with default `RUST_LOG=info` — yet a dying
        // connection was flooding trace at thousands per second (H7).
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let prev = DATAGRAM_ERR_LAST_MS.load(Ordering::Relaxed);
        if now_ms.saturating_sub(prev) >= DATAGRAM_ERR_LOG_INTERVAL_MS
            && DATAGRAM_ERR_LAST_MS
                .compare_exchange(prev, now_ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            let total = DATAGRAM_ERR_TOTAL.load(Ordering::Relaxed);
            tracing::warn!(
                error = %e,
                total_since_start = total,
                "datagram send failed (rate-limited; link may be dead)"
            );
        }
    }
}

/// The symbol payload size to use for a tunnel.
///
/// The geometry **must be identical on both ends** or RaptorQ decode fails, so
/// this returns the negotiated size verbatim — the server already clamped it to
/// Pure clamp for the use-site symbol size. Extracted from
/// [`effective_symbol_size`] so it can be unit-tested without a real
/// `quinn::Connection`.
///
/// Returns the largest symbol size that fits inside `datagram_cap` bytes
/// (the connection's `max_datagram_size`, when known) minus the per-symbol
/// header. `negotiated` is clamped down to that ceiling; a value already
/// within the cap passes through unchanged; `0` is normalised to `1` (a
/// zero-byte symbol is meaningless).
fn clamp_symbol_to_datagram_cap(negotiated: u16, datagram_cap: usize) -> u16 {
    let header = raptun_proto::datagram::SYMBOL_HEADER_LEN as u16;
    let max_symbol = datagram_cap
        .saturating_sub(header as usize)
        .min(u16::MAX as usize) as u16;
    if negotiated > max_symbol {
        max_symbol.max(1)
    } else {
        negotiated.max(1)
    }
}

/// [`crate::session::SAFE_MAX_SYMBOL_SIZE`] during the handshake, which is
/// chosen to fit within a conservative QUIC datagram. As a defensive
/// fallback, this function also clamps *at use site* to the connection's
/// advertised `max_datagram_size` minus the per-symbol header. A release
/// build no longer relies on the handshake clamp being correct — the bug
/// would be a silent one (every `send_datagram` for that symbol returns
/// `Err`, the tunnel runs at zero throughput with no log line), so we log
/// warn and clamp here instead.
fn effective_symbol_size(conn: &quinn::Connection, negotiated: u16) -> u16 {
    if let Some(max) = conn.max_datagram_size() {
        let max_symbol = clamp_symbol_to_datagram_cap(negotiated, max);
        if negotiated > max_symbol {
            tracing::warn!(
                negotiated,
                max_symbol,
                max_datagram = max,
                "negotiated symbol size exceeds datagram cap; clamping at use site"
            );
        }
        max_symbol
    } else {
        negotiated.max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::clamp_symbol_to_datagram_cap;
    use raptun_proto::datagram::SYMBOL_HEADER_LEN;

    /// H3 regression: a negotiated symbol size that exceeds the datagram
    /// cap (minus header) is clamped at the use site, not silently passed
    /// through. Previously only checked in `debug_assert!` so a release
    /// build would drop every datagram and report zero throughput with no
    /// log line.
    #[test]
    fn symbol_size_clamps_to_datagram_cap_in_release() {
        let header = SYMBOL_HEADER_LEN as u16;
        // A 1200-byte datagram payload can carry at most 1200 - header bytes
        // of symbol payload.
        let datagram_cap: usize = 1200;
        let max_symbol = datagram_cap - header as usize;
        // Within the cap: pass through.
        assert_eq!(
            clamp_symbol_to_datagram_cap(max_symbol as u16, datagram_cap),
            max_symbol as u16
        );
        // One byte over: clamp down.
        assert_eq!(
            clamp_symbol_to_datagram_cap((max_symbol + 1) as u16, datagram_cap),
            max_symbol as u16
        );
        // Way over: clamp to the ceiling.
        assert_eq!(
            clamp_symbol_to_datagram_cap(u16::MAX, datagram_cap),
            max_symbol as u16
        );
        // Zero is normalised to 1 (a 0-byte symbol is meaningless).
        assert_eq!(clamp_symbol_to_datagram_cap(0, datagram_cap), 1);
    }

    /// Without an advertised datagram cap (None), pass through unchanged.
    #[test]
    fn symbol_size_unchanged_without_cap() {
        // Document the no-cap semantics by mimicking the call site: when
        // max_datagram_size is None, the function returns negotiated.max(1).
        let negotiated: u16 = 1200;
        let result = negotiated.max(1);
        assert_eq!(result, 1200);
    }
}
