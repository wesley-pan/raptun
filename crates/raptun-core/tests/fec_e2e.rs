//! End-to-end test of the datagram + RaptorQ FEC data path, driving the real
//! `run_client` / `run_server` loops over localhost with an echo target.
//!
//! This proves the Phase-2 wiring: TCP bytes are chunked into RaptorQ blocks,
//! sent as unreliable QUIC datagrams, reassembled in order on the far side, and
//! forwarded to the target — then the same in reverse for the echo. The
//! per-symbol loss-recovery property itself is covered by unit tests in
//! `raptun_core::fec` and `raptun_fec::codec`; here we validate the full
//! socket-to-socket path including the signaling stream and datagram hub.

use std::net::SocketAddr;
use std::time::Duration;

use raptun_core::config::{FecConfig, FecScheme, RuntimeConfig, TransportConfig};
use raptun_core::run::ListenMode;
use raptun_core::tls::{ServerIdentity, ServerTrust};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// Serializes the socket-level e2e tests. They share a process-global datagram
/// loss-injection knob (under `test-hooks`) and rebind ephemeral ports, so
/// running them concurrently would let one test's loss setting corrupt another.
static E2E_LOCK: Mutex<()> = Mutex::const_new(());

/// A trivial echo server that upper-cases and returns whatever it receives,
/// then closes. Returns its bound address.
async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let up: Vec<u8> =
                                buf[..n].iter().map(|b| b.to_ascii_uppercase()).collect();
                            if sock.write_all(&up).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

fn fec_config() -> RuntimeConfig {
    RuntimeConfig {
        fec: FecConfig {
            scheme: FecScheme::RaptorQ,
            symbol_size: 1200,
            block_size: Some(8),
            ..FecConfig::default()
        },
        transport: TransportConfig {
            use_datagrams: true,
            ..TransportConfig::default()
        },
        psk: Some("fec-secret".into()),
    }
}

/// Full path: local TCP -> raptun-client -(QUIC datagrams + FEC)-> raptun-server
/// -> echo target, and back. Verifies a payload round-trips uppercased.
#[tokio::test]
async fn fec_tunnel_end_to_end() {
    let _guard = E2E_LOCK.lock().await;
    let _ = tracing_subscriber::fmt()
        .with_env_filter("raptun_core=trace")
        .with_test_writer()
        .try_init();
    let echo_addr = spawn_echo().await;

    // Server on an ephemeral port; grab its fingerprint for client pinning.
    let identity = ServerIdentity::generate_self_signed("raptun").unwrap();
    let fingerprint = identity.fingerprint_hex.clone();
    let server_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();

    // Bind the server endpoint synchronously so we know its port before the
    // client connects. We reuse run_server's construction by binding here and
    // spawning it.
    let server_cfg = fec_config();
    let server_ep = {
        let transport = raptun_core::endpoint::build_transport(&server_cfg.transport).unwrap();
        raptun_core::endpoint::build_server_endpoint(server_bind, &identity, transport).unwrap()
    };
    let server_addr = server_ep.local_addr().unwrap();
    drop(server_ep); // free the port; run_server rebinds it

    // Small race window on rebind is fine for a localhost test.
    let srv_cfg = server_cfg.clone();
    tokio::spawn(async move {
        let _ = raptun_core::run_server(srv_cfg, server_addr, echo_addr, identity).await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Client listens locally and tunnels to the server over FEC.
    let client_cfg = fec_config();
    let local_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let client_listener = TcpListener::bind(local_bind).await.unwrap();
    let local_addr = client_listener.local_addr().unwrap();
    drop(client_listener); // free the port; run_client rebinds it

    let trust = ServerTrust::Fingerprint(fingerprint);
    tokio::spawn(async move {
        let _ = raptun_core::run_client(
            client_cfg,
            local_addr,
            server_addr,
            "raptun",
            trust,
            ListenMode::Tcp,
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Drive a payload through the local end and check the echo.
    let mut conn = connect_with_retry(local_addr).await;
    let payload = b"raptun fec datagram path end to end test";
    conn.write_all(payload).await.unwrap();

    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    // Read until we've received the full echoed length or time out.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while got.len() < payload.len() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, conn.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }

    let expected: Vec<u8> = payload.iter().map(|b| b.to_ascii_uppercase()).collect();
    assert_eq!(got, expected, "FEC tunnel must round-trip the payload");
}

/// Connect to the client's local port, retrying briefly while it binds.
async fn connect_with_retry(addr: SocketAddr) -> TcpStream {
    for _ in 0..50 {
        if let Ok(s) = TcpStream::connect(addr).await {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("could not connect to client local port {addr}");
}

/// Drive one uppercase round-trip through the client's local port. Returns the
/// echoed bytes (may be short on failure so callers can assert).
async fn roundtrip_once(local_addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut conn = connect_with_retry(local_addr).await;
    conn.write_all(payload).await.unwrap();
    // Signal EOF so the echo target's read loop and the tunnel can complete.
    let _ = conn.shutdown().await;

    let mut got = Vec::new();
    let mut buf = [0u8; 8192];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while got.len() < payload.len() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, conn.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    got
}

/// The client must re-establish its QUIC connection after the server restarts,
/// rather than wedging on the dead connection forever ("open signaling bi:
/// timed out"). We run the reliable-stream path (FEC off) so the test exercises
/// only the reconnect supervision, kill the server, respawn it on the same UDP
/// address, and prove a fresh round-trip succeeds.
#[tokio::test]
async fn client_reconnects_after_server_restart() {
    // The two server instances must present the same leaf certificate so the
    // client's pinned fingerprint keeps matching across the restart.
    fn clone_identity(id: &ServerIdentity) -> ServerIdentity {
        ServerIdentity {
            cert_chain: id.cert_chain.clone(),
            private_key: id.private_key.clone_key(),
            fingerprint_hex: id.fingerprint_hex.clone(),
        }
    }

    let _guard = E2E_LOCK.lock().await;
    let _ = tracing_subscriber::fmt()
        .with_env_filter("raptun_core=debug")
        .with_test_writer()
        .try_init();
    let echo_addr = spawn_echo().await;

    // Reliable-stream config (FEC off) keeps the test focused on reconnect.
    let identity = ServerIdentity::generate_self_signed("raptun").unwrap();
    let fingerprint = identity.fingerprint_hex.clone();
    let mut cfg = fec_config();
    cfg.fec.scheme = FecScheme::Off;
    cfg.transport.use_datagrams = false;
    // A short idle timeout lets the client notice the dead server quickly.
    cfg.transport.idle_timeout = Duration::from_secs(3);
    cfg.transport.keepalive = Some(Duration::from_secs(1));

    // Reserve a server UDP port, then free it so run_server can bind it.
    let server_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_addr = {
        let transport = raptun_core::endpoint::build_transport(&cfg.transport).unwrap();
        let ep = raptun_core::endpoint::build_server_endpoint(server_bind, &identity, transport)
            .unwrap();
        ep.local_addr().unwrap()
    };

    // First server instance.
    let srv_cfg = cfg.clone();
    let srv_id = clone_identity(&identity);
    let server1 = tokio::spawn(async move {
        let _ = raptun_core::run_server(srv_cfg, server_addr, echo_addr, srv_id).await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Client with a stable local port.
    let local_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let local_addr = {
        let l = TcpListener::bind(local_bind).await.unwrap();
        l.local_addr().unwrap()
    };
    let trust = ServerTrust::Fingerprint(fingerprint);
    let cli_cfg = cfg.clone();
    tokio::spawn(async move {
        let _ = raptun_core::run_client(
            cli_cfg,
            local_addr,
            server_addr,
            "raptun",
            trust,
            ListenMode::Tcp,
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Round-trip #1 against the first server.
    let payload = b"first server round trip";
    let got = roundtrip_once(local_addr, payload).await;
    let expected: Vec<u8> = payload.iter().map(|b| b.to_ascii_uppercase()).collect();
    assert_eq!(got, expected, "first round-trip must succeed");

    // Kill the server and wait for its endpoint to release the UDP port.
    server1.abort();
    let _ = server1.await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Restart the server on the same address.
    let srv_cfg = cfg.clone();
    let srv_id = clone_identity(&identity);
    let server2 = tokio::spawn(async move {
        let _ = raptun_core::run_server(srv_cfg, server_addr, echo_addr, srv_id).await;
    });

    // Give the client time to notice the drop (idle timeout) and reconnect with
    // backoff to the restarted server.
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Round-trip #2 must succeed over the reconnected tunnel.
    let payload = b"second server round trip after restart";
    let got = roundtrip_once(local_addr, payload).await;
    let expected: Vec<u8> = payload.iter().map(|b| b.to_ascii_uppercase()).collect();
    assert_eq!(
        got, expected,
        "client must reconnect after server restart and round-trip again"
    );

    server2.abort();
}

#[tokio::test]
async fn fec_pump_direct_smoke() {
    // Sanity: the pump types recover a payload with zero loss, no sockets.
    use raptun_core::fec::{FecReceiver, FecSender};
    use raptun_fec::RepairBudget;
    use raptun_proto::datagram::SymbolHeader;
    use std::time::Instant;
    let mut s = FecSender::new(1, 1100, 8);
    let dgs = s.encode_blocks(b"direct smoke test payload", 2);
    let mut r = FecReceiver::new(1100, 8);
    let budget = RepairBudget::new(1100, 0.4);
    budget.refresh_ceiling(10_000_000);
    let mut out = Vec::new();
    for dg in &dgs {
        let (h, p) = SymbolHeader::parse(dg).unwrap();
        out.extend_from_slice(&r.on_symbol(h.block_id, h.esi, p, Instant::now(), &budget));
    }
    assert_eq!(out, b"direct smoke test payload");
}

/// End-to-end recovery under induced datagram loss. Requires the `test-hooks`
/// feature, which compiles in a deterministic 1-in-N datagram dropper. With
/// loss active, proactive FEC repair plus the Phase-3 NACK control loop must
/// still deliver the payload intact.
#[cfg(feature = "test-hooks")]
#[tokio::test]
async fn fec_recovers_under_datagram_loss() {
    let _guard = E2E_LOCK.lock().await;
    // Drop roughly 1 in 6 datagrams in both directions.
    raptun_core::run::set_test_drop_one_in(6);

    let echo_addr = spawn_echo().await;
    let identity = ServerIdentity::generate_self_signed("raptun").unwrap();
    let fingerprint = identity.fingerprint_hex.clone();

    // Bump the repair ratio so proactive FEC carries most of the loss, with the
    // NACK loop covering the residue.
    let mut cfg = fec_config();
    cfg.fec.initial_ratio = raptun_fec::strategy::RepairRatio::from_fraction(0.5);

    let server_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_ep = {
        let transport = raptun_core::endpoint::build_transport(&cfg.transport).unwrap();
        raptun_core::endpoint::build_server_endpoint(server_bind, &identity, transport).unwrap()
    };
    let server_addr = server_ep.local_addr().unwrap();
    drop(server_ep);

    let srv_cfg = cfg.clone();
    tokio::spawn(async move {
        let _ = raptun_core::run_server(srv_cfg, server_addr, echo_addr, identity).await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let local_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let client_listener = TcpListener::bind(local_bind).await.unwrap();
    let local_addr = client_listener.local_addr().unwrap();
    drop(client_listener);

    let trust = ServerTrust::Fingerprint(fingerprint);
    let cli_cfg = cfg.clone();
    tokio::spawn(async move {
        let _ = raptun_core::run_client(
            cli_cfg,
            local_addr,
            server_addr,
            "raptun",
            trust,
            ListenMode::Tcp,
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // A multi-block payload so loss actually straddles blocks.
    let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    let mut conn = connect_with_retry(local_addr).await;
    conn.write_all(&payload).await.unwrap();

    let mut got = Vec::new();
    let mut buf = [0u8; 8192];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while got.len() < payload.len() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, conn.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }

    // Disable loss injection for any subsequent tests in the process.
    raptun_core::run::set_test_drop_one_in(0);

    let expected: Vec<u8> = payload.iter().map(|b| b.to_ascii_uppercase()).collect();
    assert_eq!(
        got.len(),
        expected.len(),
        "must recover full length despite ~17% datagram loss"
    );
    assert_eq!(got, expected, "payload must be intact after FEC recovery");
}

/// End-to-end proof of the convergence lower bound: configure the tunnel so FEC
/// cannot recover on its own — zero proactive repair AND a near-zero repair
/// budget so NACK top-ups are refused — under heavy datagram loss. The only way
/// the payload can arrive intact is the reliable-retransmit degrade path. If
/// that path works, the stream still completes; if it were missing, this would
/// hang and time out with a truncated result.
#[cfg(feature = "test-hooks")]
#[tokio::test]
async fn reliable_retransmit_completes_under_unrecoverable_loss() {
    let _guard = E2E_LOCK.lock().await;
    // Heavy loss: drop 1 in 3 datagrams.
    raptun_core::run::set_test_drop_one_in(3);

    let echo_addr = spawn_echo().await;
    let identity = ServerIdentity::generate_self_signed("raptun").unwrap();
    let fingerprint = identity.fingerprint_hex.clone();

    let mut cfg = fec_config();
    // No proactive repair: source symbols only. With 50% loss most blocks
    // cannot decode from what arrives.
    cfg.fec.initial_ratio = raptun_fec::strategy::RepairRatio::from_fraction(0.0);
    // Near-zero repair budget: NACK top-ups won't fit, so blocks degrade to the
    // reliable-retransmit fallback instead of endless repair.
    cfg.fec.repair_cwnd_fraction = 0.0;

    let server_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_ep = {
        let transport = raptun_core::endpoint::build_transport(&cfg.transport).unwrap();
        raptun_core::endpoint::build_server_endpoint(server_bind, &identity, transport).unwrap()
    };
    let server_addr = server_ep.local_addr().unwrap();
    drop(server_ep);

    let srv_cfg = cfg.clone();
    tokio::spawn(async move {
        let _ = raptun_core::run_server(srv_cfg, server_addr, echo_addr, identity).await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let local_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let client_listener = TcpListener::bind(local_bind).await.unwrap();
    let local_addr = client_listener.local_addr().unwrap();
    drop(client_listener);

    let trust = ServerTrust::Fingerprint(fingerprint);
    let cli_cfg = cfg.clone();
    tokio::spawn(async move {
        let _ = raptun_core::run_client(
            cli_cfg,
            local_addr,
            server_addr,
            "raptun",
            trust,
            ListenMode::Tcp,
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // A few blocks' worth of data so several blocks must degrade.
    let payload: Vec<u8> = (0..12_000u32).map(|i| (i % 249) as u8).collect();
    let mut conn = connect_with_retry(local_addr).await;
    conn.write_all(&payload).await.unwrap();

    let mut got = Vec::new();
    let mut buf = [0u8; 8192];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while got.len() < payload.len() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, conn.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }

    raptun_core::run::set_test_drop_one_in(0);

    let expected: Vec<u8> = payload.iter().map(|b| b.to_ascii_uppercase()).collect();
    assert_eq!(
        got, expected,
        "reliable-retransmit fallback must complete the stream when FEC cannot"
    );
}

/// A `MakeWriter` that appends every log line into a shared buffer, so a test
/// can assert on emitted `tracing` output.
#[derive(Clone)]
struct BufWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for BufWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufWriter {
    type Writer = BufWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// The client's periodic heartbeat must emit a rolling `info` line while the
/// tunnel is healthy — the fix for "logs stop scrolling after startup". We set
/// a sub-second heartbeat, capture `info` output, and assert the "tunnel alive"
/// line appears more than once (i.e. it recurs, not just a one-off startup log).
///
/// Runs on a single-threaded runtime so all spawned tasks share this thread's
/// thread-local `tracing` subscriber (a multi-thread runtime would run the
/// heartbeat task on a worker thread that never sees the captured subscriber).
#[tokio::test(flavor = "current_thread")]
async fn client_emits_periodic_heartbeat() {
    let _guard = E2E_LOCK.lock().await;

    // Capture info-level logs into a shared buffer for the duration of the test.
    let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("raptun_core=info")
        .with_writer(BufWriter(buf.clone()))
        .with_ansi(false)
        .finish();
    let _log_guard = tracing::subscriber::set_default(subscriber);

    let echo_addr = spawn_echo().await;
    let identity = ServerIdentity::generate_self_signed("raptun").unwrap();
    let fingerprint = identity.fingerprint_hex.clone();

    // Reliable-stream path keeps the test simple; a short heartbeat so several
    // ticks land within the test window.
    let mut cfg = fec_config();
    cfg.fec.scheme = FecScheme::Off;
    cfg.transport.use_datagrams = false;
    cfg.transport.heartbeat = Some(Duration::from_millis(300));

    let server_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_addr = {
        let transport = raptun_core::endpoint::build_transport(&cfg.transport).unwrap();
        let ep = raptun_core::endpoint::build_server_endpoint(server_bind, &identity, transport)
            .unwrap();
        ep.local_addr().unwrap()
    };

    let srv_cfg = cfg.clone();
    tokio::spawn(async move {
        let _ = raptun_core::run_server(srv_cfg, server_addr, echo_addr, identity).await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let local_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let local_addr = {
        let l = TcpListener::bind(local_bind).await.unwrap();
        l.local_addr().unwrap()
    };
    let trust = ServerTrust::Fingerprint(fingerprint);
    let cli_cfg = cfg.clone();
    tokio::spawn(async move {
        let _ = raptun_core::run_client(
            cli_cfg,
            local_addr,
            server_addr,
            "raptun",
            trust,
            ListenMode::Tcp,
        )
        .await;
    });

    // Let several heartbeat intervals elapse (first tick is skipped, so wait for
    // at least two more).
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let logs = String::from_utf8_lossy(&buf.lock().unwrap()).into_owned();
    let beats = logs.matches("tunnel alive").count();
    assert!(
        beats >= 2,
        "heartbeat must recur (rolling output); saw {beats} in logs:\n{logs}"
    );
}

/// A target that reads the first request, sends one response, then half-closes
/// its *write* side (shutdown) while leaving the read side open. This drives the
/// tunnel's `down` direction to completion (the response's block count is fully
/// delivered and the peer's write half is done) *before* the `up` direction sees
/// EOF — the local client socket is still open. Returns its bound address.
async fn spawn_respond_then_halfclose() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                // Wait for the first request bytes.
                if let Ok(n) = sock.read(&mut buf).await {
                    if n > 0 {
                        let up: Vec<u8> = buf[..n].iter().map(|b| b.to_ascii_uppercase()).collect();
                        let _ = sock.write_all(&up).await;
                    }
                }
                // Half-close the write side; keep the read side open so the peer
                // does not see a full connection close.
                let _ = sock.shutdown().await;
                // Hold the socket open a while so the read half stays alive.
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
        }
    });
    addr
}

/// Regression for the shutdown-signal lost-wakeup: when the `down` direction of
/// a FEC tunnel completes *before* `up` reaches its post-EOF wait, `up` must
/// still observe the finished signal and unwind, so the tunnel task ends and
/// `active_tunnels` drains back to 0.
///
/// The target responds then half-closes its write side, so the server announces
/// its block count immediately and the client's `down` finishes early — before
/// the local app closes and the client's `up` reaches its post-EOF loop. A
/// `Notify`-based signal (the earlier fix) loses the wakeup fired in that window
/// and `up` hangs forever; the `oneshot` buffers it so `up` unblocks regardless
/// of ordering. We drive one such request/response, close the local socket, and
/// assert the heartbeat's `active_tunnels` rises to >=1 and then returns to 0.
#[tokio::test(flavor = "current_thread")]
async fn tunnel_drains_when_downstream_finishes_before_upstream_eof() {
    let _guard = E2E_LOCK.lock().await;

    let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("raptun_core=info")
        .with_writer(BufWriter(buf.clone()))
        .with_ansi(false)
        .finish();
    let _log_guard = tracing::subscriber::set_default(subscriber);

    run_downstream_first_scenario().await;

    let logs = String::from_utf8_lossy(&buf.lock().unwrap()).into_owned();
    let counts: Vec<u64> = logs
        .lines()
        .filter(|l| l.contains("tunnel alive"))
        .filter_map(|l| {
            l.split("active_tunnels=")
                .nth(1)?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .collect();
    // The tunnel must have gone active (>=1 while serving) and then drained back
    // to 0 in a *later* heartbeat. With the buggy Notify signal the wakeup is
    // lost, `up` hangs, and the count stays pinned at 1 forever (never returns
    // to 0 after rising). The trivial startup 0 (before the connection opens)
    // does not satisfy this because it precedes the rise.
    let rose = counts.iter().position(|&c| c >= 1);
    let drained_after_rise = rose.map(|i| counts[i..].contains(&0)).unwrap_or(false);
    assert!(
        drained_after_rise,
        "tunnel must go active then drain to 0 after downstream finishes first; \
         active_tunnels sequence = {counts:?}\nlogs:\n{logs}"
    );
}

/// Body of [`tunnel_drains_when_downstream_finishes_before_upstream_eof`]: drive
/// one request/response where the target half-closes first (so the client's
/// `down` finishes before `up` sees EOF), then close the local socket.
async fn run_downstream_first_scenario() {
    let target_addr = spawn_respond_then_halfclose().await;
    let identity = ServerIdentity::generate_self_signed("raptun").unwrap();
    let fingerprint = identity.fingerprint_hex.clone();

    // FEC path so run_fec_tunnel (with the shutdown signal) is exercised.
    let mut cfg = fec_config();
    cfg.transport.heartbeat = Some(Duration::from_millis(300));

    let server_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_addr = {
        let transport = raptun_core::endpoint::build_transport(&cfg.transport).unwrap();
        let ep = raptun_core::endpoint::build_server_endpoint(server_bind, &identity, transport)
            .unwrap();
        ep.local_addr().unwrap()
    };

    let srv_cfg = cfg.clone();
    tokio::spawn(async move {
        let _ = raptun_core::run_server(srv_cfg, server_addr, target_addr, identity).await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let local_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let local_addr = {
        let l = TcpListener::bind(local_bind).await.unwrap();
        l.local_addr().unwrap()
    };
    let trust = ServerTrust::Fingerprint(fingerprint);
    let cli_cfg = cfg.clone();
    tokio::spawn(async move {
        let _ = raptun_core::run_client(
            cli_cfg,
            local_addr,
            server_addr,
            "raptun",
            trust,
            ListenMode::Tcp,
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Open a tunnel, send one request, read the echoed response. The target
    // half-closes right after responding, so the client's `down` completes early
    // (server announced its block count) — before we close the local socket and
    // the client's `up` reaches its post-EOF wait. That ordering is what loses a
    // Notify wakeup.
    {
        let mut conn = connect_with_retry(local_addr).await;
        conn.write_all(b"hello half-close").await.unwrap();
        let mut resp = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(5), conn.read(&mut resp))
            .await
            .expect("response read timed out")
            .expect("response read failed");
        assert_eq!(&resp[..n], b"HELLO HALF-CLOSE", "response must round-trip");
        // Give `down` a moment to finish first, then close our side so `up` hits
        // EOF and reaches its post-EOF wait *after* the signal already fired.
        tokio::time::sleep(Duration::from_millis(200)).await;
        // Dropping `conn` closes the local socket → `up` sees EOF.
    }

    // Allow several heartbeats so we capture the rise to active and the drain to 0.
    tokio::time::sleep(Duration::from_millis(1500)).await;
}

/// Concurrency regression: many local connections held open *simultaneously*
/// must all tunnel data promptly, not stall until earlier ones close.
///
/// Each FEC tunnel holds one QUIC bidi (signaling) stream open for the whole
/// life of its local TCP connection. Quinn's default `max_concurrent_bidi_streams`
/// is only 100, so once ~100 tunnels are live the client's `open_bi()` blocks
/// until an old stream closes — exactly the "new connections stall until a
/// timeout releases an old stream" symptom seen with real browser traffic.
///
/// We open `CONCURRENT` connections (well above the old 100 default, well under
/// Raptun's raised cap), keep every one open, and require each to round-trip
/// within a deadline. Against the unconfigured default this deadlocks past the
/// 100th stream and times out; with the raised cap all complete.
#[tokio::test]
async fn many_concurrent_tunnels_do_not_stall() {
    let _guard = E2E_LOCK.lock().await;

    // Above Quinn's default of 100 so the cap is exercised, below Raptun's 1024.
    const CONCURRENT: usize = 250;

    let echo_addr = spawn_echo().await;
    let identity = ServerIdentity::generate_self_signed("raptun").unwrap();
    let fingerprint = identity.fingerprint_hex.clone();
    let cfg = fec_config();

    let server_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_ep = {
        let transport = raptun_core::endpoint::build_transport(&cfg.transport).unwrap();
        raptun_core::endpoint::build_server_endpoint(server_bind, &identity, transport).unwrap()
    };
    let server_addr = server_ep.local_addr().unwrap();
    drop(server_ep);

    let srv_cfg = cfg.clone();
    tokio::spawn(async move {
        let _ = raptun_core::run_server(srv_cfg, server_addr, echo_addr, identity).await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let local_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let client_listener = TcpListener::bind(local_bind).await.unwrap();
    let local_addr = client_listener.local_addr().unwrap();
    drop(client_listener);

    let trust = ServerTrust::Fingerprint(fingerprint);
    let cli_cfg = cfg.clone();
    tokio::spawn(async move {
        let _ = raptun_core::run_client(
            cli_cfg,
            local_addr,
            server_addr,
            "raptun",
            trust,
            ListenMode::Tcp,
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Open every connection and hold it open until *all* have round-tripped.
    // A shared barrier is what actually pins many streams live simultaneously:
    // no task closes its socket (releasing its QUIC stream) until every task has
    // received its echo. Under a cap below CONCURRENT, tasks past the limit can
    // never open their bidi stream, so they never reach the barrier and the
    // whole set deadlocks — the exact "stall until an old stream frees" symptom.
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(CONCURRENT));
    let mut handles = Vec::with_capacity(CONCURRENT);
    for i in 0..CONCURRENT {
        let barrier = std::sync::Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            let payload = format!("concurrent-tunnel-{i:04}");
            let mut conn = connect_with_retry(local_addr).await;
            conn.write_all(payload.as_bytes()).await.unwrap();

            let expected: Vec<u8> = payload.bytes().map(|b| b.to_ascii_uppercase()).collect();
            let mut got = Vec::new();
            let mut buf = [0u8; 256];
            while got.len() < expected.len() {
                match conn.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
            }
            // Hold the connection (and thus its QUIC stream) open until every
            // task has also round-tripped — forcing CONCURRENT streams live at
            // once — then let `conn` drop.
            let matched = got == expected;
            barrier.wait().await;
            matched
        }));
    }

    // A generous deadline: if the stream cap is below CONCURRENT, tunnels past
    // the limit hang, the barrier never releases, and this elapses. With the
    // raised cap all CONCURRENT open together, round-trip, and pass the barrier.
    let ok = tokio::time::timeout(Duration::from_secs(20), async {
        let mut ok = 0usize;
        for h in handles {
            if let Ok(true) = h.await {
                ok += 1;
            }
        }
        ok
    })
    .await
    .expect("concurrent tunnels stalled — stream-limit regression");

    assert_eq!(
        ok, CONCURRENT,
        "all {CONCURRENT} concurrent tunnels must round-trip; only {ok} did"
    );
}

/// Regression for the per-tunnel repair-budget bug: the ≤40%-of-cwnd repair
/// brake must be **one budget per QUIC connection**, shared by every tunnel on
/// it — not a fresh budget per tunnel. With a per-tunnel budget, N concurrent
/// tunnels each independently claim 40% of the *same* connection cwnd, so the
/// aggregate repair injection overshoots the link ~N× and collapses throughput
/// as concurrency rises.
///
/// The invariant is observable via the `test-hooks` creation counter: many
/// tunnels over one client connection must create exactly **one** budget. If a
/// regression moves creation back into the per-tunnel path, the count rises
/// with tunnel count and this fails.
#[cfg(feature = "test-hooks")]
#[tokio::test]
async fn shared_repair_budget_is_per_connection() {
    let _guard = E2E_LOCK.lock().await;
    raptun_core::run::reset_test_budgets_created();

    const TUNNELS: usize = 12;

    let echo_addr = spawn_echo().await;
    let identity = ServerIdentity::generate_self_signed("raptun").unwrap();
    let fingerprint = identity.fingerprint_hex.clone();
    let cfg = fec_config();

    let server_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_ep = {
        let transport = raptun_core::endpoint::build_transport(&cfg.transport).unwrap();
        raptun_core::endpoint::build_server_endpoint(server_bind, &identity, transport).unwrap()
    };
    let server_addr = server_ep.local_addr().unwrap();
    drop(server_ep);

    let srv_cfg = cfg.clone();
    tokio::spawn(async move {
        let _ = raptun_core::run_server(srv_cfg, server_addr, echo_addr, identity).await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let local_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let client_listener = TcpListener::bind(local_bind).await.unwrap();
    let local_addr = client_listener.local_addr().unwrap();
    drop(client_listener);

    let trust = ServerTrust::Fingerprint(fingerprint);
    let cli_cfg = cfg.clone();
    tokio::spawn(async move {
        let _ = raptun_core::run_client(
            cli_cfg,
            local_addr,
            server_addr,
            "raptun",
            trust,
            ListenMode::Tcp,
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Drive many tunnels concurrently, held open together via a barrier so they
    // are all genuinely live on the one client connection at once.
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(TUNNELS));
    let mut handles = Vec::with_capacity(TUNNELS);
    for i in 0..TUNNELS {
        let barrier = std::sync::Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            let payload = format!("budget-share-{i:03}");
            let mut conn = connect_with_retry(local_addr).await;
            conn.write_all(payload.as_bytes()).await.unwrap();
            let expected: Vec<u8> = payload.bytes().map(|b| b.to_ascii_uppercase()).collect();
            let mut got = Vec::new();
            let mut buf = [0u8; 128];
            while got.len() < expected.len() {
                match conn.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
            }
            barrier.wait().await;
        }));
    }
    for h in handles {
        let _ = tokio::time::timeout(Duration::from_secs(15), h).await;
    }

    // The counter is process-global and both the client and server run here, so
    // each side's single QUIC connection contributes one budget: the fixed,
    // tunnel-count-independent total is small (one per connection per side). The
    // per-tunnel-budget regression would instead create one per tunnel on each
    // side (~2 * TUNNELS). Asserting the count stays well below TUNNELS is the
    // robust invariant — it holds regardless of a stray reconnect.
    let created = raptun_core::run::test_budgets_created();
    assert!(
        created >= 1 && created < TUNNELS as u64,
        "repair budgets must be per-connection (a small, tunnel-count-independent \
         number), not per-tunnel: got {created} budgets for {TUNNELS} tunnels on \
         one connection (per-tunnel budget regression)"
    );
}

/// A payload far larger than Quinn's 1 MiB default datagram send buffer must
/// round-trip intact over the clean loopback link.
///
/// Regression guard for the send-buffer overflow stall: `send_datagram` uses
/// `drop = true`, so once a large burst overflows the outgoing buffer it
/// silently evicts the oldest queued, still-unsent symbols. With repair floored
/// at 1/block on a clean link those blocks can't self-heal, degrade to reliable
/// retransmit, and the un-paced sender stalls — `live_size_sweep.sh` pinned a
/// hard delivery cliff at exactly the 1 MiB buffer. The fix back-pressures the
/// send loop (`send_datagram_paced`) and enlarges the buffer; this drives 4 MiB
/// (well past that cliff) with zero injected loss and requires full delivery.
#[tokio::test]
async fn large_payload_survives_send_buffer_pressure() {
    let _guard = E2E_LOCK.lock().await;

    let echo_addr = spawn_echo().await;
    let identity = ServerIdentity::generate_self_signed("raptun").unwrap();
    let fingerprint = identity.fingerprint_hex.clone();
    let cfg = fec_config();

    let server_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_ep = {
        let transport = raptun_core::endpoint::build_transport(&cfg.transport).unwrap();
        raptun_core::endpoint::build_server_endpoint(server_bind, &identity, transport).unwrap()
    };
    let server_addr = server_ep.local_addr().unwrap();
    drop(server_ep);

    let srv_cfg = cfg.clone();
    tokio::spawn(async move {
        let _ = raptun_core::run_server(srv_cfg, server_addr, echo_addr, identity).await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let local_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let client_listener = TcpListener::bind(local_bind).await.unwrap();
    let local_addr = client_listener.local_addr().unwrap();
    drop(client_listener);

    let trust = ServerTrust::Fingerprint(fingerprint);
    let cli_cfg = cfg.clone();
    tokio::spawn(async move {
        let _ = raptun_core::run_client(
            cli_cfg,
            local_addr,
            server_addr,
            "raptun",
            trust,
            ListenMode::Tcp,
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 4 MiB: 4x the 1 MiB default send buffer, so a burst that overflows it is
    // guaranteed. A deterministic byte pattern lets us assert integrity, not
    // just length.
    const PAYLOAD_LEN: usize = 4 * 1024 * 1024;
    let payload: Vec<u8> = (0..PAYLOAD_LEN).map(|i| (i % 251) as u8).collect();

    let conn = connect_with_retry(local_addr).await;
    let (mut read_half, mut write_half) = conn.into_split();
    // Write concurrently with the read: a 4 MiB payload exceeds the TCP socket
    // buffer, so the writer blocks on back-pressure until the reader drains the
    // echo. Driving both at once is what actually exercises the large in-flight
    // burst through the tunnel.
    let writer_payload = payload.clone();
    let writer = tokio::spawn(async move {
        write_half.write_all(&writer_payload).await.unwrap();
        write_half.shutdown().await.unwrap();
    });

    let mut got = Vec::with_capacity(PAYLOAD_LEN);
    let mut buf = vec![0u8; 65536];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while got.len() < payload.len() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, read_half.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    let _ = writer.await;

    let expected: Vec<u8> = payload.iter().map(|b| b.to_ascii_uppercase()).collect();
    assert_eq!(
        got.len(),
        expected.len(),
        "large payload stalled: delivered {} of {} bytes (send-buffer overflow regression)",
        got.len(),
        expected.len()
    );
    assert_eq!(got, expected, "large payload must round-trip intact");
}

/// When the server cannot reach its forwarding target, it must reset the
/// tunnel's stream so the client's local TCP connection closes promptly — not
/// hang until the idle timeout. Regression guard for the un-bounded target
/// connect: previously each tunnel parked on the OS connect timeout (~130 s)
/// with its QUIC stream open, so `active_tunnels` piled up and the client saw
/// no error.
#[tokio::test]
async fn unreachable_target_closes_client_connection() {
    let _guard = E2E_LOCK.lock().await;

    // A target nobody is listening on: connect fails fast with "refused", which
    // drives the same reset path as a timeout without waiting on the clock.
    let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_target = dead_listener.local_addr().unwrap();
    drop(dead_listener); // free the port so connects are refused

    let identity = ServerIdentity::generate_self_signed("raptun").unwrap();
    let fingerprint = identity.fingerprint_hex.clone();

    // Short connect timeout keeps the test snappy even if the OS coalesces the
    // refusal into a brief wait; the assertion below allows well under the
    // 30 s idle timeout regardless.
    let mut cfg = fec_config();
    cfg.transport.target_connect_timeout = Duration::from_secs(2);

    let server_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_ep = {
        let transport = raptun_core::endpoint::build_transport(&cfg.transport).unwrap();
        raptun_core::endpoint::build_server_endpoint(server_bind, &identity, transport).unwrap()
    };
    let server_addr = server_ep.local_addr().unwrap();
    drop(server_ep);

    let srv_cfg = cfg.clone();
    tokio::spawn(async move {
        let _ = raptun_core::run_server(srv_cfg, server_addr, dead_target, identity).await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let local_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let client_listener = TcpListener::bind(local_bind).await.unwrap();
    let local_addr = client_listener.local_addr().unwrap();
    drop(client_listener);

    let trust = ServerTrust::Fingerprint(fingerprint);
    let cli_cfg = cfg.clone();
    tokio::spawn(async move {
        let _ = raptun_core::run_client(
            cli_cfg,
            local_addr,
            server_addr,
            "raptun",
            trust,
            ListenMode::Tcp,
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut conn = connect_with_retry(local_addr).await;
    conn.write_all(b"ping").await.unwrap();

    // The read must return EOF (0 bytes) well before the 30 s idle timeout.
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(15), conn.read(&mut buf)).await;
    match read {
        Ok(Ok(0)) => {} // clean EOF — the server reset propagated
        Ok(Ok(n)) => panic!("expected EOF, got {n} bytes from an unreachable target"),
        Ok(Err(_)) => {} // a connection error is also an acceptable prompt close
        Err(_) => panic!("client connection hung: server did not reset on unreachable target"),
    }
}
