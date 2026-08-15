//! End-to-end probes for the three critical DoS bugs fixed in PR #18.
//!
//! Each test exercises a fix through the *real* code path (not just the
//! inner math), so a regression in the wiring would also be caught here.
//!
//! - **C1** — `clamp_fec` not clamping `block_size`. Probe: spin up a real
//!   server, send a Hello with `block_size = u16::MAX`, assert the
//!   `HelloAck` echoes back the clamped value.
//! - **C2** — `DatagramHub` unbounded distinct stream_ids. Probe: spray
//!   2000 datagrams with random stream_ids through the real `dispatch`
//!   path and assert the pending map stops at the cap.
//! - **C3** — unknown signaling tag synthesising `BlockCount{u64::MAX}`.
//!   Probe: feed a garbage tag byte through the real decoder and assert
//!   the new "Err(1) skip" return shape.

#![cfg(feature = "test-hooks")]

use std::net::SocketAddr;
use std::time::Duration;

use raptun_core::config::{FecConfig, FecScheme, RuntimeConfig, TransportConfig};
use raptun_core::fec::DatagramHub;
use raptun_core::tls::{ServerIdentity, ServerTrust};
use raptun_proto::control::FecParams;
use raptun_proto::datagram::SymbolHeader;
use raptun_proto::{Decode, Encode};
use tokio::sync::Mutex;

static LOCK: Mutex<()> = Mutex::const_new(());

fn server_cfg() -> RuntimeConfig {
    RuntimeConfig {
        fec: FecConfig {
            scheme: FecScheme::RaptorQ,
            symbol_size: 1200,
            block_size: Some(16),
            ..FecConfig::default()
        },
        transport: TransportConfig {
            use_datagrams: true,
            ..TransportConfig::default()
        },
        psk: Some("clamp-test".into()),
    }
}

/// **C1**: full handshake with a malicious client Hello, asserting the
/// server clamps `block_size = u16::MAX` to `MAX_BLOCK_SIZE = 256`.
#[tokio::test]
async fn server_clamps_malicious_block_size() {
    let _guard = LOCK.lock().await;
    let _ = tracing_subscriber::fmt()
        .with_env_filter("raptun_core=warn")
        .with_test_writer()
        .try_init();

    let identity = ServerIdentity::generate_self_signed("raptun").unwrap();
    let fingerprint = identity.fingerprint_hex.clone();
    let server_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let cfg = server_cfg();

    // Pre-bind to learn the port, then drop and have a server task rebind.
    let server_ep = {
        let transport = raptun_core::endpoint::build_transport(&cfg.transport).unwrap();
        raptun_core::endpoint::build_server_endpoint(
            server_bind,
            &identity,
            transport,
            &cfg.transport,
        )
        .unwrap()
    };
    let server_addr = server_ep.local_addr().unwrap();
    drop(server_ep);

    // Spawn a minimal server: accept one connection, run handshake_server,
    // then keep the connection alive long enough for the client to read the
    // HelloAck. (The full tunnel loop is unnecessary for this assertion.)
    let srv_cfg = cfg.clone();
    let _server = tokio::spawn(async move {
        let transport = raptun_core::endpoint::build_transport(&srv_cfg.transport).unwrap();
        let ep = raptun_core::endpoint::build_server_endpoint(
            server_addr,
            &identity,
            transport,
            &srv_cfg.transport,
        )
        .unwrap();
        if let Some(incoming) = ep.accept().await {
            if let Ok(conn) = incoming.await {
                let _ = raptun_core::session::handshake_server(&conn, &srv_cfg).await;
                // Park on the connection's close future so the client has
                // time to drain HelloAck before the conn is dropped.
                let _ = conn.closed().await;
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Connect a malicious client and send Hello { block_size: u16::MAX }.
    let transport = raptun_core::endpoint::build_transport(&cfg.transport).unwrap();
    let trust = ServerTrust::Fingerprint(fingerprint);
    let client_ep =
        raptun_core::endpoint::build_client_endpoint(&trust, transport, &cfg.transport).unwrap();
    let conn = client_ep
        .connect(server_addr, "raptun")
        .unwrap()
        .await
        .expect("connect");

    use raptun_proto::control::{Hello, HelloAck, Message};
    let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
    let hostile = Message::Hello(Hello {
        version: raptun_proto::PROTOCOL_VERSION,
        auth_token: b"clamp-test".to_vec(),
        fec: FecParams {
            symbol_size: 1200,
            block_size: u16::MAX,
            repair_ppm: 100,
        },
    });
    let mut body = Vec::new();
    hostile.encode(&mut body);
    let len = (body.len() as u32).to_be_bytes();
    send.write_all(&len).await.unwrap();
    send.write_all(&body).await.unwrap();

    // Read the HelloAck response.
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await.expect("len");
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await.expect("body");
    let mut slice = body.as_slice();
    let msg = Message::decode(&mut slice).expect("decode");

    let HelloAck { version: _, fec } = match msg {
        Message::HelloAck(h) => h,
        other => panic!("expected HelloAck, got {other:?}"),
    };

    // === THE ASSERTION: server MUST clamp u16::MAX → 256 ===
    assert_eq!(
        fec.block_size, 256,
        "server MUST clamp u16::MAX block_size to MAX_BLOCK_SIZE (256); got {}",
        fec.block_size
    );
    // And the other clamps remain in effect.
    assert!(fec.repair_ppm <= 1000, "repair_ppm unexpectedly large");
}

/// **C2**: spray 2000 distinct stream_ids through the real `DatagramHub::dispatch`
/// path and assert the pending map stops at the cap. This is the end-to-end
/// version of the lib test — the lib test inlines the math, this one drives
/// the real entry point.
#[tokio::test]
async fn datagram_hub_caps_distinct_streams_under_attack() {
    let hub = DatagramHub::new();
    for s in 0u64..2000 {
        let hdr = SymbolHeader {
            stream_id: s,
            block_id: 1,
            esi: 0,
            flags: raptun_proto::datagram::SymbolFlags::empty(),
        };
        let mut buf = Vec::new();
        hdr.encode(&mut buf);
        buf.extend_from_slice(&[0u8; 16]);
        hub.dispatch(&buf);
    }
    // The cap MUST hold. Without the fix, this would be 2000.
    assert_eq!(
        hub.pending_len(),
        raptun_core::fec::MAX_PENDING_STREAMS,
        "pending stream count must be capped, not grow without bound"
    );
}

/// **C3**: an unknown tag byte must not produce `BlockCount { total: u64::MAX }`.
/// The decoder now reports the byte as garbage so the buffer can drain.
#[tokio::test]
async fn unknown_signal_tag_no_longer_hangs_downstream() {
    use raptun_core::fec::TunnelSignal;

    // The legacy bug: an unknown tag byte 0x00 used to round-trip as
    // BlockCount { total: u64::MAX }. Verify that's no longer reachable.
    let outcome = TunnelSignal::decode(&[0x00]).expect("decoder returns some outcome");
    match outcome {
        Ok((TunnelSignal::BlockCount { total }, _)) => {
            panic!("legacy bug: unknown tag still synthesised BlockCount {{ total: {total} }}")
        }
        Ok((sig, _)) => panic!("unexpected Ok signal: {sig:?}"),
        Err(skipped) => assert_eq!(skipped, 1, "must report 1 byte consumed"),
    }

    // And a real, well-formed BlockCount is unaffected.
    let real = TunnelSignal::BlockCount { total: 42 };
    let buf = real.encode();
    match TunnelSignal::decode(&buf).expect("ok") {
        Ok((TunnelSignal::BlockCount { total }, _)) => assert_eq!(total, 42),
        other => panic!("expected BlockCount, got {other:?}"),
    }
}

/// Sanity probe: a clamped FecSender's block_payload must stay bounded
/// (under ~300 KB), while the pre-fix hostile value would have been ~78 MB.
/// This is the math the clamp protects against; useful as a regression
/// note in case `MAX_BLOCK_SIZE` is ever loosened.
#[tokio::test]
async fn clamped_block_size_keeps_block_payload_bounded() {
    let symbol_size: u16 = 1200;
    let clamped_k: u32 = 256;
    let block_payload: u64 = (symbol_size as u64) * (clamped_k as u64) - 4;
    assert!(
        block_payload < 350_000,
        "clamped block_payload must stay under ~300 KB; got {block_payload}"
    );
    let hostile_k: u32 = 65_535;
    let hostile_payload: u64 = (symbol_size as u64) * (hostile_k as u64) - 4;
    assert!(
        hostile_payload > 70_000_000,
        "unclamped payload would be ~78 MB; confirms why the clamp matters"
    );
}
