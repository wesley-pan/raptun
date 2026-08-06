//! End-to-end loopback integration tests over a real Quinn connection.
//!
//! These prove the actual send/receive wiring — TLS handshake, control-stream
//! framing, the Raptun handshake, bidirectional stream tunnelling, and
//! unreliable-datagram symbol transport — by running a client and server over
//! localhost UDP. No mocks: real quinn endpoints, real rustls TLS 1.3.

use std::net::SocketAddr;

use bytes::Bytes;
use raptun_core::config::{FecConfig, RuntimeConfig, TransportConfig};
use raptun_core::endpoint::{build_client_endpoint, build_server_endpoint, build_transport};
use raptun_core::session::{handshake_client, handshake_server};
use raptun_core::tls::{ServerIdentity, ServerTrust};

fn config(psk: Option<&str>) -> RuntimeConfig {
    RuntimeConfig {
        fec: FecConfig::default(),
        transport: TransportConfig::default(),
        psk: psk.map(str::to_string),
    }
}

/// Spin up a server endpoint on an ephemeral port; return it plus its address
/// and the fingerprint a client should pin.
async fn spawn_server(cfg: &RuntimeConfig) -> (quinn::Endpoint, SocketAddr, String) {
    let identity = ServerIdentity::generate_self_signed("raptun.test").unwrap();
    let fingerprint = identity.fingerprint_hex.clone();
    let transport = build_transport(&cfg.transport).unwrap();
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let endpoint = build_server_endpoint(bind, &identity, transport, &cfg.transport).unwrap();
    let addr = endpoint.local_addr().unwrap();
    (endpoint, addr, fingerprint)
}

#[tokio::test]
async fn handshake_and_bidirectional_tunnel() {
    let cfg = config(Some("s3cret"));
    let (server_ep, server_addr, fingerprint) = spawn_server(&cfg).await;

    // --- Server task: accept a connection, run the handshake, echo one bi-stream.
    let server_cfg = cfg.clone();
    let server = tokio::spawn(async move {
        let incoming = server_ep.accept().await.expect("incoming");
        let conn = incoming.await.expect("server connection");
        let (_ctrl, fec) = handshake_server(&conn, &server_cfg)
            .await
            .expect("server handshake");
        // Server-clamped symbol size must be within the datagram-safe bound.
        assert!(fec.symbol_size <= raptun_core::session::SAFE_MAX_SYMBOL_SIZE);

        // Accept the tunnel stream and echo back uppercased bytes.
        let (mut send, mut recv) = conn.accept_bi().await.expect("accept tunnel bi");
        let mut buf = [0u8; 64];
        let n = recv.read(&mut buf).await.expect("read").expect("some");
        let upper: Vec<u8> = buf[..n].iter().map(|b| b.to_ascii_uppercase()).collect();
        send.write_all(&upper).await.expect("echo write");
        send.finish().expect("finish");
        // Keep the connection alive briefly so the client can read the echo.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    });

    // --- Client: connect, handshake, open a tunnel stream, send + verify echo.
    let transport = build_transport(&cfg.transport).unwrap();
    let client_ep =
        build_client_endpoint(&ServerTrust::Fingerprint(fingerprint), transport, &cfg.transport).unwrap();
    let conn = client_ep
        .connect(server_addr, "raptun.test")
        .unwrap()
        .await
        .expect("client connection");

    let (_ctrl, _fec) = handshake_client(&conn, &cfg)
        .await
        .expect("client handshake");

    let (mut send, mut recv) = conn.open_bi().await.expect("open tunnel bi");
    send.write_all(b"hello raptun").await.expect("write");
    send.finish().expect("finish");

    let mut buf = [0u8; 64];
    let n = recv.read(&mut buf).await.expect("read").expect("some");
    assert_eq!(
        &buf[..n],
        b"HELLO RAPTUN",
        "echo must be uppercased round-trip"
    );

    server.await.unwrap();
}

#[tokio::test]
async fn wrong_psk_is_rejected() {
    let server_cfg = config(Some("correct-horse"));
    let (server_ep, server_addr, fingerprint) = spawn_server(&server_cfg).await;

    let server = tokio::spawn(async move {
        let incoming = server_ep.accept().await.expect("incoming");
        let conn = incoming.await.expect("server connection");
        // Handshake must fail with an auth error.
        let result = handshake_server(&conn, &server_cfg).await;
        assert!(result.is_err(), "server must reject wrong PSK");
    });

    // Client presents the wrong PSK.
    let client_cfg = config(Some("wrong-battery"));
    let transport = build_transport(&client_cfg.transport).unwrap();
    let client_ep =
        build_client_endpoint(&ServerTrust::Fingerprint(fingerprint), transport, &client_cfg.transport).unwrap();
    let conn = client_ep
        .connect(server_addr, "raptun.test")
        .unwrap()
        .await
        .expect("client connection");

    let result = handshake_client(&conn, &client_cfg).await;
    assert!(result.is_err(), "client handshake must fail on wrong PSK");

    server.await.unwrap();
}

#[tokio::test]
async fn unreliable_datagram_symbol_round_trip() {
    let cfg = config(None);
    let (server_ep, server_addr, fingerprint) = spawn_server(&cfg).await;

    let server_cfg = cfg.clone();
    let server = tokio::spawn(async move {
        let incoming = server_ep.accept().await.expect("incoming");
        let conn = incoming.await.expect("server connection");
        let (_ctrl, _fec) = handshake_server(&conn, &server_cfg)
            .await
            .expect("server handshake");
        // Read one datagram and echo it back.
        let dg = conn.read_datagram().await.expect("read datagram");
        conn.send_datagram(dg).expect("echo datagram");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    });

    let transport = build_transport(&cfg.transport).unwrap();
    let client_ep =
        build_client_endpoint(&ServerTrust::Fingerprint(fingerprint), transport, &cfg.transport).unwrap();
    let conn = client_ep
        .connect(server_addr, "raptun.test")
        .unwrap()
        .await
        .expect("client connection");
    let (_ctrl, _fec) = handshake_client(&conn, &cfg)
        .await
        .expect("client handshake");

    // A datagram must fit under the peer's advertised max.
    assert!(conn.max_datagram_size().unwrap_or(0) >= 32);
    let payload = Bytes::from_static(b"a raptorq symbol payload");
    conn.send_datagram(payload.clone()).expect("send datagram");

    let echoed = conn.read_datagram().await.expect("read echo");
    assert_eq!(echoed, payload, "datagram must round-trip intact");

    server.await.unwrap();
}
