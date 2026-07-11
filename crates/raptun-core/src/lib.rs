//! Raptun core: everything shared by the client and server binaries.
//!
//! Responsibilities:
//!
//! * [`config`] — the effective, validated runtime configuration (the merge of
//!   CLI flags, environment, and config file lives in the binaries; this is the
//!   resolved struct they hand to core).
//! * [`tls`] — QUIC/TLS setup: self-signed certificate generation, fingerprint
//!   pinning (trust-on-first-use), and the app-level PSK check. QUIC mandates
//!   TLS 1.3, so channel encryption is not something Raptun implements itself.
//! * [`endpoint`] — building the Quinn client/server [`quinn::Endpoint`] with
//!   Raptun's transport tuning (congestion controller, windows, datagrams,
//!   keep-alive, migration).
//! * [`telemetry`] — the translation from `quinn::Connection` stats into the
//!   FEC layer's [`raptun_fec::LinkState`], including the cross-tick congestion
//!   classifier that the FEC crate deliberately does not compute itself.
//! * [`session`] — per-connection primitives: control-stream framing, the
//!   Raptun handshake, bidirectional TCP tunnelling, datagram symbol transport,
//!   and the telemetry-driven [`session::Session`] control loop.
//! * [`run`] — the top-level client and server loops the binaries call.
//!
//! Phase-1 status: the reliable-stream tunnel path is fully wired to Quinn
//! (real TLS 1.3 handshake, control-stream framing, bidirectional forwarding);
//! see the loopback integration tests. The datagram + RaptorQ FEC data path
//! plugs into [`session`] alongside the baseline (Phase 2).

pub mod config;
pub mod endpoint;
pub mod fec;
pub mod run;
pub mod session;
pub mod telemetry;
pub mod tls;

pub use config::{FecConfig, RuntimeConfig, TransportConfig};
pub use run::{run_client, run_server, ListenMode};
pub use session::{Role, Session};

/// Crate-wide error type.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("TLS/certificate error: {0}")]
    Tls(String),

    #[error("QUIC endpoint error: {0}")]
    Endpoint(String),

    #[error("handshake rejected: {0}")]
    Handshake(String),

    #[error("protocol error: {0}")]
    Proto(#[from] raptun_proto::WireError),

    #[error("FEC error: {0}")]
    Fec(#[from] raptun_fec::FecError),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CoreError>;
