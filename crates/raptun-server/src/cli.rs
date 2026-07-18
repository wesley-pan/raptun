//! `raptun-server` command-line interface.
//!
//! Mirrors the client's transport/FEC flags (both ends must agree on symbol
//! size and broadly on windows) and adds server-specific concerns: the TLS
//! identity, client-auth mode, a `--fec-max` *ceiling* that clamps whatever
//! ratio a client requests (so a misbehaving client can't amplify traffic), and
//! resource limits.

use std::time::Duration;

use clap::{Parser, ValueEnum};
use raptun_core::config::{
    CongestionControl, FecConfig, FecMode, FecScheme, RuntimeConfig, TransportConfig,
};
use raptun_fec::strategy::{RepairRatio, StrategyConfig};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum FecSchemeArg {
    Off,
    Raptorq,
    Xor,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CcArg {
    Bbr,
    Cubic,
    Newreno,
}

/// How the server authenticates clients.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ClientAuth {
    /// No client auth (anyone who passes TLS may connect).
    None,
    /// Require a matching pre-shared key in the Hello.
    Psk,
    /// Mutual TLS (client presents a certificate).
    Mtls,
}

/// Raptun server — QUIC + RaptorQ tunnel terminator.
#[derive(Debug, Parser)]
#[command(name = "raptun-server", version, about)]
pub struct Cli {
    // ---- Connectivity ----------------------------------------------------
    /// UDP address to listen on.
    #[arg(short = 'l', long, default_value = "0.0.0.0:29900")]
    pub listen: String,

    /// Target service to forward tunnelled connections to (host:port). Used in
    /// plain-TCP mode; in SOCKS5 mode the client supplies per-connection targets.
    #[arg(short = 'r', long)]
    pub target: Option<String>,

    // ---- Security --------------------------------------------------------
    /// Pre-shared key clients must present (application-level auth).
    #[arg(long, env = "RAPTUN_PSK")]
    pub psk: Option<String>,

    /// Server certificate (PEM). With --key. Mutually exclusive with --self-signed.
    #[arg(long, conflicts_with = "self_signed")]
    pub cert: Option<String>,

    /// Server private key (PEM).
    #[arg(long)]
    pub key: Option<String>,

    /// Generate a self-signed certificate at startup and print its fingerprint
    /// for clients to pin.
    #[arg(long, default_value_t = false)]
    pub self_signed: bool,

    /// Client authentication mode.
    #[arg(long, value_enum, default_value_t = ClientAuth::Psk)]
    pub client_auth: ClientAuth,

    // ---- FEC (server-side ceiling) ---------------------------------------
    /// FEC scheme offered to clients.
    #[arg(long, value_enum, default_value_t = FecSchemeArg::Raptorq)]
    pub fec: FecSchemeArg,

    /// Maximum repair overhead the server will honor, regardless of what a
    /// client requests. The safety valve against traffic amplification.
    #[arg(long, default_value_t = 0.50)]
    pub fec_max: f64,

    /// RaptorQ symbol size in bytes (must match the client).
    #[arg(long, default_value_t = 1200)]
    pub symbol_size: u16,

    // ---- Transport (QUIC) — mirrors the client ---------------------------
    #[arg(long, value_enum, default_value_t = CcArg::Bbr)]
    pub cc: CcArg,

    #[arg(long, default_value_t = 1350)]
    pub mtu: u16,

    #[arg(long, default_value_t = true)]
    pub datagram: bool,

    #[arg(long, default_value_t = 2 * 1024 * 1024)]
    pub stream_rwnd: u64,

    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    pub conn_rwnd: u64,

    #[arg(long, default_value_t = 4 * 1024 * 1024)]
    pub sockbuf: u32,

    #[arg(long, default_value_t = 10)]
    pub keepalive: u64,

    #[arg(long, default_value_t = 30)]
    pub idle_timeout: u64,

    #[arg(long, default_value_t = true)]
    pub migration: bool,

    #[arg(long = "0rtt", default_value_t = true)]
    pub zero_rtt: bool,

    #[arg(long, default_value_t = 0)]
    pub dscp: u8,

    // ---- Server limits ---------------------------------------------------
    /// Maximum concurrent client connections.
    #[arg(long, default_value_t = 4096)]
    pub max_conns: u32,

    /// Maximum concurrent tunnelled streams per connection.
    #[arg(long, default_value_t = 1024)]
    pub max_streams: u32,

    // ---- Ops -------------------------------------------------------------
    #[arg(short = 'c', long)]
    pub config: Option<String>,

    #[arg(long)]
    pub metrics: Option<String>,

    /// Performance profiling endpoint (host:port).
    #[arg(long)]
    pub pprof: Option<String>,

    #[arg(long, default_value = "info")]
    pub log_level: String,

    #[arg(long, default_value_t = false)]
    pub quiet: bool,
}

impl Cli {
    /// Fold into the core [`RuntimeConfig`]. The server runs the FEC controller
    /// in adaptive mode but clamps the ratio to `--fec-max`; the client is the
    /// one that actually chooses ratios, so the server's `initial_ratio` is only
    /// a starting suggestion.
    pub fn to_runtime_config(&self) -> RuntimeConfig {
        let scheme = match self.fec {
            FecSchemeArg::Off => FecScheme::Off,
            FecSchemeArg::Raptorq => FecScheme::RaptorQ,
            FecSchemeArg::Xor => FecScheme::Xor,
        };
        let congestion = match self.cc {
            CcArg::Bbr => CongestionControl::Bbr,
            CcArg::Cubic => CongestionControl::Cubic,
            CcArg::Newreno => CongestionControl::NewReno,
        };

        let fec = FecConfig {
            scheme,
            mode: FecMode::Adaptive,
            initial_ratio: RepairRatio::from_fraction((self.fec_max * 0.3).min(self.fec_max)),
            strategy: StrategyConfig {
                // The server's max is the hard ceiling on client requests.
                max: RepairRatio::from_fraction(self.fec_max),
                ..StrategyConfig::default()
            },
            symbol_size: self.symbol_size,
            block_size: None,
            repair_cwnd_fraction: 0.40,
        };

        let transport = TransportConfig {
            congestion,
            mtu: self.mtu,
            use_datagrams: self.datagram,
            stream_recv_window: self.stream_rwnd,
            conn_recv_window: self.conn_rwnd,
            socket_buffer: self.sockbuf,
            keepalive: (self.keepalive > 0).then(|| Duration::from_secs(self.keepalive)),
            idle_timeout: Duration::from_secs(self.idle_timeout),
            allow_migration: self.migration,
            allow_0rtt: self.zero_rtt,
            dscp: self.dscp,
            // The heartbeat log is a client-side liveness aid; the server does
            // not emit it.
            heartbeat: None,
        };

        RuntimeConfig {
            fec,
            transport,
            psk: self.psk.clone(),
        }
    }
}
