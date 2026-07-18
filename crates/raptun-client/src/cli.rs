//! `raptun-client` command-line interface.
//!
//! Flag names deliberately echo kcptun (`-l`/`-r`, `--mtu`, `--sockbuf`, …) so
//! existing users have near-zero relearning, while the FEC and QUIC-specific
//! flags express Raptun's added capabilities. See the design doc for the full
//! kcptun→Raptun parameter mapping and per-flag impact.

use std::time::Duration;

use clap::{Parser, ValueEnum};
use raptun_core::config::{
    CongestionControl, FecConfig, FecMode, FecScheme, RuntimeConfig, TransportConfig,
};
use raptun_fec::strategy::{RepairRatio, StrategyConfig};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ListenMode {
    /// Plain TCP forward: everything accepted goes to the server's `--target`.
    Tcp,
    /// SOCKS5 proxy: the client learns each connection's destination via SOCKS5.
    Socks5,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum FecSchemeArg {
    Off,
    Raptorq,
    Xor,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum FecModeArg {
    Adaptive,
    Fixed,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CcArg {
    Bbr,
    Cubic,
    Newreno,
}

/// Raptun client — QUIC + RaptorQ tunnel endpoint (local side).
#[derive(Debug, Parser)]
#[command(name = "raptun-client", version, about)]
pub struct Cli {
    // ---- Connectivity ----------------------------------------------------
    /// Local address to listen on for incoming connections.
    #[arg(short = 'l', long, default_value = "127.0.0.1:12948")]
    pub localaddr: String,

    /// Raptun server address (UDP).
    #[arg(short = 'r', long)]
    pub remoteaddr: String,

    /// How the local listener interprets connections.
    #[arg(long, value_enum, default_value_t = ListenMode::Tcp)]
    pub listen_mode: ListenMode,

    // ---- Security (replaces kcptun --key/--crypt) ------------------------
    /// Pre-shared key for *application-level auth* (NOT encryption; QUIC/TLS
    /// already encrypts). Read from $RAPTUN_PSK if the flag is omitted.
    #[arg(long, env = "RAPTUN_PSK")]
    pub psk: Option<String>,

    /// Trusted server certificate (PEM). Mutually exclusive with --fingerprint.
    #[arg(long, conflicts_with = "fingerprint")]
    pub cert: Option<String>,

    /// Trusted server certificate SHA-256 fingerprint (hex) — trust-on-first-use.
    #[arg(long)]
    pub fingerprint: Option<String>,

    /// Skip certificate verification. TESTING ONLY — enables MITM.
    #[arg(long, default_value_t = false)]
    pub insecure: bool,

    /// TLS SNI presented to the server.
    #[arg(long, default_value = "raptun")]
    pub sni: String,

    // ---- FEC (replaces kcptun --datashard/--parityshard) -----------------
    /// FEC scheme on the datagram data path.
    #[arg(long, value_enum, default_value_t = FecSchemeArg::Raptorq)]
    pub fec: FecSchemeArg,

    /// Whether the repair ratio adapts to the link or stays fixed.
    #[arg(long, value_enum, default_value_t = FecModeArg::Adaptive)]
    pub fec_mode: FecModeArg,

    /// Repair overhead for `--fec-mode fixed` (fraction, e.g. 0.15 = 15%).
    #[arg(long, default_value_t = 0.15)]
    pub fec_ratio: f64,

    /// Adaptive lower bound on repair overhead.
    #[arg(long, default_value_t = 0.02)]
    pub fec_min: f64,

    /// Adaptive upper bound on repair overhead.
    #[arg(long, default_value_t = 0.50)]
    pub fec_max: f64,

    /// RaptorQ symbol size in bytes.
    #[arg(long, default_value_t = 1200)]
    pub symbol_size: u16,

    /// Source block size K in symbols; omit for auto (derive from RTT).
    #[arg(long)]
    pub block_size: Option<u16>,

    // ---- Transport (QUIC) ------------------------------------------------
    /// Congestion controller.
    #[arg(long, value_enum, default_value_t = CcArg::Bbr)]
    pub cc: CcArg,

    /// Max UDP payload in bytes (bounds datagram/symbol size).
    #[arg(long, default_value_t = 1350)]
    pub mtu: u16,

    /// Route business data over unreliable datagrams + FEC. Set false to fall
    /// back to reliable QUIC streams (disables FEC; Phase-1 baseline).
    #[arg(long, default_value_t = true)]
    pub datagram: bool,

    /// Per-stream receive window (bytes).
    #[arg(long, default_value_t = 2 * 1024 * 1024)]
    pub stream_rwnd: u64,

    /// Connection-level receive window (bytes).
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    pub conn_rwnd: u64,

    /// Maximum concurrent tunnelled streams (QUIC bidi streams) per connection.
    /// Each live tunnel holds one, so this caps simultaneous tunnels. The QUIC
    /// default of 100 is easily exceeded by browser traffic, causing new
    /// connections to stall until an old stream closes.
    #[arg(long, default_value_t = 1024)]
    pub max_streams: u32,

    /// UDP socket buffer size (bytes).
    #[arg(long, default_value_t = 4 * 1024 * 1024)]
    pub sockbuf: u32,

    /// Keep-alive interval in seconds; 0 disables.
    #[arg(long, default_value_t = 10)]
    pub keepalive: u64,

    /// Interval in seconds for the periodic connection-status heartbeat log
    /// (RTT/cwnd/loss/active tunnels); 0 disables. A healthy tunnel is otherwise
    /// silent after startup, so this confirms liveness at the default log level.
    #[arg(long, default_value_t = 30)]
    pub heartbeat: u64,

    /// Idle timeout in seconds before an idle connection is dropped.
    #[arg(long, default_value_t = 30)]
    pub idle_timeout: u64,

    /// Allow QUIC connection migration (survives client IP changes).
    #[arg(long, default_value_t = true)]
    pub migration: bool,

    /// Allow 0-RTT resumption on reconnect.
    #[arg(long = "0rtt", default_value_t = true)]
    pub zero_rtt: bool,

    /// DSCP marking on outbound packets.
    #[arg(long, default_value_t = 0)]
    pub dscp: u8,

    // ---- Ops -------------------------------------------------------------
    /// TOML/JSON config file. CLI flags override file values.
    #[arg(short = 'c', long)]
    pub config: Option<String>,

    /// Prometheus metrics endpoint (host:port).
    #[arg(long)]
    pub metrics: Option<String>,

    /// Log level: error|warn|info|debug|trace.
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Suppress non-error output.
    #[arg(long, default_value_t = false)]
    pub quiet: bool,
}

impl Cli {
    /// Fold the parsed CLI into the core [`RuntimeConfig`].
    ///
    /// Precedence (CLI > env > file > default) is realized by clap's `env`
    /// hooks plus an explicit merge pass over `--config` that Phase-1 wiring
    /// will add here; for now the CLI/env/default layers are honored.
    pub fn to_runtime_config(&self) -> RuntimeConfig {
        let scheme = match self.fec {
            FecSchemeArg::Off => FecScheme::Off,
            FecSchemeArg::Raptorq => FecScheme::RaptorQ,
            FecSchemeArg::Xor => FecScheme::Xor,
        };
        let mode = match self.fec_mode {
            FecModeArg::Adaptive => FecMode::Adaptive,
            FecModeArg::Fixed => FecMode::Fixed,
        };
        let congestion = match self.cc {
            CcArg::Bbr => CongestionControl::Bbr,
            CcArg::Cubic => CongestionControl::Cubic,
            CcArg::Newreno => CongestionControl::NewReno,
        };

        let fec = FecConfig {
            scheme,
            mode,
            initial_ratio: RepairRatio::from_fraction(self.fec_ratio),
            strategy: StrategyConfig {
                min: RepairRatio::from_fraction(self.fec_min),
                max: RepairRatio::from_fraction(self.fec_max),
                ..StrategyConfig::default()
            },
            symbol_size: self.symbol_size,
            block_size: self.block_size,
            repair_cwnd_fraction: 0.40,
        };

        let transport = TransportConfig {
            congestion,
            mtu: self.mtu,
            use_datagrams: self.datagram,
            stream_recv_window: self.stream_rwnd,
            conn_recv_window: self.conn_rwnd,
            max_concurrent_streams: self.max_streams,
            socket_buffer: self.sockbuf,
            keepalive: (self.keepalive > 0).then(|| Duration::from_secs(self.keepalive)),
            idle_timeout: Duration::from_secs(self.idle_timeout),
            allow_migration: self.migration,
            allow_0rtt: self.zero_rtt,
            dscp: self.dscp,
            heartbeat: (self.heartbeat > 0).then(|| Duration::from_secs(self.heartbeat)),
        };

        RuntimeConfig {
            fec,
            transport,
            psk: self.psk.clone(),
        }
    }
}
