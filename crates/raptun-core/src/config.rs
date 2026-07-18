//! Resolved runtime configuration shared by client and server.
//!
//! The binaries build these structs by merging, in precedence order,
//! **CLI flags > environment > config file > defaults**. By the time a value
//! reaches core it is already resolved and validated — core never re-reads the
//! environment or the file.

use std::time::Duration;

use raptun_fec::strategy::{RepairRatio, StrategyConfig};
use raptun_proto::control::FecParams;

/// Which forward-error-correction scheme to run on the datagram path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FecScheme {
    /// No FEC: data rides reliable QUIC streams (Phase-1 baseline / escape hatch).
    Off,
    /// RaptorQ fountain code (the default, full design).
    RaptorQ,
    /// Simple XOR parity — a cheap fallback earmarked for ultra-low-latency
    /// profiles where even small-block RaptorQ CPU cost is too high. Stubbed.
    Xor,
}

/// How the repair ratio is chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FecMode {
    /// Ratio adapts to live link telemetry (recommended, the design's edge).
    Adaptive,
    /// Ratio is pinned to `FecConfig::initial_ratio` (debug/benchmarking).
    Fixed,
}

/// FEC configuration.
#[derive(Debug, Clone)]
pub struct FecConfig {
    pub scheme: FecScheme,
    pub mode: FecMode,
    /// Starting / fixed repair ratio.
    pub initial_ratio: RepairRatio,
    /// Adaptive controller bounds and gains.
    pub strategy: StrategyConfig,
    /// RaptorQ symbol payload size in bytes (datagram MTU minus header).
    pub symbol_size: u16,
    /// Source block size K, or `None` for auto (derive from RTT).
    pub block_size: Option<u16>,
    /// Fraction of cwnd that in-flight repair may occupy (the budget brake).
    pub repair_cwnd_fraction: f64,
}

impl FecConfig {
    /// The initial [`FecParams`] to advertise in the handshake.
    pub fn to_wire_params(&self) -> FecParams {
        FecParams {
            symbol_size: self.symbol_size,
            block_size: self.block_size.unwrap_or(0),
            repair_ppm: self.initial_ratio.as_ppm_thousandths(),
        }
    }
}

impl Default for FecConfig {
    fn default() -> Self {
        Self {
            scheme: FecScheme::RaptorQ,
            mode: FecMode::Adaptive,
            initial_ratio: RepairRatio::from_fraction(0.15),
            strategy: StrategyConfig::default(),
            symbol_size: 1200,
            block_size: None,
            repair_cwnd_fraction: 0.40,
        }
    }
}

/// Congestion-control algorithm selection for Quinn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionControl {
    Bbr,
    Cubic,
    NewReno,
}

/// QUIC transport tuning.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub congestion: CongestionControl,
    /// Max UDP payload (governs datagram size and thus symbol size).
    pub mtu: u16,
    /// Route business data over unreliable datagrams + FEC (`true`, default) or
    /// fall back to reliable streams (`false`, disables FEC).
    pub use_datagrams: bool,
    pub stream_recv_window: u64,
    pub conn_recv_window: u64,
    pub socket_buffer: u32,
    pub keepalive: Option<Duration>,
    pub idle_timeout: Duration,
    pub allow_migration: bool,
    pub allow_0rtt: bool,
    pub dscp: u8,
    /// Interval for the client's periodic connection-status heartbeat log
    /// (RTT / cwnd / loss / active tunnels), or `None` to disable it. This is a
    /// liveness signal at `info` level: a healthy tunnel is otherwise silent
    /// after startup, so operators see no rolling output confirming it works.
    pub heartbeat: Option<Duration>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            congestion: CongestionControl::Bbr,
            mtu: 1350,
            use_datagrams: true,
            stream_recv_window: 2 * 1024 * 1024,
            conn_recv_window: 16 * 1024 * 1024,
            socket_buffer: 4 * 1024 * 1024,
            keepalive: Some(Duration::from_secs(10)),
            idle_timeout: Duration::from_secs(30),
            allow_migration: true,
            allow_0rtt: true,
            dscp: 0,
            heartbeat: Some(Duration::from_secs(30)),
        }
    }
}

/// The complete resolved configuration for a running client or server.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub fec: FecConfig,
    pub transport: TransportConfig,
    /// App-level shared secret (authentication, not encryption). `None` allows
    /// anonymous clients (server side) or sends no token (client side).
    pub psk: Option<String>,
}
