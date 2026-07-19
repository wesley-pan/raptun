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
    /// Maximum number of concurrent QUIC bidirectional streams the peer may
    /// have open at once. Each live tunnel holds one bidi (signaling) stream
    /// for the whole life of its local TCP connection, so this directly caps
    /// how many tunnels can be active simultaneously. Quinn's own default is
    /// only 100; a browser streaming video easily exceeds that (CDN segments,
    /// page, ads, analytics keep-alives), at which point `open_bi()` blocks
    /// until an old stream closes — the "new streams stall until a timeout"
    /// symptom. Raptun raises it well above that.
    pub max_concurrent_streams: u32,
    pub socket_buffer: u32,
    pub keepalive: Option<Duration>,
    pub idle_timeout: Duration,
    /// How long the server waits for a TCP connection to its forwarding target
    /// before giving up on one tunnel. Without a bound, an unreachable target
    /// leaves each tunnel's `connect()` parked on the OS default (~130 s on
    /// Linux) while its QUIC stream stays open, so tunnels pile up
    /// (`active_tunnels` climbs) and the client waits with no error. On timeout
    /// the server resets that stream so the client's side unwinds promptly.
    /// Server-only; ignored by the client.
    pub target_connect_timeout: Duration,
    pub allow_migration: bool,
    pub allow_0rtt: bool,
    pub dscp: u8,
    /// QUIC packet-reordering threshold for loss detection (Quinn
    /// `packet_threshold`). Raised from Quinn's default of 3 so that a shaped
    /// link spreading adjacent packets across a wide delay window (e.g. the
    /// stress relay's per-packet jitter) does not misclassify late-but-arriving
    /// packets as lost - the misclassification triggers black-hole detection
    /// and cwnd collapse, which is the root cause of the spurious high loss_pct
    /// and throughput collapse observed under reordering. Higher = slower
    /// real-loss detection; 8 is a measured balance for ~100 ms jitter links.
    pub reorder_packet_threshold: u32,
    /// Fraction-of-RTT time-based loss threshold (Quinn `time_threshold`).
    /// Raised from 1.125 to 2.0 so a packet delayed beyond ~1 RTT is not
    /// declared lost - same rationale as `reorder_packet_threshold`.
    pub reorder_time_threshold: f32,
    /// Persistent-congestion threshold (Quinn
    /// `persistent_congestion_threshold`). Raised from 3 to 5 to avoid
    /// declaring persistent congestion (which slashes the cwnd to the floor)
    /// during a burst of reordering-induced spurious loss.
    pub persistent_congestion_threshold: u32,
    /// Floor on the path MTU (Quinn `min_mtu`); guards against MTU black-hole
    /// detection forcing the cwnd to minimum on a link that simply reorders.
    pub min_mtu: u16,
    /// Override Quinn's initial RTT estimate. `None` keeps Quinn's default;
    /// `Some(d)` raises the initial grace window on high-latency links where
    /// the default 33 ms makes early loss detection too aggressive.
    pub initial_rtt: Option<Duration>,
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
            max_concurrent_streams: 1024,
            socket_buffer: 4 * 1024 * 1024,
            keepalive: Some(Duration::from_secs(10)),
            idle_timeout: Duration::from_secs(30),
            target_connect_timeout: Duration::from_secs(10),
            allow_migration: true,
            allow_0rtt: true,
            dscp: 0,
            reorder_packet_threshold: 8,
            reorder_time_threshold: 2.0,
            persistent_congestion_threshold: 5,
            min_mtu: 1200,
            initial_rtt: None,
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
