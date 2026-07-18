//! `raptun-client` command-line interface.
//!
//! Flag names deliberately echo kcptun (`-l`/`-r`, `--mtu`, `--sockbuf`, …) so
//! existing users have near-zero relearning, while the FEC and QUIC-specific
//! flags express Raptun's added capabilities. See the design doc for the full
//! kcptun→Raptun parameter mapping and per-flag impact.

use std::time::Duration;

use clap::{ArgMatches, Parser, ValueEnum};
use raptun_core::config::{
    CongestionControl, FecConfig, FecMode, FecScheme, RuntimeConfig, TransportConfig,
};
use raptun_fec::strategy::{RepairRatio, StrategyConfig};
use serde::Deserialize;

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

    /// Raptun server address (UDP). Required, but may come from `--config`
    /// instead of the command line.
    #[arg(short = 'r', long)]
    pub remoteaddr: Option<String>,

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

/// File-backed configuration, mirroring the TOML in `raptun-client.example.toml`.
///
/// Every field is optional: a value present in the file fills the corresponding
/// CLI field *only* when that field was left at its default (i.e. not given on
/// the command line or via an environment variable). This realizes the
/// documented precedence `CLI > env > file > default`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FileConfig {
    pub localaddr: Option<String>,
    pub remoteaddr: Option<String>,
    pub listen_mode: Option<String>,
    pub psk: Option<String>,
    pub cert: Option<String>,
    pub fingerprint: Option<String>,
    pub insecure: Option<bool>,
    pub sni: Option<String>,
    pub metrics: Option<String>,
    pub log_level: Option<String>,
    pub quiet: Option<bool>,
    #[serde(default)]
    pub fec: FileFec,
    #[serde(default)]
    pub transport: FileTransport,
}

/// `[fec]` section of the client config file.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FileFec {
    pub scheme: Option<String>,
    pub mode: Option<String>,
    pub ratio: Option<f64>,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub symbol_size: Option<u16>,
    pub block_size: Option<u16>,
}

/// `[transport]` section of the client config file.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FileTransport {
    pub cc: Option<String>,
    pub mtu: Option<u16>,
    pub datagram: Option<bool>,
    pub stream_rwnd: Option<u64>,
    pub conn_rwnd: Option<u64>,
    pub max_streams: Option<u32>,
    pub sockbuf: Option<u32>,
    pub keepalive: Option<u64>,
    pub idle_timeout: Option<u64>,
    pub heartbeat: Option<u64>,
    pub migration: Option<bool>,
    pub zero_rtt: Option<bool>,
    pub dscp: Option<u8>,
}

/// Resolve a possibly-`env:`-prefixed secret. `"env:FOO"` reads `$FOO`; any
/// other value is returned verbatim.
fn resolve_secret(raw: String) -> Option<String> {
    if let Some(var) = raw.strip_prefix("env:") {
        std::env::var(var).ok()
    } else {
        Some(raw)
    }
}

impl Cli {
    /// Overlay values from a `--config` file onto fields the user did not set
    /// explicitly on the command line or through an environment variable.
    ///
    /// `matches` is the same [`ArgMatches`] that produced `self`; its
    /// [`clap::parser::ValueSource`] per argument is what lets us honor
    /// `CLI > env > file > default`.
    pub fn merge_file(&mut self, matches: &ArgMatches) -> anyhow::Result<()> {
        let Some(path) = self.config.clone() else {
            return Ok(());
        };
        let text = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("reading --config {path}: {e}"))?;
        let file: FileConfig =
            toml::from_str(&text).map_err(|e| anyhow::anyhow!("parsing --config {path}: {e}"))?;
        self.merge_parsed(file, matches)
    }

    /// Apply an already-parsed [`FileConfig`], honoring per-field precedence.
    /// Split out from [`Cli::merge_file`] so it is testable without touching the
    /// filesystem.
    fn merge_parsed(&mut self, file: FileConfig, matches: &ArgMatches) -> anyhow::Result<()> {
        // A field should take the file value only if the CLI left it at default.
        let from_default = |id: &str| {
            !matches!(
                matches.value_source(id),
                Some(clap::parser::ValueSource::CommandLine)
                    | Some(clap::parser::ValueSource::EnvVariable)
            )
        };

        if from_default("localaddr") {
            if let Some(v) = file.localaddr {
                self.localaddr = v;
            }
        }
        if from_default("remoteaddr") {
            if let Some(v) = file.remoteaddr {
                self.remoteaddr = Some(v);
            }
        }
        if from_default("listen_mode") {
            if let Some(v) = file.listen_mode {
                self.listen_mode = parse_enum::<ListenMode>(&v, "listen_mode")?;
            }
        }
        if from_default("psk") {
            if let Some(v) = file.psk {
                self.psk = resolve_secret(v);
            }
        }
        if from_default("cert") {
            if let Some(v) = file.cert {
                self.cert = Some(v);
            }
        }
        if from_default("fingerprint") {
            if let Some(v) = file.fingerprint {
                self.fingerprint = Some(v);
            }
        }
        if from_default("insecure") {
            if let Some(v) = file.insecure {
                self.insecure = v;
            }
        }
        if from_default("sni") {
            if let Some(v) = file.sni {
                self.sni = v;
            }
        }
        if from_default("metrics") {
            if let Some(v) = file.metrics {
                self.metrics = Some(v);
            }
        }
        if from_default("log_level") {
            if let Some(v) = file.log_level {
                self.log_level = v;
            }
        }
        if from_default("quiet") {
            if let Some(v) = file.quiet {
                self.quiet = v;
            }
        }

        // [fec]
        if from_default("fec") {
            if let Some(v) = file.fec.scheme {
                self.fec = parse_enum::<FecSchemeArg>(&v, "fec.scheme")?;
            }
        }
        if from_default("fec_mode") {
            if let Some(v) = file.fec.mode {
                self.fec_mode = parse_enum::<FecModeArg>(&v, "fec.mode")?;
            }
        }
        if from_default("fec_ratio") {
            if let Some(v) = file.fec.ratio {
                self.fec_ratio = v;
            }
        }
        if from_default("fec_min") {
            if let Some(v) = file.fec.min {
                self.fec_min = v;
            }
        }
        if from_default("fec_max") {
            if let Some(v) = file.fec.max {
                self.fec_max = v;
            }
        }
        if from_default("symbol_size") {
            if let Some(v) = file.fec.symbol_size {
                self.symbol_size = v;
            }
        }
        if from_default("block_size") {
            if let Some(v) = file.fec.block_size {
                self.block_size = Some(v);
            }
        }

        // [transport]
        if from_default("cc") {
            if let Some(v) = file.transport.cc {
                self.cc = parse_enum::<CcArg>(&v, "transport.cc")?;
            }
        }
        if from_default("mtu") {
            if let Some(v) = file.transport.mtu {
                self.mtu = v;
            }
        }
        if from_default("datagram") {
            if let Some(v) = file.transport.datagram {
                self.datagram = v;
            }
        }
        if from_default("stream_rwnd") {
            if let Some(v) = file.transport.stream_rwnd {
                self.stream_rwnd = v;
            }
        }
        if from_default("conn_rwnd") {
            if let Some(v) = file.transport.conn_rwnd {
                self.conn_rwnd = v;
            }
        }
        if from_default("max_streams") {
            if let Some(v) = file.transport.max_streams {
                self.max_streams = v;
            }
        }
        if from_default("sockbuf") {
            if let Some(v) = file.transport.sockbuf {
                self.sockbuf = v;
            }
        }
        if from_default("keepalive") {
            if let Some(v) = file.transport.keepalive {
                self.keepalive = v;
            }
        }
        if from_default("idle_timeout") {
            if let Some(v) = file.transport.idle_timeout {
                self.idle_timeout = v;
            }
        }
        if from_default("heartbeat") {
            if let Some(v) = file.transport.heartbeat {
                self.heartbeat = v;
            }
        }
        if from_default("migration") {
            if let Some(v) = file.transport.migration {
                self.migration = v;
            }
        }
        if from_default("zero_rtt") {
            if let Some(v) = file.transport.zero_rtt {
                self.zero_rtt = v;
            }
        }
        if from_default("dscp") {
            if let Some(v) = file.transport.dscp {
                self.dscp = v;
            }
        }

        Ok(())
    }

    /// Fold the parsed CLI into the core [`RuntimeConfig`].
    ///
    /// Precedence (CLI > env > file > default) is realized by clap's `env`
    /// hooks plus the [`Cli::merge_file`] pass, which must have already run.
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

/// Parse a config-file string into a clap [`ValueEnum`], mapping failures to a
/// clear error naming the offending key.
fn parse_enum<T: ValueEnum>(value: &str, key: &str) -> anyhow::Result<T> {
    T::from_str(value, true)
        .map_err(|_| anyhow::anyhow!("invalid value {value:?} for config key `{key}`"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, FromArgMatches};

    /// Parse argv into `(Cli, ArgMatches)`, then merge a TOML string as if it
    /// came from `--config`. Exercises the real precedence logic without I/O.
    fn merged(argv: &[&str], toml: &str) -> Cli {
        let matches = Cli::command().get_matches_from(argv);
        let mut cli = Cli::from_arg_matches(&matches).unwrap();
        let file: FileConfig = toml::from_str(toml).unwrap();
        cli.merge_parsed(file, &matches).unwrap();
        cli
    }

    #[test]
    fn file_fills_unset_fields() {
        let cli = merged(
            &["raptun-client", "-r", "10.0.0.1:29900"],
            "sni = \"example\"\n",
        );
        assert_eq!(cli.sni, "example", "file value must fill an unset field");
    }

    #[test]
    fn cli_overrides_file() {
        let cli = merged(
            &["raptun-client", "-r", "10.0.0.1:29900", "--sni", "from-cli"],
            "sni = \"from-file\"\n",
        );
        assert_eq!(cli.sni, "from-cli", "explicit CLI flag must beat the file");
    }

    #[test]
    fn transport_section_and_zero_rtt_id() {
        // `zero_rtt` has the flag name `0rtt`; verify the arg id used by
        // `value_source` matches the struct field so the merge actually applies.
        let cli = merged(
            &["raptun-client", "-r", "10.0.0.1:29900"],
            "[transport]\nzero_rtt = false\nheartbeat = 7\nmtu = 1400\n",
        );
        assert!(!cli.zero_rtt, "file [transport].zero_rtt must apply");
        assert_eq!(cli.heartbeat, 7);
        assert_eq!(cli.mtu, 1400);
    }

    #[test]
    fn fec_section_enum_parsing() {
        let cli = merged(
            &["raptun-client", "-r", "10.0.0.1:29900"],
            "[fec]\nmode = \"fixed\"\nratio = 0.25\n",
        );
        assert!(matches!(cli.fec_mode, FecModeArg::Fixed));
        assert_eq!(cli.fec_ratio, 0.25);
    }

    #[test]
    fn env_prefixed_psk_resolves() {
        // SAFETY: single-threaded test; set then read one process env var.
        std::env::set_var("RAPTUN_TEST_PSK_X", "sekret");
        let cli = merged(
            &["raptun-client", "-r", "10.0.0.1:29900"],
            "psk = \"env:RAPTUN_TEST_PSK_X\"\n",
        );
        assert_eq!(cli.psk.as_deref(), Some("sekret"));
        std::env::remove_var("RAPTUN_TEST_PSK_X");
    }
}
