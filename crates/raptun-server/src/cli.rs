//! `raptun-server` command-line interface.
//!
//! Mirrors the client's transport/FEC flags (both ends must agree on symbol
//! size and broadly on windows) and adds server-specific concerns: the TLS
//! identity, client-auth mode, a `--fec-max` *ceiling* that clamps whatever
//! ratio a client requests (so a misbehaving client can't amplify traffic), and
//! resource limits.

use std::time::Duration;

use clap::{ArgMatches, Parser, ValueEnum};
use raptun_core::config::{
    CongestionControl, FecConfig, FecMode, FecScheme, RuntimeConfig, TransportConfig,
};
use raptun_fec::strategy::{RepairRatio, StrategyConfig};
use serde::Deserialize;

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

/// File-backed configuration, mirroring the TOML in `raptun-server.example.toml`.
///
/// Every field is optional: a file value fills the matching CLI field only when
/// that field was left at its default (not given on the command line or via an
/// environment variable), realizing `CLI > env > file > default`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FileConfig {
    pub listen: Option<String>,
    pub target: Option<String>,
    pub psk: Option<String>,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub self_signed: Option<bool>,
    pub client_auth: Option<String>,
    pub metrics: Option<String>,
    pub pprof: Option<String>,
    pub log_level: Option<String>,
    pub quiet: Option<bool>,
    pub max_conns: Option<u32>,
    #[serde(default)]
    pub fec: FileFec,
    #[serde(default)]
    pub transport: FileTransport,
}

/// `[fec]` section of the server config file.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FileFec {
    pub scheme: Option<String>,
    pub max: Option<f64>,
    pub symbol_size: Option<u16>,
}

/// `[transport]` section of the server config file.
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

/// Parse a config-file string into a clap [`ValueEnum`], mapping failures to a
/// clear error naming the offending key.
fn parse_enum<T: ValueEnum>(value: &str, key: &str) -> anyhow::Result<T> {
    T::from_str(value, true)
        .map_err(|_| anyhow::anyhow!("invalid value {value:?} for config key `{key}`"))
}

impl Cli {
    /// Overlay values from a `--config` file onto fields the user did not set
    /// explicitly on the command line or through an environment variable.
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
    /// Split out from [`Cli::merge_file`] so it is testable without I/O.
    fn merge_parsed(&mut self, file: FileConfig, matches: &ArgMatches) -> anyhow::Result<()> {
        let from_default = |id: &str| {
            !matches!(
                matches.value_source(id),
                Some(clap::parser::ValueSource::CommandLine)
                    | Some(clap::parser::ValueSource::EnvVariable)
            )
        };

        if from_default("listen") {
            if let Some(v) = file.listen {
                self.listen = v;
            }
        }
        if from_default("target") {
            if let Some(v) = file.target {
                self.target = Some(v);
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
        if from_default("key") {
            if let Some(v) = file.key {
                self.key = Some(v);
            }
        }
        if from_default("self_signed") {
            if let Some(v) = file.self_signed {
                self.self_signed = v;
            }
        }
        if from_default("client_auth") {
            if let Some(v) = file.client_auth {
                self.client_auth = parse_enum::<ClientAuth>(&v, "client_auth")?;
            }
        }
        if from_default("metrics") {
            if let Some(v) = file.metrics {
                self.metrics = Some(v);
            }
        }
        if from_default("pprof") {
            if let Some(v) = file.pprof {
                self.pprof = Some(v);
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
        if from_default("max_conns") {
            if let Some(v) = file.max_conns {
                self.max_conns = v;
            }
        }

        // [fec]
        if from_default("fec") {
            if let Some(v) = file.fec.scheme {
                self.fec = parse_enum::<FecSchemeArg>(&v, "fec.scheme")?;
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
            max_concurrent_streams: self.max_streams,
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, FromArgMatches};

    /// Parse argv into `(Cli, ArgMatches)`, then merge a TOML string as if from
    /// `--config`. Exercises the real precedence logic without I/O.
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
            &["raptun-server"],
            "target = \"127.0.0.1:8080\"\nmax_conns = 200\n",
        );
        assert_eq!(cli.target.as_deref(), Some("127.0.0.1:8080"));
        assert_eq!(cli.max_conns, 200);
    }

    #[test]
    fn cli_overrides_file() {
        let cli = merged(
            &["raptun-server", "--max-conns", "999"],
            "max_conns = 200\n",
        );
        assert_eq!(cli.max_conns, 999, "explicit CLI flag must beat the file");
    }

    #[test]
    fn transport_and_fec_sections() {
        let cli = merged(
            &["raptun-server"],
            "[fec]\nmax = 0.3\nsymbol_size = 1100\n[transport]\nzero_rtt = false\nmtu = 1400\n",
        );
        assert_eq!(cli.fec_max, 0.3);
        assert_eq!(cli.symbol_size, 1100);
        assert!(!cli.zero_rtt);
        assert_eq!(cli.mtu, 1400);
    }

    #[test]
    fn client_auth_enum_parsing() {
        let cli = merged(&["raptun-server"], "client_auth = \"mtls\"\n");
        assert!(matches!(cli.client_auth, ClientAuth::Mtls));
    }
}
