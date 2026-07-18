//! `raptun-client` entry point.
//!
//! Parses the CLI, resolves the [`RuntimeConfig`] and server trust, and runs the
//! client tunnel loop.

mod cli;

use std::net::ToSocketAddrs;

use clap::{CommandFactory, FromArgMatches};
use cli::{Cli, ListenMode as CliListenMode};
use raptun_core::run::ListenMode;
use raptun_core::tls::ServerTrust;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let matches = Cli::command().get_matches();
    let mut args = Cli::from_arg_matches(&matches)?;
    args.merge_file(&matches)?;
    init_tracing(&args.log_level, args.quiet);

    let config = args.to_runtime_config();

    // Resolve listen + server addresses.
    let local_addr = args
        .localaddr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve --localaddr {}", args.localaddr))?;
    let remoteaddr = args.remoteaddr.as_ref().ok_or_else(|| {
        anyhow::anyhow!("--remoteaddr is required (pass -r or set it in --config)")
    })?;
    let server_addr = remoteaddr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve --remoteaddr {remoteaddr}"))?;

    // Decide how to trust the server certificate.
    let trust = if args.insecure {
        tracing::warn!("--insecure: server certificate verification disabled (MITM risk)");
        ServerTrust::Insecure
    } else if let Some(fp) = &args.fingerprint {
        ServerTrust::Fingerprint(fp.clone())
    } else if args.cert.is_some() {
        // Loading a pinned CA/cert file is a Phase-4 nicety; for now require a
        // fingerprint or --insecure, which covers the self-signed tunnel model.
        anyhow::bail!("--cert file trust is not yet wired; use --fingerprint or --insecure");
    } else {
        anyhow::bail!("no server trust configured: pass --fingerprint <hex> or --insecure");
    };

    let mode = match args.listen_mode {
        CliListenMode::Tcp => ListenMode::Tcp,
        CliListenMode::Socks5 => ListenMode::Socks5,
    };

    tracing::info!(
        local = %local_addr,
        remote = %server_addr,
        fec = ?config.fec.scheme,
        cc = ?config.transport.congestion,
        datagrams = config.transport.use_datagrams,
        "raptun-client starting"
    );

    raptun_core::run_client(config, local_addr, server_addr, &args.sni, trust, mode).await?;
    Ok(())
}

/// Initialize `tracing` from the requested level, unless `--quiet`.
fn init_tracing(level: &str, quiet: bool) {
    if quiet {
        return;
    }
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
