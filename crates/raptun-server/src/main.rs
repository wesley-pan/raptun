//! `raptun-server` entry point.
//!
//! Parses the CLI, builds the TLS identity (self-signed or PEM), and runs the
//! server accept/forward loop.

mod cli;

use std::net::ToSocketAddrs;

use clap::{CommandFactory, FromArgMatches};
use cli::Cli;
use raptun_core::tls::ServerIdentity;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let matches = Cli::command().get_matches();
    let mut args = Cli::from_arg_matches(&matches)?;
    args.merge_file(&matches)?;
    init_tracing(&args.log_level, args.quiet);

    let config = args.to_runtime_config();

    let bind = args
        .listen
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve --listen {}", args.listen))?;

    // Phase-1 requires a fixed target (plain-TCP forward mode).
    let target_str = args
        .target
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--target is required in the current (TCP) mode"))?;
    let target = target_str
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve --target {target_str}"))?;

    // Build the server's TLS identity.
    let identity = if args.self_signed {
        let id = ServerIdentity::generate_self_signed("raptun")?;
        tracing::info!(fingerprint = %id.fingerprint_hex, "generated self-signed certificate");
        id
    } else {
        let cert_path = args
            .cert
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("provide --self-signed, or --cert and --key"))?;
        let key_path = args
            .key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--cert requires --key"))?;
        let cert_pem = std::fs::read(cert_path)?;
        let key_pem = std::fs::read(key_path)?;
        ServerIdentity::load_pem(&cert_pem, &key_pem)?
    };

    tracing::info!(
        listen = %bind,
        target = %target,
        fec = ?config.fec.scheme,
        fec_max = args.fec_max,
        cc = ?config.transport.congestion,
        max_conns = args.max_conns,
        "raptun-server starting"
    );

    raptun_core::run_server(config, bind, target, identity).await?;
    Ok(())
}

fn init_tracing(level: &str, quiet: bool) {
    if quiet {
        return;
    }
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
