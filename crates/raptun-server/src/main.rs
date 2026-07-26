//! `raptun-server` entry point.
//!
//! Parses the CLI, builds the TLS identity (self-signed or PEM), and runs the
//! server accept/forward loop.

mod cli;
mod monitor_ui;

use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;

use clap::{CommandFactory, FromArgMatches};
use cli::Cli;
use raptun_core::tls::ServerIdentity;
use raptun_core::TunnelRegistry;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let matches = Cli::command().get_matches();
    let mut args = Cli::from_arg_matches(&matches)?;
    args.merge_file(&matches)?;
    // In monitor mode the TUI owns stdout, so logs go to a file to avoid
    // corrupting the display; otherwise tracing writes to stdout as before.
    init_tracing(&args.log_level, args.quiet, args.monitor, &args.monitor_log);

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

    // With --monitor, publish a tunnel registry, run the server in the
    // background, and drive the TUI on a blocking thread (crossterm's event
    // reads block). Quitting the monitor ends the process.
    if args.monitor {
        let registry = TunnelRegistry::new();
        let ui_registry = Arc::clone(&registry);
        let interval = Duration::from_millis(args.monitor_interval.max(100));
        tokio::spawn(async move {
            if let Err(e) =
                raptun_core::run_server(config, bind, target, identity, Some(registry)).await
            {
                tracing::error!(error = %e, "server loop exited");
            }
        });
        tokio::task::spawn_blocking(move || monitor_ui::run(ui_registry, interval)).await??;
        return Ok(());
    }

    raptun_core::run_server(config, bind, target, identity, None).await?;
    Ok(())
}

fn init_tracing(level: &str, quiet: bool, monitor: bool, monitor_log: &str) {
    if quiet {
        return;
    }
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    // In monitor mode redirect logs to a file so they don't tear the TUI; a
    // Mutex<File> is a MakeWriter. If the file can't be opened, fall back to
    // stdout (better a scrambled display than silently losing all logs).
    if monitor {
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(monitor_log)
        {
            Ok(file) => {
                tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .with_ansi(false)
                    .with_writer(std::sync::Mutex::new(file))
                    .init();
                return;
            }
            Err(e) => {
                eprintln!("could not open monitor log {monitor_log}: {e}; logging to stdout");
            }
        }
    }
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
