#!/usr/bin/env python3
"""Resource + metrics sampler for the raptun stress test.

Samples the server and client processes' CPU% and RSS once per second via
psutil, and tails the client log for the periodic "tunnel alive" telemetry
(rtt_ms / cwnd_bytes / loss_pct / active_tunnels). Writes two CSVs with a shared
wall-clock timestamp so the report can align resource use against link metrics.

Usage:
  monitor.py <server_pid> <client_pid> <client_log> <secs> <res_csv> <metrics_csv>
"""
import re
import sys
import time

import psutil

# Matches lines like:
#   ... tunnel alive rtt_ms=12 cwnd_bytes=3644760 loss_pct="0.00" active_tunnels=13
ALIVE_RE = re.compile(
    r"tunnel alive.*?rtt_ms=(\d+).*?cwnd_bytes=(\d+).*?"
    r'loss_pct="([\d.]+)".*?active_tunnels=(\d+)'
)


def sample_proc(p: psutil.Process):
    try:
        with p.oneshot():
            cpu = p.cpu_percent(None)  # since last call; primed below
            rss = p.memory_info().rss
            nthreads = p.num_threads()
        return cpu, rss, nthreads
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def main():
    server_pid = int(sys.argv[1])
    client_pid = int(sys.argv[2])
    client_log = sys.argv[3]
    secs = int(sys.argv[4])
    res_csv = sys.argv[5]
    metrics_csv = sys.argv[6]

    srv = psutil.Process(server_pid)
    cli = psutil.Process(client_pid)
    # Prime cpu_percent so the first real sample is meaningful.
    srv.cpu_percent(None)
    cli.cpu_percent(None)

    res_f = open(res_csv, "w")
    res_f.write("t,srv_cpu,srv_rss_mb,srv_threads,cli_cpu,cli_rss_mb,cli_threads\n")
    met_f = open(metrics_csv, "w")
    met_f.write("t,rtt_ms,cwnd_bytes,loss_pct,active_tunnels\n")

    logf = open(client_log, "r")
    logf.seek(0, 2)  # tail: start at current end

    t0 = time.time()
    next_tick = t0
    while time.time() - t0 < secs:
        # Drain any new telemetry lines emitted since the last tick.
        for line in logf:
            m = ALIVE_RE.search(line)
            if m:
                ts = time.time() - t0
                met_f.write(
                    f"{ts:.1f},{m.group(1)},{m.group(2)},{m.group(3)},{m.group(4)}\n"
                )
        met_f.flush()

        ts = time.time() - t0
        s = sample_proc(srv)
        c = sample_proc(cli)
        if s and c:
            res_f.write(
                f"{ts:.1f},{s[0]:.1f},{s[1]/1048576:.1f},{s[2]},"
                f"{c[0]:.1f},{c[1]/1048576:.1f},{c[2]}\n"
            )
            res_f.flush()

        next_tick += 1.0
        sleep = next_tick - time.time()
        if sleep > 0:
            time.sleep(sleep)

    res_f.close()
    met_f.close()
    print(f"monitor done: {res_csv}, {metrics_csv}")


if __name__ == "__main__":
    main()
