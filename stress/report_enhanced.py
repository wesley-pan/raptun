#!/usr/bin/env python3
"""Enhanced stress-test report with detailed charts and analysis.

Usage:  report_enhanced.py <run_dir>
"""
import csv
import sys
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


def read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return list(csv.DictReader(f))


def col(rows, key, cast=float):
    out = []
    for r in rows:
        try:
            out.append(cast(r[key]))
        except (KeyError, ValueError):
            out.append(None)
    return out


def stats(rows, key, cast=float):
    vals = [v for v in col(rows, key, cast) if v is not None]
    if not vals:
        return (0, 0, 0)
    return (min(vals), sum(vals) / len(vals), max(vals))


def main():
    run = sys.argv[1]
    res = read_csv(os.path.join(run, "resources.csv"))
    met = read_csv(os.path.join(run, "metrics.csv"))
    summ = read_csv(os.path.join(run, "load_summary.csv"))
    summary = {r["metric"]: r["value"] for r in summ}

    # ---- Charts (2x3 grid) ------------------------------------------------
    fig, axes = plt.subplots(3, 2, figsize=(14, 16))
    ((ax_cpu, ax_mem), (ax_loss, ax_tun), (ax_cwnd, ax_rtt)) = axes

    if res:
        t = col(res, "t")
        ax_cpu.plot(t, col(res, "srv_cpu"), label="server CPU%", color="tab:red", alpha=0.8)
        ax_cpu.plot(t, col(res, "cli_cpu"), label="client CPU%", color="tab:blue", alpha=0.8)
        ax_cpu.set_ylabel("CPU %")
        ax_cpu.set_title("Process CPU (100% = one core)")
        ax_cpu.legend(); ax_cpu.grid(True, alpha=0.3)

        ax_mem.plot(t, col(res, "srv_rss_mb"), label="server RSS", color="tab:red", alpha=0.8)
        ax_mem.plot(t, col(res, "cli_rss_mb"), label="client RSS", color="tab:blue", alpha=0.8)
        ax_mem.set_ylabel("RSS (MB)")
        ax_mem.set_title("Process memory")
        ax_mem.legend(); ax_mem.grid(True, alpha=0.3)

    if met:
        tm = col(met, "t")
        ax_loss.plot(tm, col(met, "loss_pct"), color="tab:orange", alpha=0.7, linewidth=0.5)
        ax_loss.set_ylabel("loss %")
        ax_loss.set_title("Client-reported windowed loss rate")
        ax_loss.grid(True, alpha=0.3)

        ax_tun.plot(tm, col(met, "active_tunnels", int), color="tab:green", alpha=0.8)
        ax_tun.set_ylabel("tunnels")
        ax_tun.set_title("Active tunnels")
        ax_tun.grid(True, alpha=0.3)

        cwnd_vals = col(met, "cwnd_bytes")
        cwnd_mb = [v / 1e6 if v else 0 for v in cwnd_vals]
        ax_cwnd.plot(tm, cwnd_mb, color="tab:purple", alpha=0.7, linewidth=0.5)
        ax_cwnd.set_ylabel("cwnd (MB)")
        ax_cwnd.set_title("Congestion window")
        ax_cwnd.grid(True, alpha=0.3)

        rtt_vals = col(met, "rtt_ms", int)
        ax_rtt.plot(tm, rtt_vals, color="tab:brown", alpha=0.7, linewidth=0.5)
        ax_rtt.set_ylabel("RTT (ms)")
        ax_rtt.set_title("Smoothed RTT")
        ax_rtt.set_xlabel("elapsed (s)")
        ax_rtt.grid(True, alpha=0.3)

    fig.tight_layout()
    chart = os.path.join(run, "charts.png")
    fig.savefig(chart, dpi=120)
    print(f"wrote {chart}")

    # ---- Derived stats ---------------------------------------------------
    srv_cpu = stats(res, "srv_cpu")
    cli_cpu = stats(res, "cli_cpu")
    srv_rss = stats(res, "srv_rss_mb")
    cli_rss = stats(res, "cli_rss_mb")
    loss = stats(met, "loss_pct")
    tun = stats(met, "active_tunnels", int)
    rtt = stats(met, "rtt_ms", int)
    cwnd = stats(met, "cwnd_bytes")

    # ---- Markdown --------------------------------------------------------
    md = os.path.join(run, "report.md")
    with open(md, "w") as f:
        f.write("# Raptun High-Concurrency Stress Test Report\n\n")
        f.write(f"Run directory: `{run}`\n\n")

        f.write("## Test Configuration\n\n")
        f.write("| parameter | value |\n|---|---|\n")
        f.write("| connections | 1000 |\n")
        f.write("| payload sizes | 1, 3, 5, 7, 10 MB |\n")
        f.write("| link delay | 10ms |\n")
        f.write("| link jitter | ±50ms |\n")
        f.write("| link loss | 4% |\n")
        f.write("| duration | 600s (10 min) |\n")
        f.write("| mode | reconnect after each transfer |\n\n")

        f.write("## Load Summary\n\n")
        f.write("| metric | value |\n|---|---|\n")
        for k in [
            "elapsed_s", "connections", "requests_ok", "requests_err",
            "bytes_ok", "throughput_MBps",
            "req_latency_p50_ms", "req_latency_p90_ms",
            "req_latency_p99_ms", "req_latency_max_ms",
        ]:
            if k in summary:
                f.write(f"| {k} | {summary[k]} |\n")
        ok = float(summary.get("requests_ok", 0))
        err = float(summary.get("requests_err", 0))
        total = ok + err
        if total > 0:
            f.write(f"| success_rate | {100*ok/total:.2f}% |\n")
        if ok > 0:
            elapsed = float(summary.get("elapsed_s", 1))
            f.write(f"| avg_request_rate | {ok/elapsed:.1f} req/s |\n")

        f.write("\n## Resource & Link Stats (min / avg / max)\n\n")
        f.write("| series | min | avg | max |\n|---|---|---|---|\n")
        f.write(f"| server CPU% | {srv_cpu[0]:.1f} | {srv_cpu[1]:.1f} | {srv_cpu[2]:.1f} |\n")
        f.write(f"| client CPU% | {cli_cpu[0]:.1f} | {cli_cpu[1]:.1f} | {cli_cpu[2]:.1f} |\n")
        f.write(f"| server RSS MB | {srv_rss[0]:.0f} | {srv_rss[1]:.0f} | {srv_rss[2]:.0f} |\n")
        f.write(f"| client RSS MB | {cli_rss[0]:.0f} | {cli_rss[1]:.0f} | {cli_rss[2]:.0f} |\n")
        f.write(f"| loss_pct | {loss[0]:.2f} | {loss[1]:.2f} | {loss[2]:.2f} |\n")
        f.write(f"| active_tunnels | {tun[0]:.0f} | {tun[1]:.0f} | {tun[2]:.0f} |\n")
        f.write(f"| cwnd_bytes | {cwnd[0]/1e6:.1f}M | {cwnd[1]/1e6:.1f}M | {cwnd[2]/1e6:.1f}M |\n")
        f.write(f"| rtt_ms | {rtt[0]:.0f} | {rtt[1]:.0f} | {rtt[2]:.0f} |\n")

        f.write("\n## Analysis\n\n")

        # Memory efficiency
        if tun[2] > 0 and cli_rss[2] > 0:
            mem_per_tunnel = cli_rss[2] / tun[2]
            f.write(f"- **Memory per active tunnel**: {mem_per_tunnel:.1f} MB "
                    f"(client peak RSS {cli_rss[2]:.0f} MB / {tun[2]:.0f} tunnels)\n")

        # CPU efficiency
        if ok > 0:
            elapsed = float(summary.get("elapsed_s", 1))
            bytes_ok = float(summary.get("bytes_ok", 0))
            f.write(f"- **Throughput**: {bytes_ok/elapsed/1e6:.2f} MB/s "
                    f"({ok/elapsed:.1f} req/s)\n")

        # Error analysis
        if total > 0:
            err_rate = 100 * err / total
            f.write(f"- **Error rate**: {err_rate:.2f}% ({int(err)}/{int(total)})\n")
            if err_rate > 1:
                f.write(f"  - ⚠️ High error rate — investigate client log for root cause\n")

        # Loss analysis
        if loss[1] > 5:
            f.write(f"- ⚠️ **Average loss rate {loss[1]:.1f}%** exceeds injected 4% — "
                    f"possible congestion-induced self-loss\n")
        elif loss[1] > 0.5:
            f.write(f"- **Average loss rate {loss[1]:.1f}%** — close to injected 4%, "
                    f"FEC is absorbing most of it\n")

        # cwnd analysis
        if cwnd[2] > 0:
            f.write(f"- **cwnd range**: {cwnd[0]/1e6:.1f}–{cwnd[2]/1e6:.1f} MB\n")

        f.write("\n## Charts\n\n![charts](charts.png)\n")

    print(f"wrote {md}")


if __name__ == "__main__":
    main()