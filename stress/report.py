#!/usr/bin/env python3
"""Render the raptun stress-test report: plots + a Markdown summary.

Reads resources.csv, metrics.csv, and load_summary.csv from a run directory,
produces PNG charts (server/client CPU, memory, loss_pct, active_tunnels), and
writes report.md.

Usage:  report.py <run_dir>
"""
import csv
import sys
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


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


def main():
    run = sys.argv[1]
    res = read_csv(os.path.join(run, "resources.csv"))
    met = read_csv(os.path.join(run, "metrics.csv"))
    summ = read_csv(os.path.join(run, "load_summary.csv"))
    summary = {r["metric"]: r["value"] for r in summ}

    # ---- Plots -----------------------------------------------------------
    fig, axes = plt.subplots(4, 1, figsize=(11, 15), sharex=True)

    if res:
        t = col(res, "t")
        axes[0].plot(t, col(res, "srv_cpu"), label="server CPU%", color="tab:red")
        axes[0].plot(t, col(res, "cli_cpu"), label="client CPU%", color="tab:blue")
        axes[0].set_ylabel("CPU %")
        axes[0].set_title("Process CPU (100% = one core)")
        axes[0].legend(); axes[0].grid(True, alpha=0.3)

        axes[1].plot(t, col(res, "srv_rss_mb"), label="server RSS", color="tab:red")
        axes[1].plot(t, col(res, "cli_rss_mb"), label="client RSS", color="tab:blue")
        axes[1].set_ylabel("RSS (MB)")
        axes[1].set_title("Process memory")
        axes[1].legend(); axes[1].grid(True, alpha=0.3)

    if met:
        tm = col(met, "t")
        axes[2].plot(tm, col(met, "loss_pct"), label="loss_pct", color="tab:orange")
        axes[2].set_ylabel("loss %")
        axes[2].set_title("Client-reported link loss")
        axes[2].legend(); axes[2].grid(True, alpha=0.3)

        axes[3].plot(tm, col(met, "active_tunnels", int), label="active_tunnels", color="tab:green")
        axes[3].set_ylabel("tunnels")
        axes[3].set_title("Active tunnels")
        axes[3].set_xlabel("elapsed (s)")
        axes[3].legend(); axes[3].grid(True, alpha=0.3)

    fig.tight_layout()
    chart = os.path.join(run, "charts.png")
    fig.savefig(chart, dpi=100)
    print(f"wrote {chart}")

    # ---- Derived stats ---------------------------------------------------
    def stats(rows, key, cast=float):
        vals = [v for v in col(rows, key, cast) if v is not None]
        if not vals:
            return (0, 0, 0)
        return (min(vals), sum(vals) / len(vals), max(vals))

    srv_cpu = stats(res, "srv_cpu")
    cli_cpu = stats(res, "cli_cpu")
    srv_rss = stats(res, "srv_rss_mb")
    cli_rss = stats(res, "cli_rss_mb")
    loss = stats(met, "loss_pct")
    tun = stats(met, "active_tunnels", int)
    rtt = stats(met, "rtt_ms", int)

    # ---- Markdown --------------------------------------------------------
    md = os.path.join(run, "report.md")
    with open(md, "w") as f:
        f.write("# Raptun loopback stress-test report\n\n")
        f.write(f"Run directory: `{run}`\n\n")

        f.write("## Load summary\n\n")
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
        if ok + err > 0:
            f.write(f"| success_rate | {100*ok/(ok+err):.2f}% |\n")

        f.write("\n## Resource & link stats (min / avg / max)\n\n")
        f.write("| series | min | avg | max |\n|---|---|---|---|\n")
        f.write(f"| server CPU% | {srv_cpu[0]:.0f} | {srv_cpu[1]:.0f} | {srv_cpu[2]:.0f} |\n")
        f.write(f"| client CPU% | {cli_cpu[0]:.0f} | {cli_cpu[1]:.0f} | {cli_cpu[2]:.0f} |\n")
        f.write(f"| server RSS MB | {srv_rss[0]:.0f} | {srv_rss[1]:.0f} | {srv_rss[2]:.0f} |\n")
        f.write(f"| client RSS MB | {cli_rss[0]:.0f} | {cli_rss[1]:.0f} | {cli_rss[2]:.0f} |\n")
        f.write(f"| loss_pct | {loss[0]:.2f} | {loss[1]:.2f} | {loss[2]:.2f} |\n")
        f.write(f"| active_tunnels | {tun[0]:.0f} | {tun[1]:.0f} | {tun[2]:.0f} |\n")
        f.write(f"| rtt_ms | {rtt[0]:.0f} | {rtt[1]:.0f} | {rtt[2]:.0f} |\n")

        f.write("\n## Charts\n\n![charts](charts.png)\n")

    print(f"wrote {md}")


if __name__ == "__main__":
    main()
