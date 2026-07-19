#!/usr/bin/env python3
"""Resource + metrics sampler for the raptun stress test.

Samples the server and client processes' CPU% and RSS once per second, and
tails the client log for the periodic "tunnel alive" telemetry (rtt_ms /
cwnd_bytes / loss_pct / active_tunnels). Writes two CSVs with a shared
wall-clock timestamp so the report can align resource use against link metrics.

CPU is derived from the delta of cumulative CPU time reported by `ps` between
ticks — `ps` reads any process without elevated privileges on macOS, unlike
psutil's per-process taskinfo which needs root here.

Usage:
  monitor.py <server_pid> <client_pid> <client_log> <secs> <res_csv> <metrics_csv>
"""
import re
import subprocess
import sys
import time

ALIVE_RE = re.compile(
    r"tunnel alive.*?rtt_ms=(\d+).*?cwnd_bytes=(\d+).*?"
    r'loss_pct="([\d.]+)".*?active_tunnels=(\d+)'
)


def parse_cputime(s: str) -> float:
    """Parse ps TIME like 'MM:SS.ss' or 'HH:MM:SS' into seconds."""
    s = s.strip()
    if not s:
        return 0.0
    parts = s.split(":")
    try:
        if len(parts) == 3:
            h, m, sec = parts
            return int(h) * 3600 + int(m) * 60 + float(sec)
        if len(parts) == 2:
            m, sec = parts
            return int(m) * 60 + float(sec)
        return float(parts[0])
    except ValueError:
        return 0.0


def sample(pid: int):
    """Return (cpu_seconds_cumulative, rss_bytes) or None if the process is gone."""
    try:
        out = subprocess.check_output(
            ["ps", "-o", "rss=,time=", "-p", str(pid)],
            stderr=subprocess.DEVNULL,
        ).decode().strip()
    except subprocess.CalledProcessError:
        return None
    if not out:
        return None
    # rss (KiB) then TIME; split on first whitespace run.
    fields = out.split(None, 1)
    if len(fields) < 2:
        return None
    rss_kib = int(fields[0])
    cpu_s = parse_cputime(fields[1])
    return cpu_s, rss_kib * 1024


def main():
    server_pid = int(sys.argv[1])
    client_pid = int(sys.argv[2])
    client_log = sys.argv[3]
    secs = int(sys.argv[4])
    res_csv = sys.argv[5]
    metrics_csv = sys.argv[6]

    res_f = open(res_csv, "w")
    res_f.write("t,srv_cpu,srv_rss_mb,cli_cpu,cli_rss_mb\n")
    met_f = open(metrics_csv, "w")
    met_f.write("t,rtt_ms,cwnd_bytes,loss_pct,active_tunnels\n")

    logf = open(client_log, "r")
    logf.seek(0, 2)

    prev = {server_pid: None, client_pid: None}
    prev_t = time.time()
    t0 = prev_t
    next_tick = t0 + 1.0

    while time.time() - t0 < secs:
        sleep = next_tick - time.time()
        if sleep > 0:
            time.sleep(sleep)
        now = time.time()
        dt = now - prev_t
        prev_t = now
        next_tick += 1.0
        ts = now - t0

        # Drain new telemetry lines.
        for line in logf:
            m = ALIVE_RE.search(line)
            if m:
                met_f.write(
                    f"{ts:.1f},{m.group(1)},{m.group(2)},{m.group(3)},{m.group(4)}\n"
                )
        met_f.flush()

        row = [f"{ts:.1f}"]
        ok = True
        for pid in (server_pid, client_pid):
            s = sample(pid)
            if s is None:
                ok = False
                break
            cpu_s, rss = s
            if prev[pid] is None:
                cpu_pct = 0.0
            else:
                cpu_pct = max(0.0, (cpu_s - prev[pid]) / dt * 100.0) if dt > 0 else 0.0
            prev[pid] = cpu_s
            row.append(f"{cpu_pct:.1f}")
            row.append(f"{rss/1048576:.1f}")
        if ok:
            # row = [t, srv_cpu, srv_rss, cli_cpu, cli_rss]
            res_f.write(",".join(row) + "\n")
            res_f.flush()

    res_f.close()
    met_f.close()
    print(f"monitor done: {res_csv}, {metrics_csv}")


if __name__ == "__main__":
    main()
