#!/usr/bin/env python3
"""Upstream sink service + concurrent load driver for the raptun stress test.

Subcommands:
  sink   <port>                       upstream service the raptun server forwards to
  drive  <port> <conns> <secs> <csv>  concurrent load through the client's local port

Protocol (framed so the sink knows when a request ends without closing):
  request  = 8-byte big-endian length N, then N payload bytes
  response = 8-byte big-endian N (echoed back), then 8-byte FNV-1a checksum
The driver verifies the echoed length and checksum, so a truncated or corrupted
tunnel is caught, not just a short read.
"""
import socket
import struct
import sys
import threading
import time
import zlib


def checksum(data) -> int:
    # zlib.crc32 is a fast C implementation; a pure-Python hash over 100 MB
    # payloads would dominate CPU and wreck the measurement.
    return zlib.crc32(data) & 0xFFFFFFFF


def recv_exact(sock: socket.socket, n: int) -> bytearray:
    buf = bytearray(n)
    view = memoryview(buf)
    got = 0
    while got < n:
        r = sock.recv_into(view[got:], n - got)
        if r == 0:
            raise ConnectionError(f"eof after {got}/{n}")
        got += r
    return buf


# ---------------------------------------------------------------------------
# Upstream sink: read a framed request, reply length + checksum.
# ---------------------------------------------------------------------------
def sink(port: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(4096)

    def handle(c: socket.socket):
        try:
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            while True:
                hdr = c.recv(8)
                if not hdr:
                    break
                # A request may straddle recv boundaries; complete the header.
                while len(hdr) < 8:
                    more = c.recv(8 - len(hdr))
                    if not more:
                        return
                    hdr += more
                n = struct.unpack(">Q", hdr)[0]
                body = recv_exact(c, n)
                ck = checksum(memoryview(body))
                c.sendall(struct.pack(">QQ", n, ck))
        except Exception:
            pass
        finally:
            c.close()

    while True:
        try:
            c, _ = s.accept()
        except OSError:
            break
        threading.Thread(target=handle, args=(c,), daemon=True).start()


# ---------------------------------------------------------------------------
# Load driver: `conns` workers, each looping connect→send→verify→reconnect.
# ---------------------------------------------------------------------------
MB = 1024 * 1024


def build_payload(n: int) -> bytes:
    # Deterministic, cheap to generate: a 64 KiB pattern tiled to n bytes.
    block = bytes((i % 251) for i in range(65536))
    reps = n // len(block) + 1
    return (block * reps)[:n]


def drive(port: int, conns: int, secs: int, csv_path: str):
    # Reusable payloads at a few sizes spanning 5–100 MB; picking per-request
    # keeps memory bounded while covering the size range.
    sizes = [5, 10, 20, 40, 60, 100]
    payloads = {mb: build_payload(mb * MB) for mb in sizes}
    checksums = {mb: checksum(memoryview(payloads[mb])) for mb in sizes}

    stop_at = time.time() + secs
    lock = threading.Lock()
    stats = {
        "requests_ok": 0,
        "requests_err": 0,
        "bytes_ok": 0,
        "connections": 0,
        "latencies_ms": [],  # per-request wall time
    }
    # Deterministic per-worker size/length choice without a shared RNG.
    def worker(wid: int):
        # Long vs short connection mix: even workers hold one connection and
        # stream many requests over it (long-lived); odd workers do one request
        # per connection then reconnect (short-lived churn).
        long_lived = (wid % 2 == 0)
        seq = 0
        while time.time() < stop_at:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(120)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.connect(("127.0.0.1", port))
                with lock:
                    stats["connections"] += 1

                # long-lived: several requests before closing; short: exactly 1.
                n_reqs = (3 + (wid % 4)) if long_lived else 1
                for _ in range(n_reqs):
                    if time.time() >= stop_at:
                        break
                    mb = sizes[(wid + seq) % len(sizes)]
                    seq += 1
                    payload = payloads[mb]
                    t0 = time.time()
                    s.sendall(struct.pack(">Q", len(payload)))
                    s.sendall(payload)
                    resp = recv_exact(s, 16)
                    rn, rck = struct.unpack(">QQ", resp)
                    dt = (time.time() - t0) * 1000.0
                    ok = (rn == len(payload) and rck == checksums[mb])
                    with lock:
                        if ok:
                            stats["requests_ok"] += 1
                            stats["bytes_ok"] += len(payload)
                            stats["latencies_ms"].append(dt)
                        else:
                            stats["requests_err"] += 1
                s.close()
            except Exception:
                with lock:
                    stats["requests_err"] += 1
                try:
                    s.close()
                except Exception:
                    pass
                time.sleep(0.05)  # brief backoff on failure

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(conns)]
    t_start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - t_start

    lat = sorted(stats["latencies_ms"])
    def pct(p):
        if not lat:
            return 0.0
        return lat[min(len(lat) - 1, int(len(lat) * p / 100))]

    with open(csv_path, "w") as f:
        f.write("metric,value\n")
        f.write(f"elapsed_s,{elapsed:.1f}\n")
        f.write(f"connections,{stats['connections']}\n")
        f.write(f"requests_ok,{stats['requests_ok']}\n")
        f.write(f"requests_err,{stats['requests_err']}\n")
        f.write(f"bytes_ok,{stats['bytes_ok']}\n")
        f.write(f"throughput_MBps,{stats['bytes_ok']/MB/elapsed:.2f}\n")
        f.write(f"req_latency_p50_ms,{pct(50):.1f}\n")
        f.write(f"req_latency_p90_ms,{pct(90):.1f}\n")
        f.write(f"req_latency_p99_ms,{pct(99):.1f}\n")
        f.write(f"req_latency_max_ms,{(lat[-1] if lat else 0):.1f}\n")

    print(
        f"drive done: conns={stats['connections']} ok={stats['requests_ok']} "
        f"err={stats['requests_err']} "
        f"tput={stats['bytes_ok']/MB/elapsed:.1f} MB/s "
        f"p50={pct(50):.0f}ms p99={pct(99):.0f}ms"
    )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    mode = sys.argv[1]
    if mode == "sink":
        sink(int(sys.argv[2]))
    elif mode == "drive":
        drive(int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5])
    else:
        print(__doc__)
        sys.exit(2)
