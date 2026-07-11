#!/usr/bin/env bash
#
# netem_bench.sh — real-network extreme-condition benchmark for Raptun on Linux.
#
# This is the wall-clock counterpart to `crates/raptun-core/tests/netem.rs`.
# That in-process test proves the convergence *logic* deterministically and runs
# everywhere (incl. macOS CI). This script validates the same DESIGN.md §5
# acceptance scenario against the REAL binaries over a REAL kernel qdisc, which
# only Linux + root can do.
#
# It shapes the loopback interface with `tc netem`, tunnels a payload through
# raptun-server + raptun-client (FEC datagram path), and checks the payload
# round-trips intact. Measured wall-clock transfer time is reported per scenario.
#
# Requirements: Linux, root (or CAP_NET_ADMIN), `tc` (iproute2), python3.
# Usage:        sudo ./netem_bench.sh
#
# NOTE: netem on `lo` shapes ALL loopback traffic, including QUIC's own ACKs on
# the signaling stream. That is realistic (a real bad link degrades everything)
# and is exactly the stress §5 describes.

set -euo pipefail
cd "$(dirname "$0")"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "ERROR: tc netem is Linux-only. On macOS run the portable in-process test instead:" >&2
  echo "  cargo test -p raptun-core --test netem -- --nocapture" >&2
  exit 2
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: root required to program tc qdiscs (try: sudo $0)" >&2
  exit 2
fi
command -v tc >/dev/null || { echo "ERROR: 'tc' not found (install iproute2)"; exit 2; }

IFACE="lo"
ECHO_PORT=39001
SERVER_PORT=39002
CLIENT_PORT=39003
PSK="netem-bench"
PAYLOAD_BYTES=$((256 * 1024))   # 256 KiB → many FEC blocks

# --- Build release binaries once. ---
echo "building release binaries…"
cargo build --release >/dev/null 2>&1

SRV_LOG=$(mktemp); CLI_LOG=$(mktemp)
CHILDREN=()
cleanup() {
  # Always tear the qdisc down, then kill children.
  tc qdisc del dev "$IFACE" root 2>/dev/null || true
  for pid in "${CHILDREN[@]:-}"; do kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

# Apply a netem profile to the loopback root qdisc.
#   $1 loss%  $2 delay(ms)  $3 jitter(ms)  $4 reorder%
apply_netem() {
  tc qdisc del dev "$IFACE" root 2>/dev/null || true
  if [[ "$3" -gt 0 || "$4" -gt 0 ]]; then
    tc qdisc add dev "$IFACE" root netem \
      loss "${1}%" delay "${2}ms" "${3}ms" distribution normal \
      reorder "$((100 - $4))% ${4}%"
  else
    tc qdisc add dev "$IFACE" root netem loss "${1}%" delay "${2}ms"
  fi
}

start_stack() {
  # Echo target: upper-cases whatever it receives.
  python3 - "$ECHO_PORT" <<'PY' &
import socket, sys, threading
p = int(sys.argv[1])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", p)); s.listen(16)
def h(c):
    while True:
        d = c.recv(65536)
        if not d: break
        c.sendall(d.upper())
    c.close()
while True:
    try: c,_ = s.accept()
    except OSError: break
    threading.Thread(target=h, args=(c,), daemon=True).start()
PY
  CHILDREN+=($!)
  sleep 0.5

  RUST_LOG=info ./target/release/raptun-server \
    -l 127.0.0.1:$SERVER_PORT -r 127.0.0.1:$ECHO_PORT \
    --self-signed --psk "$PSK" >"$SRV_LOG" 2>&1 &
  CHILDREN+=($!)
  sleep 1
  FINGERPRINT=$(grep -o 'SHA256:[0-9a-f]*' "$SRV_LOG" | head -1)
  [[ -n "$FINGERPRINT" ]] || { echo "FAIL: no server fingerprint"; cat "$SRV_LOG"; exit 1; }

  RUST_LOG=info ./target/release/raptun-client \
    -l 127.0.0.1:$CLIENT_PORT -r 127.0.0.1:$SERVER_PORT \
    --psk "$PSK" --fingerprint "$FINGERPRINT" >"$CLI_LOG" 2>&1 &
  CHILDREN+=($!)
  sleep 1
}

stop_stack() {
  for pid in "${CHILDREN[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  CHILDREN=()
  sleep 0.3
}

# Push PAYLOAD_BYTES through the client, verify the echo, print wall-clock ms.
run_transfer() {
  python3 - "$CLIENT_PORT" "$PAYLOAD_BYTES" <<'PY'
import socket, sys, time
port, n = int(sys.argv[1]), int(sys.argv[2])
payload = bytes((i % 251) for i in range(n))
expect  = bytes((b - 32 if 97 <= b <= 122 else b) for b in payload)  # ascii upper
s = socket.socket(); s.settimeout(60); s.connect(("127.0.0.1", port))
t0 = time.time()
s.sendall(payload)
got = bytearray()
while len(got) < n:
    chunk = s.recv(65536)
    if not chunk: break
    got.extend(chunk)
dt = (time.time() - t0) * 1000
ok = bytes(got) == expect
print(f"    bytes={len(got)}/{n} ok={ok} wall={dt:.0f}ms")
sys.exit(0 if ok else 1)
PY
}

# --- Scenarios (DESIGN.md §5 acceptance + a baseline). ---
declare -a SCENARIOS=(
  "clean          0  1   0   0"
  "mild-loss      5  20  0   0"
  "heavy-loss     20 20  0   0"
  "jitter         5  50  100 0"
  "reorder        5  20  20  25"
  "EXTREME-triple 30 20  150 25"
)

echo
printf "%-16s %-6s %-7s %-8s %-8s\n" "scenario" "loss%" "delay" "jitter" "reorder%"
echo "--------------------------------------------------------------"
FAILED=0
for row in "${SCENARIOS[@]}"; do
  read -r name loss delay jitter reorder <<<"$row"
  printf "%-16s %-6s %-7s %-8s %-8s\n" "$name" "$loss" "${delay}ms" "${jitter}ms" "$reorder"
  apply_netem "$loss" "$delay" "$jitter" "$reorder"
  start_stack
  if ! run_transfer; then
    echo "    RESULT: FAIL (payload mismatch or timeout)"
    FAILED=1
  fi
  stop_stack
done

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "ALL SCENARIOS PASSED — payload converged intact under every profile."
else
  echo "SOME SCENARIOS FAILED — see output above."
  exit 1
fi
