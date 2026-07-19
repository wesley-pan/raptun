#!/usr/bin/env bash
# End-to-end raptun loopback stress orchestrator.
#
# Brings up: upstream sink -> raptun-server -> (shaped loopback) -> raptun-client
# -> concurrent load driver, plus a resource/metrics sampler. Link shaping
# (dnctl/pf) needs root, so run the whole thing under sudo; the raptun and
# Python processes are dropped back to the invoking user so psutil can sample
# them and output files are owned correctly.
#
#   sudo ./run.sh [CONNS] [DURATION_SECS]
#
# Defaults: CONNS=250, DURATION=600 (10 min). Start small (per the plan) and
# scale up once the pipeline is proven.
set -uo pipefail
cd "$(dirname "$0")"

CONNS=${1:-250}
DURATION=${2:-600}

REPO=".."
SRV_BIN="$REPO/target/release/raptun-server"
CLI_BIN="$REPO/target/release/raptun-client"

SINK_PORT=48080
SRV_PORT=29900
CLI_PORT=48948
PSK="stress-secret"

RUN_USER=${SUDO_USER:-$(whoami)}
asuser() { sudo -u "$RUN_USER" "$@"; }

OUT="results/$(asuser date +%Y%m%d-%H%M%S)"
asuser mkdir -p "$OUT"
SRV_LOG="$OUT/server.log"
CLI_LOG="$OUT/client.log"
SINK_LOG="$OUT/sink.log"

PIDS=()
cleanup() {
  echo "--- cleanup ---"
  ./shaping.sh down || true
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  # Reap any strays.
  pkill -f 'raptun-server|raptun-client' 2>/dev/null || true
  pkill -f 'load.py sink' 2>/dev/null || true
}
trap cleanup EXIT

echo "=== raptun stress: CONNS=$CONNS DURATION=${DURATION}s out=$OUT ==="

# 1. Upstream sink (the service the server forwards to).
asuser python3 load.py sink "$SINK_PORT" >"$SINK_LOG" 2>&1 &
PIDS+=($!)
sleep 1

# 2. raptun server (self-signed; print fingerprint for the client to pin).
asuser env RUST_LOG=info "$SRV_BIN" \
  -l 127.0.0.1:$SRV_PORT -r 127.0.0.1:$SINK_PORT \
  --self-signed --psk "$PSK" --connect-timeout 15 >"$SRV_LOG" 2>&1 &
SRV_PID=$!
PIDS+=($SRV_PID)
sleep 2
FP=$(grep -o 'SHA256:[0-9a-f]*' "$SRV_LOG" | head -1)
[ -n "$FP" ] || { echo "FAIL: no server fingerprint"; cat "$SRV_LOG"; exit 1; }
echo "server fingerprint: $FP (pid $SRV_PID)"

# 3. raptun client. heartbeat 1s so the sampler gets dense telemetry.
asuser env RUST_LOG=info "$CLI_BIN" \
  -l 127.0.0.1:$CLI_PORT -r 127.0.0.1:$SRV_PORT \
  --psk "$PSK" --fingerprint "$FP" --heartbeat 1 >"$CLI_LOG" 2>&1 &
CLI_PID=$!
PIDS+=($CLI_PID)
sleep 2
echo "client pid $CLI_PID"

# 4. Shape the loopback link on the server's UDP port (root).
./shaping.sh up "$SRV_PORT"

# 5. Resource + metrics sampler (as user so psutil can read the procs).
asuser python3 monitor.py "$SRV_PID" "$CLI_PID" "$CLI_LOG" "$DURATION" \
  "$OUT/resources.csv" "$OUT/metrics.csv" &
MON_PID=$!
PIDS+=($MON_PID)

# 6. Concurrent load for the full duration.
echo "=== driving load for ${DURATION}s ==="
asuser python3 load.py drive "$CLI_PORT" "$CONNS" "$DURATION" "$OUT/load_summary.csv"

# Let the sampler flush its last tick.
wait "$MON_PID" 2>/dev/null || true

echo "=== done. artifacts in $OUT ==="
ls -la "$OUT"
