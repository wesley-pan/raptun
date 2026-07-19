#!/usr/bin/env bash
# End-to-end raptun loopback stress orchestrator.
#
# Brings up: upstream sink -> raptun-server -> (shaped loopback) -> raptun-client
# -> concurrent load driver, plus a resource/metrics sampler. Link shaping
# (dnctl/pf) needs root, so run the whole thing under sudo. Everything runs as
# root for simplicity: `$!` then refers to the real process (not a `sudo`
# wrapper), which is what the sampler needs to find the raptun PIDs.
#
#   sudo ./run.sh [CONNS] [DURATION_SECS]
#
# Defaults: CONNS=250, DURATION=600 (10 min).
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

OUT="results/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
SRV_LOG="$OUT/server.log"
CLI_LOG="$OUT/client.log"
SINK_LOG="$OUT/sink.log"

PIDS=()
cleanup() {
  echo "--- cleanup ---"
  ./shaping.sh down || true
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  pkill -f 'raptun-server|raptun-client' 2>/dev/null || true
  pkill -f 'load.py sink' 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "=== raptun stress: CONNS=$CONNS DURATION=${DURATION}s out=$OUT ==="

# 1. Upstream sink.
python3 load.py sink "$SINK_PORT" >"$SINK_LOG" 2>&1 &
PIDS+=($!)
sleep 1

# 2. raptun server (self-signed; print fingerprint for the client to pin).
RUST_LOG=info "$SRV_BIN" \
  -l 127.0.0.1:$SRV_PORT -r 127.0.0.1:$SINK_PORT \
  --self-signed --psk "$PSK" --connect-timeout 15 >"$SRV_LOG" 2>&1 &
SRV_PID=$!
PIDS+=($SRV_PID)
sleep 2
FP=$(grep -o 'SHA256:[0-9a-f]*' "$SRV_LOG" | head -1)
[ -n "$FP" ] || { echo "FAIL: no server fingerprint"; cat "$SRV_LOG"; exit 1; }
echo "server fingerprint: $FP (pid $SRV_PID)"

# 3. raptun client. heartbeat 1s so the sampler gets dense telemetry.
RUST_LOG=info "$CLI_BIN" \
  -l 127.0.0.1:$CLI_PORT -r 127.0.0.1:$SRV_PORT \
  --psk "$PSK" --fingerprint "$FP" --heartbeat 1 >"$CLI_LOG" 2>&1 &
CLI_PID=$!
PIDS+=($CLI_PID)
sleep 2
echo "client pid $CLI_PID"

# 4. Shape the loopback link on the server's UDP port (root).
./shaping.sh up "$SRV_PORT"

# 4b. Sanity-check the shaping is actually intercepting traffic: dnctl reports
#     per-pipe packet counts. We re-check after the run to confirm growth.
echo "--- dnctl pipe before load ---"; dnctl pipe 1 show 2>/dev/null | head -3 || true

# 5. Resource + metrics sampler.
python3 monitor.py "$SRV_PID" "$CLI_PID" "$CLI_LOG" "$DURATION" \
  "$OUT/resources.csv" "$OUT/metrics.csv" &
MON_PID=$!
PIDS+=($MON_PID)

# 6. Concurrent load for the full duration.
echo "=== driving load for ${DURATION}s ==="
python3 load.py drive "$CLI_PORT" "$CONNS" "$DURATION" "$OUT/load_summary.csv" || true

wait "$MON_PID" 2>/dev/null || true

echo "--- dnctl pipe after load (packet count should have grown) ---"
dnctl pipe 1 show 2>/dev/null | head -3 || true

echo "=== done. artifacts in $OUT ==="
ls -la "$OUT"
