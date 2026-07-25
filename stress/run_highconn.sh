#!/usr/bin/env bash
# High-concurrency stress test: 1000 connections, 1-10MB payloads, reconnect.
#
#   ./run_highconn.sh [CONNS] [DURATION_SECS] [DELAY_MS] [JITTER_MS] [LOSS_PCT]
#
# Defaults: CONNS=1000 DURATION=600 DELAY=10 JITTER=50 LOSS=4
set -uo pipefail
cd "$(dirname "$0")"

CONNS=${1:-1000}
DURATION=${2:-600}
DELAY_MS=${3:-10}
JITTER_MS=${4:-50}
LOSS_PCT=${5:-4}

REPO=".."
SRV_BIN="$REPO/target/release/raptun-server"
CLI_BIN="$REPO/target/release/raptun-client"

SINK_PORT=48080
SRV_PORT=29900
RELAY_PORT=29901
CLI_PORT=48948
PSK="stress-secret"

OUT="results/highconn_$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
SRV_LOG="$OUT/server.log"
CLI_LOG="$OUT/client.log"
SINK_LOG="$OUT/sink.log"
RELAY_LOG="$OUT/relay.log"

PIDS=()
cleanup() {
  echo "--- cleanup ---"
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  pkill -f 'raptun-server|raptun-client' 2>/dev/null || true
  pkill -f 'load_highconn.py sink' 2>/dev/null || true
  pkill -f 'relay.py' 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "=== raptun high-conn stress: CONNS=$CONNS DURATION=${DURATION}s "\
"link=${DELAY_MS}ms/±${JITTER_MS}ms/${LOSS_PCT}% out=$OUT ==="

# 1. Upstream sink.
python3 load_highconn.py sink "$SINK_PORT" >"$SINK_LOG" 2>&1 &
PIDS+=($!)
sleep 1

# 2. raptun server.
RUST_LOG=info "$SRV_BIN" \
  -l 127.0.0.1:$SRV_PORT -r 127.0.0.1:$SINK_PORT \
  --self-signed --psk "$PSK" --connect-timeout 15 \
  --max-conns 4096 --max-streams 4096 \
  --sockbuf 8388608 \
  >"$SRV_LOG" 2>&1 &
SRV_PID=$!
PIDS+=($SRV_PID)
sleep 2
FP=$(grep -o 'SHA256:[0-9a-f]*' "$SRV_LOG" | head -1)
[ -n "$FP" ] || { echo "FAIL: no server fingerprint"; cat "$SRV_LOG"; exit 1; }
echo "server fingerprint: $FP (pid $SRV_PID)"

# 3. Delay/loss relay.
python3 relay.py "$RELAY_PORT" "$SRV_PORT" "$DELAY_MS" "$JITTER_MS" "$LOSS_PCT" \
  >"$RELAY_LOG" 2>&1 &
PIDS+=($!)
sleep 1
cat "$RELAY_LOG"

# 4. raptun client — heartbeat 5s for dense telemetry.
RUST_LOG=info "$CLI_BIN" \
  -l 127.0.0.1:$CLI_PORT -r 127.0.0.1:$RELAY_PORT \
  --psk "$PSK" --fingerprint "$FP" --heartbeat 5 \
  --max-streams 4096 --sockbuf 8388608 \
  >"$CLI_LOG" 2>&1 &
CLI_PID=$!
PIDS+=($CLI_PID)
sleep 2
echo "client pid $CLI_PID"

# 5. Resource + metrics sampler (1s interval).
python3 monitor.py "$SRV_PID" "$CLI_PID" "$CLI_LOG" "$DURATION" \
  "$OUT/resources.csv" "$OUT/metrics.csv" &
MON_PID=$!
PIDS+=($MON_PID)

# 6. Warm-up: ramp connections over 30s to avoid thundering-herd.
echo "=== ramp-up: 30s ==="
python3 load_highconn.py drive "$CLI_PORT" 100 30 "$OUT/warmup.csv" 2>&1 || true

# 7. Full load for the remaining duration.
REMAIN=$((DURATION - 30))
echo "=== full load: ${REMAIN}s ==="
python3 load_highconn.py drive "$CLI_PORT" "$CONNS" "$REMAIN" "$OUT/load_summary.csv" 2>&1

wait "$MON_PID" 2>/dev/null || true

echo "=== done. artifacts in $OUT ==="
ls -la "$OUT"

# Generate charts.
python3 report.py "$OUT" 2>/dev/null || true