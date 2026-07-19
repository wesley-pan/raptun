#!/usr/bin/env bash
# End-to-end raptun loopback stress orchestrator.
#
# Topology:
#   load driver -> raptun-client -> relay(delay/loss) -> raptun-server -> sink
#
# Link impairment is done by a userspace UDP relay (relay.py), not kernel
# shaping: macOS pf skips loopback, so dnctl/dummynet can't touch 127.0.0.1.
# The relay adds delay + jitter + loss in both directions, which also means NO
# sudo is required. A resource/metrics sampler records CPU/RSS and the client's
# telemetry.
#
#   ./run.sh [CONNS] [DURATION_SECS] [DELAY_MS] [JITTER_MS] [LOSS_PCT]
#
# Defaults: CONNS=250 DURATION=600 DELAY=100 JITTER=50 LOSS=4
set -uo pipefail
cd "$(dirname "$0")"

CONNS=${1:-250}
DURATION=${2:-600}
DELAY_MS=${3:-100}
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

OUT="results/$(date +%Y%m%d-%H%M%S)"
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
  pkill -f 'load.py sink' 2>/dev/null || true
  pkill -f 'relay.py' 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "=== raptun stress: CONNS=$CONNS DURATION=${DURATION}s "\
"link=${DELAY_MS}ms/±${JITTER_MS}ms/${LOSS_PCT}% out=$OUT ==="

# 1. Upstream sink (the service the server forwards to).
python3 load.py sink "$SINK_PORT" >"$SINK_LOG" 2>&1 &
PIDS+=($!)
sleep 1

# 2. raptun server.
RUST_LOG=info "$SRV_BIN" \
  -l 127.0.0.1:$SRV_PORT -r 127.0.0.1:$SINK_PORT \
  --self-signed --psk "$PSK" --connect-timeout 15 >"$SRV_LOG" 2>&1 &
SRV_PID=$!
PIDS+=($SRV_PID)
sleep 2
FP=$(grep -o 'SHA256:[0-9a-f]*' "$SRV_LOG" | head -1)
[ -n "$FP" ] || { echo "FAIL: no server fingerprint"; cat "$SRV_LOG"; exit 1; }
echo "server fingerprint: $FP (pid $SRV_PID)"

# 3. Delay/loss relay between client and server.
python3 relay.py "$RELAY_PORT" "$SRV_PORT" "$DELAY_MS" "$JITTER_MS" "$LOSS_PCT" \
  >"$RELAY_LOG" 2>&1 &
PIDS+=($!)
sleep 1
cat "$RELAY_LOG"

# 4. raptun client — points at the RELAY, not the server directly. heartbeat 1s
#    so the sampler gets dense telemetry.
RUST_LOG=info "$CLI_BIN" \
  -l 127.0.0.1:$CLI_PORT -r 127.0.0.1:$RELAY_PORT \
  --psk "$PSK" --fingerprint "$FP" --heartbeat 1 >"$CLI_LOG" 2>&1 &
CLI_PID=$!
PIDS+=($CLI_PID)
sleep 2
echo "client pid $CLI_PID"

# 5. Resource + metrics sampler.
python3 monitor.py "$SRV_PID" "$CLI_PID" "$CLI_LOG" "$DURATION" \
  "$OUT/resources.csv" "$OUT/metrics.csv" &
MON_PID=$!
PIDS+=($MON_PID)

# 6. Concurrent load for the full duration.
echo "=== driving load for ${DURATION}s ==="
python3 load.py drive "$CLI_PORT" "$CONNS" "$DURATION" "$OUT/load_summary.csv" || true

wait "$MON_PID" 2>/dev/null || true

echo "=== done. artifacts in $OUT ==="
ls -la "$OUT"
