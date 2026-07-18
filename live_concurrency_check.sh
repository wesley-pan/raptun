#!/usr/bin/env bash
# Loopback LIVE verification, diagnostic version. Independent round-trips (no
# barrier), per-connection timeout, staged concurrency. Confirms whether the
# shared per-connection RepairBudget (docs/DESIGN.md §6.2) yields bounded loss
# and full delivery as concurrent tunnels climb.
set -euo pipefail
cd "$(dirname "$0")"

ECHO_PORT=19111
SERVER_PORT=19112
CLIENT_PORT=19113
PSK="live-secret"
CONNS=${CONNS:-150}
BYTES=${BYTES:-200000}
CONN_TIMEOUT=${CONN_TIMEOUT:-30}

SRV_LOG=$(mktemp)
CLI_LOG=$(mktemp)
cleanup() { kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT

python3 -c "
import socket, threading
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $ECHO_PORT)); s.listen(4096)
def handle(c):
    try:
        buf = bytearray()
        while True:
            d = c.recv(65536)
            if not d: break
            buf += d
        c.sendall(bytes(buf).upper())
    except Exception: pass
    finally: c.close()
while True:
    c,_ = s.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
" &
sleep 1

RUST_LOG=info ./target/debug/raptun-server \
    -l 127.0.0.1:$SERVER_PORT -r 127.0.0.1:$ECHO_PORT \
    --self-signed --psk "$PSK" >"$SRV_LOG" 2>&1 &
sleep 1.5
FINGERPRINT=$(grep -o 'SHA256:[0-9a-f]*' "$SRV_LOG" | head -1)
[ -n "$FINGERPRINT" ] || { echo "FAIL: no server fingerprint"; cat "$SRV_LOG"; exit 1; }
echo "server fingerprint: $FINGERPRINT"

RUST_LOG=info ./target/debug/raptun-client \
    -l 127.0.0.1:$CLIENT_PORT -r 127.0.0.1:$SERVER_PORT \
    --psk "$PSK" --fingerprint "$FINGERPRINT" --heartbeat 2 >"$CLI_LOG" 2>&1 &
sleep 1.5

echo "driving $CONNS independent round-trips, ${BYTES}B each, ${CONN_TIMEOUT}s timeout..."
python3 -c "
import socket, threading, time, sys
CONNS=$CONNS; N=$BYTES; PORT=$CLIENT_PORT; TMO=$CONN_TIMEOUT
ok=[0]; short=[0]; err=[0]; lock=threading.Lock()
payload=bytes((i%251) for i in range(N)); expected=payload.upper()
def worker(idx):
    try:
        s=socket.socket(); s.settimeout(TMO); s.connect(('127.0.0.1',PORT))
        s.sendall(payload); s.shutdown(socket.SHUT_WR)
        got=bytearray()
        while len(got)<len(expected):
            d=s.recv(65536)
            if not d: break
            got+=d
        s.close()
        with lock:
            if bytes(got)==expected: ok[0]+=1
            else: short[0]+=1
    except Exception:
        with lock: err[0]+=1
ts=[threading.Thread(target=worker,args=(i,),daemon=True) for i in range(CONNS)]
t0=time.time()
for t in ts: t.start()
for t in ts: t.join()
dt=time.time()-t0
print(f'ok={ok[0]} short={short[0]} err={err[0]} / {CONNS} in {dt:.1f}s')
sys.exit(0 if ok[0]==CONNS else 2)
" && RT_OK=1 || RT_OK=0

sleep 3
echo
echo "===== peak active_tunnels / peak loss_pct ====="
grep "tunnel alive" "$CLI_LOG" | grep -o 'active_tunnels=[0-9]*' | grep -o '[0-9]*' | sort -n | tail -1 | sed 's/^/peak active_tunnels=/'
grep "tunnel alive" "$CLI_LOG" | grep -o 'loss_pct="[0-9.]*"' | grep -o '[0-9.]*' | sort -g | tail -1 | sed 's/^/peak loss_pct=/'
echo
echo "===== client WARN/ERROR ====="; grep -icE "WARN|ERROR" "$CLI_LOG" | sed 's/^/count=/'
grep -iE "WARN|ERROR" "$CLI_LOG" | sed 's/\x1b\[[0-9;]*m//g' | awk '{print $NF}' | sort | uniq -c | head
echo "===== server WARN/ERROR ====="; grep -icE "WARN|ERROR" "$SRV_LOG" | sed 's/^/count=/'
grep -iE "WARN|ERROR" "$SRV_LOG" | sed 's/\x1b\[[0-9;]*m//g' | sort | uniq -c | head
echo
[ "$RT_OK" = "1" ] && echo "PASS: $CONNS/$CONNS round-tripped" || echo "PARTIAL/FAIL (see counts above)"
echo "logs: client=$CLI_LOG server=$SRV_LOG"
