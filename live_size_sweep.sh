#!/usr/bin/env bash
# Loopback LIVE size-sweep. One long-lived server+client tunnel pair; drives a
# sequence of round-trips at different payload SIZES to probe whether the fixed
# RaptorQ geometry (K=16, symbol_size=1200 -> 18880 B/block, repair floored at
# 1/block on a clean link) delivers every size without stalling.
#
# Block capacity = K*(symbol_size - SYMBOL_HEADER_LEN) = 16 * 1180 = 18880 B.
# Sizes below straddle the sub-block / exact-block / multi-block boundaries.
#
# Env overrides: SIZES="1 100 ...", REPS (round-trips per size), TIMEOUT, SEQ
# (run sizes sequentially vs concurrently within a size).
set -euo pipefail
cd "$(dirname "$0")"

ECHO_PORT=19121
SERVER_PORT=19122
CLIENT_PORT=19123
PSK="sweep-secret"
BLOCK=18880
SIZES=${SIZES:-"1 1000 18879 18880 18881 37760 100000 1000000 5000000"}
REPS=${REPS:-4}
TIMEOUT=${TIMEOUT:-30}

SRV_LOG=$(mktemp)
CLI_LOG=$(mktemp)
cleanup() { kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT

# Echo server: read to EOF, reply upper-cased so we verify integrity, not just length.
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
echo "block capacity: ${BLOCK}B (K=16 x 1180)"

RUST_LOG=info ./target/debug/raptun-client \
    -l 127.0.0.1:$CLIENT_PORT -r 127.0.0.1:$SERVER_PORT \
    --psk "$PSK" --fingerprint "$FINGERPRINT" --heartbeat 2 >"$CLI_LOG" 2>&1 &
sleep 1.5

echo "sizes: $SIZES  (reps=$REPS each, ${TIMEOUT}s timeout)"
echo

FAIL=0
python3 -u - "$CLIENT_PORT" "$TIMEOUT" "$REPS" "$BLOCK" $SIZES <<'PY' || FAIL=1
import socket, threading, time, sys
PORT=int(sys.argv[1]); TMO=int(sys.argv[2]); REPS=int(sys.argv[3]); BLOCK=int(sys.argv[4])
sizes=[int(x) for x in sys.argv[5:]]

def roundtrip(n):
    payload=bytes((i%251) for i in range(n)); expected=payload.upper()
    s=socket.socket(); s.settimeout(TMO); s.connect(('127.0.0.1',PORT))
    t0=time.time()
    s.sendall(payload); s.shutdown(socket.SHUT_WR)
    got=bytearray()
    while len(got)<len(expected):
        d=s.recv(65536)
        if not d: break
        got+=d
    s.close()
    dt=time.time()-t0
    return (len(got)==len(expected) and bytes(got)==expected, len(got), dt)

overall_ok=True
print(f"{'size':>9} {'blocks':>7} {'ok':>4} {'short':>6} {'err':>4} {'p50_ms':>8} {'max_ms':>8}")
for n in sizes:
    blocks=max(1,(n+BLOCK-1)//BLOCK)
    ok=short=err=0; times=[]
    res=[None]*REPS; lock=threading.Lock()
    def work(i,n=n):
        try:
            good,glen,dt=roundtrip(n)
            with lock:
                res[i]=(good,glen,dt)
        except Exception as e:
            with lock:
                res[i]=(None,0,0.0)
                sys.stderr.write(f"  size={n} rep={i} EXC {type(e).__name__}: {e}\n")
    ts=[threading.Thread(target=work,args=(i,)) for i in range(REPS)]
    for t in ts: t.start()
    for t in ts: t.join()
    for r in res:
        if r is None or r[0] is None: err+=1
        elif r[0]: ok+=1; times.append(r[2])
        else: short+=1; times.append(r[2])
    times.sort()
    p50=times[len(times)//2]*1000 if times else 0.0
    mx=times[-1]*1000 if times else 0.0
    flag="" if ok==REPS else "  <-- INCOMPLETE"
    print(f"{n:>9} {blocks:>7} {ok:>4} {short:>6} {err:>4} {p50:>8.1f} {mx:>8.1f}{flag}")
    if ok!=REPS: overall_ok=False
sys.exit(0 if overall_ok else 2)
PY

sleep 2
echo
echo "===== peak loss_pct (client telemetry) ====="
grep "tunnel alive" "$CLI_LOG" | grep -o 'loss_pct="[0-9.]*"' | grep -o '[0-9.]*' | sort -g | tail -1 | sed 's/^/peak loss_pct=/'
echo "===== client WARN/ERROR ====="; grep -icE "WARN|ERROR" "$CLI_LOG" | sed 's/^/count=/'
grep -iE "WARN|ERROR" "$CLI_LOG" | sed 's/\x1b\[[0-9;]*m//g' | awk '{print $NF}' | sort | uniq -c | head
echo "===== server WARN/ERROR ====="; grep -icE "WARN|ERROR" "$SRV_LOG" | sed 's/^/count=/'
grep -iE "WARN|ERROR" "$SRV_LOG" | sed 's/\x1b\[[0-9;]*m//g' | awk '{print $NF}' | sort | uniq -c | head
echo
[ "$FAIL" = "0" ] && echo "PASS: every size fully round-tripped" || echo "FAIL/INCOMPLETE: see table above"
echo "logs: client=$CLI_LOG server=$SRV_LOG"
