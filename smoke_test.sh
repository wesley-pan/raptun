#!/usr/bin/env bash
# End-to-end smoke test: start a TCP echo server, tunnel it through
# raptun-server + raptun-client, and verify a payload round-trips.
set -euo pipefail
cd "$(dirname "$0")"

ECHO_PORT=19001
SERVER_PORT=19002
CLIENT_PORT=19003
PSK="smoke-secret"

cleanup() { kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT

# 1. A trivial TCP echo server using python (uppercases input).
python3 -c "
import socket, threading
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $ECHO_PORT)); s.listen(5)
def handle(c):
    data = c.recv(65536)
    c.sendall(data.upper())
    c.close()
while True:
    c,_ = s.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
" &
sleep 1

# 2. raptun-server: forward tunnelled connections to the echo server.
#    Capture its self-signed fingerprint from the logs.
SRV_LOG=$(mktemp)
RUST_LOG=info ./target/debug/raptun-server \
    -l 127.0.0.1:$SERVER_PORT -r 127.0.0.1:$ECHO_PORT \
    --self-signed --psk "$PSK" >"$SRV_LOG" 2>&1 &
sleep 1
FINGERPRINT=$(grep -o 'SHA256:[0-9a-f]*' "$SRV_LOG" | head -1)
echo "server fingerprint: $FINGERPRINT"
[ -n "$FINGERPRINT" ] || { echo "FAIL: no fingerprint"; cat "$SRV_LOG"; exit 1; }

# 3. raptun-client: listen locally, pin the fingerprint.
RUST_LOG=info ./target/debug/raptun-client \
    -l 127.0.0.1:$CLIENT_PORT -r 127.0.0.1:$SERVER_PORT \
    --psk "$PSK" --fingerprint "$FINGERPRINT" >/tmp/raptun-client.log 2>&1 &
sleep 1

# 4. Send a payload through the client and check the echo came back uppercased.
RESULT=$(python3 -c "
import socket
s = socket.socket(); s.connect(('127.0.0.1', $CLIENT_PORT))
s.sendall(b'raptun end to end'); print(s.recv(65536).decode()); s.close()
")
echo "round-trip result: '$RESULT'"
[ "$RESULT" = "RAPTUN END TO END" ] && echo "PASS: end-to-end tunnel works" || { echo "FAIL"; exit 1; }
