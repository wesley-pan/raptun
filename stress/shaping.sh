#!/usr/bin/env bash
# Loopback link shaping for the raptun stress test, via macOS dummynet
# (dnctl + pf). Injects ~100 ms delay and <5% packet loss on traffic to/from
# the raptun server's UDP port on 127.0.0.1.
#
# NOTE on jitter: macOS dummynet's dnctl has only a fixed `delay` knob (no
# jitter/profile), and pf's `probability` attribute is rejected on `dummynet`
# action rules, so the "split across several delay pipes by probability" trick
# used on Linux tc-netem is not available here. This shaper therefore applies a
# *fixed* 100 ms one-way delay plus uniform loss. Jitter is a documented gap of
# the macOS harness; the Linux `netem_bench.sh` path can add true jitter.
#
# Requires sudo (pf + dnctl are privileged). Usage:
#   sudo ./shaping.sh up <server_udp_port>
#   sudo ./shaping.sh down
set -euo pipefail

ANCHOR="raptun-stress"
PLR=${PLR:-0.04}          # 4% loss, under the 5% ceiling
DELAY=${DELAY:-100}       # one-way propagation delay (ms)

cmd=${1:-}
port=${2:-}

case "$cmd" in
  up)
    [ -n "$port" ] || { echo "usage: sudo $0 up <server_udp_port>" >&2; exit 2; }

    # Single dummynet pipe: fixed delay + uniform loss.
    dnctl pipe 1 config delay "$DELAY" plr "$PLR"

    # pf rules: shape both directions of the server's UDP port. Loaded into a
    # dedicated anchor so teardown is clean.
    cat <<PF | pfctl -a "$ANCHOR" -f -
dummynet in  quick proto udp from any to any port $port pipe 1
dummynet out quick proto udp from any to any port $port pipe 1
PF

    # Enable pf if not already on (idempotent; ignore "already enabled").
    pfctl -E 2>/dev/null || true
    echo "shaping up: port=$port delay=${DELAY}ms plr=$PLR (no jitter on macOS)"
    ;;

  down)
    dnctl pipe 1 delete 2>/dev/null || true
    pfctl -a "$ANCHOR" -F all 2>/dev/null || true
    echo "shaping down"
    ;;

  *)
    echo "usage: sudo $0 {up <server_udp_port>|down}" >&2
    exit 2
    ;;
esac
