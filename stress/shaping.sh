#!/usr/bin/env bash
# Loopback link shaping for the raptun stress test, via macOS dummynet
# (dnctl + pf). Injects ~100 ms delay, ~50 ms jitter, and <5% packet loss on
# traffic to/from the raptun server's UDP port on 127.0.0.1.
#
# dummynet has no native jitter knob, so jitter is approximated by splitting
# the shaped traffic across three pipes with delays {50,100,150} ms at equal
# probability — mean 100 ms, spread ±50 ms. Loss is a uniform plr on each pipe.
#
# Requires sudo (pf + dnctl are privileged). Usage:
#   sudo ./shaping.sh up <server_udp_port>
#   sudo ./shaping.sh down
set -euo pipefail

ANCHOR="raptun-stress"
PLR=${PLR:-0.04}          # 4% loss, under the 5% ceiling
D_LO=${D_LO:-50}          # jitter low  (100 - 50)
D_MID=${D_MID:-100}       # center delay
D_HI=${D_HI:-150}         # jitter high (100 + 50)

cmd=${1:-}
port=${2:-}

case "$cmd" in
  up)
    [ -n "$port" ] || { echo "usage: sudo $0 up <server_udp_port>" >&2; exit 2; }

    # Three dummynet pipes: same loss, delays spread around the 100 ms center.
    dnctl pipe 1 config delay "$D_LO"  plr "$PLR"
    dnctl pipe 2 config delay "$D_MID" plr "$PLR"
    dnctl pipe 3 config delay "$D_HI"  plr "$PLR"

    # pf rules: shape both directions of the server's UDP port. `prob` splits
    # packets across the three delay pipes to synthesize jitter. Rules are
    # loaded into a dedicated anchor so teardown is clean.
    cat <<PF | pfctl -a "$ANCHOR" -f -
dummynet in  quick proto udp from any to any port $port pipe 1 prob 0.34
dummynet in  quick proto udp from any to any port $port pipe 2 prob 0.5
dummynet in  quick proto udp from any to any port $port pipe 3
dummynet out quick proto udp from any port $port to any pipe 1 prob 0.34
dummynet out quick proto udp from any port $port to any pipe 2 prob 0.5
dummynet out quick proto udp from any port $port to any pipe 3
PF

    # Enable pf if not already on (idempotent; ignore "already enabled").
    pfctl -E 2>/dev/null || true
    echo "shaping up: port=$port delay~${D_MID}ms jitter±$((D_MID-D_LO))ms plr=$PLR"
    ;;

  down)
    dnctl pipe 1 delete 2>/dev/null || true
    dnctl pipe 2 delete 2>/dev/null || true
    dnctl pipe 3 delete 2>/dev/null || true
    pfctl -a "$ANCHOR" -F all 2>/dev/null || true
    echo "shaping down"
    ;;

  *)
    echo "usage: sudo $0 {up <server_udp_port>|down}" >&2
    exit 2
    ;;
esac
