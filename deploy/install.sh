#!/usr/bin/env bash
# Deploy raptun-server as a systemd service.
#
# Usage:
#   sudo ./install.sh [--binary /path/to/raptun-server]
#
# What it does:
#   1. Copies the binary to /usr/local/bin/
#   2. Creates a dedicated 'raptun' system user
#   3. Installs config, TLS placeholders, and the env secrets file
#   4. Installs the systemd unit and enables it
#
# Re-running is safe: existing files are overwritten, the unit is reloaded.

set -euo pipefail

BINARY=""
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Parse arguments.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary) BINARY="$2"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# Must run as root.
if [[ "${EUID}" -ne 0 ]]; then
    echo "error: run with sudo" >&2
    exit 1
fi

# Locate the binary: CLI flag > release build > debug build.
if [[ -z "$BINARY" ]]; then
    for candidate in \
        "$SCRIPT_DIR/../target/release/raptun-server" \
        "$SCRIPT_DIR/../target/debug/raptun-server"; do
        if [[ -x "$candidate" ]]; then
            BINARY="$candidate"
            break
        fi
    done
fi
if [[ -z "$BINARY" || ! -x "$BINARY" ]]; then
    echo "error: raptun-server binary not found; build first or pass --binary <path>" >&2
    exit 1
fi
echo "binary: $BINARY"

# ── 1. Install binary ────────────────────────────────────────────────────────
install -o root -g root -m 755 "$BINARY" /usr/local/bin/raptun-server
echo "installed /usr/local/bin/raptun-server"

# ── 2. Create system user ────────────────────────────────────────────────────
if ! id -u raptun &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin raptun
    echo "created system user 'raptun'"
fi

# ── 3. Config directory and files ────────────────────────────────────────────
install -d -o root -g raptun -m 750 /etc/raptun

# Main config file (always updated from repo).
install -o root -g raptun -m 640 \
    "$SCRIPT_DIR/raptun-server.toml" /etc/raptun/raptun-server.toml
echo "installed /etc/raptun/raptun-server.toml"

# Secrets env file: only create if it doesn't already exist to avoid clobbering
# a live PSK on re-install.
if [[ ! -f /etc/raptun/env ]]; then
    cat > /etc/raptun/env <<'EOF'
# Environment variables loaded by the raptun-server systemd unit.
# chmod 640, owned root:raptun — never commit this file.
RAPTUN_PSK=change-me
EOF
    chmod 640 /etc/raptun/env
    chown root:raptun /etc/raptun/env
    echo "created /etc/raptun/env  <-- set RAPTUN_PSK before starting the service"
else
    echo "skipped /etc/raptun/env  (already exists)"
fi


# ── 4. systemd unit ──────────────────────────────────────────────────────────
install -o root -g root -m 644 \
    "$SCRIPT_DIR/raptun-server.service" /etc/systemd/system/raptun-server.service
echo "installed /etc/systemd/system/raptun-server.service"

systemctl daemon-reload
systemctl enable raptun-server

echo ""
echo "Done. Next steps:"
echo "  1. Edit /etc/raptun/env       — set RAPTUN_PSK"
echo "  2. Edit /etc/raptun/raptun-server.toml — set 'target' to your backend"
echo "  3. After first start, copy the 'SHA256:...' fingerprint from the logs"
echo "     and pass it to clients via --fingerprint"
echo "  4. sudo systemctl start raptun-server"
echo "  5. sudo systemctl status raptun-server"
