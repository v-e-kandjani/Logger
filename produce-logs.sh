#!/usr/bin/env bash
# ==============================================================================
# Valtrivo LogSeal - Synthetic Test Log Generator CLI
# Usage:
#   bash produce-logs.sh [COUNT] [VENDOR] [TARGET]
# Examples:
#   bash produce-logs.sh 25 watchguard
#   bash produce-logs.sh 50 fortinet
#   bash produce-logs.sh 100 all 127.0.0.1:514
# ==============================================================================

COUNT="${1:-25}"
VENDOR="${2:-all}"
TARGET="${3:-127.0.0.1:514}"

# Determine directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Producing $COUNT test logs (vendor: $VENDOR) -> $TARGET..."

DOCKER_CMD="docker compose"
if ! docker compose ps syslog-app &>/dev/null 2>&1 && sudo docker compose ps syslog-app &>/dev/null 2>&1; then
    DOCKER_CMD="sudo docker compose"
fi

if $DOCKER_CMD ps syslog-app &>/dev/null 2>&1; then
    CONTAINER_TARGET="$TARGET"
    if [ "$TARGET" = "127.0.0.1:514" ] || [ "$TARGET" = "localhost:514" ]; then
        CONTAINER_TARGET="127.0.0.1:5514"
    fi
    $DOCKER_CMD exec -T syslog-app /opt/syslog-platform/bin/syslog-platform produce-logs --count "$COUNT" --vendor "$VENDOR" --target "$CONTAINER_TARGET"
else
    # Fallback to python probe if containers aren't ready
    python3 -c "
import socket, time
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
parts = '$TARGET'.split(':')
host = parts[0]
port = int(parts[1]) if len(parts) > 1 else 514
for i in range($COUNT):
    now = time.strftime('%b %d %H:%M:%S')
    msg = f'<14>{now} WatchGuard-Firebox-M370 firewall: msg_id=\"3000-0148\" disp=\"Allow\" policy=\"HTTPS-Proxy-00\" src=\"10.0.1.{i+10}\" dst=\"198.51.100.4\" pr=\"tcp\" sent=1420 rcvd=6520'.encode()
    sock.sendto(msg, (host, port))
    time.sleep(0.04)
print(f'Successfully sent {$COUNT} synthetic syslog messages to $TARGET')
"
fi
