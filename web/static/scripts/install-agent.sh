#!/usr/bin/env bash
# ==============================================================================
# Valtrivo LogSeal - Cross-Platform Native Agent Installer
# Platforms: Linux (systemd: Ubuntu, Debian, RHEL, Rocky, CentOS, Alpine, SUSE) & macOS (launchd)
# ==============================================================================
set -euo pipefail

# Terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "=================================================================="
echo "         VALTRIVO LOGSEAL - NATIVE AGENT INSTALLER               "
echo "=================================================================="
echo -e "${NC}"

# Root privileges check
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] This installer must be run as root (or using sudo).${NC}"
    echo "Usage: sudo bash install-agent.sh --server <URL> --token <TOKEN>"
    exit 1
fi

SERVER_URL=""
TOKEN=""
INSECURE="false"
INSTALL_DIR="/opt/logger-agent"
CONFIG_DIR="/etc/logger-agent"
SERVICE_NAME="logger-agent"

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --server|-s)
            SERVER_URL="$2"
            shift 2
            ;;
        --token|-t)
            TOKEN="$2"
            shift 2
            ;;
        --insecure|-k)
            INSECURE="true"
            shift
            ;;
        --help|-h)
            echo "Usage: sudo bash install-agent.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --server, -s <URL>     LogSeal Server URL (e.g. https://logger.corp.local:8443)"
            echo "  --token, -t <TOKEN>    Enrollment Token (lp_ea_...)"
            echo "  --insecure, -k         Allow self-signed or insecure TLS certificates"
            echo "  --help, -h             Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Interactive prompts if missing
if [ -z "$SERVER_URL" ]; then
    read -r -p "Enter LogSeal Server URL [http://localhost:8080]: " input_server
    SERVER_URL="${input_server:-http://localhost:8080}"
fi
SERVER_URL="${SERVER_URL%/}"

if [ -z "$TOKEN" ]; then
    read -r -p "Enter Enrollment Token (lp_ea_...): " input_token
    TOKEN="$input_token"
fi

if [ -z "$TOKEN" ]; then
    echo -e "${RED}[ERROR] Enrollment token is required. Generate one from LogSeal Endpoint > Tokens.${NC}"
    exit 1
fi

# Detect Operating System and Architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64|amd64)
        TARGET_ARCH="amd64"
        ;;
    aarch64|arm64)
        TARGET_ARCH="arm64"
        ;;
    *)
        echo -e "${RED}[ERROR] Unsupported CPU architecture: $ARCH${NC}"
        exit 1
        ;;
esac

echo -e "${BLUE}[*] Platform detected: ${BOLD}${OS}/${TARGET_ARCH}${NC}"
echo -e "${BLUE}[*] Target LogSeal Server: ${BOLD}${SERVER_URL}${NC}"

# Create directories
mkdir -p "$INSTALL_DIR/bin"
mkdir -p "$CONFIG_DIR"
mkdir -p "/var/log/logger-agent"

# Download or copy binary
BINARY_NAME="logger-agent"
if [ "$OS" = "darwin" ]; then
    BINARY_URL="${SERVER_URL}/static/bin/logger-agent-darwin-${TARGET_ARCH}"
else
    BINARY_URL="${SERVER_URL}/static/bin/logger-agent-linux-${TARGET_ARCH}"
fi

echo -e "${BLUE}[*] Fetching agent binary...${NC}"
CURL_OPTS="-sSL"
if [ "$INSECURE" = "true" ]; then
    CURL_OPTS="${CURL_OPTS} -k"
fi

# Download with fallback to local build if server has no pre-compiled binary distribution
if ! curl $CURL_OPTS -f "$BINARY_URL" -o "$INSTALL_DIR/bin/$BINARY_NAME" 2>/dev/null; then
    echo -e "${YELLOW}[!] Remote precompiled binary not found at ${BINARY_URL}.${NC}"
    # Check if running on local server machine with binary in path
    if command -v logger-agent >/dev/null 2>&1; then
        cp "$(command -v logger-agent)" "$INSTALL_DIR/bin/$BINARY_NAME"
        echo -e "${GREEN}[✓] Copied existing local logger-agent binary.${NC}"
    elif [ -f "./bin/logger-agent" ]; then
        cp "./bin/logger-agent" "$INSTALL_DIR/bin/$BINARY_NAME"
        echo -e "${GREEN}[✓] Copied ./bin/logger-agent.${NC}"
    elif command -v go >/dev/null 2>&1 && [ -d "./agent/cmd/logger-agent" ]; then
        echo -e "${BLUE}[*] Compiling native agent binary from local Go source...${NC}"
        go build -o "$INSTALL_DIR/bin/$BINARY_NAME" ./agent/cmd/logger-agent
        echo -e "${GREEN}[✓] Compiled logger-agent successfully.${NC}"
    else
        echo -e "${RED}[ERROR] Could not obtain logger-agent binary. Please ensure Go is installed or binary is hosted on server.${NC}"
        exit 1
    fi
fi

chmod +x "$INSTALL_DIR/bin/$BINARY_NAME"

# Write Configuration File
CONFIG_FILE="$CONFIG_DIR/logger-agent.json"
echo -e "${BLUE}[*] Writing configuration to ${CONFIG_FILE}...${NC}"

cat <<EOF > "$CONFIG_FILE"
{
  "server_url": "${SERVER_URL}",
  "enrollment_token": "${TOKEN}",
  "insecure_tls": ${INSECURE},
  "log_level": "info",
  "data_dir": "${INSTALL_DIR}/data",
  "heartbeat_interval_sec": 30,
  "identity_file": "${CONFIG_DIR}/identity.json"
}
EOF

chmod 600 "$CONFIG_FILE"
mkdir -p "${INSTALL_DIR}/data"

# Setup System Service
if [ "$OS" = "linux" ]; then
    if command -v systemctl >/dev/null 2>&1; then
        echo -e "${BLUE}[*] Configuring systemd service...${NC}"
        SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
        cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=Valtrivo LogSeal - Cross-Platform Native Endpoint Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/bin/${BINARY_NAME} -config ${CONFIG_FILE}
Restart=always
RestartSec=5s
LimitNOFILE=65536
StandardOutput=append:/var/log/logger-agent/agent.log
StandardError=append:/var/log/logger-agent/agent-error.log

[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload
        systemctl enable "$SERVICE_NAME"
        systemctl restart "$SERVICE_NAME"

        echo -e "${GREEN}[✓] Service ${SERVICE_NAME} enabled and started successfully!${NC}"
        systemctl status "$SERVICE_NAME" --no-pager || true
    else
        echo -e "${YELLOW}[!] systemd not detected. Run manually: ${INSTALL_DIR}/bin/${BINARY_NAME} -config ${CONFIG_FILE}${NC}"
    fi

elif [ "$OS" = "darwin" ]; then
    echo -e "${BLUE}[*] Configuring macOS launchd daemon...${NC}"
    PLIST_FILE="/Library/LaunchDaemons/com.valtrivo.logger-agent.plist"
    cat <<EOF > "$PLIST_FILE"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.valtrivo.logger-agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/bin/${BINARY_NAME}</string>
        <string>-config</string>
        <string>${CONFIG_FILE}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/logger-agent/agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/logger-agent/agent-error.log</string>
</dict>
</plist>
EOF

    chmod 644 "$PLIST_FILE"
    launchctl unload "$PLIST_FILE" 2>/dev/null || true
    launchctl load -w "$PLIST_FILE"
    echo -e "${GREEN}[✓] macOS launchd daemon loaded successfully!${NC}"
fi

echo ""
echo -e "${GREEN}${BOLD}=================================================================="
echo -e "   LOGGER AGENT INSTALLATION COMPLETED SUCCESSFULLY!             "
echo -e "==================================================================${NC}"
echo -e "Agent Version : $("$INSTALL_DIR/bin/$BINARY_NAME" -v || echo 'v0.1.0')"
echo -e "Config File   : ${CONFIG_FILE}"
echo -e "Log Directory : /var/log/logger-agent/"
echo -e "Verify Status : systemctl status ${SERVICE_NAME}"
echo ""
