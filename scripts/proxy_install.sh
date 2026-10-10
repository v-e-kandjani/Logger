#!/usr/bin/env bash
# ==============================================================================
# Valtrivo LogSeal - Edge Proxy Node Installer for Ubuntu Minimal & Debian Linux
# ==============================================================================
# Automatically deploys the lightweight standalone edge forwarder daemon,
# configures local syslog spooling, and connects to Cloud Logger.
# ==============================================================================

set -e

# Terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${CYAN}${BOLD}"
echo "=================================================================="
echo "    VALTRIVO LOGSEAL - EDGE PROXY FORWARDER NODE INSTALLER        "
echo "=================================================================="
echo -e "${NC}"

# Check for root / sudo
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] This installer must be run as root (or with sudo).${NC}"
    echo "Usage: sudo bash proxy_install.sh [options]"
    exit 1
fi

ENDPOINT=""
TOKEN=""
NODE_NAME=""
INSECURE="true"
UDP_PORT="514"
TCP_PORT="514"

# Parse command line options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --endpoint|-e)
            ENDPOINT="$2"
            shift 2
            ;;
        --token|-t)
            TOKEN="$2"
            shift 2
            ;;
        --name|-n)
            NODE_NAME="$2"
            shift 2
            ;;
        --udp-port)
            UDP_PORT="$2"
            shift 2
            ;;
        --tcp-port)
            TCP_PORT="$2"
            shift 2
            ;;
        --insecure)
            INSECURE="true"
            shift
            ;;
        --help|-h)
            echo "Usage: sudo bash proxy_install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --endpoint, -e <URL>     Cloud Logger Endpoint (e.g. https://168.231.106.208:8443)"
            echo "  --token, -t <TOKEN>      Authentication Token from Cloud Settings"
            echo "  --name, -n <NAME>        Friendly node identifier (e.g. branch-istanbul)"
            echo "  --udp-port <PORT>        Local syslog UDP listen port (default: 514)"
            echo "  --tcp-port <PORT>        Local syslog TCP listen port (default: 514)"
            echo "  --insecure               Allow self-signed TLS certificates (default: true)"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

# If arguments missing and run in interactive shell, prompt the user
if [ -z "$ENDPOINT" ] || [ -z "$TOKEN" ]; then
    echo -e "${YELLOW}[Interactive Setup] Configuration arguments not supplied.${NC}"
    echo ""
    
    if [ -z "$ENDPOINT" ]; then
        read -r -p "Enter Cloud Logger Endpoint URL [https://168.231.106.208:8443]: " input_ep
        ENDPOINT="${input_ep:-https://168.231.106.208:8443}"
    fi

    if [ -z "$NODE_NAME" ]; then
        DEFAULT_NAME="$(hostname -s 2>/dev/null || echo 'edge-proxy-node')"
        read -r -p "Enter Edge Node Name [${DEFAULT_NAME}]: " input_name
        NODE_NAME="${input_name:-$DEFAULT_NAME}"
    fi

    if [ -z "$TOKEN" ]; then
        read -r -p "Enter Edge Node Token: " input_token
        TOKEN="${input_token}"
    fi
fi

# Clean up endpoint URL
ENDPOINT="${ENDPOINT%/}"
if [[ ! "$ENDPOINT" =~ ^https?:// ]]; then
    ENDPOINT="https://${ENDPOINT}"
fi

if [ -z "$TOKEN" ]; then
    echo -e "${RED}[ERROR] Node token is required. Generate one in Cloud Settings -> Edge Proxy Düğümleri.${NC}"
    exit 1
fi

if [ -z "$NODE_NAME" ]; then
    NODE_NAME="$(hostname -s 2>/dev/null || echo 'edge-node')"
fi

echo -e "\n${BLUE}[1/5] Checking prerequisites...${NC}"
if ! command -v curl &> /dev/null; then
    echo "Installing curl..."
    apt-get update -qq && apt-get install -y -qq curl ca-certificates
fi

echo -e "${BLUE}[2/5] Creating directory layout...${NC}"
mkdir -p /etc/logseal
mkdir -p /var/spool/logseal
mkdir -p /var/log/logseal
chmod 700 /etc/logseal
chmod 750 /var/spool/logseal

echo -e "${BLUE}[3/5] Fetching logseal-proxy binary from Cloud (${ENDPOINT})...${NC}"
BINARY_INSTALLED=false

# Method A: Download compiled binary from Cloud
if curl -k -fsSL "${ENDPOINT}/api/v1/edge/download-binary" -o /usr/local/bin/logseal-proxy 2>/dev/null; then
    chmod +x /usr/local/bin/logseal-proxy
    BINARY_INSTALLED=true
    echo -e "${GREEN}[OK] Downloaded logseal-proxy binary from Cloud.${NC}"
fi

# Method B: If local file exists (e.g. copied manually)
if [ "$BINARY_INSTALLED" = false ]; then
    if [ -f "./bin/logseal-proxy" ]; then
        cp ./bin/logseal-proxy /usr/local/bin/logseal-proxy
        chmod +x /usr/local/bin/logseal-proxy
        BINARY_INSTALLED=true
        echo -e "${GREEN}[OK] Copied local ./bin/logseal-proxy binary.${NC}"
    elif [ -f "./logseal-proxy" ]; then
        cp ./logseal-proxy /usr/local/bin/logseal-proxy
        chmod +x /usr/local/bin/logseal-proxy
        BINARY_INSTALLED=true
        echo -e "${GREEN}[OK] Copied local ./logseal-proxy binary.${NC}"
    fi
fi

# Method C: Compile on the fly if Go is installed
if [ "$BINARY_INSTALLED" = false ] && command -v go &> /dev/null; then
    if [ -d "./cmd/proxy" ]; then
        echo "Building logseal-proxy from source using local Go..."
        CGO_ENABLED=0 go build -ldflags="-s -w" -o /usr/local/bin/logseal-proxy ./cmd/proxy/main.go
        chmod +x /usr/local/bin/logseal-proxy
        BINARY_INSTALLED=true
        echo -e "${GREEN}[OK] Compiled logseal-proxy from source.${NC}"
    fi
fi

if [ "$BINARY_INSTALLED" = false ]; then
    echo -e "${RED}[ERROR] Could not obtain logseal-proxy binary from Cloud (${ENDPOINT}/api/v1/edge/download-binary) or local source.${NC}"
    echo "Please ensure the Cloud service is reachable or copy logseal-proxy to /usr/local/bin/logseal-proxy."
    exit 1
fi

echo -e "${BLUE}[4/5] Generating configuration at /etc/logseal/proxy.json...${NC}"
cat <<EOF > /etc/logseal/proxy.json
{
  "endpoint": "${ENDPOINT}",
  "node_name": "${NODE_NAME}",
  "token": "${TOKEN}",
  "listen_udp": ":${UDP_PORT}",
  "listen_tcp": ":${TCP_PORT}",
  "spool_dir": "/var/spool/logseal",
  "insecure_tls": ${INSECURE},
  "max_batch_size": 500,
  "max_spool_mb": 500
}
EOF
chmod 600 /etc/logseal/proxy.json

echo -e "${BLUE}[5/5] Configuring systemd service...${NC}"
cat <<EOF > /etc/systemd/system/logseal-proxy.service
[Unit]
Description=Valtrivo LogSeal - Edge Proxy Forwarder Node
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/logseal-proxy -config /etc/logseal/proxy.json
Restart=always
RestartSec=5
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable logseal-proxy.service
systemctl restart logseal-proxy.service

echo ""
echo -e "${GREEN}${BOLD}==================================================================${NC}"
echo -e "${GREEN}${BOLD}     VALTRIVO LOGSEAL EDGE PROXY INSTALLED & STARTED!             ${NC}"
echo -e "${GREEN}${BOLD}==================================================================${NC}"
echo -e "Node Name        : ${BOLD}${NODE_NAME}${NC}"
echo -e "Cloud Endpoint   : ${BOLD}${ENDPOINT}${NC}"
echo -e "Syslog Listeners : ${BOLD}UDP :${UDP_PORT} | TCP :${TCP_PORT}${NC}"
echo -e "Local Spool Dir  : ${BOLD}/var/spool/logseal${NC}"
echo -e "Service Status   : ${BOLD}systemctl status logseal-proxy${NC}"
echo -e "Live Logs        : ${BOLD}journalctl -u logseal-proxy -f${NC}"
echo -e "${GREEN}${BOLD}==================================================================${NC}"
echo -e "${CYAN}Transmission schedule is centrally managed by the Cloud.${NC}"
echo ""
