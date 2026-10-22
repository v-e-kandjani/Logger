#!/usr/bin/env bash
# ==============================================================================
# Valtrivo LogSeal - Multi-Platform Agent & Installer Build Script
# Generates:
#   1. Standalone binaries (Linux, Windows, macOS Universal) -> web/static/bin/
#   2. Windows self-contained installer -> web/static/downloads/logger-agent-setup.exe
#   3. macOS Apple Disk Image -> web/static/downloads/logger-agent-installer.dmg
#   4. macOS Installer Package -> web/static/downloads/logger-agent-macos.pkg
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"

cd "$ROOT_DIR"

BIN_DIR="$ROOT_DIR/web/static/bin"
DL_DIR="$ROOT_DIR/web/static/downloads"
TMP_DIR="$(mktemp -d -t logger-build-XXXXXX)"

trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$BIN_DIR" "$DL_DIR"

VERSION="v0.1.3"
BUILD_DATE="$(date +%Y-%m-%d)"
COMMIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"
LDFLAGS="-s -w -X github.com/syslog-platform/logger/agent/internal/version.Version=${VERSION} -X github.com/syslog-platform/logger/agent/internal/version.BuildDate=${BUILD_DATE} -X github.com/syslog-platform/logger/agent/internal/version.CommitSHA=${COMMIT_SHA}"

echo "=================================================================="
echo "    VALTRIVO LOGSEAL - BUILDING AGENT INSTALLERS (${VERSION})     "
echo "=================================================================="
echo "Build Date : ${BUILD_DATE}"
echo "Commit SHA : ${COMMIT_SHA}"
echo ""

# ------------------------------------------------------------------------------
# 1. COMPILE STANDALONE AGENT BINARIES
# ------------------------------------------------------------------------------
echo "[1/4] Compiling cross-platform agent binaries..."

echo "  -> Linux amd64..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="${LDFLAGS}" -o "$BIN_DIR/logger-agent-linux-amd64" ./agent/cmd/logger-agent

echo "  -> Linux arm64..."
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="${LDFLAGS}" -o "$BIN_DIR/logger-agent-linux-arm64" ./agent/cmd/logger-agent

echo "  -> Windows amd64..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="${LDFLAGS}" -o "$BIN_DIR/logger-agent-windows-amd64.exe" ./agent/cmd/logger-agent

echo "  -> macOS arm64 (Apple Silicon)..."
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="${LDFLAGS}" -o "$TMP_DIR/agent-darwin-arm64" ./agent/cmd/logger-agent

echo "  -> macOS amd64 (Intel)..."
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="${LDFLAGS}" -o "$TMP_DIR/agent-darwin-amd64" ./agent/cmd/logger-agent

if command -v lipo >/dev/null 2>&1; then
    echo "  -> Creating macOS Universal binary via lipo..."
    lipo -create -output "$BIN_DIR/logger-agent-darwin-universal" "$TMP_DIR/agent-darwin-arm64" "$TMP_DIR/agent-darwin-amd64"
else
    echo "  -> lipo not available; copying arm64 as universal..."
    cp "$TMP_DIR/agent-darwin-arm64" "$BIN_DIR/logger-agent-darwin-universal"
fi
cp "$TMP_DIR/agent-darwin-arm64" "$BIN_DIR/logger-agent-darwin-arm64"
cp "$TMP_DIR/agent-darwin-amd64" "$BIN_DIR/logger-agent-darwin-amd64"

# ------------------------------------------------------------------------------
# 2. BUILD WINDOWS STANDALONE INSTALLER (.EXE)
# ------------------------------------------------------------------------------
echo ""
echo "[2/4] Building Windows installer (.exe)..."
cp "$BIN_DIR/logger-agent-windows-amd64.exe" "$ROOT_DIR/agent/cmd/installer-windows/logger-agent.exe"

CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -tags windows_installer -trimpath -ldflags="${LDFLAGS}" \
    -o "$DL_DIR/logger-agent-setup.exe" \
    "$ROOT_DIR/agent/cmd/installer-windows"

rm -f "$ROOT_DIR/agent/cmd/installer-windows/logger-agent.exe"
echo "  [✓] Built: $DL_DIR/logger-agent-setup.exe ($(ls -lh "$DL_DIR/logger-agent-setup.exe" | awk '{print $5}'))"

# ------------------------------------------------------------------------------
# 3. BUILD MACOS PKG PACKAGE
# ------------------------------------------------------------------------------
echo ""
echo "[3/4] Preparing macOS package (.pkg)..."
PKG_STAGING="$TMP_DIR/pkg-root"
PKG_SCRIPTS="$TMP_DIR/pkg-scripts"
mkdir -p "$PKG_STAGING/opt/logger-agent/bin" "$PKG_STAGING/opt/logger-agent/data" "$PKG_STAGING/etc/logger-agent" "$PKG_STAGING/Library/LaunchDaemons" "$PKG_SCRIPTS"

cp "$BIN_DIR/logger-agent-darwin-universal" "$PKG_STAGING/opt/logger-agent/bin/logger-agent"
chmod 755 "$PKG_STAGING/opt/logger-agent/bin/logger-agent"

cat << 'EOF' > "$PKG_STAGING/Library/LaunchDaemons/com.valtrivo.logger-agent.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.valtrivo.logger-agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/logger-agent/bin/logger-agent</string>
        <string>-config</string>
        <string>/etc/logger-agent/config.json</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/logger-agent/agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/logger-agent/agent-error.log</string>
    <key>WorkingDirectory</key>
    <string>/opt/logger-agent</string>
</dict>
</plist>
EOF
chmod 644 "$PKG_STAGING/Library/LaunchDaemons/com.valtrivo.logger-agent.plist"

cat << 'EOF' > "$PKG_SCRIPTS/postinstall"
#!/bin/bash
mkdir -p /var/log/logger-agent /opt/logger-agent/data /etc/logger-agent

if [ ! -f /etc/logger-agent/config.json ]; then
    cat << 'CFG' > /etc/logger-agent/config.json
{
  "server_url": "http://localhost:8080",
  "enrollment_token": "<TOKEN>",
  "insecure_tls": false,
  "log_level": "info",
  "data_dir": "/opt/logger-agent/data",
  "heartbeat_interval_sec": 30,
  "identity_file": "/etc/logger-agent/identity.json"
}
CFG
    chmod 600 /etc/logger-agent/config.json
fi

chmod 755 /opt/logger-agent/bin/logger-agent
chown root:wheel /Library/LaunchDaemons/com.valtrivo.logger-agent.plist

launchctl unload -w /Library/LaunchDaemons/com.valtrivo.logger-agent.plist 2>/dev/null || true
launchctl load -w /Library/LaunchDaemons/com.valtrivo.logger-agent.plist 2>/dev/null || true
exit 0
EOF
chmod +x "$PKG_SCRIPTS/postinstall"

if command -v pkgbuild >/dev/null 2>&1; then
    pkgbuild --root "$PKG_STAGING" \
             --scripts "$PKG_SCRIPTS" \
             --identifier "com.valtrivo.logger-agent" \
             --version "${VERSION#v}" \
             --install-location "/" \
             "$DL_DIR/logger-agent-macos.pkg"
    echo "  [✓] Built: $DL_DIR/logger-agent-macos.pkg ($(ls -lh "$DL_DIR/logger-agent-macos.pkg" | awk '{print $5}'))"
fi

# ------------------------------------------------------------------------------
# 4. BUILD MACOS APPLE DISK IMAGE (.DMG)
# ------------------------------------------------------------------------------
echo ""
echo "[4/4] Building macOS Installer (.dmg)..."
DMG_STAGING="$TMP_DIR/dmg-root"
mkdir -p "$DMG_STAGING/bin"

cp "$BIN_DIR/logger-agent-darwin-universal" "$DMG_STAGING/bin/logger-agent"
cp "$PKG_STAGING/Library/LaunchDaemons/com.valtrivo.logger-agent.plist" "$DMG_STAGING/com.valtrivo.logger-agent.plist"

if [ -f "$DL_DIR/logger-agent-macos.pkg" ]; then
    cp "$DL_DIR/logger-agent-macos.pkg" "$DMG_STAGING/Install LOGGER Agent.pkg"
fi

# Create double-clickable installer script
cat << 'EOF' > "$DMG_STAGING/Install LOGGER Agent.command"
#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
clear
echo "=================================================================="
echo "         VALTRIVO LOGSEAL - MACOS AGENT INSTALLER                 "
echo "=================================================================="
echo ""
echo "This installer configures LOGGER Agent as a system launchd daemon."
echo "Please enter your Mac administrator password when prompted."
echo ""

sudo mkdir -p /opt/logger-agent/bin /opt/logger-agent/data /etc/logger-agent /var/log/logger-agent

echo "[*] Installing universal binary to /opt/logger-agent/bin..."
sudo cp "$DIR/bin/logger-agent" /opt/logger-agent/bin/logger-agent
sudo chmod 755 /opt/logger-agent/bin/logger-agent

if [ ! -f /etc/logger-agent/config.json ]; then
    echo ""
    read -r -p "Enter LogSeal Server URL [http://localhost:8080]: " input_server
    SERVER_URL="${input_server:-http://localhost:8080}"
    read -r -p "Enter Enrollment Token (lp_ea_...): " input_token
    TOKEN="${input_token:-<TOKEN>}"

    sudo tee /etc/logger-agent/config.json > /dev/null << CFGEOF
{
  "server_url": "${SERVER_URL%/}",
  "enrollment_token": "$TOKEN",
  "insecure_tls": false,
  "log_level": "info",
  "data_dir": "/opt/logger-agent/data",
  "heartbeat_interval_sec": 30,
  "identity_file": "/etc/logger-agent/identity.json"
}
CFGEOF
    sudo chmod 600 /etc/logger-agent/config.json
fi

echo "[*] Registering system launchd daemon..."
sudo cp "$DIR/com.valtrivo.logger-agent.plist" /Library/LaunchDaemons/com.valtrivo.logger-agent.plist
sudo chmod 644 /Library/LaunchDaemons/com.valtrivo.logger-agent.plist
sudo chown root:wheel /Library/LaunchDaemons/com.valtrivo.logger-agent.plist

sudo launchctl unload -w /Library/LaunchDaemons/com.valtrivo.logger-agent.plist 2>/dev/null || true
sudo launchctl load -w /Library/LaunchDaemons/com.valtrivo.logger-agent.plist

echo ""
echo "=================================================================="
echo " [✓] VALTRIVO LOGSEAL AGENT INSTALLED SUCCESSFULLY!               "
echo "=================================================================="
echo " Service   : com.valtrivo.logger-agent"
echo " Binary    : /opt/logger-agent/bin/logger-agent"
echo " Config    : /etc/logger-agent/config.json"
echo " Log File  : /var/log/logger-agent/agent.log"
echo " Verify    : sudo launchctl list | grep logger"
echo "=================================================================="
echo ""
read -r -p "Press Enter to exit..."
EOF
chmod +x "$DMG_STAGING/Install LOGGER Agent.command"

# Create double-clickable uninstaller script
cat << 'EOF' > "$DMG_STAGING/Uninstall LOGGER Agent.command"
#!/bin/bash
clear
echo "=================================================================="
echo "       VALTRIVO LOGSEAL - MACOS AGENT UNINSTALLER                 "
echo "=================================================================="
echo ""
echo "Please enter your Mac administrator password to remove the agent."
echo ""

sudo launchctl unload -w /Library/LaunchDaemons/com.valtrivo.logger-agent.plist 2>/dev/null || true
sudo rm -f /Library/LaunchDaemons/com.valtrivo.logger-agent.plist
sudo rm -rf /opt/logger-agent

echo ""
echo "=================================================================="
echo " [✓] VALTRIVO LOGSEAL AGENT HAS BEEN REMOVED FROM THIS MAC.       "
echo "=================================================================="
echo "Note: Configuration at /etc/logger-agent was preserved for safety."
echo ""
read -r -p "Press Enter to exit..."
EOF
chmod +x "$DMG_STAGING/Uninstall LOGGER Agent.command"

# Create Documentation / README
cat << EOF > "$DMG_STAGING/README.txt"
==================================================================
Valtrivo LogSeal - macOS Endpoint Agent (${VERSION})
==================================================================

INSTALLATION OPTIONS:
1. Double-click "Install LOGGER Agent.pkg" to run the guided macOS
   installation wizard.
   OR
2. Double-click "Install LOGGER Agent.command" in Terminal to install
   and interactively configure your Server URL and Enrollment Token.

VERIFICATION:
Open Terminal and run:
  sudo launchctl list | grep logger-agent
  tail -f /var/log/logger-agent/agent.log

UNINSTALLATION:
Double-click "Uninstall LOGGER Agent.command" to stop and remove the service.

For documentation and manuals:
Visit the LogSeal Web Console > Endpoint Security > Installation Guide.
==================================================================
EOF

if command -v hdiutil >/dev/null 2>&1; then
    rm -f "$DL_DIR/logger-agent-installer.dmg"
    hdiutil create -volname "LOGGER Agent Installer" \
                   -srcfolder "$DMG_STAGING" \
                   -ov -format UDZO \
                   "$DL_DIR/logger-agent-installer.dmg"
    echo "  [✓] Built: $DL_DIR/logger-agent-installer.dmg ($(ls -lh "$DL_DIR/logger-agent-installer.dmg" | awk '{print $5}'))"
else
    echo "  [!] hdiutil is only available on macOS. Skipping DMG generation."
fi

echo ""
echo "=================================================================="
echo "                     BUILD SUMMARY                                "
echo "=================================================================="
ls -lh "$DL_DIR"
echo ""
ls -lh "$BIN_DIR"
echo "=================================================================="
echo "Done!"
