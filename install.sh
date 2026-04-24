#!/usr/bin/env bash
# XCockpit SIEM - One-shot Linux installer
set -euo pipefail

INSTALL_DIR="/opt/xcockpit-siem"
SERVICE_USER="siem"

echo "======================================="
echo "  XCockpit SIEM Installer"
echo "======================================="

# --- Prerequisites check ---
echo "[1/8] Checking prerequisites..."
if ! python3 --version 2>&1 | grep -qE "3\.(11|12|13)"; then
    echo "ERROR: Python 3.11+ required (found: $(python3 --version 2>&1))"
    exit 1
fi
if ! node --version &>/dev/null; then
    echo "ERROR: Node.js required for frontend build"
    echo "Install: curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt-get install -y nodejs"
    exit 1
fi
echo "    Python $(python3 --version 2>&1 | awk '{print $2}'), Node $(node --version)"

# --- Create system user ---
echo "[2/8] Creating system user '$SERVICE_USER'..."
id -u "$SERVICE_USER" &>/dev/null || useradd -r -s /sbin/nologin "$SERVICE_USER"

# --- Copy files ---
echo "[3/8] Installing to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"/{data,logs,backups}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rsync -a --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
    --exclude='frontend/node_modules' --exclude='frontend/dist' \
    "$SCRIPT_DIR/" "$INSTALL_DIR/"

# --- Python venv ---
echo "[4/8] Setting up Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip -q
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
echo "    Python packages installed"

# --- Generate secrets & .env (do this BEFORE frontend build so .env always exists) ---
echo "[5/8] Generating secrets..."
JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
INGEST_API_KEY=$(python3 -c "import secrets; print(secrets.token_hex(24))")

if [ ! -f "$INSTALL_DIR/.env" ]; then
    cat > "$INSTALL_DIR/.env" <<EOF
# XCockpit SIEM environment variables
# Edit this file with your XCockpit API settings

JWT_SECRET=$JWT_SECRET
INGEST_API_KEY=$INGEST_API_KEY

# XCockpit connection (required for data pull)
XCOCKPIT_URL=https://xcockpit.cycraft.ai
XCOCKPIT_CUSTOMER_KEY=your-customer-key-here
XCOCKPIT_API_KEY=your-xcockpit-api-key-here
EOF
    chmod 600 "$INSTALL_DIR/.env"
    echo "    Generated new .env at $INSTALL_DIR/.env"
    echo "    >>> IMPORTANT: edit .env and fill in your XCockpit credentials <<<"
else
    echo "    Existing .env preserved"
fi

# --- Frontend build ---
echo "[6/8] Building frontend..."
cd "$INSTALL_DIR/frontend"
# Use 'npm install' instead of 'npm ci' — ci requires package-lock.json
npm install
npm run build
cd "$INSTALL_DIR"
echo "    Frontend built"

# --- systemd service ---
echo "[7/8] Installing systemd service..."
cp "$INSTALL_DIR/systemd/xcockpit-siem.service" /etc/systemd/system/
sed -i "s|__INSTALL_DIR__|$INSTALL_DIR|g" /etc/systemd/system/xcockpit-siem.service
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
systemctl daemon-reload
systemctl enable xcockpit-siem
echo "    systemd service enabled"

# --- logrotate ---
cat > /etc/logrotate.d/xcockpit-siem <<EOF
$INSTALL_DIR/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 $SERVICE_USER $SERVICE_USER
}
EOF

# --- Start service ---
echo "[8/8] Starting service..."
systemctl start xcockpit-siem
sleep 2
if systemctl is-active xcockpit-siem --quiet; then
    echo "    Service started successfully"
else
    echo "    WARNING: service not active"
    echo "    Check logs: journalctl -u xcockpit-siem -n 50"
fi

HOST_IP=$(hostname -I | awk '{print $1}')
echo ""
echo "======================================="
echo "  Installation complete!"
echo "======================================="
echo ""
echo "  Web UI:        http://$HOST_IP:8000"
echo "  API docs:      http://$HOST_IP:8000/docs"
echo "  Default login: admin / admin"
echo ""
echo "  Next step: fill in XCockpit credentials"
echo "  >>> sudo nano $INSTALL_DIR/.env <<<"
echo ""
echo "  Then restart: sudo systemctl restart xcockpit-siem"
echo "  View logs:    journalctl -u xcockpit-siem -f"
echo ""
echo "  IMPORTANT: Change the default admin password after first login!"
