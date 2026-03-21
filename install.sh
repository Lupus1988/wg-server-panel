#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/wg-panel"
CLIENTS_DIR="$APP_DIR/clients"
VENV_DIR="$APP_DIR/venv"
SERVICE_FILE="/etc/systemd/system/wg-panel.service"
SCRIPT_FILE="/usr/local/bin/wg-panel-dynu-update.sh"

if [[ $EUID -ne 0 ]]; then
  echo "Bitte als root ausführen: sudo ./install.sh"
  exit 1
fi

if ! command -v apt >/dev/null 2>&1; then
  echo "Dieses Installationsskript unterstützt aktuell nur Debian/Ubuntu mit apt."
  exit 1
fi

echo "[1/8] Pakete installieren"
apt update
apt install -y wireguard iptables python3 python3-venv python3-pip curl

echo "[2/8] Verzeichnisse anlegen"
mkdir -p "$APP_DIR" "$CLIENTS_DIR" "$APP_DIR/lan-targets"

echo "[3/9] Dateien kopieren"
cp panel/app.py "$APP_DIR/app.py"
cp scripts/wg-panel-dynu-update.sh "$SCRIPT_FILE"
chmod 700 "$SCRIPT_FILE"
cp systemd/wg-panel-dynu.service /etc/systemd/system/wg-panel-dynu.service
cp systemd/wg-panel-dynu.timer /etc/systemd/system/wg-panel-dynu.timer

echo "[4/9] Beispiel-Konfigurationen anlegen, falls nicht vorhanden"
[[ -f "$APP_DIR/server.json" ]] || cp example-config/server.json "$APP_DIR/server.json"
[[ -f "$APP_DIR/ddns.json" ]] || cp example-config/ddns.json "$APP_DIR/ddns.json"
[[ -f "$CLIENTS_DIR/clients.json" ]] || cp example-config/clients.json "$CLIENTS_DIR/clients.json"
[[ -f "$APP_DIR/lan-targets/lan-targets.json" ]] || cp example-config/lan-targets.json "$APP_DIR/lan-targets/lan-targets.json"

echo "[5/9] Python venv einrichten"
if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
fi

echo "[6/9] Python-Abhängigkeiten installieren"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install flask qrcode pillow

echo "[7/9] IPv4-Forwarding aktivieren"
printf "net.ipv4.ip_forward=1\n" > /etc/sysctl.d/99-wg-panel.conf
sysctl --system >/dev/null

echo "[8/9] systemd-Service installieren"
cp systemd/wg-panel.service "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable wg-panel

echo "[9/9] Service starten"
systemctl restart wg-panel

echo
echo "Fertig."
echo "Panel: http://SERVER-IP:5000"
echo "DDNS-Updater-Timer muss bei Bedarf separat eingerichtet werden."
