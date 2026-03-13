#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/etc/wg-panel-dynu.env"
NETRC_FILE="/etc/wg-panel-dynu.netrc"
STATE_DIR="/var/lib/wg-panel-dynu"
LAST_IP_FILE="$STATE_DIR/last_ip"

mkdir -p "$STATE_DIR"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "FEHLER: $ENV_FILE fehlt"
  exit 1
fi

if [[ ! -f "$NETRC_FILE" ]]; then
  echo "FEHLER: $NETRC_FILE fehlt"
  exit 1
fi

source "$ENV_FILE"

CURRENT_IP="$(curl -4fsS https://api.ipify.org)"

LAST_IP=""
if [[ -f "$LAST_IP_FILE" ]]; then
  LAST_IP="$(cat "$LAST_IP_FILE")"
fi

if [[ "$CURRENT_IP" == "$LAST_IP" ]]; then
  echo "IP unverändert: $CURRENT_IP"
  exit 0
fi

for host in $DYNU_HOSTS; do
  curl -4fsS --netrc-file "$NETRC_FILE" \
  "https://api.dynu.com/nic/update?hostname=${host}&myip=${CURRENT_IP}" >/dev/null
done

echo "$CURRENT_IP" > "$LAST_IP_FILE"

echo "Dynu aktualisiert → $CURRENT_IP"
