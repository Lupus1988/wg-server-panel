from flask import Flask, request, redirect, url_for, render_template_string, abort, Response
import subprocess
import json
from pathlib import Path
import ipaddress
import qrcode
from io import BytesIO
import base64
import tarfile
import tempfile
from datetime import datetime
from urllib.request import urlopen
import urllib.error
import html

app = Flask(__name__)

CLIENTS_FILE = Path("/opt/wg-panel/clients/clients.json")
SERVER_FILE = Path("/opt/wg-panel/server.json")
DDNS_FILE = Path("/opt/wg-panel/ddns.json")
WG_CONF = Path("/etc/wireguard/wg0.conf")

DYNU_ENV_FILE = Path("/etc/wg-panel-dynu.env")
DYNU_NETRC_FILE = Path("/etc/wg-panel-dynu.netrc")
DYNU_UPDATE_SCRIPT = "/usr/local/bin/wg-panel-dynu-update.sh"

ONLINE_HANDSHAKE_SECONDS = 180


def run_cmd(cmd, input_text=None):
    result = subprocess.run(cmd, input=input_text, capture_output=True, text=True, check=True)
    return result.stdout.strip()


def load_json(path, default):
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    tmp.replace(path)


def load_clients():
    data = load_json(CLIENTS_FILE, {"clients": []})
    if "clients" not in data or not isinstance(data["clients"], list):
        data = {"clients": []}
    return data


def save_clients(data):
    save_json(CLIENTS_FILE, data)


def detect_public_ip():
    urls = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://ipv4.icanhazip.com",
    ]
    for url in urls:
        try:
            with urlopen(url, timeout=3) as r:
                value = r.read().decode("utf-8").strip()
                ipaddress.ip_address(value)
                return value
        except (urllib.error.URLError, ValueError, TimeoutError):
            continue
        except Exception:
            continue
    return ""


def load_server_settings():
    data = load_json(SERVER_FILE, {})
    endpoint = str(data.get("endpoint", "")).strip()
    return {
        "endpoint": endpoint,
        "port": int(data.get("port", 51820)),
        "dns": str(data.get("dns", "10.200.200.1")).strip(),
        "allowed_ips": str(data.get("allowed_ips", "10.200.200.0/24")).strip(),
    }


def get_server_settings_with_auto_endpoint():
    data = load_server_settings()
    detected = ""
    auto_used = False
    if not data["endpoint"]:
        detected = detect_public_ip()
        if detected:
            data["endpoint"] = detected
            auto_used = True
    return data, detected, auto_used


def save_server_settings(data):
    save_json(SERVER_FILE, data)


def load_ddns_settings():
    data = load_json(DDNS_FILE, {})
    return {
        "enabled": bool(data.get("enabled", False)),
        "provider": str(data.get("provider", "dynu")).strip() or "dynu",
        "hostname": str(data.get("hostname", "")).strip(),
        "use_as_endpoint": bool(data.get("use_as_endpoint", True)),
    }


def save_ddns_settings(data):
    save_json(DDNS_FILE, data)


def read_dynu_env_hosts():
    if not DYNU_ENV_FILE.exists():
        return ""
    for raw in DYNU_ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("DYNU_HOSTS="):
            value = line.split("=", 1)[1].strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            return value
    return ""


def write_dynu_env_hosts(hostname):
    DYNU_ENV_FILE.write_text(f'DYNU_HOSTS="{hostname}"\n', encoding="utf-8")
    DYNU_ENV_FILE.chmod(0o600)


def read_dynu_netrc():
    username = ""
    password = ""
    if not DYNU_NETRC_FILE.exists():
        return username, password

    for raw in DYNU_NETRC_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("login "):
            username = line.split(" ", 1)[1].strip()
        elif line.startswith("password "):
            password = line.split(" ", 1)[1].strip()
    return username, password


def write_dynu_netrc(username, password):
    content = (
        "machine api.dynu.com\n"
        f"login {username}\n"
        f"password {password}\n"
    )
    DYNU_NETRC_FILE.write_text(content, encoding="utf-8")
    DYNU_NETRC_FILE.chmod(0o600)


def get_effective_endpoint():
    ddns = load_ddns_settings()
    if ddns["enabled"] and ddns["use_as_endpoint"] and ddns["hostname"]:
        return ddns["hostname"], "ddns"

    server, _, _ = get_server_settings_with_auto_endpoint()
    return server["endpoint"], "server"


def find_client(key):
    data = load_clients()
    for c in data["clients"]:
        if c["public_key"] == key:
            return c
    return None


def peer_exists(public_key):
    if not WG_CONF.exists():
        return False
    text = WG_CONF.read_text(encoding="utf-8")
    return f"PublicKey = {public_key}" in text


def get_server_runtime():
    address = None
    with WG_CONF.open("r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("Address"):
                address = line.split("=", 1)[1].strip()
                break

    if not address:
        raise RuntimeError("Address nicht gefunden")

    iface = ipaddress.ip_interface(address)
    pub = run_cmd(["wg", "show", "wg0", "public-key"])
    saved, _, _ = get_server_settings_with_auto_endpoint()
    effective_endpoint, endpoint_source = get_effective_endpoint()

    return {
        "server_ip": str(iface.ip),
        "network": str(iface.network),
        "server_public_key": pub,
        "endpoint": effective_endpoint,
        "endpoint_source": endpoint_source,
        "port": saved["port"],
        "dns": saved["dns"] or str(iface.ip),
        "allowed_ips": saved["allowed_ips"] or str(iface.network),
    }


def generate_keypair():
    priv = run_cmd(["wg", "genkey"])
    pub = run_cmd(["wg", "pubkey"], input_text=priv + "\n")
    return priv, pub


def public_from_private(private_key):
    return run_cmd(["wg", "pubkey"], input_text=private_key.strip() + "\n")


def get_next_free_ip():
    server = get_server_runtime()
    net = ipaddress.ip_network(server["network"], strict=False)

    data = load_clients()
    used = {server["server_ip"]}
    for c in data["clients"]:
        if c.get("ip"):
            used.add(c["ip"])

    for host in net.hosts():
        ip = str(host)
        if ip not in used:
            return ip

    raise RuntimeError("keine freie IP")


def add_peer(public, ip, name):
    if peer_exists(public):
        return
    with WG_CONF.open("a", encoding="utf-8") as f:
        f.write(f"\n# wg-panel-name: {name}\n")
        f.write("[Peer]\n")
        f.write(f"PublicKey = {public}\n")
        f.write(f"AllowedIPs = {ip}/32\n")


def remove_peer(public):
    with WG_CONF.open("r", encoding="utf-8") as f:
        text = f.read()

    blocks = text.split("\n[Peer]\n")
    new = blocks[0]

    for b in blocks[1:]:
        if f"PublicKey = {public}" in b:
            continue
        new += "\n[Peer]\n" + b

    with WG_CONF.open("w", encoding="utf-8") as f:
        f.write(new.rstrip() + "\n")


def restart_wg():
    run_cmd(["systemctl", "restart", "wg-quick@wg0"])


def build_client_config(client):
    server = get_server_runtime()

    if client.get("mode") == "server":
        allowed = f"{server['server_ip']}/32"
    else:
        allowed = server["allowed_ips"]

    return f"""[Interface]
PrivateKey = {client['private_key']}
Address = {client['ip']}/32
DNS = {server['dns']}

[Peer]
PublicKey = {server['server_public_key']}
Endpoint = {server['endpoint']}:{server['port']}
AllowedIPs = {allowed}
PersistentKeepalive = 25
"""


def generate_qr_base64(text):
    qr = qrcode.QRCode(box_size=8, border=2)
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image()
    buf = BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


def human_bytes(num):
    num = int(num)
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    value = float(num)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{num} B"


def handshake_text(epoch_str):
    epoch = int(epoch_str)
    if epoch == 0:
        return "nie"
    now = int(datetime.now().timestamp())
    delta = max(0, now - epoch)
    dt = datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")
    if delta < 60:
        age = f"vor {delta}s"
    elif delta < 3600:
        age = f"vor {delta // 60}m"
    elif delta < 86400:
        age = f"vor {delta // 3600}h"
    else:
        age = f"vor {delta // 86400}d"
    return f"{dt} ({age})"


def is_online_by_handshake(epoch_str):
    try:
        epoch = int(epoch_str)
    except Exception:
        return False
    if epoch <= 0:
        return False
    now = int(datetime.now().timestamp())
    return (now - epoch) <= ONLINE_HANDSHAKE_SECONDS


def get_live_stats():
    dump = run_cmd(["wg", "show", "wg0", "dump"])
    lines = [line for line in dump.splitlines() if line.strip()]
    peers = {}
    for line in lines[1:]:
        p = line.split("\t")
        online = is_online_by_handshake(p[4])
        peers[p[0]] = {
            "endpoint_live": p[2] or "-",
            "allowed_ips_live": p[3],
            "handshake_raw": p[4],
            "handshake": handshake_text(p[4]),
            "rx": human_bytes(p[5]),
            "tx": human_bytes(p[6]),
            "online": online,
            "status_text": "Online" if online else "Offline",
        }
    return peers


def generate_server_config():
    priv, pub = generate_keypair()
    config = f"""[Interface]
Address = 10.200.200.1/24
ListenPort = 51820
PrivateKey = {priv}

# NAT für VPN-Clients
PostUp = iptables -t nat -A POSTROUTING -s 10.200.200.0/24 -o eth0 -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s 10.200.200.0/24 -o eth0 -j MASQUERADE
"""
    return priv, pub, config


def parse_wg_config(text):
    parsed = {"Interface": {}, "Peer": {}}
    section = None

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line == "[Interface]":
            section = "Interface"
            continue
        if line == "[Peer]":
            section = "Peer"
            continue
        if "=" in line and section:
            key, value = line.split("=", 1)
            parsed[section][key.strip()] = value.strip()

    return parsed


def infer_mode_from_allowed(allowed_ips, server_ip):
    values = [v.strip() for v in (allowed_ips or "").split(",") if v.strip()]
    if values == [f"{server_ip}/32"]:
        return "server"
    return "all"


def endpoint_warning_html(server):
    if server.get("endpoint"):
        return ""
    return """
<div class="card warn">
<strong>Hinweis:</strong> Es ist aktuell kein Endpoint verfügbar.
Bitte in den <a href="/ddns">DDNS-Einstellungen</a> einen Hostnamen setzen oder in den <a href="/server/settings">Server-Einstellungen</a> einen gültigen Endpoint eintragen.
</div>
"""


BASE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>WG Server Panel</title>
<style>
body{background:#111;color:#eee;font-family:Arial,sans-serif;padding:20px}
.card{background:#1b1b1b;padding:16px;border-radius:8px;margin-bottom:20px}
.card.warn{border:1px solid #9c7a14;background:#2a2210}
button{background:#2d6cdf;color:white;border:0;padding:8px 12px;border-radius:6px;margin-right:5px;cursor:pointer}
button.secondary{background:#444}
.delete{background:#c0392b}
table{width:100%;border-collapse:collapse}
td,th{padding:10px;border-bottom:1px solid #333;text-align:left;vertical-align:top}
input,select{width:100%;padding:8px;background:#000;color:white;border:1px solid #333;border-radius:6px;box-sizing:border-box}
input[type=checkbox]{width:24px;height:24px;transform:scale(1.35);margin-right:12px;vertical-align:middle}
textarea{width:100%;height:320px;background:#000;color:#d7f7ff;border:1px solid #333;border-radius:6px;padding:10px;box-sizing:border-box}
a.btn{display:inline-block;background:#2d6cdf;color:#fff;text-decoration:none;padding:8px 12px;border-radius:6px;margin-right:5px}
a.btn.secondary{background:#444}
.grid{display:grid;grid-template-columns:minmax(0,1fr) 420px;gap:20px;align-items:start}
.qrbox{background:#fff;display:block;padding:12px;border-radius:8px;text-align:center}
.qrbox img{display:block;width:100%;height:auto;max-width:380px;margin:0 auto}
label{display:block;margin:10px 0 10px;font-weight:bold}
footer{margin-top:28px;padding:18px 0 4px 0;color:#7f8ea3;font-size:14px;text-align:center}
.badge{display:inline-block;padding:4px 10px;border-radius:999px;font-weight:bold;font-size:13px}
.badge.online{background:#193d24;color:#7ee08a;border:1px solid #2f7d45}
.badge.offline{background:#3b1919;color:#ff8d8d;border:1px solid #8a3434}
.actions{white-space:nowrap}
.actions a,.actions button{margin-bottom:6px}
code{background:#000;padding:2px 6px;border-radius:4px}
pre{white-space:pre-wrap;word-break:break-word;background:#000;border:1px solid #333;border-radius:6px;padding:10px}
.formrow{margin:10px 0 14px}
.inline-code{display:inline-block;background:#000;border:1px solid #333;border-radius:6px;padding:3px 8px;margin:2px 4px 2px 0;word-break:break-all}
.kv{margin:6px 0}
.kv-label{display:inline-block;min-width:210px;color:#aab3c2;font-weight:bold}
.host-badge{display:inline-block;background:#0f1720;border:1px solid #2d6cdf;color:#d7e7ff;padding:4px 10px;border-radius:999px;font-weight:bold;word-break:break-all}
</style>
<script>
function kopiereTextAusTextarea(id){
  const el = document.getElementById(id);
  if(!el){ return; }
  el.focus();
  el.select();
  el.setSelectionRange(0, el.value.length);
  try{
    document.execCommand('copy');
  }catch(e){
  }
}
</script>
</head>
<body>
{{ body|safe }}
<footer>WG Server Panel v1.4 · by Lupus1988</footer>
</body>
</html>
"""


@app.route("/")
def index():
    data = load_clients()
    server = get_server_runtime()
    ddns = load_ddns_settings()
    stats = get_live_stats()

    sorted_clients = sorted(
        data["clients"],
        key=lambda c: (
            0 if stats.get(c["public_key"], {}).get("online") else 1,
            c.get("name", "").lower()
        )
    )

    rows = ""
    for c in sorted_clients:
        st = stats.get(c["public_key"], {
            "handshake": "nie",
            "rx": "0 B",
            "tx": "0 B",
            "online": False,
            "status_text": "Offline",
        })

        name = html.escape(c["name"])
        ip = html.escape(c["ip"])
        endpoint = html.escape(f"{server['endpoint']}:{server['port']}" if server["endpoint"] else f"(nicht gesetzt):{server['port']}")
        mode_text = "Kommunikation Server only" if c.get("mode") == "server" else "Kommunikation Alle Clients"
        mode_text = html.escape(mode_text)
        handshake = html.escape(st["handshake"])
        rx = html.escape(st["rx"])
        tx = html.escape(st["tx"])
        key = c["public_key"]
        status_class = "online" if st["online"] else "offline"
        status_text = "Online" if st["online"] else "Offline"

        rows += f"""
<tr>
<td>{name}</td>
<td>{ip}/32</td>
<td><span class="badge {status_class}">{status_text}</span></td>
<td>{endpoint}</td>
<td>{mode_text}</td>
<td>{handshake}</td>
<td>{rx}</td>
<td>{tx}</td>
<td class="actions">
<a class="btn secondary" href="/client/{key}/view">Konfig</a>
<a class="btn secondary" href="/client/{key}/download">Download</a>
<form style="display:inline" method="post" action="/client/delete" onsubmit="return confirm('Client wirklich löschen?');">
<input type="hidden" name="public_key" value="{key}">
<button class="delete" type="submit">Löschen</button>
</form>
</td>
</tr>
"""

    ddns_info = ""
    if ddns["enabled"] and ddns["hostname"]:
        ddns_info = f"""
<div class="card">
<div class="kv"><span class="kv-label">DDNS aktiv</span> <span class="host-badge">{html.escape(ddns["hostname"])}</span></div>
<div class="kv"><span class="kv-label">Als Endpoint verwenden</span> {"Ja" if ddns["use_as_endpoint"] else "Nein"}</div>
</div>
"""

    body = f"""
<h1>WG Server Panel</h1>

{endpoint_warning_html(server)}
{ddns_info}

<div class="card">
<a class="btn" href="/client/new">Neuen Client erstellen</a>
<a class="btn secondary" href="/client/import">Client importieren</a>
<a class="btn secondary" href="/server/settings">Server-Einstellungen</a>
<a class="btn secondary" href="/ddns">DDNS</a>
<a class="btn secondary" href="/backup/export">Backup exportieren</a>
<a class="btn secondary" href="/backup/import">Backup importieren</a>
<a class="btn secondary" href="/">Aktualisieren</a>
</div>

<div class="card">
<table>
<tr>
<th>Name</th>
<th>IP</th>
<th>Status</th>
<th>Endpoint</th>
<th>Modus</th>
<th>Letzter Handshake</th>
<th>RX</th>
<th>TX</th>
<th>Aktionen</th>
</tr>
{rows if rows else '<tr><td colspan="9">Keine Clients vorhanden.</td></tr>'}
</table>
</div>
"""
    return render_template_string(BASE, body=body)


@app.route("/ddns", methods=["GET", "POST"])
def ddns_settings():
    data = load_ddns_settings()
    saved = False
    update_output = ""
    username, existing_password = read_dynu_netrc()
    env_hosts = read_dynu_env_hosts()

    if request.method == "POST":
        action = (request.form.get("action") or "save").strip()

        if action == "save":
            hostname = (request.form.get("hostname") or "").strip()
            username_new = (request.form.get("username") or "").strip()
            password_new = (request.form.get("password") or "").strip()

            data = {
                "enabled": request.form.get("enabled") == "on",
                "provider": "dynu",
                "hostname": hostname,
                "use_as_endpoint": request.form.get("use_as_endpoint") == "on",
            }
            save_ddns_settings(data)

            if hostname:
                write_dynu_env_hosts(hostname)

            if username_new or password_new or existing_password:
                write_dynu_netrc(
                    username_new or username,
                    password_new or existing_password
                )

            saved = True
            username, existing_password = read_dynu_netrc()
            env_hosts = read_dynu_env_hosts()

        elif action == "update_now":
            try:
                update_output = run_cmd([DYNU_UPDATE_SCRIPT])
            except subprocess.CalledProcessError as e:
                text = (e.stdout or "").strip()
                err = (e.stderr or "").strip()
                update_output = "\n".join([x for x in [text, err] if x]) or "Update fehlgeschlagen."
            data = load_ddns_settings()
            username, existing_password = read_dynu_netrc()
            env_hosts = read_dynu_env_hosts()

    hostname_value = data["hostname"] or env_hosts
    masked_password_hint = "Gespeichertes Passwort bleibt erhalten, wenn das Feld leer bleibt." if existing_password else "Noch kein Passwort gespeichert."

    body = f"""
<h1>DDNS</h1>

<div class="card">
<form method="post">
<input type="hidden" name="action" value="save">

<div class="formrow">
<label><input type="checkbox" name="enabled" {"checked" if data["enabled"] else ""}> DDNS aktivieren</label>
</div>

<label>Provider</label>
<input value="Dynu" readonly>

<label>Hostname</label>
<input name="hostname" value="{html.escape(hostname_value)}" placeholder="z. B. meinserver.freeddns.org">

<label>Dynu Benutzername</label>
<input name="username" value="{html.escape(username)}" placeholder="Dynu Benutzername">

<label>Dynu Passwort</label>
<input type="password" name="password" value="" placeholder="Dynu Passwort">

<p>{html.escape(masked_password_hint)}</p>

<div class="formrow">
<label><input type="checkbox" name="use_as_endpoint" {"checked" if data["use_as_endpoint"] else ""}> Hostname als WireGuard-Endpoint verwenden</label>
</div>

<br>
<button type="submit">Speichern</button>
<a class="btn secondary" href="/">Zurück</a>
</form>
{"<p>Gespeichert.</p>" if saved else ""}
</div>

<div class="card">
<h2>DDNS sofort aktualisieren</h2>
<form method="post">
<input type="hidden" name="action" value="update_now">
<button type="submit">IP jetzt aktualisieren</button>
<a class="btn secondary" href="/ddns">Neu laden</a>
</form>
{("<pre>" + html.escape(update_output) + "</pre>") if update_output else ""}
</div>

<div class="card warn">
<strong>Hinweis:</strong> Zugangsdaten werden als Root-Dateien gespeichert:<br><br>
<span class="inline-code">/etc/wg-panel-dynu.env</span>
<span class="inline-code">/etc/wg-panel-dynu.netrc</span>
<br><br>
Das automatische Update läuft unabhängig per systemd-Timer.
</div>
"""
    return render_template_string(BASE, body=body)


@app.route("/server/settings", methods=["GET", "POST"])
def server_settings():
    saved_data = load_server_settings()
    ddns = load_ddns_settings()
    detected_ip = detect_public_ip()
    display_endpoint = (
        ddns["hostname"]
        if ddns["enabled"] and ddns["hostname"]
        else (saved_data["endpoint"] or detected_ip)
    )
    saved = False

    if request.method == "POST":
        data = {
            "endpoint": (request.form.get("endpoint") or "").strip(),
            "port": int((request.form.get("port") or "51820").strip()),
            "dns": (request.form.get("dns") or "").strip(),
            "allowed_ips": (request.form.get("allowed_ips") or "").strip(),
        }
        save_server_settings(data)
        saved_data = load_server_settings()
        ddns = load_ddns_settings()
        detected_ip = detect_public_ip()
        display_endpoint = (
            ddns["hostname"]
            if ddns["enabled"] and ddns["hostname"]
            else (saved_data["endpoint"] or detected_ip)
        )
        saved = True

    notice = ""
    if ddns["enabled"] and ddns["hostname"]:
        notice = f"""
<div class="card warn">
<strong>Aktiver Endpoint:</strong> DDNS ist aktiv, daher wird aktuell <code>{html.escape(ddns["hostname"])}</code> als Endpoint verwendet.
Der statische Endpoint wird erst wieder verwendet, wenn DDNS deaktiviert ist.
</div>
"""
    elif display_endpoint:
        notice = f"""
<div class="card warn">
<strong>Aktiver Endpoint:</strong> DDNS ist aus, daher wird aktuell <code>{html.escape(display_endpoint)}</code> als Endpoint verwendet.
</div>
"""
    else:
        notice = """
<div class="card warn">
<strong>Hinweis:</strong> Es ist aktuell weder ein DDNS-Hostname noch eine öffentliche IP als Endpoint verfügbar.
</div>
"""

    body = f"""
<h1>Server-Einstellungen</h1>

{notice}

<div class="card">
<form method="post">
<label>Endpoint</label>
<input name="endpoint" value="{html.escape(display_endpoint or '')}">

<label>Port</label>
<input name="port" type="number" value="{saved_data['port']}">

<label>DNS</label>
<input name="dns" value="{html.escape(saved_data['dns'])}">

<label>AllowedIPs</label>
<input name="allowed_ips" value="{html.escape(saved_data['allowed_ips'])}">

<br><br>
<button type="submit">Speichern</button>
<a class="btn secondary" href="/">Zurück</a>
</form>
{"<p>Gespeichert.</p>" if saved else ""}
</div>

<div class="card">
<h2>Server neu generieren</h2>
<p><strong>Warnung:</strong> Erstellt neue Server-Keys und setzt den WireGuard-Server auf Standardwerte zurück. Danach funktionieren alle bisherigen Clients nicht mehr.</p>
<a class="btn secondary" href="/server/generate">Server neu generieren</a>
</div>
"""
    return render_template_string(BASE, body=body)


@app.route("/server/generate", methods=["GET", "POST"])
def server_generate():
    if request.method == "POST":
        confirm_text = (request.form.get("confirm_text") or "").strip()
        if confirm_text != "GENERATE":
            body = """
<h1>Server neu generieren</h1>
<div class="card">
<p><strong>Fehler:</strong> Zur Bestätigung muss exakt <code>GENERATE</code> eingegeben werden.</p>
<a class="btn secondary" href="/server/generate">Zurück</a>
</div>
"""
            return render_template_string(BASE, body=body)

        old_server = load_server_settings()
        _, pub, new_conf = generate_server_config()

        backup = f"/etc/wireguard/wg0.conf.before-generate-server.{run_cmd(['date', '+%F-%H%M%S'])}"
        run_cmd(["cp", str(WG_CONF), backup])

        with WG_CONF.open("w", encoding="utf-8") as f:
            f.write(new_conf)

        save_clients({"clients": []})

        endpoint = old_server["endpoint"] or detect_public_ip()
        save_server_settings({
            "endpoint": endpoint,
            "port": 51820,
            "dns": "10.200.200.1",
            "allowed_ips": "10.200.200.0/24"
        })

        restart_wg()

        endpoint_info = f"<p><strong>Statischer Server-Endpoint:</strong> <code>{html.escape(endpoint)}</code></p>" if endpoint else "<p><strong>Statischer Server-Endpoint:</strong> nicht erkannt.</p>"

        body = f"""
<h1>Server neu generiert</h1>
<div class="card">
<p><strong>Neuer Server Public Key:</strong> <code>{html.escape(pub)}</code></p>
{endpoint_info}
<p><strong>Backup:</strong> <code>{html.escape(backup)}</code></p>
<p><strong>Wichtig:</strong> Alle bisherigen Clients sind jetzt ungültig und müssen neu erstellt werden.</p>
<br>
<a class="btn secondary" href="/">Zur Übersicht</a>
<a class="btn secondary" href="/server/settings">Server-Einstellungen</a>
</div>
"""
        return render_template_string(BASE, body=body)

    body = """
<h1>Server neu generieren</h1>

<div class="card">
<p><strong>Warnung:</strong> Diese Aktion erzeugt neue Server-Keys, überschreibt <code>/etc/wireguard/wg0.conf</code> und entfernt alle bisherigen Clients.</p>
<p>Danach funktionieren alle bestehenden Clients nicht mehr.</p>

<form method="post">
<label>Zur Bestätigung exakt GENERATE eingeben</label>
<input name="confirm_text" placeholder="GENERATE">
<br><br>
<button class="delete" type="submit">Server jetzt neu generieren</button>
<a class="btn secondary" href="/server/settings">Abbrechen</a>
</form>
</div>
"""
    return render_template_string(BASE, body=body)


@app.route("/client/new", methods=["GET", "POST"])
def client_new():
    error = ""

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        mode = request.form.get("mode", "all")

        if not name:
            error = "Name fehlt."
        else:
            data = load_clients()
            if any(c["name"] == name for c in data["clients"]):
                error = "Ein Client mit diesem Namen existiert bereits."
            else:
                priv, pub = generate_keypair()
                ip = get_next_free_ip()

                data["clients"].append({
                    "name": name,
                    "ip": ip,
                    "public_key": pub,
                    "private_key": priv,
                    "mode": mode
                })
                save_clients(data)

                add_peer(pub, ip, name)
                restart_wg()

                return redirect(url_for("client_view", key=pub))

    body = f"""
<h1>Neuer Client</h1>

<div class="card">
<form method="post">

<label>Name</label>
<input name="name">

<label>Kommunikation</label>
<select name="mode">
<option value="server">Kommunikation Server only (Server ↔ Client)</option>
<option value="all" selected>Kommunikation Alle Clients (Client ↔ Server ↔ Clients)</option>
</select>

<br><br>

<button type="submit">Client erstellen</button>
<a class="btn secondary" href="/">Abbrechen</a>
</form>

{"<p>" + html.escape(error) + "</p>" if error else ""}
</div>
"""
    return render_template_string(BASE, body=body)


@app.route("/client/import", methods=["GET", "POST"])
def client_import():
    error = ""

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        config_text = (request.form.get("config_text") or "").strip()

        if not config_text:
            error = "Konfiguration fehlt."
        else:
            try:
                parsed = parse_wg_config(config_text)
                server = get_server_runtime()

                priv = parsed["Interface"].get("PrivateKey", "").strip()
                address = parsed["Interface"].get("Address", "").strip()
                peer_pub = parsed["Peer"].get("PublicKey", "").strip()
                allowed_ips = parsed["Peer"].get("AllowedIPs", "").strip()

                if not priv:
                    raise ValueError("PrivateKey in [Interface] fehlt.")
                if not address:
                    raise ValueError("Address in [Interface] fehlt.")
                if not peer_pub:
                    raise ValueError("PublicKey in [Peer] fehlt.")

                if peer_pub != server["server_public_key"]:
                    raise ValueError("Die importierte Konfiguration gehört nicht zu diesem WireGuard-Server.")

                iface = ipaddress.ip_interface(address)
                ip = str(iface.ip)
                pub = public_from_private(priv)
                mode = infer_mode_from_allowed(allowed_ips, server["server_ip"])

                if not name:
                    name = f"Import-{ip}"

                data = load_clients()

                if any(c["public_key"] == pub for c in data["clients"]):
                    raise ValueError("Dieser Client ist bereits importiert.")
                if any(c["ip"] == ip for c in data["clients"]):
                    raise ValueError("Diese Client-IP existiert bereits.")
                if any(c["name"] == name for c in data["clients"]):
                    raise ValueError("Ein Client mit diesem Namen existiert bereits.")

                data["clients"].append({
                    "name": name,
                    "ip": ip,
                    "public_key": pub,
                    "private_key": priv,
                    "mode": mode
                })
                save_clients(data)

                add_peer(pub, ip, name)
                restart_wg()

                return redirect(url_for("client_view", key=pub))

            except Exception as e:
                error = str(e)

    body = f"""
<h1>Client importieren</h1>

<div class="card">
<p>Hier kann eine vorhandene WireGuard-Client-Konfiguration importiert werden.</p>
<form method="post">
<label>Name (optional)</label>
<input name="name" placeholder="z. B. Laptop Norman">

<label>Client-Konfiguration</label>
<textarea name="config_text" placeholder="[Interface]&#10;PrivateKey = ...&#10;Address = ...&#10;&#10;[Peer]&#10;PublicKey = ...&#10;Endpoint = ...&#10;AllowedIPs = ...&#10;PersistentKeepalive = 25"></textarea>

<br><br>
<button type="submit">Client importieren</button>
<a class="btn secondary" href="/">Abbrechen</a>
</form>

{"<p>" + html.escape(error) + "</p>" if error else ""}
</div>
"""
    return render_template_string(BASE, body=body)


@app.route("/client/<path:key>/view")
def client_view(key):
    c = find_client(key)
    if not c:
        abort(404)

    cfg = build_client_config(c)
    qr_b64 = generate_qr_base64(cfg)
    mode_text = "Kommunikation Server only" if c.get("mode") == "server" else "Kommunikation Alle Clients"

    body = f"""
<h1>Client-Konfiguration</h1>

<div class="grid">
  <div class="card">
    <h2>{html.escape(c['name'])}</h2>
    <p><strong>IP:</strong> {html.escape(c['ip'])}/32</p>
    <p><strong>Modus:</strong> {html.escape(mode_text)}</p>

    <textarea id="cfg" readonly>{html.escape(cfg)}</textarea>

    <br><br>
    <button type="button" onclick="kopiereTextAusTextarea('cfg')">Konfiguration kopieren</button>
    <a class="btn secondary" href="/client/{c['public_key']}/download">Download .conf</a>
    <a class="btn secondary" href="/">Fertig</a>
  </div>

  <div class="card">
    <h2>QR-Code</h2>
    <div class="qrbox">
      <img src="data:image/png;base64,{qr_b64}" alt="WireGuard QR-Code">
    </div>
  </div>
</div>
"""
    return render_template_string(BASE, body=body)


@app.route("/client/<path:key>/download")
def client_download(key):
    c = find_client(key)
    if not c:
        abort(404)

    cfg = build_client_config(c)
    filename = f"{c['name'].replace(' ', '_')}.conf"

    return Response(
        cfg,
        mimetype="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.route("/client/delete", methods=["POST"])
def delete_client():
    key = request.form["public_key"]

    data = load_clients()
    data["clients"] = [c for c in data["clients"] if c["public_key"] != key]
    save_clients(data)

    remove_peer(key)
    restart_wg()

    return redirect("/", code=303)


@app.route("/backup/export")
@app.route("/backup/all")
def backup_all():
    stamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
    tmpdir = Path(tempfile.mkdtemp(prefix="wgpanel-backup-"))
    tar_path = tmpdir / f"wg-panel-backup-{stamp}.tar.gz"

    with tarfile.open(tar_path, "w:gz") as tar:
        if CLIENTS_FILE.exists():
            tar.add(CLIENTS_FILE, arcname="clients.json")
        if SERVER_FILE.exists():
            tar.add(SERVER_FILE, arcname="server.json")
        if DDNS_FILE.exists():
            tar.add(DDNS_FILE, arcname="ddns.json")
        if WG_CONF.exists():
            tar.add(WG_CONF, arcname="wg0.conf")

    data = tar_path.read_bytes()
    return Response(
        data,
        mimetype="application/gzip",
        headers={"Content-Disposition": f'attachment; filename="{tar_path.name}"'}
    )


@app.route("/backup/import", methods=["GET", "POST"])
def backup_import():
    error = ""

    if request.method == "POST":
        up = request.files.get("backup_file")
        if not up or not up.filename:
            error = "Keine Backup-Datei ausgewählt."
        else:
            try:
                raw = up.read()
                tmpdir = Path(tempfile.mkdtemp(prefix="wgpanel-import-"))
                archive = tmpdir / "import.tar.gz"
                archive.write_bytes(raw)

                with tarfile.open(archive, "r:gz") as tar:
                    names = set(tar.getnames())
                    required = {"clients.json", "server.json", "wg0.conf"}
                    if not required.issubset(names):
                        raise ValueError("Backup unvollständig. Benötigt: clients.json, server.json, wg0.conf")
                    tar.extractall(path=tmpdir)

                clients_src = tmpdir / "clients.json"
                server_src = tmpdir / "server.json"
                ddns_src = tmpdir / "ddns.json"
                wg_src = tmpdir / "wg0.conf"

                json.loads(clients_src.read_text(encoding="utf-8"))
                json.loads(server_src.read_text(encoding="utf-8"))
                if ddns_src.exists():
                    json.loads(ddns_src.read_text(encoding="utf-8"))

                CLIENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
                CLIENTS_FILE.write_text(clients_src.read_text(encoding="utf-8"), encoding="utf-8")
                SERVER_FILE.write_text(server_src.read_text(encoding="utf-8"), encoding="utf-8")
                if ddns_src.exists():
                    DDNS_FILE.write_text(ddns_src.read_text(encoding="utf-8"), encoding="utf-8")
                WG_CONF.write_text(wg_src.read_text(encoding="utf-8"), encoding="utf-8")

                restart_wg()
                return redirect("/", code=303)

            except Exception as e:
                error = str(e)

    body = f"""
<h1>Backup importieren</h1>

<div class="card">
<p>Erwartet eine <code>.tar.gz</code>-Datei aus dem Export des Panels mit:</p>
<ul>
<li><code>clients.json</code></li>
<li><code>server.json</code></li>
<li><code>wg0.conf</code></li>
<li><code>ddns.json</code> (optional)</li>
</ul>

<form method="post" enctype="multipart/form-data">
<label>Backup-Datei</label>
<input type="file" name="backup_file" accept=".gz,.tar.gz,application/gzip">

<br><br>
<button type="submit">Backup importieren</button>
<a class="btn secondary" href="/">Abbrechen</a>
</form>

{"<p>" + html.escape(error) + "</p>" if error else ""}
</div>
"""
    return render_template_string(BASE, body=body)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
