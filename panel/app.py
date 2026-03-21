from flask import Flask, request, redirect, url_for, render_template_string, abort, Response, session
import subprocess
import json
from pathlib import Path
import ipaddress
import qrcode
from io import BytesIO
import base64
import tarfile
import tempfile
from datetime import datetime, timedelta
from urllib.request import urlopen
import urllib.error
import html
import secrets
import time
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


CLIENTS_FILE = Path("/opt/wg-panel/clients/clients.json")
SERVER_FILE = Path("/opt/wg-panel/server.json")
DDNS_FILE = Path("/opt/wg-panel/ddns.json")
SERVER_PEERS_FILE = Path("/opt/wg-panel/server-peers/server-peers.json")
LAN_TARGETS_FILE = Path("/opt/wg-panel/lan-targets/lan-targets.json")
WG_CONF = Path("/etc/wireguard/wg0.conf")

DYNU_ENV_FILE = Path("/etc/wg-panel-dynu.env")
DYNU_NETRC_FILE = Path("/etc/wg-panel-dynu.netrc")
DYNU_UPDATE_SCRIPT = "/usr/local/bin/wg-panel-dynu-update.sh"

ONLINE_HANDSHAKE_SECONDS = 180

AUTH_FILE = Path("/opt/wg-panel/auth.json")
SECRET_FILE = Path("/opt/wg-panel/secret.key")
AUDIT_LOG_FILE = Path("/opt/wg-panel/audit.log")

SESSION_TIMEOUT_MINUTES = 20
RESET_PIN_MAX_ATTEMPTS = 5
RESET_PIN_LOCK_SECONDS = 900
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCK_SECONDS = 600
IP_BLOCK_MAX_ATTEMPTS = 10
IP_BLOCK_SECONDS = 600
IP_BLOCK_FILE = Path("/opt/wg-panel/ip-block.json")


def load_or_create_secret_key():
    if SECRET_FILE.exists():
        return SECRET_FILE.read_text(encoding="utf-8").strip()

    SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    secret_key = secrets.token_hex(32)
    SECRET_FILE.write_text(secret_key, encoding="utf-8")
    try:
            SECRET_FILE.chmod(0o600)
    except Exception:
        pass
    return secret_key


def load_auth():
    data = load_json(AUTH_FILE, {})
    if not isinstance(data, dict):
        return {}
    return data


def save_auth(data):
    save_json(AUTH_FILE, data)
    try:
        AUTH_FILE.chmod(0o600)
    except Exception:
        pass


def is_auth_configured():
    data = load_auth()
    return bool(data.get("username") and data.get("password_hash") and data.get("reset_pin_hash"))


def write_audit_log(message):
    AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with AUDIT_LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(f"{timestamp} {message}\n")
    try:
        AUDIT_LOG_FILE.chmod(0o600)
    except Exception:
        pass


def init_auth_defaults():
    data = load_auth()
    changed = False

    defaults = {
        "username": "",
        "password_hash": "",
        "reset_pin_hash": "",
        "failed_reset_attempts": 0,
        "reset_locked_until": 0,
        "failed_login_attempts": 0,
        "login_locked_until": 0,
        "created_at": "",
        "updated_at": "",
    }

    for key, value in defaults.items():
        if key not in data:
            data[key] = value
            changed = True

    if changed:
        save_auth(data)








def is_session_valid():
    if not session.get("logged_in"):
        return False

    last_seen = session.get("last_seen", 0)
    now = int(time.time())

    if not isinstance(last_seen, int):
        try:
            last_seen = int(last_seen)
        except Exception:
            last_seen = 0

    if now - last_seen > SESSION_TIMEOUT_MINUTES * 60:
        session.clear()
        return False

    session["last_seen"] = now
    session.permanent = False
    return True


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        return view_func(*args, **kwargs)
    return wrapped


@app.before_request
def enforce_auth():
    open_paths = {"/login", "/setup", "/reset-access", "/factory-reset"}
    path = request.path or "/"

    if path.startswith("/static"):
        return

    if not is_auth_configured():
        if path != "/setup":
            return redirect(url_for("setup"), code=303)
        return

    if path in open_paths:
        return

    if not is_session_valid():
        return redirect(url_for("login"), code=303)


@app.after_request
def apply_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' 'unsafe-inline' data: blob:; "
        "img-src 'self' data: blob:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "form-action 'self'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    return response

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

def load_ip_block():
    return load_json(IP_BLOCK_FILE, {})

def save_ip_block(data):
    save_json(IP_BLOCK_FILE, data)


def normalize_lan_targets(data):
    targets = data.get("targets", []) if isinstance(data, dict) else []
    out = []
    for t in targets:
        if not isinstance(t, dict):
            continue
        name = str(t.get("name", "")).strip() or "LAN-Ziel"
        ip_value = str(t.get("ip", t.get("address", ""))).strip()
        if not ip_value:
            continue
        try:
            if "/" in ip_value:
                ip_value = str(ipaddress.ip_network(ip_value, strict=False))
            else:
                ip_value = str(ipaddress.ip_address(ip_value))
        except Exception:
            continue
        out.append({
            "id": str(t.get("id", "")).strip() or secrets.token_hex(8),
            "name": name,
            "ip": ip_value,
            "enabled": bool(t.get("enabled", True)),
            "comment": str(t.get("comment", "")).strip(),
        })
    return {"targets": out}


def load_lan_targets():
    return normalize_lan_targets(load_json(LAN_TARGETS_FILE, {"targets": []}))


def save_lan_targets(data):
    save_json(LAN_TARGETS_FILE, normalize_lan_targets(data))
    apply_client_firewall()


def get_active_lan_targets():
    return [t for t in load_lan_targets()["targets"] if t.get("enabled", True)]


def get_active_lan_target_ips():
    return [t.get("ip", "").strip() for t in get_active_lan_targets() if t.get("ip")]


def normalize_client_access_profile(client):
    level_raw = str(client.get("access_level", "")).strip()
    profile = str(client.get("access_profile", "")).strip()
    mode = str(client.get("mode", "")).strip()

    if level_raw in {"1", "2", "3"}:
        level = int(level_raw)
    elif isinstance(client.get("access_level"), int) and client.get("access_level") in {1, 2, 3}:
        level = int(client.get("access_level"))
    elif profile == "server_only" or mode == "server":
        level = 1
    elif profile in {"vpn_clients", "local_only", "local_network"} or mode == "local":
        level = 2
    else:
        level = 3

    client["access_level"] = level
    client["access_profile"] = {
        1: "server_only",
        2: "vpn_clients",
        3: "lan_targets",
    }[level]

    if "enabled" not in client:
        client["enabled"] = True

    return client

def load_clients():
    data = load_json(CLIENTS_FILE, {"clients": []})
    if "clients" not in data or not isinstance(data["clients"], list):
        data = {"clients": []}

    for c in data["clients"]:
        normalize_client_access_profile(c)

    return data




def apply_client_firewall():
    import subprocess

    server = get_server_runtime()
    clients = load_clients()["clients"]
    lan_targets = get_active_lan_target_ips()

    subprocess.run(["iptables", "-F", "WG-CLIENTS"], stderr=subprocess.DEVNULL)
    subprocess.run(["iptables", "-N", "WG-CLIENTS"], stderr=subprocess.DEVNULL)

    if subprocess.run(["iptables", "-C", "FORWARD", "-j", "WG-CLIENTS"], stderr=subprocess.DEVNULL).returncode != 0:
        subprocess.run(["iptables", "-I", "FORWARD", "1", "-j", "WG-CLIENTS"])

    subprocess.run(["iptables", "-A", "WG-CLIENTS", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])

    server_ip = str(server.get("server_vpn_ip", "")).split("/")[0].strip()

    for c in clients:
        ip = c.get("ip")
        level = int(c.get("access_level", 3))

        if not ip:
            continue

        src = f"{ip}/32"

        if server_ip:
            subprocess.run(["iptables", "-A", "WG-CLIENTS", "-s", src, "-d", f"{server_ip}/32", "-j", "ACCEPT"])

        if level >= 2:
            subprocess.run(["iptables", "-A", "WG-CLIENTS", "-s", src, "-d", server["client_network"], "-j", "ACCEPT"])

        if level >= 3:
            for target in lan_targets:
                subprocess.run(["iptables", "-A", "WG-CLIENTS", "-s", src, "-d", target, "-j", "ACCEPT"])

        subprocess.run(["iptables", "-A", "WG-CLIENTS", "-s", src, "-j", "DROP"])


def save_clients(data):
    if "clients" not in data or not isinstance(data["clients"], list):
        data = {"clients": []}

    for c in data["clients"]:
        normalize_client_access_profile(c)

    save_json(CLIENTS_FILE, data)
    apply_client_firewall()


def is_wg_running():
    result = subprocess.run(
        ["systemctl", "is-active", "wg-quick@wg0"],
        capture_output=True,
        text=True
    )
    return result.stdout.strip() == "active"


def get_server_status():
    server = get_server_runtime()
    servers = load_server_peers()

    status = {
        "online": False,
        "status_text": "Offline",
        "status_class": "offline",
        "endpoint": f"{server['endpoint']}:{server['port']}" if server["endpoint"] else f"(nicht gesetzt):{server['port']}",
        "handshake": "-",
        "rx": "0 B",
        "tx": "0 B",
    }

    if not is_wg_running():
        return status

    try:
        dump = run_cmd(["wg", "show", "wg0", "dump"])
        lines = [line for line in dump.splitlines() if line.strip()]
        if lines:
            iface = lines[0].split("\t")
            status["online"] = True
            status["status_text"] = "Online"
            status["status_class"] = "online"
            status["handshake"] = "Server aktiv"
            status["rx"] = human_bytes(iface[4])
            status["tx"] = human_bytes(iface[5])
    except Exception:
        pass

    return status


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
    server_vpn_ip = str(data.get("server_vpn_ip", data.get("server_ip", "10.200.0.1"))).strip() or "10.200.0.1"
    client_network = str(data.get("client_network", data.get("network", data.get("allowed_ips", "10.200.1.0/24")))).strip() or "10.200.1.0/24"
    lan_network = str(data.get("lan_network", "192.168.0.0/24")).strip() or "192.168.0.0/24"
    return {
        "endpoint": endpoint,
        "port": int(data.get("port", 51820)),
        "dns": str(data.get("dns", "10.200.1.1")).strip() or "10.200.1.1",
        "allowed_ips": str(data.get("allowed_ips", "10.200.0.0/16")).strip() or "10.200.0.0/16",
        "server_vpn_ip": server_vpn_ip,
        "client_network": client_network,
        "lan_network": lan_network,
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


def channel_sort_key(value):
    try:
        return int(value)
    except Exception:
        return 999999

def render_mesh_plan_compact(mesh_plan, local_channel_raw=None):
    if not mesh_plan:
        return """<div class="card"><h2>Mesh-Plan</h2><p>Keine Remote-Server vorhanden.</p></div>"""

    rows = []
    for item in mesh_plan:
        local_checked = "checked" if item.get("local_approved") else ""
        remote_checked = "checked" if item.get("remote_approved") else ""
        if item.get("link_state") == "active":
            badge = '<span class="badge online">aktiv</span>'
        elif item.get("link_state") == "waiting":
            badge = '<span class="badge warn">wartet</span>'
        else:
            badge = '<span class="badge offline">aus</span>'
        rows.append(f"""
<tr>
<td>{html.escape(item.get('name','Unbenannt'))}</td>
<td>{html.escape(item.get('server_vpn_ip','-'))}</td>
<td>{html.escape(item.get('client_network','-'))}</td>
<td>
<form method="post" action="/server/mesh-approve">
<input type="hidden" name="public_key" value="{html.escape(item.get('public_key',''))}">
<input type="checkbox" onchange="this.form.submit()" {local_checked}>
</form>
</td>
<td><input type="checkbox" disabled {remote_checked}></td>
<td>{badge}</td>
<td><span class="badge {('online' if str(item.get('status_text','Offline')).lower() == 'online' else 'offline')}">{html.escape(item.get('status_text','Offline'))}</span></td>
<td>{html.escape(item.get('handshake','nie'))}</td>
</tr>
""")

    return f"""
<div class="card">
<h2>Mesh-Plan</h2>
<p>Link aktiv nur wenn <strong>meine Freigabe</strong> und <strong>Remote-Freigabe</strong> gesetzt sind.</p>
<table>
<tr>
<th>Server</th>
<th>Server-VPN</th>
<th>Client-Netz</th>
<th>Meine Freigabe</th>
<th>Remote</th>
<th>Link</th>
<th>Status</th>
<th>Handshake</th>
</tr>
{''.join(rows)}
</table>
</div>
"""

def next_channel_name(existing_channels):
    used = set()
    for item in existing_channels:
        try:
            used.add(int(item))
        except Exception:
            continue
    for i in range(1, 256):
        if i not in used:
            return str(i)
    raise RuntimeError("kein freier Server-Slot mehr verfügbar")

def normalize_server_peers(data):
    if "servers" not in data or not isinstance(data["servers"], list):
        data = {"servers": []}

    assigned_slots = []
    for s in data["servers"]:
        if "enabled" not in s:
            s["enabled"] = True

        slot = str(s.get("slot", "")).strip()
        if not slot:
            legacy_network = str(s.get("client_network", s.get("network", ""))).strip()
            if legacy_network.startswith("10.200.") and legacy_network.endswith(".0/24"):
                try:
                    slot = str(int(legacy_network.split('.')[2]))
                except Exception:
                    slot = ""
        if not slot:
            slot = next_channel_name(assigned_slots)
        s["slot"] = slot
        assigned_slots.append(slot)

        try:
            slot_num = int(slot)
        except Exception:
            slot_num = 1

        s["server_vpn_ip"] = str(s.get("server_vpn_ip", f"10.200.0.{slot_num}")).strip() or f"10.200.0.{slot_num}"
        s["client_network"] = str(s.get("client_network", s.get("network", f"10.200.{slot_num}.0/24"))).strip() or f"10.200.{slot_num}.0/24"
        s["network"] = s["client_network"]
        s["local_approved"] = bool(s.get("local_approved", False))
        s["remote_approved"] = bool(s.get("remote_approved", False))
        s["remote_status_known"] = bool(s.get("remote_status_known", s["remote_approved"]))

    data["servers"].sort(key=lambda s: channel_sort_key(s.get("slot", "")))
    return data

def load_server_peers():
    data = load_json(SERVER_PEERS_FILE, {"servers": []})
    return normalize_server_peers(data)


def save_server_peers(data):
    save_json(SERVER_PEERS_FILE, normalize_server_peers(data))


def is_local_server_slave():
    return False

def slave_guard_response():
    return redirect("/server/connect", code=303)

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
    addresses = []
    private_key = None

    with WG_CONF.open("r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("Address"):
                raw = line.split("=", 1)[1].strip()
                addresses = [part.strip() for part in raw.split(",") if part.strip()]
            elif line.startswith("PrivateKey"):
                private_key = line.split("=", 1)[1].strip()

    if not addresses:
        raise RuntimeError("Address nicht gefunden")

    iface_first = ipaddress.ip_interface(addresses[0])
    saved, _, _ = get_server_settings_with_auto_endpoint()

    try:
        pub = run_cmd(["wg", "show", "wg0", "public-key"])
    except Exception:
        if private_key:
            pub = public_from_private(private_key)
        else:
            raise RuntimeError("PublicKey konnte weder live noch aus der Konfiguration ermittelt werden")

    effective_endpoint, endpoint_source = get_effective_endpoint()
    client_network = saved["client_network"] or str(iface_first.network)
    server_vpn_ip = saved["server_vpn_ip"] or str(iface_first.ip)

    return {
        "server_ip": server_vpn_ip,
        "server_vpn_ip": server_vpn_ip,
        "network": client_network,
        "client_network": client_network,
        "lan_network": saved.get("lan_network", "192.168.0.0/24"),
        "server_public_key": pub,
        "endpoint": effective_endpoint,
        "endpoint_source": endpoint_source,
        "port": saved["port"],
        "dns": saved["dns"] or server_vpn_ip,
        "allowed_ips": saved["allowed_ips"] or "10.200.0.0/16",
    }

def generate_keypair():
    priv = run_cmd(["wg", "genkey"])
    pub = run_cmd(["wg", "pubkey"], input_text=priv + "\n")
    return priv, pub


def public_from_private(private_key):
    return run_cmd(["wg", "pubkey"], input_text=private_key.strip() + "\n")


def channel_networks(channel=None, current_public_key=None, only_enabled=True):
    peers = load_server_peers().get("servers", [])
    nets = []
    for s in peers:
        if only_enabled and not s.get("enabled", True):
            continue
        if not (s.get("local_approved") and s.get("remote_approved")):
            continue
        network = str(s.get("client_network", s.get("network", ""))).strip()
        if network:
            nets.append(network)
    seen = []
    for n in nets:
        if n not in seen:
            seen.append(n)
    return seen

def allowed_ips_for_server_peer(server_peer):
    values = []
    server_ip = str(server_peer.get("server_vpn_ip", "")).strip()
    if server_ip:
        values.append(f"{server_ip}/32")
    client_network = str(server_peer.get("client_network", server_peer.get("network", ""))).strip()
    if client_network and server_peer.get("local_approved") and server_peer.get("remote_approved"):
        values.append(client_network)
    return ",".join(values) if values else client_network

def write_server_peer_block(f, server_peer):
    f.write("\n# server-peer\n")
    f.write("[Peer]\n")
    f.write(f"PublicKey = {server_peer.get('public_key','')}\n")
    f.write(f"AllowedIPs = {allowed_ips_for_server_peer(server_peer)}\n")
    f.write(f"Endpoint = {server_peer.get('endpoint','')}\n")
    f.write("PersistentKeepalive = 25\n")


def get_next_free_ip():
    server = get_server_runtime()
    net = ipaddress.ip_network(server["client_network"], strict=False)

    data = load_clients()
    used = {server["server_vpn_ip"]}
    for c in data["clients"]:
        if c.get("ip"):
            used.add(c["ip"])

    preferred_gateway = str(next(net.hosts())) if net.num_addresses > 2 else None

    for host in net.hosts():
        ip = str(host)
        if ip == preferred_gateway:
            continue
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
    try:
        run_cmd(["systemctl", "restart", "wg-quick@wg0"])
        return True
    except Exception:
        return False


def get_local_server_channel():
    return load_server_settings().get("client_network", "10.200.1.0/24")

def channel_has_other_master(channel, exclude_public_key="", include_local=True):
    return False

def get_client_allowed_ips(client, server):
    values = []
    for value in [
        f"{server.get('server_vpn_ip', '').strip()}/32" if server.get("server_vpn_ip") else "",
        str(server.get("client_network", "")).strip(),
        str(server.get("lan_network", "")).strip(),
    ]:
        if value and value not in values:
            values.append(value)
    return ",".join(values)

def build_client_config(client):
    server = get_server_runtime()
    allowed = get_client_allowed_ips(client, server)

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
    try:
        dump = run_cmd(["wg", "show", "wg0", "dump"])
    except Exception:
        return {}

    lines = [line for line in dump.splitlines() if line.strip()]
    peers = {}
    for line in lines[1:]:
        p = line.split("\t")
        if len(p) < 7:
            continue
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
Address = 10.200.0.1/24,10.200.1.1/24
ListenPort = 51820
PrivateKey = {priv}

# NAT für VPN-Clients
PostUp = iptables -t nat -A POSTROUTING -s 10.200.1.0/24 -o eth0 -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s 10.200.1.0/24 -o eth0 -j MASQUERADE
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
    values = {v.strip() for v in (allowed_ips or "").split(",") if v.strip()}
    server_value = f"{server_ip}/32"
    has_server = server_value in values
    has_client_net = any(v.startswith("10.") and "/" in v for v in values if v != server_value)
    has_lan = any(v.startswith("192.168.") or v.startswith("172.") for v in values)

    if values == {server_value}:
        return 1
    if has_client_net and not has_lan:
        return 2
    return 3

def rebuild_server_peer_blocks():
    if not WG_CONF.exists():
        return
    text = WG_CONF.read_text(encoding="utf-8")
    blocks = text.split("\n[Peer]\n")
    kept = [blocks[0]]
    for b in blocks[1:]:
        if "# server-peer" in b:
            continue
        kept.append("[Peer]\n" + b)
    new_text = kept[0].rstrip() + "\n"
    for piece in kept[1:]:
        new_text += "\n" + piece.lstrip("\n")
    WG_CONF.write_text(new_text.rstrip() + "\n", encoding="utf-8")


def client_level_label(level):
    level = int(level or 3)
    return {
        1: "Level 1 – Server",
        2: "Level 2 – Server + VPN-Clients",
        3: "Level 3 – Server + VPN-Clients + LAN-Ziele",
    }.get(level, f"Level {level}")


def mesh_link_state(server_peer):
    if server_peer.get("local_approved") and server_peer.get("remote_approved"):
        return "active"
    if server_peer.get("local_approved") or server_peer.get("remote_approved"):
        return "waiting"
    return "blocked"


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
:root{
  --space-1:8px;
  --space-2:16px;
  --space-3:24px;
  --radius:14px;
  --bg:#0f141b;
  --bg-elev:#161d26;
  --card:#1b2430;
  --card-2:#212c3a;
  --text:#e8edf3;
  --text-muted:#9fb0c3;
  --border:#2d3a4c;
  --primary:#4f8cff;
  --primary-2:#376fe0;
  --secondary:#2a3442;
  --success:#1f9d55;
  --warning:#c58a00;
  --danger:#c23b3b;
  --nav-bg:#121922;
  --nav-link:#c9d4df;
  --nav-active-bg:rgba(79,140,255,.16);
  --nav-active-text:#ffffff;
  --nav-active-border:#4f8cff;
}
body.light{
  --bg:#eef3f9;
  --bg-elev:#ffffff;
  --card:#ffffff;
  --card-2:#f4f7fb;
  --text:#14202b;
  --text-muted:#5a6b7c;
  --border:#d3dde8;
  --primary:#2f6feb;
  --primary-2:#1f5bd1;
  --secondary:#e4ebf3;
  --success:#1f8a4c;
  --warning:#b77900;
  --danger:#b42318;
  --nav-bg:#ffffff;
  --nav-link:#2c3e50;
  --nav-active-bg:rgba(47,111,235,.12);
  --nav-active-text:#0f2a4d;
  --nav-active-border:#2f6feb;
}
html,body{margin:0;padding:0;background:var(--bg);color:var(--text);}
body{font-family:Arial,sans-serif;line-height:1.45;}
.topbar{
  display:flex;
  justify-content:space-between;
  align-items:flex-start;
  gap:var(--space-2);
  padding:var(--space-2) var(--space-3);
  background:var(--nav-bg);
  border-bottom:1px solid var(--border);
}
.topbar h1{
  margin:4px 0 0 0;
  font-size:1.45rem;
  line-height:1.2;
}
.topbar-eyebrow{
  color:var(--text-muted);
  font-size:.78rem;
  font-weight:700;
  letter-spacing:.08em;
  text-transform:uppercase;
}
.topbar-actions{
  display:flex;
  flex-wrap:wrap;
  justify-content:flex-end;
  gap:var(--space-1);
}
.container{padding:var(--space-3);}
.stack{display:grid;gap:var(--space-3);}

.card{
  position:relative;
}

.card{
  box-shadow:0 1px 2px rgba(0,0,0,.04);

  background:var(--card);
  border:1px solid var(--border);
  border-radius:var(--radius);
  padding:var(--space-2);
  box-sizing:border-box;
}
.card + .card{margin-top:var(--space-2);}
.card h2,.card h3{margin:0 0 var(--space-2) 0;}
.section-title{margin:0 0 var(--space-2) 0;font-size:1.35rem;font-weight:700;}
.muted,label small,.meta{color:var(--text-muted);}
table{width:100%;border-collapse:collapse;background:transparent;}
th,td{text-align:left;padding:12px;border-bottom:1px solid var(--border);vertical-align:top;}
th{color:var(--text-muted);font-weight:700;}
button,.btn{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  min-height:38px;
  padding:0 12px;
  border-radius:10px;
  border:1px solid var(--border);
  background:var(--secondary);
  color:var(--text);
  text-decoration:none;
  cursor:pointer;
  transition:.15s ease;
}
button:hover,.btn:hover{
  border-color:var(--nav-active-border);
}
button.primary,.btn.primary{
  background:var(--primary);
  border-color:var(--primary);
  color:#fff;
}
button.primary:hover,.btn.primary:hover{
  background:var(--primary-2);
}
.btn.secondary.active{
  background:var(--nav-active-bg);
  color:var(--nav-active-text);
  border-color:var(--nav-active-border);
  font-weight:700;
}
.btn.delete{
  border-color:rgba(194,59,59,.35);
}
.btn.delete:hover{
  background:rgba(194,59,59,.12);
  border-color:var(--danger);
}
input,select,textarea{
  box-shadow:inset 0 1px 2px rgba(0,0,0,.03);

  width:100%;
  min-height:38px;
  box-sizing:border-box;
  padding:8px 10px;
  border-radius:10px;
  border:1px solid var(--border);
  background:var(--bg-elev);
  color:var(--text);
}
form{margin:0;}
label{
  display:block;
  margin:0 0 6px 0;
  color:var(--text-muted);
  font-size:.95rem;
  font-weight:600;
}
.form-grid{display:grid;gap:var(--space-2);}
footer{
  padding:0 var(--space-3) var(--space-3) var(--space-3);
  color:var(--text-muted);
  font-size:.9rem;
}
.subnav{
  display:flex;
  flex-wrap:wrap;
  gap:var(--space-1);
  align-items:center;
}
.subnav-link{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  min-height:38px;
  padding:0 12px;
  border-radius:10px;
  border:1px solid var(--border);
  background:var(--secondary);
  color:var(--text);
  text-decoration:none;
  cursor:pointer;
  transition:.15s ease;
}
.subnav-link:hover{
  border-color:var(--nav-active-border);
  background:var(--card-2);
}

.page-head{
  display:flex;
  justify-content:space-between;
  align-items:flex-start;
  gap:var(--space-2);
  margin-bottom:var(--space-2);
}
.meshwarn-compact{
  padding:10px 12px;
  border-radius:12px;
  border:1px solid var(--border);
  background:var(--card);
  font-size:.9rem;
  cursor:pointer;
  user-select:none;
  transition:.15s ease;
}
.meshwarn-compact:hover{
  border-color:var(--nav-active-border);
  transform:translateY(-1px);
}
.meshwarn-compact.warn:hover{
  box-shadow:0 0 0 1px rgba(197,138,0,.18);
}
.meshwarn-compact.ok:hover{
  box-shadow:0 0 0 1px rgba(31,157,85,.18);
}
.meshwarn-compact.warn{
  border-color:#8a6d1d;
  background:#3a2f0b;
  color:#f5e6a8;
}
.meshwarn-compact.ok{
  border-color:rgba(31,157,85,.35);
  background:rgba(31,157,85,.10);
}

body.light .subnav-link:hover{
  background:#edf3f9;
}

.badge{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  min-width:78px;
  min-height:30px;
  padding:0 10px;
  border-radius:999px;
  border:1px solid var(--border);
  font-size:.9rem;
  font-weight:700;
  line-height:1;
  white-space:nowrap;
}
.badge.online{
  background:rgba(31,157,85,.18);
  border-color:rgba(31,157,85,.40);
  color:#9fe0b1;
}
.badge.offline{
  background:rgba(194,59,59,.16);
  border-color:rgba(194,59,59,.40);
  color:#ffb1b1;
}
.badge.warn{
  background:rgba(197,138,0,.18);
  border-color:rgba(197,138,0,.45);
  color:#f5e6a8;
}
.config-textarea{
  min-height:220px;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  line-height:1.35;
  resize:vertical;
}
.config-textarea-lg{
  min-height:320px;
}
.config-textarea-client{
  min-height:420px;
}


.clients-header{
  display:flex;
  justify-content:space-between;
  align-items:flex-start;
  margin-bottom:10px;
}

position:static;
  display:flex;
  flex-direction:column;
  gap:6px;
  background:rgba(255,255,255,0.04);
  border:1px solid var(--border);
  border-radius:10px;
  padding:12px 16px;
  font-size:.9rem;
  line-height:1.4;
  min-width:200px;
}

  position:absolute;
  right:20px;
  top:20px;
  display:flex;
  flex-direction:column;
  gap:6px;
  background:rgba(255,255,255,0.04);
  border:1px solid var(--border);
  border-radius:10px;
  padding:12px 16px;
  font-size:.9rem;
  line-height:1.4;
  min-width:200px;
  z-index:10;
}

  position:absolute;
  right:20px;
  top:20px;
  display:flex;
  flex-direction:column;
  gap:8px;
  background:rgba(255,255,255,0.03);
  border:1px solid var(--border);
  border-radius:10px;
  padding:10px 14px;
  font-size:.9rem;
  min-width:160px;
}

.level-info-table.compact th,
.level-info-table.compact td{
  padding:6px 10px;
}


.level-help{
  position:relative;
  display:inline-flex;
  align-items:center;
  gap:8px;
}
.level-help-btn{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  width:22px;
  height:22px;
  border-radius:999px;
  border:1px solid var(--border);
  background:rgba(255,255,255,0.04);
  color:var(--text);
  font-size:.85rem;
  font-weight:700;
  line-height:1;
  cursor:pointer;
  text-decoration:none;
}
.level-help-btn:hover{
  background:rgba(255,255,255,0.08);
}
.level-help-pop{
  display:none;
  position:absolute;
  top:28px;
  left:0;
  min-width:220px;
  padding:10px 12px;
  border-radius:10px;
  border:1px solid var(--border);
  background:var(--card);
  box-shadow:0 12px 30px rgba(0,0,0,.28);
  z-index:50;
}
.level-help:hover .level-help-pop,
.level-help:focus-within .level-help-pop{
  display:block;
}
.level-help-pop div + div{
  margin-top:6px;
}
.inline-level-form{
  margin:0;
}
.inline-level-form select{
  width:auto;
  min-width:0;
  display:inline-block;
  padding-right:18px;
}

.level-info-table.compact td:first-child{
  width:120px;
  font-weight:600;
}

.level-info-table{
  margin-top:12px;
  width:100%;
}
.level-info-table th,.level-info-table td{
  padding:10px 12px;
}
.cfg-qr-wrap{
  display:grid;
  grid-template-columns:minmax(0,1fr) minmax(320px,420px);
  gap:16px;
  align-items:start;
}
.cfg-col,.qr-col{
  min-width:0;
}
.qrbox-side{
  display:flex;
  align-items:center;
  justify-content:center;
  min-height:420px;
}
.qrbox-side img{
  width:100%;
  max-width:420px;
  height:auto;
  aspect-ratio:1/1;
  object-fit:contain;
}
@media (max-width: 980px){
  .cfg-qr-wrap{
    grid-template-columns:1fr;
  }
  .qrbox-side{
    min-height:auto;
  }
  .qrbox-side img{
    max-width:100%;
  }
}

@media (max-width: 860px){
  .topbar{
    flex-direction:column;
    align-items:stretch;
    padding:var(--space-2);
  }
  .topbar-actions{
    justify-content:flex-start;
  }
  .container{
    padding:var(--space-2);
  }
  footer{
    padding:0 var(--space-2) var(--space-2) var(--space-2);
  }
}
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

function toggleBlock(id){
  const el = document.getElementById(id);
  if(!el){ return; }
  el.style.display = (el.style.display === 'block') ? 'none' : 'block';
}

function toggleTheme(){
  const isLight = document.body.classList.toggle('light');
  localStorage.setItem('theme', isLight ? 'light' : 'dark');
}

document.addEventListener('DOMContentLoaded', function(){
  const saved = localStorage.getItem('theme');
  if(saved === 'light'){
    document.body.classList.add('light');
  }
});

</script>
</head>
<body>
<div class="topbar">
  <div>
    <div class="topbar-eyebrow">Operations Console</div>
    <h1>WG Server Panel</h1>
  </div>
  <div class="topbar-actions">
    <a href="/" class="btn secondary {{ 'active' if request.path == '/' else '' }}">Dashboard</a>
    <a href="/lan-targets" class="btn secondary {{ 'active' if request.path.startswith('/lan-targets') else '' }}">LAN-Ziele</a>
    <a href="/server/settings" class="btn secondary {{ 'active' if request.path.startswith('/server/settings') else '' }}">Server</a>
    <a href="/ddns" class="btn secondary {{ 'active' if request.path.startswith('/ddns') else '' }}">DDNS</a>
    <a href="/logout" class="btn delete">Logout</a>
    <button class="btn" onclick="toggleTheme()">Theme</button>
  </div>
</div>

<div class="container">
  <div class="stack">
    {{ body|safe }}
  </div>
</div>
<footer>WG Server Panel v1.4 · by Lupus1988</footer>
</body>
</html>
"""



@app.route("/setup", methods=["GET", "POST"])
def setup():
    if is_auth_configured():
        return redirect(url_for("login"), code=303)

    error = ""

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""
        reset_pin = (request.form.get("reset_pin") or "").strip()

        if not username or not password or not password2 or not reset_pin:
            error = "Bitte alle Felder ausfüllen."
        elif password != password2:
            error = "Die Passwörter stimmen nicht überein."
        elif len(password) < 8:
            error = "Das Passwort muss mindestens 8 Zeichen lang sein."
        elif len(reset_pin) < 4:
            error = "Die Reset-PIN muss mindestens 4 Zeichen lang sein."
        else:
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            data = load_auth()
            data["username"] = username
            data["password_hash"] = generate_password_hash(password)
            data["reset_pin_hash"] = generate_password_hash(reset_pin)
            data["failed_reset_attempts"] = 0
            data["reset_locked_until"] = 0
            data["created_at"] = now_str
            data["updated_at"] = now_str
            save_auth(data)
            write_audit_log(f"{username} completed initial panel setup")
            return redirect(url_for("login"), code=303)

    body = f"""
<h1>Panel-Ersteinrichtung</h1>

<div class="card">
<p>Es ist noch kein Panel-Zugang eingerichtet.</p>

<form method="post">
<label>Benutzername</label>
<input type="text" name="username" required>

<label>Passwort</label>
<input type="password" name="password" required>

<label>Passwort wiederholen</label>
<input type="password" name="password2" required>

<label>Reset-PIN</label>
<input type="password" name="reset_pin" required>
<div style="margin-top:8px;padding:10px 12px;border:1px solid #3a3f4b;border-radius:8px;background:#1b1f27;font-size:16px;line-height:1.5;">
<strong>ℹ Reset-PIN</strong><br>
Diese PIN wird benötigt, um den Panel-Zugang zurückzusetzen, falls Benutzername oder Passwort vergessen wurden.<br>
Der Reset löscht nur die Zugangsdaten des Panels – alle WireGuard-Konfigurationen bleiben erhalten.
</div>

<br>
<p style="opacity:.85;">Die Sitzung läuft nach 20 Minuten Inaktivität automatisch ab.</p>

<button type="submit">Einrichtung abschließen</button>
</form>

{"<p>" + html.escape(error) + "</p>" if error else ""}
</div>
"""
    return render_template_string(BASE, body=body)


@app.route("/login", methods=["GET", "POST"])
def login():
    if not is_auth_configured():
        return redirect(url_for("setup"), code=303)

    if is_session_valid():
        return redirect(url_for("index"), code=303)

    error = ""
    info = ""
    auth = load_auth()
    now_ts = int(time.time())
    locked_until = int(auth.get("login_locked_until", 0) or 0)

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if locked_until > now_ts:
            remaining = locked_until - now_ts
            minutes = max(1, (remaining + 59) // 60)
            error = ""
        elif not username or not password:
            error = "Bitte Benutzername und Passwort eingeben."
        elif username == auth.get("username") and check_password_hash(auth.get("password_hash", ""), password):
            auth["failed_login_attempts"] = 0
            auth["login_locked_until"] = 0
            save_auth(auth)

            session.clear()
            session["logged_in"] = True
            session["username"] = username
            session["last_seen"] = int(time.time())
            session.permanent = False
            write_audit_log(f"{username} logged in")
            return redirect(url_for("index"), code=303)
        else:
            attempts = int(auth.get("failed_login_attempts", 0) or 0) + 1
            auth["failed_login_attempts"] = attempts

            if attempts >= LOGIN_MAX_ATTEMPTS:
                auth["login_locked_until"] = now_ts + LOGIN_LOCK_SECONDS
                auth["failed_login_attempts"] = 0
                save_auth(auth)
                write_audit_log(f"login locked after too many invalid attempts for username={username or 'empty'}")
                error = ""
            else:
                save_auth(auth)
                write_audit_log(f"invalid login attempt for username={username or 'empty'}")
                error = f"Ungültiger Benutzername oder Passwort. Verbleibende Versuche: {LOGIN_MAX_ATTEMPTS - attempts}"

        auth = load_auth()
        locked_until = int(auth.get("login_locked_until", 0) or 0)

    if locked_until > now_ts:
        remaining = locked_until - now_ts
        minutes = max(1, (remaining + 59) // 60)
        info = f"Login ist aktuell gesperrt. Erneut versuchen in ca. {minutes} Minute(n)."

    body = f"""
<h1>Login</h1>

<div class="card">
<form method="post">
<label>Benutzername</label>
<input type="text" name="username" required>

<label>Passwort</label>
<input type="password" name="password" required>

<br>
<p style="opacity:.85;">Die Sitzung läuft nach 20 Minuten Inaktivität automatisch ab.</p>

<button type="submit">Anmelden</button>
<a class="btn secondary" href="/reset-access">Zugang zurücksetzen</a>
</form>

{"<div style=\"margin-top:14px;padding:12px 14px;border:1px solid #8a6d1d;border-radius:8px;background:#3a2f0b;color:#f5e6a8;line-height:1.5;\">⚠ " + html.escape(info) + "</div>" if info else ""}
{"<p>" + html.escape(error) + "</p>" if error else ""}
</div>
"""
    return render_template_string(BASE, body=body)


@app.route("/logout")
def logout():
    username = session.get("username", "unknown")
    session.clear()
    write_audit_log(f"{username} logged out")
    return redirect(url_for("login"), code=303)


@app.route("/reset-access", methods=["GET", "POST"])
def reset_access():
    if not is_auth_configured():
        return redirect(url_for("setup"), code=303)

    error = ""
    info = ""
    warning = ""
    auth = load_auth()
    now_ts = int(time.time())
    locked_until = int(auth.get("reset_locked_until", 0) or 0)
    failed_attempts = int(auth.get("failed_reset_attempts", 0) or 0)
    show_factory_reset = failed_attempts >= 3 or locked_until > now_ts

    if request.method == "POST":
        reset_pin = (request.form.get("reset_pin") or "").strip()
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""

        if locked_until > now_ts:
            remaining = locked_until - now_ts
            minutes = max(1, (remaining + 59) // 60)
            info = f"Reset-Zugang ist aktuell gesperrt. Erneut versuchen in ca. {minutes} Minute(n)."
            error = ""
        elif not reset_pin or not username or not password or not password2:
            error = "Bitte alle Felder ausfüllen."
        elif password != password2:
            error = "Die Passwörter stimmen nicht überein."
        elif len(password) < 8:
            error = "Das Passwort muss mindestens 8 Zeichen lang sein."
        elif len(reset_pin) < 4:
            error = "Die Reset-PIN ist ungültig."
        elif not check_password_hash(auth.get("reset_pin_hash", ""), reset_pin):
            attempts = int(auth.get("failed_reset_attempts", 0) or 0) + 1
            auth["failed_reset_attempts"] = attempts
            show_factory_reset = attempts >= 3

            if attempts >= RESET_PIN_MAX_ATTEMPTS:
                auth["reset_locked_until"] = now_ts + RESET_PIN_LOCK_SECONDS
                auth["failed_reset_attempts"] = 0
                save_auth(auth)
                write_audit_log("reset access locked after too many invalid reset PIN attempts")
                remaining = RESET_PIN_LOCK_SECONDS
                minutes = max(1, (remaining + 59) // 60)
                info = f"Reset-Zugang ist aktuell gesperrt. Erneut versuchen in ca. {minutes} Minute(n)."
                error = ""
                show_factory_reset = True
            else:
                save_auth(auth)
                write_audit_log("invalid reset PIN attempt")
                error = f"Ungültige Reset-PIN. Verbleibende Versuche: {RESET_PIN_MAX_ATTEMPTS - attempts}"

                if attempts >= 3:
                    warning = "Die Reset-PIN wurde mehrfach falsch eingegeben. Falls die PIN nicht mehr bekannt ist, kann ein Werksreset durchgeführt werden. Dabei werden alle Panel-Einstellungen gelöscht."
        else:
            auth["username"] = username
            auth["password_hash"] = generate_password_hash(password)
            auth["failed_reset_attempts"] = 0
            auth["reset_locked_until"] = 0
            auth["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            save_auth(auth)
            session.clear()
            write_audit_log(f"{username} reset panel access via reset PIN")
            return redirect(url_for("login"), code=303)

        auth = load_auth()
        locked_until = int(auth.get("reset_locked_until", 0) or 0)
        failed_attempts = int(auth.get("failed_reset_attempts", 0) or 0)
        show_factory_reset = show_factory_reset or failed_attempts >= 3

    if locked_until > now_ts and not info:
        remaining = locked_until - now_ts
        minutes = max(1, (remaining + 59) // 60)
        info = f"Reset-Zugang ist aktuell gesperrt. Erneut versuchen in ca. {minutes} Minute(n)."

    if show_factory_reset and not warning:
        warning = "Die Reset-PIN wurde mehrfach falsch eingegeben. Falls die PIN nicht mehr bekannt ist, kann ein Werksreset durchgeführt werden. Dabei werden alle Panel-Einstellungen gelöscht."

    factory_reset_html = ""
    if show_factory_reset:
        factory_reset_html = """
<div style="margin-top:14px;padding:12px 14px;border:1px solid #8a6d1d;border-radius:8px;background:#3a2f0b;color:#f5e6a8;line-height:1.5;">
⚠ """ + html.escape(warning) + """<br><br>
<form method="get" action="/factory-reset" style="margin-top:12px;"><button type="submit" style="background:#c0392b;">Werksreset</button></form>
</div>
"""

    body = f"""
<h1>Zugang zurücksetzen</h1>

<div class="card">
<p>Mit der Reset-PIN können Benutzername und Passwort des Panels zurückgesetzt werden.</p>
<p>Alle WireGuard-, Server- und Client-Konfigurationen bleiben erhalten.</p>

<form method="post">
<label>Reset-PIN</label>
<input type="password" name="reset_pin" required>

<label>Neuer Benutzername</label>
<input type="text" name="username" required>

<label>Neues Passwort</label>
<input type="password" name="password" required>

<label>Neues Passwort wiederholen</label>
<input type="password" name="password2" required>

<br><br>
<button type="submit">Zugang zurücksetzen</button>
<a class="btn secondary" href="/login">Zurück</a>
</form>

{"<div style=\"margin-top:14px;padding:12px 14px;border:1px solid #8a6d1d;border-radius:8px;background:#3a2f0b;color:#f5e6a8;line-height:1.5;\">⚠ " + html.escape(info) + "</div>" if info else ""}
{"<p>" + html.escape(error) + "</p>" if error else ""}
{factory_reset_html}
</div>
"""
    return render_template_string(BASE, body=body)



@app.route("/factory-reset", methods=["GET", "POST"])
def factory_reset():
    if not is_auth_configured():
        return redirect(url_for("setup"), code=303)

    auth = load_auth()
    failed_attempts = int(auth.get("failed_reset_attempts", 0) or 0)
    locked_until = int(auth.get("reset_locked_until", 0) or 0)
    now_ts = int(time.time())
    if failed_attempts < 3 and locked_until <= now_ts:
        return redirect(url_for("reset_access"), code=303)

    error = ""
    confirm_text = "WERKSRESET"

    if request.method == "POST":
        confirmation = (request.form.get("confirmation") or "").strip()

        if confirmation != confirm_text:
            error = f'Bitte zur Bestätigung exakt "{confirm_text}" eingeben.'
        else:
            import shutil, secrets

            for path in [AUTH_FILE, SERVER_FILE, DDNS_FILE]:
                try:
                    if path.exists():
                        path.unlink()
                except Exception:
                    pass

            for d in [
                Path("/opt/wg-panel/clients"),
                Path("/opt/wg-panel/server-peers")
            ]:
                try:
                    if d.exists():
                        shutil.rmtree(d)
                except Exception:
                    pass

            # neuen Secret-Key erzeugen
            try:
                secret_path = Path("/opt/wg-panel/secret.key")
                new_key = secrets.token_hex(32)
                secret_path.write_text(new_key)
                secret_path.chmod(0o600)
            except Exception:
                pass

            session.clear()
            write_audit_log("factory reset executed")
            return redirect(url_for("setup"), code=303)

    body = f"""
<h1>Werksreset</h1>

<div class="card">
<div style="margin-bottom:14px;padding:12px 14px;border:1px solid #8a6d1d;border-radius:8px;background:#3a2f0b;color:#f5e6a8;line-height:1.5;">
⚠ Achtung: Beim Werksreset werden alle Panel-Einstellungen gelöscht.<br>
Dazu gehören Zugangsdaten, Server-, Client-, DDNS- und Mesh-Konfigurationen.
</div>

<p>Um den Werksreset auszuführen, gib bitte zur Bestätigung exakt folgenden Text ein:</p>
<p><strong>{confirm_text}</strong></p>

<form method="post">
<label>Bestätigungstext</label>
<input type="text" name="confirmation" required>

<br><br>
<button type="submit" style="background:#c0392b;">Werksreset endgültig ausführen</button>
<a class="btn secondary" href="/reset-access">Abbrechen</a>
</form>

{"<p>" + html.escape(error) + "</p>" if error else ""}
</div>
"""
    return render_template_string(BASE, body=body)


@app.route("/server/control/<action>")
def server_control(action):
    if action == "start":
        run_cmd(["systemctl","start","wg-quick@wg0"])
    elif action == "stop":
        run_cmd(["systemctl","stop","wg-quick@wg0"])
    elif action == "restart":
        run_cmd(["systemctl","restart","wg-quick@wg0"])
    return redirect("/")

@app.route("/")
def index():
    data = load_clients()
    if not WG_CONF.exists():
        return redirect("/server/generate")
    server = get_server_runtime()
    ddns = load_ddns_settings()
    stats = get_live_stats()
    server_status = get_server_status()

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
        key = c["public_key"]
        status_class = "online" if st["online"] else "offline"
        status_text = "Online" if st["online"] else "Offline"
        row_style = ' style="opacity:0.45;"' if not c.get("enabled", True) else ""
        checked = "checked" if c.get("enabled", True) else ""
        rows += f"""
<tr class="disabled-client"{row_style}>
<td><form method="post" action="/client/toggle"><input type="hidden" name="public_key" value="{key}"><input type="checkbox" onchange="this.form.submit()" {checked}></form></td>
<td>{html.escape(c["name"])}</td>
<td>{html.escape(c["ip"])}/32</td>
<td><span class="badge {status_class}">{status_text}</span></td>
<td>
<form method="post" action="/client/level" class="inline-level-form">
<input type="hidden" name="public_key" value="{key}">
<select name="access_level" onchange="this.form.submit()">
<option value="1" {"selected" if int(c.get("access_level", 3) or 3) == 1 else ""}>Level 1</option>
<option value="2" {"selected" if int(c.get("access_level", 3) or 3) == 2 else ""}>Level 2</option>
<option value="3" {"selected" if int(c.get("access_level", 3) or 3) == 3 else ""}>Level 3</option>
</select>
</form>
</td>
<td>{html.escape(st["handshake"])}</td>
<td>{html.escape(st["rx"])}</td>
<td>{html.escape(st["tx"])}</td>
<td class="actions"><a class="btn secondary" href="/client/{key}/view">Konfig</a>
<a class="btn secondary" href="/client/{key}/download">Download</a>
<form style="display:inline" method="post" action="/client/delete" onsubmit="return confirm('Client wirklich löschen?');"><input type="hidden" name="public_key" value="{key}"><button class="delete" type="submit">Löschen</button></form></td>
</tr>
"""

    ddns_info = ""
    if ddns["enabled"] and ddns["hostname"]:
        ddns_info = (
            '<div class="card">'
            f'<div class="kv"><span class="kv-label">DDNS aktiv</span> <span class="host-badge">{html.escape(ddns["hostname"])}</span></div>'
            f'<div class="kv"><span class="kv-label">Als Endpoint verwenden</span> {"Ja" if ddns["use_as_endpoint"] else "Nein"}</div>'
            '</div>'
        )

    body = f"""
<div class="subnav card">
  <a class="subnav-link" href="/client/new">+ Client</a>
  <a class="subnav-link" href="/client/import">Import</a>
  <a class="subnav-link" href="/backup/export">Backup Export</a>
  <a class="subnav-link" href="/backup/import">Backup Import</a>
  <a class="subnav-link" href="/">Aktualisieren</a>
</div>

{endpoint_warning_html(server)}
{ddns_info}

<div class="card">
<h2>WireGuard Server</h2>
<table>
<tr>
<th>Status</th>
<th>Endpoint</th>
<th>Server-VPN</th>
<th>Client-Netz</th>
<th>Handshake</th>
<th>RX</th>
<th>TX</th>
</tr>
<tr>
<td><span class="badge {server_status['status_class']}">{server_status['status_text']}</span></td>
<td>{server_status['endpoint']}</td>
<td>{html.escape(server['server_vpn_ip'])}</td>
<td>{html.escape(server['client_network'])}</td>
<td>{server_status['handshake']}</td>
<td>{server_status['rx']}</td>
<td>{server_status['tx']}</td>
</tr>
</table>
<br>
<a class="btn" href="/server/control/start">Start</a>
<a class="btn secondary" href="/server/control/stop">Stop</a>
<a class="btn secondary" href="/server/control/restart">Neustart</a>
<a class="btn secondary" href="/server/settings">Server-Einstellungen</a>
</div>

<div class="card">


<h2>Clients</h2>


<table>
<tr>
<th>Aktiv</th>
<th>Name</th>
<th>IP</th>
<th>Status</th>
<th><span class="level-help">Freigabe-Level <button type="button" class="level-help-btn" aria-label="Info zu Freigabe-Level">?</button><span class="level-help-pop"><div><strong>Level 1:</strong> nur Server</div><div><strong>Level 2:</strong> Server + lokale VPN-Clients</div><div><strong>Level 3:</strong> Level 2 + ausgewählte LAN-Ziele</div></span></span></th>
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



@app.route("/server/connect", methods=["GET","POST"])
def server_connect():
    return redirect("/", code=303)


def _legacy_server_connect_disabled():
    server = get_server_runtime()
    servers = load_server_peers()
    stats = get_live_stats()

    rows = ""
    mesh_plan = []
    for s in servers["servers"]:
        st = stats.get(s.get("public_key", ""), {
            "handshake": "nie",
            "rx": "0 B",
            "tx": "0 B",
            "online": False,
            "status_text": "Offline",
        })
        status_class = "online" if st["online"] else "offline"
        checked = "checked" if s.get("enabled", True) else ""
        row_style = ' style="opacity:0.45;"' if not s.get("enabled", True) else ""
        link_state = mesh_link_state(s)
        link_label = {
            "active": "aktiv",
            "waiting": "wartet",
            "blocked": "aus",
        }[link_state]
        rows += f"""
<tr{row_style}>
<td>
<form method="post" action="/server/toggle">
<input type="hidden" name="public_key" value="{s.get('public_key','')}">
<input type="checkbox" onchange="this.form.submit()" {checked}>
</form>
</td>
<td>{html.escape(s.get('name',''))}</td>
<td>{html.escape(s.get('server_vpn_ip','-'))}</td>
<td>{html.escape(s.get('client_network','-'))}</td>
<td><span class="badge {status_class}">{st['status_text']}</span></td>
<td>{html.escape(s.get('endpoint',''))}</td>
<td><span class="badge {('online' if link_state == 'active' else 'warn' if link_state == 'waiting' else 'offline')}">{html.escape(link_label)}</span></td>
<td>{html.escape(st['handshake'])}</td>
<td>{html.escape(st['rx'])}</td>
<td>{html.escape(st['tx'])}</td>
<td class="actions">
<a class="btn secondary" href="/server/{s.get('public_key','')}/view">Konfig</a>
<form style="display:inline" method="post" action="/server/delete" onsubmit="return confirm('Server-Verbindung wirklich löschen?');">
<input type="hidden" name="public_key" value="{s.get('public_key','')}">
<button class="delete" type="submit">Löschen</button>
</form>
</td>
</tr>
"""
        mesh_plan.append({
            "name": s.get("name", "Unbenannt"),
            "public_key": s.get("public_key", ""),
            "server_vpn_ip": s.get("server_vpn_ip", "-"),
            "client_network": s.get("client_network", "-"),
            "local_approved": s.get("local_approved", False),
            "remote_approved": s.get("remote_approved", False),
            "link_state": link_state,
            "status_text": st["status_text"],
            "handshake": st["handshake"],
        })

    body = f"""
<div class="subnav card">
  <a class="subnav-link" href="/server/connect/export">Eigene Serverdaten</a>
  <a class="subnav-link" href="/server/add">+ Server</a>
  <a class="subnav-link" href="/server/settings">Server-Einstellungen</a>
  <a class="subnav-link" href="/server/connect">Aktualisieren</a>
</div>

<div class="card">
<h2>Lokaler Server</h2>
<table>
<tr><th>Name</th><th>Server-VPN</th><th>Client-Netz</th><th>Endpoint</th></tr>
<tr><td>Dieser Server</td><td>{html.escape(server['server_vpn_ip'])}</td><td>{html.escape(server['client_network'])}</td><td>{html.escape((server['endpoint'] or '-') + ':' + str(server['port']))}</td></tr>
</table>
</div>

{render_mesh_plan_compact(mesh_plan, None)}

<div class="card">
<h2>Serverliste</h2>
<table>
<tr>
<th>Aktiv</th>
<th>Name</th>
<th>Server-VPN</th>
<th>Client-Netz</th>
<th>Status</th>
<th>Endpoint</th>
<th>Link</th>
<th>Letzter Handshake</th>
<th>RX</th>
<th>TX</th>
<th>Aktionen</th>
</tr>
{rows if rows else '<tr><td colspan="11">Keine Remote-Server vorhanden.</td></tr>'}
</table>
</div>
"""
    return render_template_string(BASE, body=body)

@app.route("/server/connect/export")
def server_connect_export():
    server = get_server_runtime()
    server_export = f"""Name = Dieser Server
PublicKey = {server['server_public_key']}
Endpoint = {server['endpoint']}:{server['port']}
ServerVPN = {server['server_vpn_ip']}
ClientNetwork = {server['client_network']}"""

    body = f"""
<h1>Eigene Serverdaten</h1>
<div class="card">
<h2>Server-Konfiguration</h2>
<textarea id="servercfgexport" class="config-textarea config-textarea-lg" readonly>{server_export}</textarea>
<br><br>
<button type="button" onclick="kopiereTextAusTextarea('servercfgexport')">Konfiguration kopieren</button>
<a class="btn secondary" href="/server/connect">Zurück</a>
</div>
"""
    return render_template_string(BASE, body=body)

@app.route("/server/add", methods=["GET", "POST"])
def server_add():
    message = ""

    if request.method == "POST":
        cfg = (request.form.get("config_text") or "").strip()
        name = (request.form.get("name") or "").strip()
        try:
            parsed = {}
            for line in cfg.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    parsed[k.strip()] = v.strip()

            pub = parsed.get("PublicKey")
            endpoint = parsed.get("Endpoint")
            server_vpn_ip = parsed.get("ServerVPN") or ""
            client_network = parsed.get("ClientNetwork") or parsed.get("Network") or ""
            if not pub or not endpoint:
                raise ValueError("PublicKey oder Endpoint fehlt")

            peer_data = load_server_peers()
            if any(s.get("public_key") == pub for s in peer_data["servers"]):
                raise ValueError("Server ist bereits vorhanden")

            slots = [s.get("slot", "") for s in peer_data["servers"]]
            slot = next_channel_name(slots)
            slot_num = int(slot)
            if not name:
                name = endpoint.split(":", 1)[0]
            peer_entry = {
                "name": name,
                "public_key": pub,
                "endpoint": endpoint,
                "enabled": True,
                "slot": slot,
                "server_vpn_ip": server_vpn_ip or f"10.200.0.{slot_num}",
                "client_network": client_network or f"10.200.{slot_num}.0/24",
                "network": client_network or f"10.200.{slot_num}.0/24",
                "local_approved": False,
                "remote_approved": False,
                "remote_status_known": False,
            }
            peer_data["servers"].append(peer_entry)
            save_server_peers(peer_data)
            rebuild_server_peer_blocks()
            restart_wg()
            return redirect("/server/connect", code=303)
        except Exception as e:
            message = str(e)

    body = f"""
<h1>Server hinzufügen</h1>
<div class="card">
<p>Hier kann ein weiterer Mesh-Server hinzugefügt werden.</p>
<form method="post">
<label>Name</label>
<input name="name" placeholder="z. B. Office">
<label>Server-Konfiguration</label>
<textarea name="config_text" class="config-textarea config-textarea-lg" placeholder="PublicKey = ...&#10;Endpoint = 198.51.100.10:51820&#10;ServerVPN = 10.200.0.2&#10;ClientNetwork = 10.200.2.0/24"></textarea>
<br><br>
<button type="submit">Server hinzufügen</button>
<a class="btn secondary" href="/server/connect">Zurück</a>
</form>
<p>{html.escape(message)}</p>
</div>
"""
    return render_template_string(BASE, body=body)

@app.route("/server/toggle", methods=["POST"])
def toggle_server():
    key = request.form["public_key"]
    data = load_server_peers()
    for s in data["servers"]:
        if s.get("public_key") == key:
            s["enabled"] = not s.get("enabled", True)
            break
    save_server_peers(data)
    rebuild_server_peer_blocks()
    restart_wg()
    return redirect("/server/connect", code=303)

@app.route("/server/local-channel", methods=["POST"])
def server_local_channel():
    return redirect("/server/connect", code=303)

@app.route("/server/channel", methods=["POST"])
def server_channel():
    return redirect("/server/connect", code=303)

@app.route("/server/mesh-approve", methods=["POST"])
def server_mesh_approve():
    key = request.form["public_key"]
    data = load_server_peers()
    for s in data["servers"]:
        if s.get("public_key") == key:
            s["local_approved"] = not s.get("local_approved", False)
            break
    save_server_peers(data)
    rebuild_server_peer_blocks()
    restart_wg()
    return redirect("/server/connect", code=303)

@app.route("/server/<path:key>/view")
def server_view(key):
    data = load_server_peers()
    s = next((x for x in data["servers"] if x.get("public_key") == key), None)
    if not s:
        abort(404)

    cfg = f"""Name = {s.get('name','')}
PublicKey = {s.get('public_key','')}
Endpoint = {s.get('endpoint','')}
ServerVPN = {s.get('server_vpn_ip','')}
ClientNetwork = {s.get('client_network','')}"""

    body = f"""
<h1>Server-Konfiguration</h1>
<div class="card">
  <h2>{html.escape(s.get('name',''))}</h2>
  <textarea id="servercfgview" readonly>{html.escape(cfg)}</textarea>
  <br><br>
  <button type="button" onclick="kopiereTextAusTextarea('servercfgview')">Konfiguration kopieren</button>
  <a class="btn secondary" href="/server/connect">Zurück</a>
</div>
"""
    return render_template_string(BASE, body=body)

@app.route("/server/delete", methods=["POST"])
def delete_server():
    key = request.form["public_key"]
    data = load_server_peers()
    data["servers"] = [s for s in data["servers"] if s.get("public_key") != key]
    save_server_peers(data)
    rebuild_server_peer_blocks()
    restart_wg()
    return redirect("/server/connect", code=303)

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
            "allowed_ips": (request.form.get("allowed_ips") or "10.200.0.0/16").strip(),
            "server_vpn_ip": (request.form.get("server_vpn_ip") or "10.200.0.1").strip(),
            "client_network": (request.form.get("client_network") or "10.200.1.0/24").strip(),
        }
        save_server_settings(data)
        saved_data = load_server_settings()
        display_endpoint = (
            ddns["hostname"]
            if ddns["enabled"] and ddns["hostname"]
            else (saved_data["endpoint"] or detect_public_ip())
        )
        saved = True

    notice = ""
    if ddns["enabled"] and ddns["hostname"]:
        notice = f"""
<div class="card warn"><strong>Aktiver Endpoint:</strong> DDNS ist aktiv, daher wird aktuell <code>{html.escape(ddns['hostname'])}</code> verwendet.</div>
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
<label>Server-VPN-IP</label>
<input name="server_vpn_ip" value="{html.escape(saved_data['server_vpn_ip'])}">
<label>Client-Netz</label>
<input name="client_network" value="{html.escape(saved_data['client_network'])}">
<label>Client-AllowedIPs (Infofeld, derzeit nicht maßgeblich)</label>
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


def detect_local_lan_network():
    import ipaddress
    import subprocess

    try:
        route_out = subprocess.run(
            ["ip", "-4", "route", "get", "1.1.1.1"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

        parts = route_out.split()
        dev = ""
        src_ip = ""
        for i, part in enumerate(parts):
            if part == "dev" and i + 1 < len(parts):
                dev = parts[i + 1]
            if part == "src" and i + 1 < len(parts):
                src_ip = parts[i + 1]

        if not dev or not src_ip:
            raise ValueError("no_route_info")

        addr_out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", dev],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

        cidr = ""
        for token in addr_out.split():
            if "/" in token and token.count(".") == 3:
                cidr = token
                break

        if not cidr:
            raise ValueError("no_cidr")

        net = ipaddress.ip_interface(cidr).network
        return str(net)
    except Exception:
        return "192.168.0.0/24"


@app.route("/server/generate", methods=["GET", "POST"])
def server_generate():
    detected_lan = detect_local_lan_network()
    error = ""

    if request.method == "POST":
        confirm_text = (request.form.get("confirm_text") or "").strip()
        lan_network = (request.form.get("lan_network") or "").strip()

        if confirm_text != "GENERATE":
            error = 'Zur Bestätigung muss exakt <code>GENERATE</code> eingegeben werden.'
        elif not lan_network:
            error = 'Bitte ein LAN-Netz im CIDR-Format angeben, z. B. <code>192.168.0.0/24</code>.'
        else:
            try:
                import ipaddress
                lan_network = str(ipaddress.ip_network(lan_network, strict=False))
            except Exception:
                error = 'Ungültiges LAN-Netz. Bitte CIDR-Format verwenden, z. B. <code>192.168.0.0/24</code>.'

        if not error:
            old_server = load_server_settings()
            _, pub, new_conf = generate_server_config()
            backup = f"/etc/wireguard/wg0.conf.before-generate-server.{run_cmd(['date', '+%F-%H%M%S'])}"
            if WG_CONF.exists():
                run_cmd(["cp", str(WG_CONF), backup])
            with WG_CONF.open("w", encoding="utf-8") as f:
                f.write(new_conf)
            save_clients({"clients": []})
            endpoint = old_server["endpoint"] or detect_public_ip()
            save_server_settings({
                "endpoint": endpoint,
                "port": 51820,
                "dns": "10.200.1.1",
                "allowed_ips": f"10.200.1.0/24,{lan_network}",
                "server_vpn_ip": "10.200.0.1",
                "client_network": "10.200.1.0/24",
                "lan_network": lan_network,
            })
            restart_wg()
            body = f"""
<h1>Server neu generiert</h1>
<div class="card">
<p><strong>Neuer Server Public Key:</strong> <code>{html.escape(pub)}</code></p>
<p><strong>Erkanntes/gespeichertes LAN-Netz:</strong> <code>{html.escape(lan_network)}</code></p>
<p><strong>Backup:</strong> <code>{html.escape(backup)}</code></p>
<p><strong>Wichtig:</strong> UDP-Port <code>51820</code> muss im Router auf diesen Server weitergeleitet/freigegeben sein.</p>
<p><strong>Wichtig:</strong> Alle bisherigen Clients sind jetzt ungültig und müssen neu erstellt werden.</p>
<br>
<a class="btn secondary" href="/">Zur Übersicht</a>
<a class="btn secondary" href="/server/settings">Server-Einstellungen</a>
</div>
"""
            return render_template_string(BASE, body=body)

    body = f"""
<h1>Server neu generieren</h1>
<div class="card">
<div style="display:flex; justify-content:space-between; align-items:flex-start; gap:24px; flex-wrap:wrap;">
  <div style="flex:1; min-width:320px;">
    <p><strong>Warnung:</strong> Diese Aktion erzeugt neue Server-Keys, überschreibt <code>/etc/wireguard/wg0.conf</code> und entfernt alle bisherigen Clients.</p>
    <p>Danach funktionieren alle bestehenden Clients nicht mehr.</p>
  </div>
  <div style="width:420px; max-width:100%; border:2px solid #f0c419; color:#f0c419; border-radius:14px; padding:18px; box-sizing:border-box;">
    <strong>Hinweis:</strong> UDP-Port <span style="font-size:1em; text-decoration:underline; font-weight:700;">51820</span> muss im Router auf diesen Server weitergeleitet/freigegeben sein.
  </div>
</div>
{f'<p><strong>Fehler:</strong> {error}</p>' if error else ''}
<form method="post">
<label>Erkanntes LAN-Netz (bei Bedarf anpassen)</label>
<input name="lan_network" value="{html.escape((request.form.get('lan_network') or detected_lan).strip())}" placeholder="192.168.0.0/24">
<br><br>
<label>Zur Bestätigung exakt GENERATE eingeben</label>
<input name="confirm_text" placeholder="GENERATE">
<br><br>
<button class="delete" type="submit">Server jetzt neu generieren</button>
<a class="btn secondary" href="/server/settings">Abbrechen</a>
</form>
</div>
"""
    return render_template_string(BASE, body=body)

@app.route("/lan-targets", methods=["GET", "POST"])
def lan_targets():
    error = ""
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        ip_value = (request.form.get("ip") or "").strip()
        comment = (request.form.get("comment") or "").strip()

        if not name or not ip_value:
            error = "Name und IP/CIDR sind erforderlich."
        else:
            try:
                if "/" in ip_value:
                    ip_value = str(ipaddress.ip_network(ip_value, strict=False))
                else:
                    ip_value = str(ipaddress.ip_address(ip_value))
                data = load_lan_targets()
                if any(t.get("ip") == ip_value for t in data["targets"]):
                    raise ValueError("Dieses LAN-Ziel existiert bereits.")
                data["targets"].append({
                    "id": secrets.token_hex(8),
                    "name": name,
                    "ip": ip_value,
                    "enabled": True,
                    "comment": comment,
                })
                save_lan_targets(data)
                return redirect("/lan-targets", code=303)
            except Exception as e:
                error = str(e)

    rows = ""
    for t in load_lan_targets()["targets"]:
        checked = "checked" if t.get("enabled", True) else ""
        row_style = ' style="opacity:0.45;"' if not t.get("enabled", True) else ""
        rows += f"""
<tr{row_style}>
<td>
<form method="post" action="/lan-targets/toggle">
<input type="hidden" name="target_id" value="{html.escape(t.get('id',''))}">
<input type="checkbox" onchange="this.form.submit()" {checked}>
</form>
</td>
<td>{html.escape(t.get('name',''))}</td>
<td>{html.escape(t.get('ip',''))}</td>
<td>{html.escape(t.get('comment','')) or '-'}</td>
<td class="actions">
<form style="display:inline" method="post" action="/lan-targets/delete" onsubmit="return confirm('LAN-Ziel wirklich löschen?');">
<input type="hidden" name="target_id" value="{html.escape(t.get('id',''))}">
<button class="delete" type="submit">Löschen</button>
</form>
</td>
</tr>
"""

    body = f"""

<div class="card">
<h2>LAN-Ziel hinzufügen</h2>
<form method="post">
<label>Name</label>
<input name="name" placeholder="z. B. NAS">
<label>IP oder Netz</label>
<input name="ip" placeholder="z. B. 192.168.0.10 oder 192.168.0.0/24">
<label>Kommentar (optional)</label>
<input name="comment" placeholder="optional">
<br><br>
<button type="submit">LAN-Ziel speichern</button>
<a class="btn secondary" href="/">Zurück</a>
</form>
{"<p>" + html.escape(error) + "</p>" if error else ""}
</div>

<div class="card">
<h2>Freigegebene LAN-Ziele</h2>
<p>Diese Ziele sind für Clients mit Level 3 erreichbar.</p>
<table>
<tr><th>Aktiv</th><th>Name</th><th>IP / Netz</th><th>Kommentar</th><th>Aktionen</th></tr>
{rows if rows else '<tr><td colspan="5">Keine LAN-Ziele vorhanden.</td></tr>'}
</table>
</div>
"""
    return render_template_string(BASE, body=body)

@app.route("/lan-targets/toggle", methods=["POST"])
def lan_targets_toggle():
    target_id = (request.form.get("target_id") or "").strip()
    data = load_lan_targets()
    for t in data["targets"]:
        if t.get("id") == target_id:
            t["enabled"] = not t.get("enabled", True)
            break
    save_lan_targets(data)
    return redirect("/lan-targets", code=303)

@app.route("/lan-targets/delete", methods=["POST"])
def lan_targets_delete():
    target_id = (request.form.get("target_id") or "").strip()
    data = load_lan_targets()
    data["targets"] = [t for t in data["targets"] if t.get("id") != target_id]
    save_lan_targets(data)
    return redirect("/lan-targets", code=303)


@app.route("/client/new", methods=["GET", "POST"])
def client_new():
    error = ""
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        try:
            level = int(request.form.get("access_level", "3"))
        except Exception:
            level = 3
        if level not in {1, 2, 3}:
            level = 3

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
                    "access_level": level,
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
<label>Freigabe-Level</label>
<select name="access_level">
<option value="1">Level 1</option>
<option value="2">Level 2</option>
<option value="3" selected>Level 3</option>
</select>
<table class="level-info-table compact">
<tr><th>Level</th><th>Freigabe</th></tr>
<tr><td>Level 1</td><td>nur Server</td></tr>
<tr><td>Level 2</td><td>Server + lokale VPN-Clients</td></tr>
<tr><td>Level 3</td><td>Level 2 + ausgewählte LAN-Ziele</td></tr>
</table>
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
                if not priv or not address or not peer_pub:
                    raise ValueError("Konfiguration unvollständig")
                if peer_pub != server["server_public_key"]:
                    raise ValueError("Die importierte Konfiguration gehört nicht zu diesem WireGuard-Server.")
                iface = ipaddress.ip_interface(address)
                ip = str(iface.ip)
                pub = public_from_private(priv)
                level = infer_mode_from_allowed(allowed_ips, server["server_vpn_ip"])
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
                    "access_level": level,
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
    mode_text = client_level_label(c.get("access_level", 3))

    body = f"""
<h1>Client-Konfiguration</h1>
<div class="grid">
  <div class="card">
    <h2>{html.escape(c['name'])}</h2>
    <p><strong>IP:</strong> {html.escape(c['ip'])}/32</p>
    <p><strong>Freigabe:</strong> {html.escape(mode_text)}</p>
    <div class="cfg-qr-wrap">
      <div class="cfg-col">
        <textarea id="cfg" class="config-textarea config-textarea-client" readonly>{html.escape(cfg)}</textarea>
      </div>
      <div class="qr-col">
        <div class="qrbox qrbox-side"><img src="data:image/png;base64,{qr_b64}" alt="WireGuard QR-Code"></div>
      </div>
    </div>
    <br><br>
    <button type="button" onclick="kopiereTextAusTextarea('cfg')">Konfiguration kopieren</button>
    <a class="btn secondary" href="/client/{c['public_key']}/download">Download .conf</a>
    <a class="btn secondary" href="/">Fertig</a>
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



@app.route("/client/level", methods=["POST"])
def update_client_level():
    key = (request.form.get("public_key") or "").strip()
    level_raw = (request.form.get("access_level") or "3").strip()

    if level_raw not in {"1", "2", "3"}:
        return redirect("/", code=303)

    data = load_clients()
    changed = False

    for c in data["clients"]:
        if c["public_key"] == key:
            c["access_level"] = int(level_raw)
            normalize_client_access_profile(c)
            changed = True
            break

    if changed:
        save_clients(data)

    return redirect("/", code=303)

@app.route("/client/toggle", methods=["POST"])
def toggle_client():
    key = request.form["public_key"]

    data = load_clients()

    for c in data["clients"]:
        if c["public_key"] == key:

            enabled = c.get("enabled", True)
            c["enabled"] = not enabled

            if c["enabled"]:
                add_peer(c["public_key"], c["ip"], c["name"])
            else:
                remove_peer(c["public_key"])

            break

    save_clients(data)
    restart_wg()

    return redirect("/")

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
        if LAN_TARGETS_FILE.exists():
            tar.add(LAN_TARGETS_FILE, arcname="lan-targets.json")
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
                lan_targets_src = tmpdir / "lan-targets.json"
                wg_src = tmpdir / "wg0.conf"

                json.loads(clients_src.read_text(encoding="utf-8"))
                json.loads(server_src.read_text(encoding="utf-8"))
                if ddns_src.exists():
                    json.loads(ddns_src.read_text(encoding="utf-8"))
                if lan_targets_src.exists():
                    json.loads(lan_targets_src.read_text(encoding="utf-8"))

                CLIENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
                CLIENTS_FILE.write_text(clients_src.read_text(encoding="utf-8"), encoding="utf-8")
                SERVER_FILE.write_text(server_src.read_text(encoding="utf-8"), encoding="utf-8")
                if ddns_src.exists():
                    DDNS_FILE.write_text(ddns_src.read_text(encoding="utf-8"), encoding="utf-8")
                if lan_targets_src.exists():
                    LAN_TARGETS_FILE.parent.mkdir(parents=True, exist_ok=True)
                    LAN_TARGETS_FILE.write_text(lan_targets_src.read_text(encoding="utf-8"), encoding="utf-8")
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
<li><code>lan-targets.json</code> (optional)</li>
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



app.secret_key = load_or_create_secret_key()
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=SESSION_TIMEOUT_MINUTES)
init_auth_defaults()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
