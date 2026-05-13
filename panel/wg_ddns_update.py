from __future__ import annotations

import ipaddress
import json
import urllib.error
from pathlib import Path
from urllib.request import urlopen

from ddns_providers import perform_provider_update


DDNS_FILE = Path("/opt/wg-panel/ddns.json")
DDNS_SECRET_FILE = Path("/etc/wg-panel-ddns-secrets.json")
STATE_FILE = Path("/var/lib/wg-panel-ddns/state.json")

IPV4_SOURCES = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://ipv4.icanhazip.com",
]
IPV6_SOURCES = [
    "https://api6.ipify.org",
    "https://ipv6.icanhazip.com",
]
TIMEOUT_SECONDS = 5


def load_json(path: Path, default):
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def save_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)


def request_public_ip_version(sources: list[str], version: int) -> str:
    for source in sources:
        try:
            with urlopen(source, timeout=TIMEOUT_SECONDS) as response:
                value = response.read().decode("utf-8").strip()
            ip = ipaddress.ip_address(value)
            if ip.version == version:
                return value
        except (urllib.error.URLError, ValueError, TimeoutError):
            continue
        except Exception:
            continue
    return ""


def main() -> int:
    settings = load_json(DDNS_FILE, {})
    if not settings.get("enabled"):
        print("DDNS deaktiviert.")
        return 0

    provider = str(settings.get("provider", "dynu")).strip().lower() or "dynu"
    hostname = str(settings.get("hostname", "")).strip().lower()
    ip_mode = str(settings.get("ip_mode", "dual")).strip().lower() or "dual"
    if not hostname:
        raise RuntimeError("Hostname fehlt.")

    secrets = load_json(DDNS_SECRET_FILE, {"username": "", "password": ""})
    username = str(secrets.get("username", "")).strip()
    password = str(secrets.get("password", ""))

    ipv4 = request_public_ip_version(IPV4_SOURCES, 4) if ip_mode in ("ipv4", "dual") else ""
    ipv6 = request_public_ip_version(IPV6_SOURCES, 6) if ip_mode in ("ipv6", "dual") else ""
    result = perform_provider_update(provider, hostname, username, password, ip_mode, ipv4, ipv6, TIMEOUT_SECONDS)

    state = {
        "provider": provider,
        "hostname": hostname,
        "ip_mode": ip_mode,
        "last_public_ipv4": ipv4,
        "last_public_ipv6": ipv6,
        "last_result": result,
    }
    save_json(STATE_FILE, state)
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
