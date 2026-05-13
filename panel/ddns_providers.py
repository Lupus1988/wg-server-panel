from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


PROVIDER_SPECS = {
    "dynu": {
        "label": "Dynu",
        "hostname_placeholder": "z. B. meinhost.freeddns.org",
        "username_label": "Dynu Benutzername",
        "password_label": "Dynu Passwort",
        "show_username": True,
        "require_username": True,
        "help": "Für Dynu werden Benutzername und Passwort benötigt.",
        "ip_mode_help": {"ipv4": "IPv4 aktualisiert den A-Record.", "ipv6": "IPv6 aktualisiert den AAAA-Record über myipv6.", "dual": "Dual Stack aktualisiert A und AAAA gemeinsam."},
        "create_error": "Bitte alle Dynu-Pflichtfelder ausfüllen.",
        "update_error": "Bitte den Dynu-Benutzernamen eingeben.",
        "supported_ip_modes": ["ipv4", "ipv6", "dual"],
    },
    "duckdns": {
        "label": "DuckDNS",
        "hostname_placeholder": "z. B. meinname oder meinname.duckdns.org",
        "username_label": "Benutzername",
        "password_label": "DuckDNS Token",
        "show_username": False,
        "require_username": False,
        "help": "Für DuckDNS genügt die Subdomain und dein Account-Token. Das Feld Benutzername wird dabei nicht verwendet.",
        "ip_mode_help": {"ipv4": "IPv4 setzt nur die IPv4-Adresse bei DuckDNS.", "ipv6": "IPv6 setzt nur die IPv6-Adresse bei DuckDNS.", "dual": "Dual Stack setzt IPv4 und IPv6 gemeinsam."},
        "create_error": "Bitte den DuckDNS-Token eingeben.",
        "update_error": "Bitte den DuckDNS-Token eingeben.",
        "supported_ip_modes": ["ipv4", "ipv6", "dual"],
    },
    "noip": {
        "label": "No-IP",
        "hostname_placeholder": "z. B. meinname.ddns.net",
        "username_label": "No-IP Benutzername",
        "password_label": "No-IP Passwort / DDNS Key",
        "show_username": True,
        "require_username": True,
        "help": "Für No-IP werden Benutzername und Passwort oder alternativ ein DDNS-Key im Passwort-Feld verwendet.",
        "ip_mode_help": {"ipv4": "Für IPv4 wird der Host per myip mit einer A-Adresse aktualisiert.", "ipv6": "Für IPv6 muss der Host beim Anbieter IPv6-fähig angelegt sein."},
        "create_error": "Bitte die No-IP-Zugangsdaten eingeben.",
        "update_error": "Bitte den No-IP-Benutzernamen eingeben.",
        "supported_ip_modes": ["ipv4", "ipv6"],
    },
    "freedns": {
        "label": "FreeDNS / afraid.org",
        "hostname_placeholder": "z. B. meinhost.mooo.com",
        "username_label": "Benutzername",
        "password_label": "FreeDNS Update-Token oder komplette Update-URL",
        "show_username": False,
        "require_username": False,
        "help": "Für FreeDNS / afraid.org reicht das v2-Update-Token oder direkt die komplette Update-URL aus der Oberfläche.",
        "ip_mode_help": {"ipv4": "IPv4 nutzt den normalen FreeDNS-Sync-Endpunkt.", "ipv6": "IPv6 nutzt den FreeDNS-v6-Sync-Endpunkt."},
        "create_error": "Bitte das FreeDNS-Update-Token oder die Update-URL eingeben.",
        "update_error": "Bitte das FreeDNS-Update-Token oder die Update-URL eingeben.",
        "supported_ip_modes": ["ipv4", "ipv6"],
    },
    "dynv6": {
        "label": "dynv6",
        "hostname_placeholder": "z. B. meinname.dynv6.net",
        "username_label": "Benutzername",
        "password_label": "dynv6 Token",
        "show_username": False,
        "require_username": False,
        "help": "Für dynv6 werden Hostname/Zone und der HTTP-Token verwendet.",
        "ip_mode_help": {"ipv4": "IPv4 aktualisiert die IPv4-Adresse der Zone.", "ipv6": "IPv6 aktualisiert die IPv6-Adresse der Zone.", "dual": "Dual Stack übermittelt IPv4 und IPv6 in einem Lauf."},
        "create_error": "Bitte den dynv6-Token eingeben.",
        "update_error": "Bitte den dynv6-Token eingeben.",
        "supported_ip_modes": ["ipv4", "ipv6", "dual"],
    },
    "desec": {
        "label": "deSEC",
        "hostname_placeholder": "z. B. home.dedyn.io",
        "username_label": "Benutzername",
        "password_label": "deSEC Token",
        "show_username": False,
        "require_username": False,
        "help": "Für deSEC gibst du den vollständigen Hostnamen und einen API-Token an.",
        "ip_mode_help": {"ipv4": "IPv4 aktualisiert den A-Record.", "ipv6": "IPv6 aktualisiert den AAAA-Record.", "dual": "Dual Stack aktualisiert A und AAAA gemeinsam."},
        "create_error": "Bitte den deSEC-Token eingeben.",
        "update_error": "Bitte den deSEC-Token eingeben.",
        "supported_ip_modes": ["ipv4", "ipv6", "dual"],
    },
    "he": {
        "label": "Hurricane Electric Free DNS",
        "hostname_placeholder": "z. B. dyn.example.com",
        "username_label": "Benutzername",
        "password_label": "HE Dynamic DNS Passwort",
        "show_username": False,
        "require_username": False,
        "help": "Für Hurricane Electric wird der vollständige Hostname plus das in dns.he.net generierte Dynamic-DNS-Passwort verwendet.",
        "ip_mode_help": {"ipv4": "IPv4 aktualisiert den A-Record.", "ipv6": "IPv6 aktualisiert den AAAA-Record.", "dual": "Dual Stack führt getrennte Updates für IPv4 und IPv6 aus."},
        "create_error": "Bitte das Hurricane-Electric-Dynamic-DNS-Passwort eingeben.",
        "update_error": "Bitte das Hurricane-Electric-Dynamic-DNS-Passwort eingeben.",
        "supported_ip_modes": ["ipv4", "ipv6", "dual"],
    },
    "cloudns": {
        "label": "ClouDNS",
        "hostname_placeholder": "z. B. home.example.com",
        "username_label": "Benutzername",
        "password_label": "ClouDNS Dynamic URL oder q-Token",
        "show_username": False,
        "require_username": False,
        "help": "Für ClouDNS bitte die Dynamic URL des gewünschten A-Records oder nur den q-Token aus dieser URL eintragen.",
        "ip_mode_help": {"ipv4": "Für IPv4 die Dynamic-URL des A-Records bzw. den IPv4-q-Token verwenden.", "ipv6": "Für IPv6 die Dynamic-URL des AAAA-Records bzw. den IPv6-q-Token verwenden."},
        "create_error": "Bitte die ClouDNS Dynamic URL oder den q-Token eingeben.",
        "update_error": "Bitte die ClouDNS Dynamic URL oder den q-Token eingeben.",
        "supported_ip_modes": ["ipv4", "ipv6"],
    },
    "ydns": {
        "label": "YDNS",
        "hostname_placeholder": "z. B. meinname.ydns.io",
        "username_label": "YDNS Benutzername / API Username",
        "password_label": "YDNS Passwort / API Passwort",
        "show_username": True,
        "require_username": True,
        "help": "Für YDNS werden Hostname sowie die normalen Zugangsdaten oder die separaten API-Zugangsdaten verwendet.",
        "ip_mode_help": {"ipv4": "IPv4 aktualisiert die A-Adresse des Hosts.", "ipv6": "IPv6 aktualisiert die AAAA-Adresse des Hosts."},
        "create_error": "Bitte die YDNS-Zugangsdaten eingeben.",
        "update_error": "Bitte den YDNS-Benutzernamen eingeben.",
        "supported_ip_modes": ["ipv4", "ipv6"],
    },
    "ddnss": {
        "label": "ddnss.de",
        "hostname_placeholder": "z. B. meinname.ddnss.de",
        "username_label": "ddnss.de Benutzername",
        "password_label": "ddnss.de Passwort",
        "show_username": True,
        "require_username": True,
        "help": "Für ddnss.de werden Benutzername, Passwort und Hostname verwendet.",
        "ip_mode_help": {"ipv4": "IPv4 aktualisiert den A-Record.", "ipv6": "IPv6 aktualisiert den AAAA-Record über ip6.", "dual": "Dual Stack aktualisiert IPv4 und IPv6 gemeinsam."},
        "create_error": "Bitte die ddnss.de-Zugangsdaten eingeben.",
        "update_error": "Bitte den ddnss.de-Benutzernamen eingeben.",
        "supported_ip_modes": ["ipv4", "ipv6", "dual"],
    },
    "cloudflare": {
        "label": "Cloudflare",
        "hostname_placeholder": "z. B. home.example.com",
        "username_label": "Cloudflare Zone ID",
        "password_label": "Cloudflare API Token",
        "show_username": True,
        "require_username": True,
        "help": "Für Cloudflare gibst du den vollständigen Hostnamen, die Zone ID und einen API-Token mit DNS Read und DNS Write an.",
        "ip_mode_help": {"ipv4": "IPv4 pflegt nur den A-Record in Cloudflare.", "ipv6": "IPv6 pflegt nur den AAAA-Record in Cloudflare.", "dual": "Dual Stack legt bzw. aktualisiert A und AAAA gemeinsam an."},
        "create_error": "Bitte Cloudflare Zone ID und API-Token eingeben.",
        "update_error": "Bitte die Cloudflare Zone ID eingeben.",
        "supported_ip_modes": ["ipv4", "ipv6", "dual"],
    },
}


def request_text(url: str, timeout_seconds: int, headers: dict[str, str] | None = None) -> str:
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "wg-panel/1.0"})
    with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
        return response.read().decode("utf-8").strip()


def dynu_update(hostname: str, username: str, password: str, ipv4: str, ipv6: str, timeout_seconds: int) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    params = {"hostname": hostname}
    if ipv4:
        params["myip"] = ipv4
    elif ipv6:
        params["myip"] = "no"
    if ipv6:
        params["myipv6"] = ipv6
    elif ipv4:
        params["myipv6"] = "no"
    req = urllib.request.Request(
        f"https://api.dynu.com/nic/update?{urllib.parse.urlencode(params)}",
        headers={"Authorization": f"Basic {token}", "User-Agent": "wg-panel/1.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
        return response.read().decode("utf-8").strip()


def normalize_duckdns_domain(hostname: str) -> str:
    domain = hostname.strip().lower()
    if domain.endswith(".duckdns.org"):
        domain = domain[: -len(".duckdns.org")]
    return domain.strip(".")


def duckdns_update(hostname: str, token: str, ipv4: str, ipv6: str, timeout_seconds: int) -> str:
    domain = normalize_duckdns_domain(hostname)
    if not domain:
        raise ValueError("DuckDNS-Subdomain fehlt.")
    params_map = {"domains": domain, "token": token, "verbose": "true"}
    if ipv4:
        params_map["ip"] = ipv4
    elif ipv6:
        params_map["ip"] = ""
    if ipv6:
        params_map["ipv6"] = ipv6
    body = request_text(f"https://www.duckdns.org/update?{urllib.parse.urlencode(params_map)}", timeout_seconds)
    if not body.startswith("OK"):
        raise RuntimeError(body or "DuckDNS-Update fehlgeschlagen.")
    return body


def noip_update(hostname: str, username: str, password: str, ip_value: str, timeout_seconds: int) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    params = urllib.parse.urlencode({"hostname": hostname, "myip": ip_value})
    req = urllib.request.Request(
        f"https://dynupdate.no-ip.com/nic/update?{params}",
        headers={"Authorization": f"Basic {token}", "User-Agent": "wg-panel/1.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
        body = response.read().decode("utf-8").strip()
    if not body:
        raise RuntimeError("No-IP-Update lieferte keine Antwort.")
    return body


def freedns_update(hostname: str, token_or_url: str, ip_mode: str, timeout_seconds: int) -> str:
    value = token_or_url.strip()
    if not value:
        raise ValueError("FreeDNS-Token fehlt.")
    if value.startswith(("http://", "https://")):
        update_url = value
    else:
        base = "https://v6.sync.afraid.org/u/" if ip_mode == "ipv6" else "https://sync.afraid.org/u/"
        update_url = f"{base}{value.strip('/')}/"
    body = request_text(update_url, timeout_seconds)
    if not body:
        raise RuntimeError("FreeDNS-Update lieferte keine Antwort.")
    return body


def dynv6_update(hostname: str, token: str, ipv4: str, ipv6: str, timeout_seconds: int) -> str:
    params_map = {"zone": hostname, "token": token}
    if ipv4:
        params_map["ipv4"] = ipv4
    if ipv6:
        params_map["ipv6"] = ipv6
    body = request_text(f"https://dynv6.com/api/update?{urllib.parse.urlencode(params_map)}", timeout_seconds)
    if not body:
        raise RuntimeError("dynv6-Update lieferte keine Antwort.")
    return body


def desec_update(hostname: str, token: str, ipv4: str, ipv6: str, timeout_seconds: int) -> str:
    params_map = {"hostname": hostname, "myipv4": ipv4 if ipv4 else "", "myipv6": ipv6 if ipv6 else "preserve"}
    req = urllib.request.Request(
        f"https://update.dedyn.io/?{urllib.parse.urlencode(params_map)}",
        headers={"User-Agent": "wg-panel/1.0", "Authorization": f"Token {token}"},
    )
    with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
        body = response.read().decode("utf-8").strip()
    if not body:
        raise RuntimeError("deSEC-Update lieferte keine Antwort.")
    return body


def he_update(hostname: str, password: str, ipv4: str, ipv6: str, timeout_seconds: int) -> str:
    responses = []
    for ip_value in [ipv4, ipv6]:
        if not ip_value:
            continue
        params = urllib.parse.urlencode({"hostname": hostname, "password": password, "myip": ip_value})
        body = request_text(f"https://dyn.dns.he.net/nic/update?{params}", timeout_seconds)
        if not body:
            raise RuntimeError("Hurricane-Electric-Update lieferte keine Antwort.")
        responses.append(body)
    return " | ".join(responses)


def cloudns_update(hostname: str, token_or_url: str, ip_mode: str, timeout_seconds: int) -> str:
    value = token_or_url.strip()
    if not value:
        raise ValueError("ClouDNS Dynamic URL fehlt.")
    if value.startswith(("http://", "https://")):
        update_url = value
    else:
        base = "https://ipv6.cloudns.net/api/dynamicURL/?q=" if ip_mode == "ipv6" else "https://ipv4.cloudns.net/api/dynamicURL/?q="
        update_url = f"{base}{urllib.parse.quote(value, safe='')}"
    body = request_text(update_url, timeout_seconds)
    if not body:
        raise RuntimeError("ClouDNS-Update lieferte keine Antwort.")
    return body


def ydns_update(hostname: str, username: str, password: str, ip_value: str, timeout_seconds: int) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    params = urllib.parse.urlencode({"host": hostname, "ip": ip_value})
    req = urllib.request.Request(
        f"https://ydns.io/api/v1/update/?{params}",
        headers={"Authorization": f"Basic {token}", "User-Agent": "wg-panel/1.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
        body = response.read().decode("utf-8").strip()
    if not body:
        raise RuntimeError("YDNS-Update lieferte keine Antwort.")
    return body


def ddnss_update(hostname: str, username: str, password: str, ipv4: str, ipv6: str, timeout_seconds: int) -> str:
    params_map = {"user": username, "pwd": password, "host": hostname}
    if ipv4:
        params_map["ip"] = ipv4
    if ipv6:
        params_map["ip6"] = ipv6
    body = request_text(f"https://www.ddnss.de/upd.php?{urllib.parse.urlencode(params_map)}", timeout_seconds)
    if not body:
        raise RuntimeError("ddnss.de-Update lieferte keine Antwort.")
    return body


def cloudflare_api_request(method: str, path: str, api_token: str, timeout_seconds: int, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    body = None
    headers = {"Authorization": f"Bearer {api_token}", "User-Agent": "wg-panel/1.0", "Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"https://api.cloudflare.com/client/v4{path}", data=body, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
        data = json.loads(response.read().decode("utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError("Cloudflare-Antwort ungültig.")
    if not data.get("success", False):
        errors = data.get("errors") or []
        if errors and isinstance(errors, list) and isinstance(errors[0], dict) and errors[0].get("message"):
            raise RuntimeError(str(errors[0]["message"]))
        raise RuntimeError("Cloudflare-API-Fehler.")
    return data


def cloudflare_upsert_record(hostname: str, zone_id: str, api_token: str, record_type: str, content: str, timeout_seconds: int) -> str:
    encoded_name = urllib.parse.quote(hostname, safe="")
    records = cloudflare_api_request("GET", f"/zones/{zone_id}/dns_records?type={record_type}&name={encoded_name}", api_token, timeout_seconds).get("result") or []
    if records:
        record = records[0]
        record_id = str(record.get("id", "")).strip()
        if not record_id:
            raise RuntimeError("Cloudflare-Record-ID fehlt.")
        cloudflare_api_request(
            "PATCH",
            f"/zones/{zone_id}/dns_records/{record_id}",
            api_token,
            timeout_seconds,
            payload={"type": record_type, "name": hostname, "content": content, "ttl": int(record.get("ttl", 120) or 120), "proxied": bool(record.get("proxied", False))},
        )
        return f"updated {record_type} {hostname} -> {content}"
    cloudflare_api_request(
        "POST",
        f"/zones/{zone_id}/dns_records",
        api_token,
        timeout_seconds,
        payload={"type": record_type, "name": hostname, "content": content, "ttl": 120, "proxied": False},
    )
    return f"created {record_type} {hostname} -> {content}"


def cloudflare_update(hostname: str, zone_id: str, api_token: str, ipv4: str, ipv6: str, timeout_seconds: int) -> str:
    responses = []
    if ipv4:
        responses.append(cloudflare_upsert_record(hostname, zone_id, api_token, "A", ipv4, timeout_seconds))
    if ipv6:
        responses.append(cloudflare_upsert_record(hostname, zone_id, api_token, "AAAA", ipv6, timeout_seconds))
    return " | ".join(responses)


def perform_provider_update(provider: str, hostname: str, username: str, password: str, ip_mode: str, ipv4: str, ipv6: str, timeout_seconds: int) -> str:
    if provider == "dynu":
        return dynu_update(hostname, username, password, ipv4, ipv6, timeout_seconds)
    if provider == "duckdns":
        return duckdns_update(hostname, password, ipv4, ipv6, timeout_seconds)
    if provider == "noip":
        return noip_update(hostname, username, password, ipv4 or ipv6, timeout_seconds)
    if provider == "freedns":
        return freedns_update(hostname, password, ip_mode, timeout_seconds)
    if provider == "dynv6":
        return dynv6_update(hostname, password, ipv4, ipv6, timeout_seconds)
    if provider == "desec":
        return desec_update(hostname, password, ipv4, ipv6, timeout_seconds)
    if provider == "he":
        return he_update(hostname, password, ipv4, ipv6, timeout_seconds)
    if provider == "cloudns":
        return cloudns_update(hostname, password, ip_mode, timeout_seconds)
    if provider == "ydns":
        return ydns_update(hostname, username, password, ipv4 or ipv6, timeout_seconds)
    if provider == "ddnss":
        return ddnss_update(hostname, username, password, ipv4, ipv6, timeout_seconds)
    if provider == "cloudflare":
        return cloudflare_update(hostname, username, password, ipv4, ipv6, timeout_seconds)
    raise RuntimeError(f"Provider nicht unterstützt: {provider}")
