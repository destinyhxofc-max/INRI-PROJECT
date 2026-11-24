import json
import os
import threading
import time
import unicodedata
import urllib.error
import urllib.request
from pathlib import Path

from . import config
from .db import row, rows, write
from .security import client_ip

_DATA = None
_DATA_LOCK = threading.Lock()
CACHE_SECONDS = 86400
REGION_SUFFIXES = (" state", " province", " region", " federal capital territory", " fct")


def normalize_region(name):
    if not name:
        return ""
    text = unicodedata.normalize("NFKD", str(name)).encode("ascii", "ignore").decode()
    text = " ".join(text.lower().replace("-", " ").replace("_", " ").split())
    for suffix in REGION_SUFFIXES:
        if text.endswith(suffix):
            text = text[: -len(suffix)].strip()
    return text


def _geo_data():
    global _DATA
    if _DATA is None:
        with _DATA_LOCK:
            if _DATA is None:
                path = Path(__file__).resolve().parent / "data" / "geo.json"
                _DATA = json.loads(path.read_text(encoding="utf-8"))
    return _DATA


def countries():
    return _geo_data()["countries"]


def states_for(code):
    return _geo_data()["states"].get((code or "").upper(), [])


def country_name(code):
    code = (code or "").upper()
    for item in countries():
        if item["code"] == code:
            return item["name"]
    return code


def is_local_ip(ip):
    if not ip:
        return True
    if ip.startswith(("127.", "10.", "192.168.", "::1", "fc", "fd")):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return True
        except (ValueError, IndexError):
            return False
    return ip in {"0.0.0.0", ""}


def _fetch_json(url, timeout=4):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "DestinyH4X/1.0 (+geo-check)", "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", "replace"))


def _lookup_remote(ip):
    try:
        data = _fetch_json(f"https://ipwho.is/{ip}")
        if data.get("success") and data.get("country_code"):
            return {
                "ok": True,
                "country_code": data["country_code"].upper(),
                "country_name": data.get("country") or country_name(data["country_code"]),
                "region": data.get("region") or "",
            }
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        pass
    try:
        data = _fetch_json(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName"
        )
        if data.get("status") == "success" and data.get("countryCode"):
            return {
                "ok": True,
                "country_code": data["countryCode"].upper(),
                "country_name": data.get("country") or country_name(data["countryCode"]),
                "region": data.get("regionName") or "",
            }
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        pass
    return {"ok": False, "country_code": "", "country_name": "", "region": ""}


def lookup(ip=None):
    ip = ip or client_ip()
    override_country = os.environ.get("GEO_OVERRIDE_COUNTRY", "").strip()
    if override_country:
        code = override_country.upper()
        if len(code) != 2:
            for item in countries():
                if item["name"].lower() == override_country.lower():
                    code = item["code"]
                    break
        return {
            "ok": True,
            "ip": ip,
            "country_code": code,
            "country_name": country_name(code),
            "region": os.environ.get("GEO_OVERRIDE_REGION", "").strip(),
            "source": "override",
        }
    if config.env_bool("ALLOW_GEO_TEST"):
        from flask import request

        test_country = (request.headers.get("X-Test-Country") or "").strip().upper()
        if test_country:
            return {
                "ok": True,
                "ip": ip,
                "country_code": test_country,
                "country_name": country_name(test_country),
                "region": (request.headers.get("X-Test-Region") or "").strip(),
                "source": "test-header",
            }
    if is_local_ip(ip):
        return {
            "ok": False,
            "ip": ip,
            "country_code": "",
            "country_name": "",
            "region": "",
            "source": "local",
        }
    cached = row("SELECT * FROM geo_cache WHERE ip = ?", (ip,))
    if cached and time.time() - cached["ts"] < CACHE_SECONDS:
        return {
            "ok": bool(cached["ok"]),
            "ip": ip,
            "country_code": cached["country_code"] or "",
            "country_name": cached["country_name"] or "",
            "region": cached["region"] or "",
            "source": "cache",
        }
    result = _lookup_remote(ip)
    write(
        "INSERT INTO geo_cache (ip, ok, country_code, country_name, region, ts) VALUES (?, ?, ?, ?, ?, ?)"
        " ON CONFLICT(ip) DO UPDATE SET ok = excluded.ok, country_code = excluded.country_code,"
        " country_name = excluded.country_name, region = excluded.region, ts = excluded.ts",
        (
            ip,
            1 if result["ok"] else 0,
            result["country_code"],
            result["country_name"],
            result["region"],
            int(time.time()),
        ),
    )
    result["ip"] = ip
    result["source"] = "live"
    return result


def find_rule(country_code, region):
    code = (country_code or "").upper()
    region_key = normalize_region(region)
    if not code:
        return None
    candidates = rows("SELECT * FROM geo_rules WHERE country_code = ?", (code,))
    for rule in candidates:
        if not rule["region_key"]:
            return rule
        if rule["region_key"] == region_key:
            return rule
    return None


def evaluation(ip=None):
    from .services import get_setting

    info = lookup(ip)
    rules = rows("SELECT * FROM geo_rules")
    mode = get_setting("geo.mode", "block")
    if not info["ok"]:
        fail_open = get_setting("geo.fail_open", "1") == "1"
        return {
            "known": False,
            "locked": False if fail_open else bool(rules) and mode == "block",
            "mode": mode,
            "info": info,
            "rule": None,
        }
    rule = find_rule(info["country_code"], info["region"])
    if mode == "allow" and rules:
        locked = rule is None
    else:
        locked = rule is not None
    return {
        "known": True,
        "locked": locked,
        "mode": mode,
        "info": info,
        "rule": rule,
    }


def allowlisted(ip, entries):
    if not entries:
        return True
    import ipaddress

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in entries:
        try:
            if address in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            if entry == ip:
                return True
    return False
