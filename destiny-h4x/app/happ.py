import base64
import hashlib
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from flask import request

from . import config
from .security import now, pack_token, unpack_token
from .services import (
    env_locked,
    format_duration,
    get_setting,
    key_remaining,
    key_state,
    maintenance_state,
)

CRYPTO_API = "https://crypto.happ.su/api-v2.php"
_crypto_cache = {}
_crypto_lock = threading.Lock()


def proxy_config():
    return {
        "protocol": (get_setting("happ.protocol", "vless") or "vless").lower(),
        "host": (get_setting("happ.host", "") or "").strip(),
        "port": str(get_setting("happ.port", "443") or "443").strip(),
        "uuid": get_setting("happ.uuid", "") or "",
        "password": get_setting("happ.password", "") or "",
        "sni": (get_setting("happ.sni", "") or "").strip(),
        "path": (get_setting("happ.path", "/") or "/").strip(),
        "network": (get_setting("happ.network", "ws") or "ws").lower(),
        "security": (get_setting("happ.security", "tls") or "tls").lower(),
        "flow": (get_setting("happ.flow", "") or "").strip(),
        "fp": (get_setting("happ.fp", "chrome") or "").strip(),
        "remark": (get_setting("happ.remark", "DESTINY H4X") or "DESTINY H4X").strip(),
        "ss_method": (get_setting("happ.ss_method", "aes-256-gcm") or "aes-256-gcm").strip(),
        "alpn": (get_setting("happ.alpn", "") or "").strip(),
        "pbk": (get_setting("happ.pbk", "") or "").strip(),
        "sid": (get_setting("happ.sid", "") or "").strip(),
        "crypto_link": get_setting("happ.crypto_link", "1") == "1",
    }


def admin_config():
    conf = proxy_config()
    masked = dict(conf)
    masked["uuid_set"] = bool(conf["uuid"])
    masked["password_set"] = bool(conf["password"])
    masked["uuid"] = "••••••••" if conf["uuid"] else ""
    masked["password"] = "••••••••" if conf["password"] else ""
    masked["locked"] = {
        "protocol": env_locked("happ.protocol"),
        "host": env_locked("happ.host"),
        "port": env_locked("happ.port"),
        "uuid": env_locked("happ.uuid"),
        "password": env_locked("happ.password"),
        "sni": env_locked("happ.sni"),
        "path": env_locked("happ.path"),
        "network": env_locked("happ.network"),
        "security": env_locked("happ.security"),
        "flow": env_locked("happ.flow"),
        "fp": env_locked("happ.fp"),
        "remark": env_locked("happ.remark"),
        "crypto_link": env_locked("happ.crypto_link"),
        "ss_method": env_locked("happ.ss_method"),
        "alpn": env_locked("happ.alpn"),
        "pbk": env_locked("happ.pbk"),
        "sid": env_locked("happ.sid"),
    }
    masked["base_url"] = public_base_url()
    masked["base_url_locked"] = env_locked("site.public_base_url")
    return masked


def validate_config(conf):
    errors = []
    protocol = conf.get("protocol", "vless")
    if protocol not in {"vless", "trojan", "ss"}:
        errors.append("Protocol must be vless, trojan or ss.")
    host = (conf.get("host") or "").strip()
    if not host:
        errors.append("Server host is required.")
    elif any(char.isspace() for char in host) or "/" in host:
        errors.append("Server host must be a domain or IP address.")
    try:
        port = int(conf.get("port") or 0)
        if not 1 <= port <= 65535:
            errors.append("Port must be between 1 and 65535.")
    except ValueError:
        errors.append("Port must be a number.")
    network = (conf.get("network") or "").lower()
    if network not in {"ws", "tcp", "grpc"}:
        errors.append("Network must be ws, tcp or grpc.")
    security = (conf.get("security") or "").lower()
    if security not in {"tls", "reality", "none"}:
        errors.append("Security must be tls, reality or none.")
    path = conf.get("path") or "/"
    if not path.startswith("/"):
        errors.append("Path must start with /.")
    if protocol == "vless":
        try:
            uuid.UUID(conf.get("uuid") or "")
        except (ValueError, TypeError):
            errors.append("A valid VLESS UUID is required.")
        if security == "reality" and not (conf.get("pbk") or "").strip():
            errors.append("Reality public key (pbk) is required for reality security.")
    if protocol in {"trojan", "ss"} and not (conf.get("password") or "").strip():
        errors.append("Password is required for this protocol.")
    return errors


def _remark(base, remaining):
    text = base or "DESTINY H4X"
    if remaining is not None:
        text = f"{text} | {format_duration(remaining)} left"
    return text


def build_uri(conf, remark=None, remaining=None):
    protocol = conf.get("protocol", "vless")
    host = conf["host"]
    port = int(conf.get("port") or 443)
    path = conf.get("path") or "/"
    network = (conf.get("network") or "ws").lower()
    security = (conf.get("security") or "tls").lower()
    sni = conf.get("sni") or host
    label = _remark(remark or conf.get("remark") or "DESTINY H4X", remaining)
    fragment = urllib.parse.quote(label, safe="")

    if protocol == "vless":
        params = [("encryption", "none"), ("security", security), ("type", network)]
        if security in {"tls", "reality"}:
            params.append(("sni", sni))
            if conf.get("fp"):
                params.append(("fp", conf["fp"]))
            if conf.get("alpn"):
                params.append(("alpn", conf["alpn"]))
        if security == "reality":
            params.append(("pbk", conf.get("pbk", "")))
            if conf.get("sid"):
                params.append(("sid", conf["sid"]))
            if conf.get("flow"):
                params.append(("flow", conf["flow"]))
        if network == "ws":
            params.append(("host", host))
            params.append(("path", path))
        elif network == "grpc":
            params.append(("serviceName", path.strip("/") or "destiny"))
        else:
            params.append(("headerType", "none"))
        query = urllib.parse.urlencode(params, quote_via=urllib.parse.quote, safe="")
        return f"vless://{conf['uuid']}@{host}:{port}?{query}#{fragment}"

    if protocol == "trojan":
        params = [("security", security), ("type", network)]
        if security in {"tls", "reality"}:
            params.append(("sni", sni))
            if conf.get("fp"):
                params.append(("fp", conf["fp"]))
            if conf.get("alpn"):
                params.append(("alpn", conf["alpn"]))
        if network == "ws":
            params.append(("host", host))
            params.append(("path", path))
        elif network == "grpc":
            params.append(("serviceName", path.strip("/") or "destiny"))
        query = urllib.parse.urlencode(params, quote_via=urllib.parse.quote, safe="")
        return f"trojan://{urllib.parse.quote(conf['password'], safe='')}@{host}:{port}?{query}#{fragment}"

    method = conf.get("ss_method") or "aes-256-gcm"
    credentials = base64.urlsafe_b64encode(
        f"{method}:{conf.get('password', '')}".encode("utf-8")
    ).decode().rstrip("=")
    return f"ss://{credentials}@{host}:{port}#{fragment}"


def public_base_url():
    configured = (get_setting("site.public_base_url", "") or "").strip().rstrip("/")
    if configured:
        return configured
    base = request.url_root.rstrip("/")
    if request.headers.get("X-Forwarded-Proto", "").lower() == "https" and base.startswith("http://"):
        base = "https://" + base[len("http://"):]
    return base


def subscription_token(key_id, device_id):
    timestamp = now()
    return pack_token(
        {"k": int(key_id), "d": device_id, "iat": timestamp, "exp": timestamp + 1800},
        "sub",
    )


def read_subscription_token(token):
    payload = unpack_token(token, "sub")
    if not payload:
        return None
    try:
        payload["k"] = int(payload["k"])
    except (KeyError, TypeError, ValueError):
        return None
    if not payload.get("d"):
        return None
    return payload


def subscription_body(key):
    conf = proxy_config()
    remaining = key_remaining(key)
    uri = build_uri(conf, conf.get("remark"), remaining)
    return base64.b64encode(uri.encode("utf-8")).decode()


def subscription_headers(key):
    conf = proxy_config()
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-store",
        "profile-title": conf.get("remark") or "DESTINY H4X",
        "profile-update-interval": "1",
        "subscription-userinfo": f"upload=0; download=0; total=0; expire={int(key.get('expires_at') or 0)}",
        "profile-web-page-url": public_base_url(),
    }
    support = (get_setting("site.support_url", "") or "").strip()
    if support:
        headers["support-url"] = support
    return headers


def crypto_link(subscription_url):
    cache_key = hashlib.sha256(subscription_url.encode()).hexdigest()
    with _crypto_lock:
        cached = _crypto_cache.get(cache_key)
        if cached and cached[0] > time.time():
            return cached[1]
    payload = json.dumps({"url": subscription_url}).encode("utf-8")
    request_obj = urllib.request.Request(
        CRYPTO_API,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "DestinyH4X/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request_obj, timeout=8) as response:
            data = json.loads(response.read(65536).decode("utf-8", "replace"))
        link = data.get("encrypted_link") or ""
        if not link.startswith("happ://crypt"):
            return ""
    except (urllib.error.URLError, TimeoutError, ValueError, OSError, json.JSONDecodeError):
        return ""
    with _crypto_lock:
        _crypto_cache[cache_key] = (time.time() + 1200, link)
    return link


def connect_payload(key, device_id):
    maintenance = maintenance_state()
    if maintenance["on"]:
        return None, "maintenance"
    if validate_config(proxy_config()):
        return None, "config"
    state = key_state(key)
    if state != "active":
        return None, state
    if key.get("expires_at") and int(key["expires_at"]) <= now():
        return None, "expired"
    token = subscription_token(key["id"], device_id)
    sub_url = f"{public_base_url()}/sub/{token}"
    encrypted = ""
    if proxy_config().get("crypto_link"):
        encrypted = crypto_link(sub_url)
    return {
        "subscription_url": sub_url,
        "deeplink": encrypted,
        "encrypted": bool(encrypted),
        "remaining": key_remaining(key),
        "expires_at": int(key.get("expires_at") or 0),
    }, None


def test_payload():
    conf = proxy_config()
    errors = validate_config(conf)
    sample = dict(conf)
    if not sample.get("host"):
        sample["host"] = "server.example.com"
    if not sample.get("uuid") or errors:
        sample["uuid"] = "00000000-0000-4000-8000-000000000000"
    if not sample.get("password"):
        sample["password"] = "test-password"
    try:
        uri = build_uri(sample, "DESTINY H4X TEST", 600)
    except Exception as exc:  # pragma: no cover - defensive, surfaced to admin
        uri = ""
        errors.append(f"Could not build URI: {exc}")
    return {
        "ok": not errors,
        "errors": errors,
        "uri": uri,
        "target": get_setting("test.target_url", "https://cp.cloudflare.com/generate_204"),
        "crypto_enabled": conf.get("crypto_link"),
    }
