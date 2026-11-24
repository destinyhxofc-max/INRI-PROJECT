import base64
import hashlib
import hmac
import ipaddress
import json
import secrets
import threading
import time
from functools import wraps

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import current_app, g, jsonify, redirect, request, url_for

from . import config
from .db import get_db, row, write

SESSION_COOKIES = {"user": "dh4x_u", "reseller": "dh4x_r", "admin": "dh4x_a"}
SESSION_TTL = {"user": 7 * 24 * 3600, "reseller": 12 * 3600, "admin": 8 * 3600}
CSRF_COOKIE = "dh4x_csrf"
DEVICE_COOKIE = "dh4x_dev"


def now():
    return int(time.time())


def sha256(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32
    )
    return "scrypt$16384$8$1${}${}".format(
        base64.b64encode(salt).decode(), base64.b64encode(digest).decode()
    )


def verify_password(password, stored):
    try:
        scheme, n, r, p, salt_b64, digest_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def client_ip():
    cached = getattr(g, "_client_ip", None)
    if cached:
        return cached
    ip = ""
    if config.trusted_proxy():
        for header in ("CF-Connecting-IP", "X-Real-IP"):
            candidate = request.headers.get(header, "").strip()
            if candidate:
                ip = candidate
                break
        if not ip:
            forwarded = request.headers.get("X-Forwarded-For", "")
            if forwarded:
                ip = forwarded.split(",")[0].strip()
    if not ip:
        ip = request.remote_addr or ""
    try:
        parsed = ipaddress.ip_address(ip)
        ip = str(parsed)
    except ValueError:
        ip = "0.0.0.0"
    g._client_ip = ip
    return ip


def user_agent():
    return (request.headers.get("User-Agent") or "")[:400]


def _secret():
    return current_app.config["SECRET_KEY"].encode("utf-8")


def sign_text(text):
    return base64.urlsafe_b64encode(
        hmac.new(_secret(), text.encode("utf-8"), hashlib.sha256).digest()
    ).decode().rstrip("=")


def queue_cookie(name, value, max_age, httponly=True):
    pending = getattr(g, "_pending_cookies", None)
    if pending is None:
        pending = {}
        g._pending_cookies = pending
    pending[name] = {
        "value": value,
        "max_age": max_age,
        "httponly": httponly,
        "secure": current_app.config["SESSION_COOKIE_SECURE"],
        "samesite": "Lax",
        "path": "/",
    }


def apply_pending_cookies(response):
    for name, spec in getattr(g, "_pending_cookies", {}).items():
        response.set_cookie(
            name,
            spec["value"],
            max_age=spec["max_age"],
            httponly=spec["httponly"],
            secure=spec["secure"],
            samesite=spec["samesite"],
            path=spec["path"],
        )
    return response


def ensure_csrf():
    token = getattr(g, "_csrf_token", None)
    if token:
        return token
    cookie = request.cookies.get(CSRF_COOKIE, "")
    if "." in cookie:
        candidate, signature = cookie.rsplit(".", 1)
        if candidate and hmac.compare_digest(signature, sign_text(candidate)):
            g._csrf_token = candidate
            return candidate
    token = secrets.token_urlsafe(24)
    queue_cookie(CSRF_COOKIE, token + "." + sign_text(token), 7 * 24 * 3600, httponly=False)
    g._csrf_token = token
    return token


def csrf_valid():
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return True
    cookie = request.cookies.get(CSRF_COOKIE, "")
    if "." not in cookie:
        return False
    cookie_token, signature = cookie.rsplit(".", 1)
    if not cookie_token or not hmac.compare_digest(signature, sign_text(cookie_token)):
        return False
    supplied = request.headers.get("X-CSRF-Token")
    if not supplied and request.form:
        supplied = request.form.get("_csrf")
    if not supplied:
        payload = request.get_json(silent=True) or {}
        supplied = payload.get("_csrf") if isinstance(payload, dict) else None
    return bool(supplied) and hmac.compare_digest(str(supplied), cookie_token)


def create_session(role, subject_id, device_id=""):
    token = secrets.token_urlsafe(32)
    ttl = SESSION_TTL[role]
    timestamp = now()
    write(
        "INSERT INTO sessions (role, subject_id, device_id, token_hash, ip, ua, created_at, last_seen, expires_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            role,
            str(subject_id),
            str(device_id or "")[:128],
            sha256(token),
            client_ip(),
            user_agent(),
            timestamp,
            timestamp,
            timestamp + ttl,
        ),
    )
    queue_cookie(SESSION_COOKIES[role], token, ttl, httponly=True)
    loaded = getattr(g, "_sessions", None)
    if loaded is not None:
        loaded.pop(role, None)
    return token


def current_session(role):
    loaded = getattr(g, "_sessions", None)
    if loaded is None:
        loaded = {}
        g._sessions = loaded
    if role in loaded:
        return loaded[role]
    token = request.cookies.get(SESSION_COOKIES[role], "")
    found = None
    if token and len(token) <= 128:
        found = row(
            "SELECT * FROM sessions WHERE token_hash = ? AND role = ? AND revoked = 0 AND expires_at > ?",
            (sha256(token), role, now()),
        )
        if found:
            if now() - found["last_seen"] > 300:
                write("UPDATE sessions SET last_seen = ? WHERE id = ?", (now(), found["id"]))
            found["subject"] = found["subject_id"]
    loaded[role] = found
    return found


def destroy_session(role):
    token = request.cookies.get(SESSION_COOKIES[role], "")
    if token:
        write(
            "UPDATE sessions SET revoked = 1 WHERE token_hash = ? AND role = ?",
            (sha256(token), role),
        )
    queue_cookie(SESSION_COOKIES[role], "", 0, httponly=True)
    loaded = getattr(g, "_sessions", None)
    if loaded is not None:
        loaded.pop(role, None)


def revoke_sessions_for_ip(ip):
    write(
        "UPDATE sessions SET revoked = 1 WHERE ip = ? AND revoked = 0",
        (ip,),
    )


def pack_token(payload, purpose):
    body = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).decode().rstrip("=")
    signature = base64.urlsafe_b64encode(
        hmac.new(_secret(), f"{purpose}|{body}".encode("utf-8"), hashlib.sha256).digest()
    ).decode().rstrip("=")
    return f"{body}.{signature}"


def unpack_token(token, purpose, max_age=None):
    if not token or token.count(".") != 1 or len(token) > 2048:
        return None
    body, signature = token.split(".", 1)
    expected = base64.urlsafe_b64encode(
        hmac.new(_secret(), f"{purpose}|{body}".encode("utf-8"), hashlib.sha256).digest()
    ).decode().rstrip("=")
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        padded = body + "=" * (-len(body) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    expiry = int(payload.get("exp", 0) or 0)
    if expiry and expiry < now():
        return None
    if max_age is not None and now() - int(payload.get("iat", 0)) > max_age:
        return None
    return payload


def _aes_key():
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"destiny-h4x", info=b"happ-secret")
    return hkdf.derive(_secret())


def encrypt_secret(plain):
    if not plain:
        return ""
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_aes_key()).encrypt(nonce, plain.encode("utf-8"), b"dh4x")
    return base64.urlsafe_b64encode(nonce + ciphertext).decode()


def decrypt_secret(encoded):
    if not encoded:
        return ""
    try:
        raw = base64.urlsafe_b64decode(encoded.encode())
        return AESGCM(_aes_key()).decrypt(raw[:12], raw[12:], b"dh4x").decode("utf-8")
    except Exception:
        return ""


_rate_lock = threading.Lock()
_rate_buckets = {}


def check_rate(scope, limit, window, block_for=0):
    key = f"{scope}:{client_ip()}"
    timestamp = time.time()
    with _rate_lock:
        if len(_rate_buckets) > 4000:
            for stale in [k for k, v in _rate_buckets.items() if timestamp - v["start"] > 3600]:
                _rate_buckets.pop(stale, None)
        state = _rate_buckets.get(key)
        if state and state.get("blocked_until", 0) > timestamp:
            return False
        if not state or timestamp - state["start"] > window:
            state = {"start": timestamp, "hits": [], "blocked_until": 0}
            _rate_buckets[key] = state
        state["hits"] = [hit for hit in state["hits"] if timestamp - hit < window]
        state["hits"].append(timestamp)
        if len(state["hits"]) > limit:
            if block_for:
                state["blocked_until"] = timestamp + block_for
            return False
    return True


def rate_limited(scope, limit, window, block_for=0):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not check_rate(scope, limit, window, block_for):
                if request.path.startswith("/admin/api") or request.path.endswith("/api") or request.is_json:
                    return jsonify(ok=False, error="Too many attempts. Try again later."), 429
                return "Too many attempts. Try again later.", 429
            return view(*args, **kwargs)

        return wrapper

    return decorator


def audit(actor, action, detail=""):
    write(
        "INSERT INTO audit (actor, action, detail, ip, created_at) VALUES (?, ?, ?, ?, ?)",
        (str(actor)[:120], str(action)[:80], str(detail)[:500], client_ip(), now()),
    )
    total = get_db().execute("SELECT COUNT(*) FROM audit").fetchone()[0]
    if total > 20000:
        write(
            "DELETE FROM audit WHERE id IN (SELECT id FROM audit ORDER BY id ASC LIMIT ?)",
            (total - 15000,),
        )


def require_admin(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        session_data = current_session("admin")
        if not session_data:
            if request.path.startswith("/admin/api"):
                return jsonify(ok=False, error="Authentication required."), 401
            return redirect(url_for("admin.login"))
        return view(*args, **kwargs)

    return wrapper


def require_reseller(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        session_data = current_session("reseller")
        if not session_data:
            if request.path.startswith("/reseller/api"):
                return jsonify(ok=False, error="Authentication required."), 401
            return redirect(url_for("reseller.login"))
        return view(*args, **kwargs)

    return wrapper


def require_user(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        session_data = current_session("user")
        if not session_data:
            if request.path.startswith("/api"):
                return jsonify(ok=False, error="Activation required."), 401
            return redirect(url_for("public.index"))
        return view(*args, **kwargs)

    return wrapper
