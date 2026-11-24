import ipaddress
import re

from flask import Response, current_app, request

from . import security, services

HONEYPOT_PATHS = (
    "/wp-login.php",
    "/wp-admin",
    "/wp-content",
    "/xmlrpc.php",
    "/phpmyadmin",
    "/pma",
    "/admin.php",
    "/administrator",
    "/setup.php",
    "/install.php",
    "/shell.php",
    "/cmd.php",
    "/c99.php",
    "/config.php",
    "/hnap1",
    "/boaform",
    "/manager/html",
    "/actuator",
    "/server-status",
    "/solr",
    "/console",
    "/owa",
    "/autodiscover",
)

SUSPICIOUS_PATHS = HONEYPOT_PATHS + (
    "/.env",
    "/.git",
    "/.svn",
    "/.aws",
    "/.ds_store",
    "/vendor/phpunit",
    "/docker-compose.yml",
    "/backup",
    "/db.sql",
    "/dump.sql",
    "/etc/passwd",
    "/cgi-bin",
    "/geoserver",
)

DECOY_PATHS = {"/wp-login.php", "/wp-admin", "/admin.php", "/administrator"}

SCANNER_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|zgrab|nuclei|gobuster|dirbuster|ffuf|wfuzz|"
    r"acunetix|nessus|openvas|metasploit|hydra|havij|commix|xsstrike|joomscan|wpscan)",
    re.I,
)

ATTACK_PAYLOAD = re.compile(
    r"(union\s+select|information_schema|sleep\s*\(\s*\d|benchmark\s*\(|load_file\s*\(|"
    r"\.\./\.\.|%2e%2e%2f|%2e%2e/|/etc/passwd|/bin/(?:ba)?sh|base64_decode\s*\(|"
    r"<script|onerror\s*=|onload\s*=|javascript:|document\.cookie|"
    r"eval\s*\(|system\s*\(|exec\s*\(|passthru\s*\(|shell_exec\s*\(|"
    r"\$\{jndi:|gopher://|dict://|wget\s+http|curl\s+http|nc\s+-e|"
    r"(?:;|\||&&)\s*(?:cat|ls|rm|sh|bash|python|perl)\b)",
    re.I,
)

HWID_RE = re.compile(r"^[A-Za-z0-9_.:-]{8,128}$")
HWID_HEADERS = ("X-Device-Id", "X-HWID", "X-Hwid", "X-Device", "Device-Id")
HWID_KEYS = ("device", "device_id", "deviceid", "hwid", "hw_id")
BODY_LIMIT = 16384
FLOOD_LIMIT = 600
FLOOD_WINDOW = 60

DECOY_LOGIN = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Log In</title></head>
<body>
<h1>Log In</h1>
<form method="post" action="">
<p><label>Username or Email Address<br><input name="log" type="text" autocomplete="username"></label></p>
<p><label>Password<br><input name="pwd" type="password" autocomplete="current-password"></label></p>
<p><button type="submit">Log In</button></p>
</form>
</body></html>"""


def _is_private(ip):
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved


def _spared(ip):
    if not ip or _is_private(ip):
        return True
    if security.current_session("admin"):
        return True
    allowed = current_app.config.get("ADMIN_ALLOWED_IPS") or []
    if allowed:
        from .geoip import allowlisted

        if allowlisted(ip, allowed):
            return True
    return False


def _body():
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return ""
    if (request.content_length or 0) > BODY_LIMIT:
        return ""
    ctype = (request.content_type or "").lower()
    if not any(part in ctype for part in ("application/json", "text/", "application/x-www-form-urlencoded")):
        return ""
    try:
        return request.get_data(cache=True, as_text=True, parse_form_data=False)[:BODY_LIMIT]
    except (OSError, ValueError):
        return ""


def _capture_hwid(body):
    for header in HWID_HEADERS:
        value = (request.headers.get(header) or "").strip()
        if HWID_RE.match(value):
            return value
    data = None
    if request.is_json:
        payload = request.get_json(silent=True)
        data = payload if isinstance(payload, dict) else None
    elif request.form:
        data = request.form
    if data:
        for key in HWID_KEYS:
            value = str(data.get(key) or "").strip()
            if HWID_RE.match(value):
                return value
    if body:
        match = re.search(r'"(?:device|device_id|hwid|hw_id)"\s*:\s*"([A-Za-z0-9_.:-]{8,128})"', body)
        if match:
            return match.group(1)
    return ""


def _judge(kind, detail, hwid, path):
    ip = security.client_ip()
    captured = hwid if HWID_RE.match(hwid or "") else ""
    spared = _spared(ip)
    if not spared:
        services.ban_ip(ip, f"SHERIFF {kind}: {detail}"[:300])
        security.revoke_sessions_for_ip(ip)
        if captured:
            services.ban_hwid(captured, f"SHERIFF {kind}: {detail}"[:300])
            services.revoke_sessions_for_hwid(captured)
    security.audit(
        "sheriff",
        f"probe_{kind}",
        f"{ip} {path} {detail} hwid={captured or '-'}{' (spared)' if spared else ''}"[:500],
    )


def screen():
    if services.get_setting("sentinel.enabled", "1") != "1":
        return None
    path = "/" + (request.path or "/").strip("/").lower()
    ua = security.user_agent()
    body = _body()
    parsed = path
    if request.query_string:
        parsed += "?" + request.query_string.decode("utf-8", "replace")
    honeypot = next(
        (
            item
            for item in SUSPICIOUS_PATHS
            if parsed == item or parsed.startswith(item + "?") or parsed.startswith(item + "/")
        ),
        None,
    )
    bad_ua = SCANNER_UA.search(ua or "")
    attack = ATTACK_PAYLOAD.search(parsed) or (body and ATTACK_PAYLOAD.search(body))
    if not (honeypot or bad_ua or attack):
        if path.startswith("/static/"):
            return None
        if security.check_rate("sheriff", FLOOD_LIMIT, FLOOD_WINDOW):
            return None
        _judge("flood", f">{FLOOD_LIMIT}/{FLOOD_WINDOW}s", "", path)
        return Response("Too many requests.", status=429, mimetype="text/plain")
    hwid = _capture_hwid(body)
    if honeypot:
        _judge("honeypot", honeypot, hwid, path)
        if request.method == "POST":
            return Response("Wrong username or password.", status=401, mimetype="text/html")
        if honeypot in DECOY_PATHS:
            return Response(DECOY_LOGIN, status=200, mimetype="text/html")
        return Response("Not found", status=404, mimetype="text/plain")
    if bad_ua:
        _judge("scanner", (bad_ua.group(1) or "")[:40], hwid, path)
        return Response("Blocked", status=403, mimetype="text/plain")
    _judge("payload", (attack.group(0) or "")[:60], hwid, path)
    return Response("Blocked", status=403, mimetype="text/plain")
