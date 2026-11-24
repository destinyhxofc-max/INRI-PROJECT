import re

from flask import Blueprint, Response, jsonify, redirect, render_template, request, session, url_for

from . import geoip, happ, security, services

public_bp = Blueprint("public", __name__)
DEVICE_RE = re.compile(r"^[A-Za-z0-9_.:-]{8,128}$")
KEY_RE = re.compile(r"^[A-Z0-9-]{6,64}$")
GEO_FRESH_SECONDS = 1800


def geo_payload():
    payload = session.get("geo_ok") or {}
    if payload and security.now() - int(payload.get("ts", 0)) < GEO_FRESH_SECONDS:
        return payload
    return None


def user_key():
    data = security.current_session("user")
    if not data:
        return None, None
    try:
        key_id = int(data["subject_id"])
    except (TypeError, ValueError):
        return data, None
    return data, services.key_by_id(key_id)


@public_bp.get("/")
def index():
    data, key = user_key()
    if data and key and services.key_state(key) in {"active"}:
        return redirect(url_for("public.dashboard"))
    if geo_payload():
        return redirect(url_for("public.activate"))
    return render_template("verify.html")


@public_bp.post("/api/geo/check")
@security.rate_limited("geo", 30, 60)
def geo_check():
    result = geoip.evaluation()
    if result["locked"]:
        session.pop("geo_ok", None)
        security.audit(
            "geo",
            "geo_block",
            f"{result['info'].get('country_code')}/{result['info'].get('region')}",
        )
        return (
            jsonify(
                ok=False,
                locked=True,
                message=services.get_setting("geo.locked_note", "State locked"),
                country=result["info"].get("country_name") or result["info"].get("country_code"),
                region=result["info"].get("region") or "",
            ),
            403,
        )
    session["geo_ok"] = {
        "ts": security.now(),
        "country": result["info"].get("country_code", ""),
        "region": result["info"].get("region", ""),
    }
    session.permanent = False
    return jsonify(ok=True, redirect=url_for("public.activate"))


@public_bp.get("/activate")
def activate():
    if not geo_payload():
        return redirect(url_for("public.index"))
    result = geoip.evaluation()
    if result["locked"]:
        session.pop("geo_ok", None)
        return redirect(url_for("public.index"))
    data, key = user_key()
    if data and key and services.key_state(key) == "active":
        return redirect(url_for("public.dashboard"))
    notice = ""
    reason = request.args.get("reason", "")
    if reason == "expired":
        notice = "This key has expired. Get a new one from DESTINY H4X."
    elif reason == "revoked":
        notice = "This key has been turned off. Contact DESTINY H4X."
    maintenance = services.maintenance_state()
    if maintenance["on"]:
        return render_template("maintenance.html", scope="activation")
    return render_template("activation.html", notice=notice, geo=geo_payload())


@public_bp.post("/api/activate")
@security.rate_limited("activate", 20, 300, 300)
def activate_api():
    if services.maintenance_state()["on"]:
        return (
            jsonify(ok=False, error="maintenance", message="DESTINY H4X is on maintenance. Come back later."),
            503,
        )
    geo = geoip.evaluation()
    if geo["locked"]:
        return (
            jsonify(
                ok=False,
                error="state_locked",
                message=services.get_setting("geo.locked_note", "State locked"),
            ),
            403,
        )
    payload = request.get_json(silent=True) or {}
    raw_key = re.sub(r"\s+", "", str(payload.get("key") or "")).upper()
    device = str(payload.get("device") or "").strip()
    if not KEY_RE.match(raw_key):
        return jsonify(ok=False, error="invalid", message="Enter a valid access key."), 400
    if not DEVICE_RE.match(device):
        return jsonify(ok=False, error="device", message="Device ID is invalid. Reload the page."), 400
    if services.is_hwid_banned(device):
        security.audit("sheriff", "banned_device", device)
        return jsonify(ok=False, error="banned", message="This device is banned."), 403
    reason, key = services.activate_key(raw_key, device, security.client_ip(), security.user_agent())
    if reason != "ok":
        messages = {
            "invalid": "That key is not valid.",
            "revoked": "This key has been turned off. Contact DESTINY H4X.",
            "other_device": "This key is already used on another device.",
            "expired": "This key has expired. Get a new one from DESTINY H4X.",
            "maintenance": "DESTINY H4X is on maintenance. Come back later.",
        }
        status = 409 if reason in {"other_device", "revoked", "expired"} else 400
        return jsonify(ok=False, error=reason, message=messages.get(reason, "Key not accepted.")), status
    security.create_session("user", key["id"], device)
    security.audit(f"key:{key['code']}", "activate", device)
    return jsonify(
        ok=True,
        remaining=services.key_remaining(key),
        expires_at=key["expires_at"],
        redirect=url_for("public.dashboard"),
    )


@public_bp.get("/dashboard")
@security.require_user
def dashboard():
    data, key = user_key()
    if not key:
        security.destroy_session("user")
        return redirect(url_for("public.index"))
    state = services.key_state(key)
    if state not in {"active"}:
        security.destroy_session("user")
        return redirect(url_for("public.activate", reason=state))
    device = data.get("device_id") or ""
    if not services.device_allowed(key, device):
        security.destroy_session("user")
        return redirect(url_for("public.activate", reason="other_device"))
    banned_device = services.is_hwid_banned(device)
    if banned_device:
        security.destroy_session("user")
        return render_template("banned.html", ban=banned_device, ip=security.client_ip()), 403
    return render_template(
        "dashboard.html",
        key=key,
        device=device,
        remaining=services.key_remaining(key),
        maintenance=services.maintenance_state(),
        expires_at=key["expires_at"],
    )


@public_bp.get("/api/status")
@security.require_user
def status_api():
    data, key = user_key()
    if not key:
        security.destroy_session("user")
        return jsonify(ok=False, error="session"), 401
    if services.is_hwid_banned(data.get("device_id")):
        security.destroy_session("user")
        return jsonify(ok=False, error="banned", message="This device is banned."), 403
    state = services.key_state(key)
    return jsonify(
        ok=state == "active",
        state=state,
        remaining=services.key_remaining(key),
        expires_at=key["expires_at"],
        maintenance=services.maintenance_state()["on"],
        server_time=security.now(),
    )


@public_bp.post("/api/connect")
@security.require_user
@security.rate_limited("connect", 20, 300)
def connect_api():
    data, key = user_key()
    if not key:
        security.destroy_session("user")
        return jsonify(ok=False, error="session"), 401
    device = data.get("device_id") or ""
    if not services.device_allowed(key, device):
        security.destroy_session("user")
        return jsonify(ok=False, error="other_device", message="This key belongs to another device."), 403
    if services.is_hwid_banned(device):
        security.destroy_session("user")
        return jsonify(ok=False, error="banned", message="This device is banned."), 403
    payload, error = happ.connect_payload(key, device)
    if error == "maintenance":
        return (
            jsonify(ok=False, error="maintenance", message="DESTINY H4X is on maintenance. Come back later."),
            503,
        )
    if error:
        if error == "config":
            return (
                jsonify(
                    ok=False,
                    error="config",
                    message="The server is not configured yet. Contact support.",
                ),
                503,
            )
        return (
            jsonify(
                ok=False,
                error=error,
                message="This key is no longer active." if error in {"expired", "revoked"} else "Cannot connect.",
            ),
            410,
        )
    security.audit(f"key:{key['code']}", "connect", "happ")
    return jsonify(ok=True, **payload)


@public_bp.post("/api/logout")
def logout():
    security.destroy_session("user")
    return jsonify(ok=True, redirect=url_for("public.index"))


@public_bp.get("/sub/<token>")
@security.rate_limited("sub", 120, 60)
def subscription(token):
    payload = happ.read_subscription_token(token)
    if not payload:
        return Response("invalid", status=403, mimetype="text/plain")
    key = services.key_by_id(payload["k"])
    if not key or not services.device_allowed(key, payload["d"]):
        return Response("invalid", status=403, mimetype="text/plain")
    if services.is_banned(security.client_ip()):
        return Response("banned", status=403, mimetype="text/plain")
    if services.is_hwid_banned(payload["d"]):
        return Response("banned", status=403, mimetype="text/plain")
    state = services.key_state(key)
    headers = happ.subscription_headers(key)
    if state == "revoked":
        return Response("", status=410, headers=headers, content_type="text/plain; charset=utf-8")
    if state == "expired":
        return Response("", status=410, headers=headers, content_type="text/plain; charset=utf-8")
    if services.maintenance_state()["on"]:
        headers["announce"] = "DESTINY H4X ON MAINTENANCE - COME BACK LATER"
        return Response("", status=200, headers=headers, content_type="text/plain; charset=utf-8")
    body = happ.subscription_body(key)
    return Response(body, status=200, headers=headers, content_type="text/plain; charset=utf-8")


@public_bp.get("/healthz")
def healthz():
    return Response("ok", mimetype="text/plain")


@public_bp.get("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /\n", mimetype="text/plain")


@public_bp.get("/banned")
def banned_page():
    return render_template("banned.html", ban=services.is_banned(security.client_ip()), ip=security.client_ip()), 403
