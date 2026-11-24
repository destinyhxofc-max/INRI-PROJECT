import hmac
import secrets
from decimal import Decimal, InvalidOperation
from pathlib import Path

from flask import (
    Blueprint,
    Response,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from . import geoip, happ, security, services

admin_bp = Blueprint("admin", __name__)


def fail(message, status=400, **extra):
    payload = {"ok": False, "error": message}
    payload.update(extra)
    return jsonify(payload), status


def parse_money(raw):
    if raw is None or str(raw).strip() == "":
        return None
    try:
        amount = Decimal(str(raw).replace(",", "").strip())
    except InvalidOperation:
        return None
    if amount < 0:
        return None
    try:
        return int((amount * 100).quantize(Decimal("1")))
    except InvalidOperation:
        return None


def read_photo(upload):
    if not upload or not upload.filename:
        return None, None, None
    data = upload.read()
    if len(data) > 2 * 1024 * 1024:
        return None, None, "Picture must be 2MB or smaller."
    if data.startswith(b"\xff\xd8\xff"):
        extension = ".jpg"
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        extension = ".png"
    elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        extension = ".webp"
    else:
        return None, None, "Picture must be a JPG, PNG or WEBP image."
    return data, extension, None


def save_photo(data, extension, reseller_id):
    filename = f"reseller_{reseller_id}_{secrets.token_hex(8)}{extension}"
    target = Path(current_app.config["UPLOAD_DIR"]) / filename
    target.write_bytes(data)
    return filename


def remove_photo(filename):
    if not filename:
        return
    target = Path(current_app.config["UPLOAD_DIR"]) / Path(filename).name
    try:
        target.unlink(missing_ok=True)
    except OSError:
        pass


def session_label(item):
    try:
        subject_id = int(item["subject_id"])
    except (TypeError, ValueError):
        return item["role"].title()
    if item["role"] == "user":
        key = services.key_by_id(subject_id)
        return f"Key {key['code']}" if key else "Key (deleted)"
    if item["role"] == "reseller":
        reseller = services.reseller_by_id(subject_id)
        return f"Reseller {reseller['username']}" if reseller else "Reseller (deleted)"
    return "Admin"


@admin_bp.get("/admin")
def login():
    if security.current_session("admin"):
        return redirect(url_for("admin.dashboard"))
    return render_template("admin_login.html")


@admin_bp.post("/admin/login")
def login_post():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    expected_user = current_app.config["ADMIN_USERNAME"]
    user_ok = hmac.compare_digest(username.encode(), expected_user.encode())
    pass_ok = security.verify_password(password, current_app.config["ADMIN_PASSWORD_HASH"])
    if not (user_ok and pass_ok):
        if not security.check_rate("admin_login_fail", 5, 300, 900):
            return render_template("admin_login.html", error="Too many attempts. Try again later."), 429
        security.audit("admin", "login_failed", username[:60])
        return render_template("admin_login.html", error="Wrong username or password."), 401
    security.create_session("admin", "admin")
    security.audit("admin", "login", "")
    return redirect(url_for("admin.dashboard"))


@admin_bp.get("/admin/dashboard")
@security.require_admin
def dashboard():
    return render_template("admin.html")


@admin_bp.post("/admin/logout")
def logout():
    security.destroy_session("admin")
    return redirect(url_for("admin.login"))


@admin_bp.get("/admin/api/overview")
@security.require_admin
def overview():
    stats = services.stats()
    config_errors = happ.validate_config(happ.proxy_config())
    locked = sum(1 for value in happ.admin_config()["locked"].values() if value)
    return jsonify(
        ok=True,
        stats=stats,
        maintenance=services.maintenance_state(),
        geo_mode=services.geo_mode(),
        geo_rules=len(services.list_geo_rules()),
        config_errors=config_errors,
        locked_fields=locked,
        audit=[
            {
                "actor": item["actor"],
                "action": item["action"],
                "detail": item["detail"],
                "ip": item["ip"],
                "created_at": item["created_at"],
            }
            for item in services.recent_audit(30)
        ],
        admin=current_app.config["ADMIN_USERNAME"],
        ip=security.client_ip(),
        base_url=happ.public_base_url(),
        server_time=security.now(),
        open_requests=stats["requests"],
        revenue_label=services.format_money(stats["revenue"]),
    )


# ---------------------------------------------------------------- keys


@admin_bp.get("/admin/api/keys")
@security.require_admin
def keys_list():
    search = request.args.get("q", "").strip()
    return jsonify(
        ok=True,
        keys=[
            {
                "id": key["id"],
                "code": key["code"],
                "kind": key["kind"],
                "state": key["state"],
                "remaining_label": key["remaining_label"],
                "remaining": key["remaining"],
                "plan": key.get("plan_name") or "",
                "reseller": key.get("reseller_username") or "",
                "created_by": key["created_by"],
                "created_at": key["created_at"],
                "expires_at": key["expires_at"],
                "device_count": key["device_count"],
                "note": key["note"],
                "status": key["status"],
            }
            for key in services.list_keys(search)
        ],
    )


@admin_bp.post("/admin/api/keys")
@security.require_admin
def keys_create():
    payload = request.get_json(silent=True) or {}
    seconds = services.unit_seconds(payload.get("value", 0), payload.get("unit", "minutes"))
    if not seconds:
        return fail("Choose a valid duration (10 seconds to 10 years).")
    kind = payload.get("kind") if payload.get("kind") in {"single", "unlimited"} else "single"
    try:
        count = int(payload.get("count") or 1)
    except (TypeError, ValueError):
        return fail("Key count is invalid.")
    plan_id = payload.get("plan_id")
    try:
        plan_id = int(plan_id) if plan_id else None
    except (TypeError, ValueError):
        return fail("Plan is invalid.")
    if plan_id and not services.plan_by_id(plan_id):
        return fail("Plan not found.")
    codes = services.create_keys(
        count,
        seconds,
        kind,
        plan_id=plan_id,
        created_by="admin",
        note=str(payload.get("note") or "")[:200],
    )
    security.audit("admin", "keys_create", f"{len(codes)} x {seconds}s {kind}")
    return jsonify(ok=True, codes=codes, count=len(codes))


@admin_bp.post("/admin/api/keys/<int:key_id>/revoke")
@security.require_admin
def key_revoke(key_id):
    key = services.key_by_id(key_id)
    if not key:
        return fail("Key not found.", 404)
    services.revoke_key(key_id)
    security.audit("admin", "key_revoke", key["code"])
    return jsonify(ok=True)


@admin_bp.delete("/admin/api/keys/<int:key_id>")
@security.require_admin
def key_delete(key_id):
    key = services.key_by_id(key_id)
    if not key:
        return fail("Key not found.", 404)
    services.delete_key(key_id)
    security.audit("admin", "key_delete", key["code"])
    return jsonify(ok=True)


@admin_bp.get("/admin/api/keys/export")
@security.require_admin
def keys_export():
    keys = services.list_keys("", 1000)
    body = "\n".join(
        f"{key['code']}\t{key['state']}\t{key['kind']}\t{key['remaining_label']}\t{key.get('plan_name') or ''}"
        for key in keys
    )
    security.audit("admin", "keys_export", str(len(keys)))
    return Response(
        body + ("\n" if body else ""),
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=destiny-h4x-keys.txt"},
    )


@admin_bp.post("/admin/api/test-key")
@security.require_admin
def test_key():
    codes = services.create_keys(1, 600, "single", created_by="admin", note="Test config")
    security.audit("admin", "test_key", codes[0])
    return jsonify(ok=True, code=codes[0], seconds=600, activate_url=url_for("public.index", _external=False))


# ---------------------------------------------------------------- plans


@admin_bp.get("/admin/api/plans")
@security.require_admin
def plans_list():
    return jsonify(
        ok=True,
        plans=[
            {
                "id": plan["id"],
                "name": plan["name"],
                "seconds": plan["seconds"],
                "duration": services.format_duration(plan["seconds"]),
                "price_cents": plan["price_cents"],
                "price_label": services.format_money(plan["price_cents"]),
                "stock": plan["stock"],
                "sold": plan["sold"],
                "active": bool(plan["active"]),
            }
            for plan in services.list_plans()
        ],
    )


@admin_bp.post("/admin/api/plans")
@security.require_admin
def plan_create():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name") or "").strip()
    seconds = services.unit_seconds(payload.get("value", 0), payload.get("unit", "minutes"))
    price = parse_money(payload.get("price"))
    try:
        stock = int(payload.get("stock") or 0)
    except (TypeError, ValueError):
        return fail("Stock is invalid.")
    if not name:
        return fail("Plan name is required.")
    if not seconds:
        return fail("Choose a valid duration.")
    if price is None:
        return fail("Price is invalid.")
    plan_id = services.create_plan(name, seconds, price, stock)
    security.audit("admin", "plan_create", f"{name} {seconds}s {price}c stock {stock}")
    return jsonify(ok=True, id=plan_id)


@admin_bp.patch("/admin/api/plans/<int:plan_id>")
@security.require_admin
def plan_update(plan_id):
    plan = services.plan_by_id(plan_id)
    if not plan:
        return fail("Plan not found.", 404)
    payload = request.get_json(silent=True) or {}
    fields = {}
    if "name" in payload:
        name = str(payload["name"]).strip()
        if not name:
            return fail("Plan name cannot be empty.")
        fields["name"] = name
    if "price" in payload:
        price = parse_money(payload["price"])
        if price is None:
            return fail("Price is invalid.")
        fields["price_cents"] = price
    if "stock" in payload:
        try:
            fields["stock"] = max(0, int(payload["stock"]))
        except (TypeError, ValueError):
            return fail("Stock is invalid.")
    if "active" in payload:
        fields["active"] = 1 if payload["active"] else 0
    if "value" in payload or "unit" in payload:
        seconds = services.unit_seconds(
            payload.get("value", 0), payload.get("unit", "minutes")
        )
        if not seconds:
            return fail("Choose a valid duration.")
        fields["seconds"] = seconds
    services.update_plan(plan_id, fields)
    security.audit("admin", "plan_update", str(plan_id))
    return jsonify(ok=True)


@admin_bp.post("/admin/api/plans/<int:plan_id>/stock")
@security.require_admin
def plan_stock(plan_id):
    plan = services.plan_by_id(plan_id)
    if not plan:
        return fail("Plan not found.", 404)
    payload = request.get_json(silent=True) or {}
    try:
        amount = int(payload.get("amount") or 0)
    except (TypeError, ValueError):
        return fail("Stock amount is invalid.")
    if amount == 0:
        return fail("Stock amount cannot be zero.")
    services.add_stock(plan_id, amount)
    security.audit("admin", "plan_stock", f"{plan_id} {amount:+d}")
    return jsonify(ok=True, stock=services.plan_by_id(plan_id)["stock"])


@admin_bp.delete("/admin/api/plans/<int:plan_id>")
@security.require_admin
def plan_delete(plan_id):
    services.delete_plan(plan_id)
    security.audit("admin", "plan_delete", str(plan_id))
    return jsonify(ok=True)


# ---------------------------------------------------------------- resellers


@admin_bp.get("/admin/api/resellers")
@security.require_admin
def resellers_list():
    return jsonify(
        ok=True,
        resellers=[
            {
                "id": item["id"],
                "username": item["username"],
                "first_name": item["first_name"],
                "last_name": item["last_name"],
                "age": item["age"],
                "balance_cents": item["balance_cents"],
                "balance_label": services.format_money(item["balance_cents"]),
                "spent_label": services.format_money(item["spent"]),
                "key_count": item["key_count"],
                "active": bool(item["active"]),
                "photo": bool(item["photo"]),
                "created_at": item["created_at"],
            }
            for item in services.list_resellers()
        ],
    )


@admin_bp.post("/admin/api/resellers")
@security.require_admin
def reseller_create():
    form = request.form
    balance = parse_money(form.get("balance", "0"))
    if balance is None:
        return fail("Balance is invalid.")
    photo_data, photo_ext, error = read_photo(request.files.get("photo"))
    if error:
        return fail(error)
    age = form.get("age", "").strip()
    try:
        age = int(age) if age else None
        if age is not None and not 13 <= age <= 120:
            return fail("Age must be between 13 and 120.")
    except ValueError:
        return fail("Age is invalid.")
    reseller_id, error = services.create_reseller(
        form.get("username", ""),
        form.get("password", ""),
        form.get("first_name", ""),
        form.get("last_name", ""),
        age,
        balance,
    )
    if error:
        return fail(error)
    if photo_data:
        filename = save_photo(photo_data, photo_ext, reseller_id)
        services.update_reseller(reseller_id, {"photo": filename})
    security.audit("admin", "reseller_create", form.get("username", ""))
    return jsonify(ok=True, id=reseller_id)


@admin_bp.patch("/admin/api/resellers/<int:reseller_id>")
@security.require_admin
def reseller_update(reseller_id):
    reseller = services.reseller_by_id(reseller_id)
    if not reseller:
        return fail("Reseller not found.", 404)
    payload = request.get_json(silent=True) or {}
    fields = {}
    for key in ("first_name", "last_name"):
        if key in payload:
            text = str(payload[key]).strip()
            if not text:
                return fail("Name fields cannot be empty.")
            fields[key] = text[:60]
    if "age" in payload:
        try:
            age = int(payload["age"])
            if not 13 <= age <= 120:
                return fail("Age must be between 13 and 120.")
            fields["age"] = age
        except (TypeError, ValueError):
            return fail("Age is invalid.")
    if "active" in payload:
        fields["active"] = 1 if payload["active"] else 0
    if "balance_delta" in payload:
        delta = parse_money(payload["balance_delta"])
        if not delta:
            return fail("Enter a balance amount to add or remove.")
        signed = -delta if payload.get("subtract") else delta
        new_balance = reseller["balance_cents"] + signed
        if new_balance < 0:
            return fail("Balance cannot go below zero.")
        fields["balance_cents"] = new_balance
    if "set_balance" in payload:
        balance = parse_money(payload["set_balance"])
        if balance is None:
            return fail("Balance is invalid.")
        fields["balance_cents"] = balance
    services.update_reseller(reseller_id, fields)
    if payload.get("password"):
        password = str(payload["password"])
        if len(password) < 6:
            return fail("Password must be at least 6 characters.")
        services.set_reseller_password(reseller_id, password)
    security.audit("admin", "reseller_update", reseller["username"])
    return jsonify(ok=True)


@admin_bp.delete("/admin/api/resellers/<int:reseller_id>")
@security.require_admin
def reseller_delete(reseller_id):
    reseller = services.reseller_by_id(reseller_id)
    if not reseller:
        return fail("Reseller not found.", 404)
    remove_photo(reseller["photo"])
    services.delete_reseller(reseller_id)
    security.audit("admin", "reseller_delete", reseller["username"])
    return jsonify(ok=True)


# ---------------------------------------------------------------- bans


@admin_bp.get("/admin/api/bans")
@security.require_admin
def bans_list():
    return jsonify(
        ok=True,
        bans=[
            {
                "ip": item["ip"],
                "reason": item["reason"],
                "created_at": item["created_at"],
                "expires_at": item["expires_at"],
            }
            for item in services.list_bans()
        ],
        hwid_bans=[
            {
                "hwid": item["hwid"],
                "reason": item["reason"],
                "created_at": item["created_at"],
                "expires_at": item["expires_at"],
            }
            for item in services.list_hwid_bans()
        ],
    )


@admin_bp.post("/admin/api/bans")
@security.require_admin
def ban_create():
    payload = request.get_json(silent=True) or {}
    ip = services.valid_ip(payload.get("ip", "")) if str(payload.get("ip") or "").strip() else ""
    hwid = services.clean_hwid(payload.get("hwid", ""))
    if not ip and not hwid:
        return fail("Enter an IP address or a device ID.")
    seconds = None
    if payload.get("amount"):
        seconds = services.unit_seconds(payload.get("amount"), payload.get("unit", "hours"))
        if not seconds:
            return fail("Choose a valid ban duration.")
    if ip:
        services.ban_ip(ip, payload.get("reason", ""), seconds)
        security.revoke_sessions_for_ip(ip)
        security.audit("admin", "ban", ip)
    if hwid:
        services.ban_hwid(hwid, payload.get("reason", ""), seconds)
        services.revoke_sessions_for_hwid(hwid)
        security.audit("admin", "ban_hwid", hwid)
    return jsonify(ok=True, ip=ip, hwid=hwid)


@admin_bp.delete("/admin/api/bans/<ip>")
@security.require_admin
def ban_delete(ip):
    normalized = services.valid_ip(ip)
    if not normalized:
        return fail("Invalid IP.")
    services.unban_ip(normalized)
    security.audit("admin", "unban", normalized)
    return jsonify(ok=True)


@admin_bp.delete("/admin/api/hwid-bans/<hwid>")
@security.require_admin
def hwid_ban_delete(hwid):
    cleaned = services.clean_hwid(hwid)
    if not cleaned:
        return fail("Invalid device ID.")
    services.unban_hwid(cleaned)
    security.audit("admin", "unban_hwid", cleaned)
    return jsonify(ok=True)


@admin_bp.get("/admin/api/sentinel")
@security.require_admin
def sentinel_state():
    return jsonify(ok=True, enabled=services.get_setting("sentinel.enabled", "1") == "1")


@admin_bp.post("/admin/api/sentinel")
@security.require_admin
def sentinel_update():
    payload = request.get_json(silent=True) or {}
    enabled = bool(payload.get("enabled"))
    services.set_setting("sentinel.enabled", "1" if enabled else "0")
    security.audit("admin", "sentinel", "on" if enabled else "off")
    return jsonify(ok=True, enabled=enabled)


# ---------------------------------------------------------------- geo


@admin_bp.get("/admin/api/geo")
@security.require_admin
def geo_state():
    code = (request.args.get("country") or "").upper()
    return jsonify(
        ok=True,
        mode=services.geo_mode(),
        fail_open=services.get_setting("geo.fail_open", "1") == "1",
        note=services.get_setting("geo.locked_note", "State locked"),
        rules=services.list_geo_rules(),
        countries=geoip.countries(),
        selected=code,
        states=geoip.states_for(code) if code else [],
    )


@admin_bp.post("/admin/api/geo/rules")
@security.require_admin
def geo_add():
    payload = request.get_json(silent=True) or {}
    code = str(payload.get("country_code") or "").strip().upper()
    if len(code) != 2:
        return fail("Choose a country.")
    region = str(payload.get("region") or "").strip()
    region_key = geoip.normalize_region(region) if region else ""
    ok, error = services.add_geo_rule(code, geoip.country_name(code), region_key, region[:120])
    if not ok:
        return fail(error, 409)
    security.audit("admin", "geo_lock", f"{code}/{region or 'ALL'}")
    return jsonify(ok=True)


@admin_bp.delete("/admin/api/geo/rules/<int:rule_id>")
@security.require_admin
def geo_remove(rule_id):
    services.remove_geo_rule(rule_id)
    security.audit("admin", "geo_unlock", str(rule_id))
    return jsonify(ok=True)


@admin_bp.post("/admin/api/geo/mode")
@security.require_admin
def geo_mode_set():
    payload = request.get_json(silent=True) or {}
    services.set_geo_mode(payload.get("mode", "block"))
    if "fail_open" in payload:
        services.set_setting("geo.fail_open", "1" if payload["fail_open"] else "0")
    if "note" in payload and str(payload["note"]).strip():
        services.set_setting("geo.locked_note", str(payload["note"]).strip()[:80])
    security.audit("admin", "geo_mode", payload.get("mode", "block"))
    return jsonify(ok=True)


@admin_bp.post("/admin/api/geo/lookup")
@security.require_admin
def geo_lookup():
    payload = request.get_json(silent=True) or {}
    ip = services.valid_ip(payload.get("ip") or security.client_ip())
    if not ip:
        return fail("Enter a valid IP address.")
    info = geoip.lookup(ip)
    rule = geoip.find_rule(info.get("country_code"), info.get("region"))
    return jsonify(ok=True, info=info, locked=rule is not None, rule=rule)


# ---------------------------------------------------------------- maintenance


@admin_bp.post("/admin/api/maintenance")
@security.require_admin
def maintenance_set():
    payload = request.get_json(silent=True) or {}
    state = services.set_maintenance(bool(payload.get("on")))
    security.audit("admin", "maintenance", "on" if state["on"] else "off")
    return jsonify(ok=True, maintenance=state)


# ---------------------------------------------------------------- config


@admin_bp.get("/admin/api/config")
@security.require_admin
def config_get():
    conf = happ.admin_config()
    conf["site"] = {
        "buy_url": services.get_setting("site.buy_url", ""),
        "support_url": services.get_setting("site.support_url", ""),
        "currency": services.get_setting("site.currency", "NGN"),
        "public_base_url": services.get_setting("site.public_base_url", ""),
        "test_target": services.get_setting("test.target_url", ""),
        "geo_note": services.get_setting("geo.locked_note", "State locked"),
        "fail_open": services.get_setting("geo.fail_open", "1") == "1",
    }
    conf["site_locked"] = {
        "buy_url": services.env_locked("site.buy_url"),
        "support_url": services.env_locked("site.support_url"),
        "currency": services.env_locked("site.currency"),
        "public_base_url": services.env_locked("site.public_base_url"),
    }
    conf["test"] = happ.test_payload()
    return jsonify(ok=True, config=conf)


@admin_bp.post("/admin/api/config")
@security.require_admin
def config_save():
    payload = request.get_json(silent=True) or {}
    proxy_fields = {
        "protocol": "happ.protocol",
        "host": "happ.host",
        "port": "happ.port",
        "uuid": "happ.uuid",
        "password": "happ.password",
        "sni": "happ.sni",
        "path": "happ.path",
        "network": "happ.network",
        "security": "happ.security",
        "flow": "happ.flow",
        "fp": "happ.fp",
        "remark": "happ.remark",
        "ss_method": "happ.ss_method",
        "alpn": "happ.alpn",
        "pbk": "happ.pbk",
        "sid": "happ.sid",
    }
    changed = []
    for field, setting in proxy_fields.items():
        if field not in payload or services.env_locked(setting):
            continue
        value = payload[field]
        if value is None:
            continue
        value = str(value).strip()
        if field in {"uuid", "password"}:
            if not value or value.startswith("••"):
                continue
        services.set_setting(setting, value)
        changed.append(field)
    if "crypto_link" in payload and not services.env_locked("happ.crypto_link"):
        services.set_setting("happ.crypto_link", "1" if payload["crypto_link"] else "0")
        changed.append("crypto_link")
    site_fields = {
        "buy_url": "site.buy_url",
        "support_url": "site.support_url",
        "currency": "site.currency",
        "public_base_url": "site.public_base_url",
        "test_target": "test.target_url",
        "geo_note": "geo.locked_note",
    }
    for field, setting in site_fields.items():
        if field not in payload or services.env_locked(setting):
            continue
        value = str(payload[field] or "").strip()
        if setting == "site.public_base_url":
            value = value.rstrip("/")
            if value and not value.startswith(("http://", "https://")):
                return fail("Public base URL must start with http:// or https://")
        services.set_setting(setting, value[:300])
        changed.append(field)
    if "fail_open" in payload:
        services.set_setting("geo.fail_open", "1" if payload["fail_open"] else "0")
        changed.append("fail_open")
    errors = happ.validate_config(happ.proxy_config())
    security.audit("admin", "config_save", ", ".join(changed)[:300])
    return jsonify(ok=True, changed=changed, errors=errors, test=happ.test_payload())


@admin_bp.post("/admin/api/config/test")
@security.require_admin
def config_test():
    return jsonify(ok=True, test=happ.test_payload())


# ---------------------------------------------------------------- requests


@admin_bp.get("/admin/api/requests")
@security.require_admin
def requests_list():
    return jsonify(
        ok=True,
        requests=[
            {
                "id": item["id"],
                "plan": item["plan_name"],
                "username": item["username"],
                "name": f"{item['first_name']} {item['last_name']}",
                "note": item["note"],
                "status": item["status"],
                "created_at": item["created_at"],
            }
            for item in services.list_restock_requests()
        ],
    )


@admin_bp.post("/admin/api/requests/<int:request_id>/close")
@security.require_admin
def request_close(request_id):
    payload = request.get_json(silent=True) or {}
    status = payload.get("status") if payload.get("status") in {"done", "rejected"} else "done"
    services.close_restock_request(request_id, status)
    security.audit("admin", "restock_close", f"{request_id} {status}")
    return jsonify(ok=True)


@admin_bp.delete("/admin/api/requests/<int:request_id>")
@security.require_admin
def request_delete(request_id):
    services.close_restock_request(request_id, "deleted")
    return jsonify(ok=True)


# ---------------------------------------------------------------- sessions / audit


@admin_bp.get("/admin/api/sessions")
@security.require_admin
def sessions_list():
    return jsonify(
        ok=True,
        sessions=[
            {
                "id": item["id"],
                "role": item["role"],
                "label": session_label(item),
                "ip": item["ip"],
                "ua": item["ua"],
                "created_at": item["created_at"],
                "last_seen": item["last_seen"],
                "expires_at": item["expires_at"],
            }
            for item in services.list_sessions()
        ],
    )


@admin_bp.delete("/admin/api/sessions/<int:session_id>")
@security.require_admin
def session_kill(session_id):
    services.kill_session(session_id)
    security.audit("admin", "session_kill", str(session_id))
    return jsonify(ok=True)


@admin_bp.get("/admin/api/audit")
@security.require_admin
def audit_list():
    return jsonify(
        ok=True,
        audit=[
            {
                "actor": item["actor"],
                "action": item["action"],
                "detail": item["detail"],
                "ip": item["ip"],
                "created_at": item["created_at"],
            }
            for item in services.recent_audit(200)
        ],
    )
