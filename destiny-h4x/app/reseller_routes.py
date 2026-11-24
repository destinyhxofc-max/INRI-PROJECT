from pathlib import Path

from flask import (
    Blueprint,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)

from . import security, services

reseller_bp = Blueprint("reseller", __name__)


def logged_reseller():
    data = security.current_session("reseller")
    if not data:
        return None, None
    try:
        reseller_id = int(data["subject_id"])
    except (TypeError, ValueError):
        return data, None
    return data, services.reseller_by_id(reseller_id)


@reseller_bp.get("/reseller")
def login():
    if security.current_session("reseller"):
        return redirect(url_for("reseller.dashboard"))
    return render_template(
        "reseller_login.html",
        disabled=request.args.get("disabled") == "1",
        maintenance=services.maintenance_state(),
    )


@reseller_bp.post("/reseller/login")
def login_post():
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    reseller = services.reseller_by_username(username)
    if (
        not reseller
        or not reseller["active"]
        or not security.verify_password(password, reseller["pass_hash"])
    ):
        if not security.check_rate("reseller_login_fail", 6, 300, 600):
            return render_template(
                "reseller_login.html",
                error="Too many attempts. Try again later.",
                maintenance=services.maintenance_state(),
            ), 429
        security.audit("reseller", "login_failed", username)
        return render_template(
            "reseller_login.html",
            error="Wrong username or password.",
            maintenance=services.maintenance_state(),
        ), 401
    security.create_session("reseller", reseller["id"])
    security.audit(f"reseller:{reseller['username']}", "login", "")
    return redirect(url_for("reseller.dashboard", welcome="1"))


@reseller_bp.get("/reseller/dashboard")
@security.require_reseller
def dashboard():
    data, reseller = logged_reseller()
    if not reseller:
        security.destroy_session("reseller")
        return redirect(url_for("reseller.login"))
    if not reseller["active"]:
        security.destroy_session("reseller")
        return redirect(url_for("reseller.login", disabled="1"))
    plans = services.list_plans(active_only=True)
    return render_template(
        "reseller.html",
        reseller=reseller,
        plans=plans,
        keys=services.reseller_keys(reseller["id"]),
        purchases=services.reseller_purchases(reseller["id"]),
        requests=[item for item in services.list_restock_requests() if item["reseller_id"] == reseller["id"]],
        maintenance=services.maintenance_state(),
        welcome=request.args.get("welcome") == "1",
        photo_url=url_for("reseller.photo", reseller_id=reseller["id"]) if reseller["photo"] else "",
    )


@reseller_bp.get("/reseller/photo/<int:reseller_id>")
def photo(reseller_id):
    admin = security.current_session("admin")
    data, reseller = logged_reseller()
    if not admin and (not data or int(data["subject_id"]) != reseller_id):
        return "Not found", 404
    target = services.reseller_by_id(reseller_id)
    if not target or not target["photo"]:
        return "Not found", 404
    filename = Path(target["photo"]).name
    return send_from_directory(
        current_app.config["UPLOAD_DIR"],
        filename,
        max_age=60,
        mimetype="image/jpeg" if filename.lower().endswith(".jpg") else None,
    )


@reseller_bp.post("/reseller/logout")
def logout():
    security.destroy_session("reseller")
    return redirect(url_for("reseller.login"))


@reseller_bp.post("/reseller/buy")
@security.require_reseller
@security.rate_limited("reseller_buy", 30, 60)
def buy():
    data, reseller = logged_reseller()
    if not reseller or not reseller["active"]:
        return jsonify(ok=False, error="Account is disabled."), 403
    payload = request.get_json(silent=True) or {}
    try:
        plan_id = int(payload.get("plan_id") or 0)
    except (TypeError, ValueError):
        return jsonify(ok=False, error="Choose a plan."), 400
    result, error = services.buy_plan(reseller["id"], plan_id)
    if error:
        return jsonify(ok=False, error=error), 409
    security.audit(f"reseller:{reseller['username']}", "buy", f"{result['code']} plan {plan_id}")
    return jsonify(
        ok=True,
        code=result["code"],
        plan=result["plan"]["name"],
        balance_cents=services.reseller_by_id(reseller["id"])["balance_cents"],
    )


@reseller_bp.post("/reseller/restock")
@security.require_reseller
def restock():
    data, reseller = logged_reseller()
    if not reseller or not reseller["active"]:
        return jsonify(ok=False, error="Account is disabled."), 403
    payload = request.get_json(silent=True) or {}
    try:
        plan_id = int(payload.get("plan_id") or 0)
    except (TypeError, ValueError):
        return jsonify(ok=False, error="Choose a plan."), 400
    ok, error = services.request_restock(reseller["id"], plan_id, payload.get("note", ""))
    if not ok:
        return jsonify(ok=False, error=error), 409
    security.audit(f"reseller:{reseller['username']}", "restock_request", f"plan {plan_id}")
    return jsonify(ok=True)


@reseller_bp.get("/reseller/api/state")
@security.require_reseller
def state_api():
    data, reseller = logged_reseller()
    if not reseller:
        return jsonify(ok=False, error="session"), 401
    return jsonify(
        ok=True,
        balance_cents=reseller["balance_cents"],
        balance_label=services.format_money(reseller["balance_cents"]),
        active=bool(reseller["active"]),
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
            }
            for plan in services.list_plans(active_only=True)
        ],
        keys=[
            {
                "code": key["code"],
                "state": key["state"],
                "remaining": key["remaining"],
                "remaining_label": key["remaining_label"],
                "plan": key.get("plan_name") or "",
                "kind": key["kind"],
                "expires_at": key["expires_at"],
                "created_at": key["created_at"],
            }
            for key in services.reseller_keys(reseller["id"])
        ],
        purchases=[
            {
                "plan": item.get("plan_name") or "Deleted plan",
                "code": item.get("code") or "",
                "price_label": services.format_money(item["unit_price_cents"]),
                "created_at": item["created_at"],
            }
            for item in services.reseller_purchases(reseller["id"])
        ],
        requests=[
            {
                "id": item["id"],
                "plan": item["plan_name"],
                "status": item["status"],
                "created_at": item["created_at"],
            }
            for item in services.list_restock_requests()
            if item["reseller_id"] == reseller["id"]
        ],
        maintenance=services.maintenance_state()["on"],
        server_time=security.now(),
    )
