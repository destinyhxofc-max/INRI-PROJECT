import os

from flask import Flask, jsonify, redirect, render_template, request, url_for

from . import config, geoip, security, sentinel, services
from .db import close_db, init_db

BANNED_ENDPOINTS = {"public.healthz", "public.robots", "public.banned_page", "static"}


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=False)
    app.config.update(
        SECRET_KEY=config.get_secret_key(),
        DATABASE_PATH=str(config.DB_PATH),
        UPLOAD_DIR=str(config.UPLOAD_DIR),
        SESSION_COOKIE_NAME="dh4x_sess",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=config.session_secure(),
        MAX_CONTENT_LENGTH=4 * 1024 * 1024,
        HSTS=config.session_secure(),
        ADMIN_ALLOWED_IPS=config.admin_allowed_ips(),
    )
    if test_config:
        app.config.update(test_config)

    config.INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    admin_username, admin_password = config.admin_credentials()
    app.config["ADMIN_USERNAME"] = admin_username
    app.config["ADMIN_PASSWORD_HASH"] = security.hash_password(admin_password)
    if not os.environ.get("ADMIN_PASSWORD"):
        app.logger.warning(
            "ADMIN_PASSWORD is not set. Generated credentials are in %s",
            config.ADMIN_PASSWORD_FILE,
        )

    init_db(app)
    with app.app_context():
        services.ensure_defaults()
        services.sync_env_settings()

    app.teardown_appcontext(close_db)

    from .admin_routes import admin_bp
    from .public_routes import public_bp
    from .reseller_routes import reseller_bp

    app.register_blueprint(public_bp)
    app.register_blueprint(reseller_bp)
    app.register_blueprint(admin_bp)

    register_guards(app)
    register_headers(app)
    register_template_helpers(app)
    register_error_handlers(app)
    return app


def is_api_path():
    return (
        request.path.startswith("/api/")
        or request.path.startswith("/admin/api")
        or request.path.startswith("/reseller/api")
    )


def geo_verified():
    stored = request.environ.get("dh4x.geo")
    if stored:
        return stored
    from flask import session

    payload = session.get("geo_ok") or {}
    if payload and security.now() - int(payload.get("ts", 0)) < 1800:
        request.environ["dh4x.geo"] = payload
        return payload
    return None


def register_guards(app):
    @app.before_request
    def guard():
        if request.endpoint in {"static", "public.healthz", "public.robots"}:
            return None
        if request.path.startswith("/admin") and app.config["ADMIN_ALLOWED_IPS"]:
            if not geoip.allowlisted(security.client_ip(), app.config["ADMIN_ALLOWED_IPS"]):
                return "Not found", 404
        if request.endpoint not in BANNED_ENDPOINTS:
            ban = services.is_banned(security.client_ip())
            if ban:
                if is_api_path():
                    return (
                        jsonify(ok=False, error="banned", message="This IP is banned."),
                        403,
                    )
                return render_template("banned.html", ban=ban, ip=security.client_ip()), 403
            shield = sentinel.screen()
            if shield is not None:
                return shield
        if not security.csrf_valid():
            if is_api_path():
                return jsonify(ok=False, error="Invalid session. Reload the page."), 403
            return "Invalid session. Reload the page.", 403
        if request.blueprint == "public":
            exempt = {
                "public.index",
                "public.geo_check",
                "public.subscription",
                "public.healthz",
                "public.robots",
                "public.banned_page",
            }
            if request.endpoint not in exempt and not geo_verified():
                if is_api_path():
                    return (
                        jsonify(
                            ok=False,
                            error="verify_required",
                            message="Location check required. Reload the activation page.",
                        ),
                        403,
                    )
                return redirect(url_for("public.index"))
        return None


def register_headers(app):
    @app.after_request
    def headers(response):
        response = security.apply_pending_cookies(response)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Robots-Tag", "noindex, nofollow")
        response.headers.setdefault(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
        )
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none';"
            " form-action 'self'; img-src 'self' data:; style-src 'self'; script-src 'self';"
            " connect-src 'self'; font-src 'self'",
        )
        if request.path.startswith("/static/"):
            response.headers.setdefault("Cache-Control", "public, max-age=86400")
        else:
            response.headers.setdefault("Cache-Control", "no-store")
        if app.config.get("HSTS") and (
            request.is_secure or request.headers.get("X-Forwarded-Proto") == "https"
        ):
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response


def register_template_helpers(app):
    @app.context_processor
    def helpers():
        pending_admin = security.current_session("admin")
        return {
            "csrf_token": security.ensure_csrf,
            "app_name": config.APP_NAME,
            "buy_url": services.get_setting("site.buy_url", ""),
            "support_url": services.get_setting("site.support_url", ""),
            "currency": services.get_setting("site.currency", "NGN"),
            "maintenance": services.maintenance_state(),
            "maintenance_note": services.get_setting("geo.locked_note", "State locked"),
            "is_admin": bool(pending_admin),
        }

    app.jinja_env.filters["duration"] = services.format_duration
    app.jinja_env.filters["money"] = services.format_money


def register_error_handlers(app):
    @app.errorhandler(404)
    def not_found(_error):
        if is_api_path():
            return jsonify(ok=False, error="Not found"), 404
        return "Not found", 404

    @app.errorhandler(413)
    def too_large(_error):
        if is_api_path():
            return jsonify(ok=False, error="File is too large (max 4MB)."), 413
        return "File is too large.", 413

    @app.errorhandler(500)
    def server_error(error):
        app.logger.exception("Unhandled error: %s", error)
        if is_api_path():
            return jsonify(ok=False, error="Server error"), 500
        return "Server error", 500
