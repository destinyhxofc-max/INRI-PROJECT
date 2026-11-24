import ipaddress
import os
import re
import secrets
import sqlite3

from . import config
from .db import get_db, row, rows, transaction, value, write
from .security import decrypt_secret, encrypt_secret, hash_password, now

CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
SECRET_SETTINGS = {"happ.uuid", "happ.password"}
UNITS = {"seconds": 1, "minutes": 60, "hours": 3600, "days": 86400, "weeks": 604800, "months": 2592000}
DEVICE_RE = re.compile(r"^[A-Za-z0-9_.:-]{8,128}$")


def ensure_defaults():
    for key, val in config.DEFAULT_SETTINGS.items():
        write("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, val))


def sync_env_settings():
    for env_name, setting_key in {**config.PROXY_ENV, **config.SITE_ENV}.items():
        raw = os.environ.get(env_name)
        if raw is None or raw.strip() == "":
            continue
        if setting_key in {"happ.crypto_link", "sentinel.enabled"}:
            raw = "1" if raw.strip().lower() in {"1", "true", "yes", "on"} else "0"
        set_setting(setting_key, raw.strip())


def env_locked(key):
    env_map = {**config.PROXY_ENV, **config.SITE_ENV}
    for env_name, setting_key in env_map.items():
        if setting_key == key and os.environ.get(env_name, "").strip():
            return True
    return False


def get_setting(key, default=None):
    stored = value("SELECT value FROM settings WHERE key = ?", (key,))
    if stored is None:
        stored = config.DEFAULT_SETTINGS.get(key, default)
    if key in SECRET_SETTINGS:
        return decrypt_secret(stored)
    return stored


def set_setting(key, val):
    if key in SECRET_SETTINGS and val:
        val = encrypt_secret(str(val))
    write(
        "INSERT INTO settings (key, value) VALUES (?, ?)"
        " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, str(val)),
    )


def set_settings(values):
    for key, val in values.items():
        set_setting(key, val)


def unit_seconds(amount, unit):
    try:
        amount = int(amount)
    except (TypeError, ValueError):
        return None
    seconds = UNITS.get(str(unit).lower())
    if not seconds:
        return None
    total = amount * seconds
    if total < 10 or total > 10 * 365 * 86400:
        return None
    return total


def format_duration(seconds):
    seconds = int(seconds or 0)
    if seconds <= 0:
        return "expired"
    for unit, label in ((86400, "day"), (3600, "hour"), (60, "minute")):
        if seconds >= unit and seconds % unit == 0:
            count = seconds // unit
            return f"{count} {label}{'s' if count != 1 else ''}"
    if seconds >= 86400:
        return f"{seconds // 86400}d {seconds % 86400 // 3600}h"
    if seconds >= 3600:
        return f"{seconds // 3600}h {seconds % 3600 // 60}m"
    if seconds >= 60:
        return f"{seconds // 60}m {seconds % 60}s"
    return f"{seconds}s"


def format_money(cents, currency=None):
    currency = currency or get_setting("site.currency", "NGN")
    return f"{currency} {(int(cents or 0) / 100):,.2f}"


def generate_code():
    blocks = ["".join(secrets.choice(CODE_ALPHABET) for _ in range(4)) for _ in range(3)]
    return "DYH4X-" + "-".join(blocks)


def maintenance_state():
    on = get_setting("maintenance", "0") == "1"
    try:
        started = int(get_setting("maintenance_started_at", "0") or 0)
    except ValueError:
        started = 0
    return {"on": on, "started_at": started}


def set_maintenance(on):
    state = maintenance_state()
    if on:
        if not state["on"]:
            set_settings({"maintenance": "1", "maintenance_started_at": str(now())})
        return maintenance_state()
    if state["on"] and state["started_at"]:
        elapsed = max(0, now() - state["started_at"])
        write(
            "UPDATE keys SET expires_at = expires_at + ? WHERE expires_at IS NOT NULL AND expires_at > ?",
            (elapsed, state["started_at"]),
        )
    set_settings({"maintenance": "0", "maintenance_started_at": "0"})
    return maintenance_state()


def key_remaining(key):
    if not key or key.get("expires_at") is None or key.get("status") == "revoked":
        return None
    reference = now()
    maintenance = maintenance_state()
    if maintenance["on"] and maintenance["started_at"]:
        reference = min(reference, maintenance["started_at"])
    return max(0, int(key["expires_at"]) - reference)


def key_state(key):
    if not key:
        return "invalid"
    if key.get("status") == "revoked":
        return "revoked"
    if key.get("status") == "unused":
        return "unused"
    remaining = key_remaining(key)
    if remaining is not None and remaining <= 0:
        return "expired"
    return "active"


def decorate_key(key):
    if not key:
        return key
    key["remaining"] = key_remaining(key)
    key["state"] = key_state(key)
    key["remaining_label"] = (
        "not started" if key["remaining"] is None else format_duration(key["remaining"])
    )
    return key


def create_keys(count, seconds, kind, plan_id=None, reseller_id=None, created_by="admin", note=""):
    count = max(1, min(int(count or 1), 500))
    kind = kind if kind in {"single", "unlimited"} else "single"
    codes = []
    stamp = now()
    with transaction() as db:
        for _ in range(count):
            for attempt in range(6):
                code = generate_code()
                try:
                    db.execute(
                        "INSERT INTO keys (code, plan_id, reseller_id, created_by, kind, validity_seconds,"
                        " status, created_at, note) VALUES (?, ?, ?, ?, ?, ?, 'unused', ?, ?)",
                        (code, plan_id, reseller_id, created_by, kind, seconds, stamp, note),
                    )
                    codes.append(code)
                    break
                except sqlite3.IntegrityError:
                    if attempt == 5:
                        raise
    return codes


def key_by_code(code):
    return row("SELECT * FROM keys WHERE code = ?", ((code or "").strip().upper(),))


def key_by_id(key_id):
    return row("SELECT * FROM keys WHERE id = ?", (key_id,))


def list_keys(search="", limit=300):
    sql = (
        "SELECT k.*, p.name AS plan_name, r.username AS reseller_username,"
        " (SELECT COUNT(*) FROM key_devices d WHERE d.key_id = k.id) AS device_count"
        " FROM keys k LEFT JOIN plans p ON p.id = k.plan_id"
        " LEFT JOIN resellers r ON r.id = k.reseller_id"
    )
    args = []
    if search:
        sql += " WHERE k.code LIKE ? OR k.note LIKE ? OR r.username LIKE ?"
        like = f"%{search.strip()}%"
        args = [like, like, like]
    sql += " ORDER BY k.id DESC LIMIT ?"
    args.append(max(1, min(limit, 1000)))
    return [decorate_key(item) for item in rows(sql, args)]


def activate_key(code, device, ip, ua):
    key = key_by_code(code)
    if not key:
        return "invalid", None
    if key["status"] == "revoked":
        return "revoked", key
    state = key_state(key)
    if state == "expired":
        return "expired", key
    maintenance = maintenance_state()
    if maintenance["on"]:
        return "maintenance", key
    if key["kind"] == "single":
        if key["hwid"] and key["hwid"] != device:
            return "other_device", key
    stamp = now()
    with transaction() as db:
        if key["status"] == "unused":
            expires = stamp + int(key["validity_seconds"])
            db.execute(
                "UPDATE keys SET status = 'active', first_used_at = ?, expires_at = ?, hwid = ?"
                " WHERE id = ? AND status = 'unused'",
                (stamp, expires, device if key["kind"] == "single" else None, key["id"]),
            )
        elif key["kind"] == "single" and not key["hwid"]:
            db.execute("UPDATE keys SET hwid = ? WHERE id = ?", (device, key["id"]))
        db.execute(
            "INSERT OR IGNORE INTO key_devices (key_id, device_id, ip, ua, first_seen) VALUES (?, ?, ?, ?, ?)",
            (key["id"], device, ip, ua, stamp),
        )
    return "ok", key_by_id(key["id"])


def device_allowed(key, device):
    if not key:
        return False
    if key["kind"] == "unlimited":
        return True
    return bool(key.get("hwid")) and key["hwid"] == device


def revoke_key(key_id):
    write("UPDATE keys SET status = 'revoked' WHERE id = ?", (key_id,))
    write(
        "UPDATE sessions SET revoked = 1 WHERE role = 'user' AND subject_id = ?",
        (str(key_id),),
    )


def delete_key(key_id):
    write("UPDATE sessions SET revoked = 1 WHERE role = 'user' AND subject_id = ?", (str(key_id),))
    write("DELETE FROM keys WHERE id = ?", (key_id,))


def create_plan(name, seconds, price_cents, stock):
    return write(
        "INSERT INTO plans (name, seconds, price_cents, stock, active, created_at) VALUES (?, ?, ?, ?, 1, ?)",
        (name.strip()[:80], int(seconds), int(price_cents), max(0, int(stock)), now()),
    )


def update_plan(plan_id, fields):
    allowed = {"name", "seconds", "price_cents", "stock", "active"}
    pairs = [(key, val) for key, val in fields.items() if key in allowed]
    if not pairs:
        return
    sql = "UPDATE plans SET " + ", ".join(f"{key} = ?" for key, _ in pairs) + " WHERE id = ?"
    write(sql, [val for _, val in pairs] + [plan_id])


def add_stock(plan_id, amount):
    write("UPDATE plans SET stock = MAX(0, stock + ?) WHERE id = ?", (int(amount), plan_id))


def delete_plan(plan_id):
    write("DELETE FROM plans WHERE id = ?", (plan_id,))


def list_plans(active_only=False):
    sql = (
        "SELECT p.*, (SELECT COUNT(*) FROM keys k WHERE k.plan_id = p.id) AS sold"
        " FROM plans p"
    )
    if active_only:
        sql += " WHERE p.active = 1"
    sql += " ORDER BY p.price_cents ASC, p.id DESC"
    return rows(sql)


def plan_by_id(plan_id):
    return row("SELECT * FROM plans WHERE id = ?", (plan_id,))


def create_reseller(username, password, first_name, last_name, age, balance_cents, photo=""):
    username = username.strip().lower()
    if not username or not password or not first_name.strip() or not last_name.strip():
        return None, "Name, username and password are required."
    try:
        user_id = write(
            "INSERT INTO resellers (username, pass_hash, first_name, last_name, age, balance_cents,"
            " photo, active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
            (
                username,
                hash_password(password),
                first_name.strip()[:60],
                last_name.strip()[:60],
                int(age) if age else None,
                int(balance_cents),
                photo,
                now(),
            ),
        )
    except sqlite3.IntegrityError:
        return None, "That username is already taken."
    return user_id, None


def update_reseller(reseller_id, fields):
    allowed = {"first_name", "last_name", "age", "balance_cents", "active", "photo"}
    pairs = [(key, val) for key, val in fields.items() if key in allowed]
    if not pairs:
        return
    sql = "UPDATE resellers SET " + ", ".join(f"{key} = ?" for key, _ in pairs) + " WHERE id = ?"
    write(sql, [val for _, val in pairs] + [reseller_id])


def set_reseller_password(reseller_id, password):
    write("UPDATE resellers SET pass_hash = ? WHERE id = ?", (hash_password(password), reseller_id))


def delete_reseller(reseller_id):
    write("UPDATE keys SET reseller_id = NULL WHERE reseller_id = ?", (reseller_id,))
    write("DELETE FROM resellers WHERE id = ?", (reseller_id,))


def reseller_by_username(username):
    return row("SELECT * FROM resellers WHERE username = ?", ((username or "").strip().lower(),))


def reseller_by_id(reseller_id):
    return row("SELECT * FROM resellers WHERE id = ?", (reseller_id,))


def list_resellers():
    return rows(
        "SELECT r.*, (SELECT COUNT(*) FROM keys k WHERE k.reseller_id = r.id) AS key_count,"
        " (SELECT COALESCE(SUM(unit_price_cents), 0) FROM purchases p WHERE p.reseller_id = r.id) AS spent"
        " FROM resellers r ORDER BY r.id DESC"
    )


def buy_plan(reseller_id, plan_id):
    code = generate_code()
    stamp = now()
    with transaction() as db:
        plan = db.execute("SELECT * FROM plans WHERE id = ? AND active = 1", (plan_id,)).fetchone()
        if not plan:
            return None, "That plan is not available."
        buyer = db.execute("SELECT * FROM resellers WHERE id = ? AND active = 1", (reseller_id,)).fetchone()
        if not buyer:
            return None, "Reseller account is disabled."
        if plan["stock"] <= 0:
            return None, "This plan is sold out. Request a restock from the admin."
        if buyer["balance_cents"] < plan["price_cents"]:
            return None, "Balance is too low for this plan."
        stock_update = db.execute(
            "UPDATE plans SET stock = stock - 1 WHERE id = ? AND stock > 0", (plan_id,)
        )
        if stock_update.rowcount != 1:
            return None, "This plan is sold out. Request a restock from the admin."
        balance_update = db.execute(
            "UPDATE resellers SET balance_cents = balance_cents - ? WHERE id = ? AND balance_cents >= ?",
            (plan["price_cents"], reseller_id, plan["price_cents"]),
        )
        if balance_update.rowcount != 1:
            return None, "Balance is too low for this plan."
        key_id = db.execute(
            "INSERT INTO keys (code, plan_id, reseller_id, created_by, kind, validity_seconds,"
            " status, created_at, note) VALUES (?, ?, ?, ?, 'single', ?, 'unused', ?, ?)",
            (code, plan_id, reseller_id, f"reseller:{reseller_id}", plan["seconds"], stamp, f"Plan: {plan['name']}"),
        ).lastrowid
        db.execute(
            "INSERT INTO purchases (reseller_id, plan_id, unit_price_cents, key_id, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (reseller_id, plan_id, plan["price_cents"], key_id, stamp),
        )
    return {"code": code, "plan": dict(plan), "key_id": key_id}, None


def request_restock(reseller_id, plan_id, note=""):
    existing = row(
        "SELECT id FROM restock_requests WHERE reseller_id = ? AND plan_id = ? AND status = 'open'",
        (reseller_id, plan_id),
    )
    if existing:
        return False, "You already have an open restock request for this plan."
    write(
        "INSERT INTO restock_requests (reseller_id, plan_id, note, status, created_at)"
        " VALUES (?, ?, ?, 'open', ?)",
        (reseller_id, plan_id, str(note)[:300], now()),
    )
    return True, None


def list_restock_requests(status=None):
    sql = (
        "SELECT rr.*, p.name AS plan_name, r.username, r.first_name, r.last_name"
        " FROM restock_requests rr JOIN plans p ON p.id = rr.plan_id"
        " JOIN resellers r ON r.id = rr.reseller_id"
    )
    args = []
    if status:
        sql += " WHERE rr.status = ?"
        args.append(status)
    sql += " ORDER BY rr.id DESC LIMIT 200"
    return rows(sql, args)


def close_restock_request(request_id, status="done"):
    write(
        "UPDATE restock_requests SET status = ?, handled_at = ? WHERE id = ?",
        (status, now(), request_id),
    )


def reseller_keys(reseller_id):
    found = rows(
        "SELECT k.*, p.name AS plan_name FROM keys k LEFT JOIN plans p ON p.id = k.plan_id"
        " WHERE k.reseller_id = ? ORDER BY k.id DESC LIMIT 300",
        (reseller_id,),
    )
    return [decorate_key(item) for item in found]


def reseller_purchases(reseller_id):
    return rows(
        "SELECT p.*, pl.name AS plan_name, k.code FROM purchases p"
        " LEFT JOIN plans pl ON pl.id = p.plan_id LEFT JOIN keys k ON k.id = p.key_id"
        " WHERE p.reseller_id = ? ORDER BY p.id DESC LIMIT 100",
        (reseller_id,),
    )


def valid_ip(text):
    try:
        return str(ipaddress.ip_address(str(text).strip()))
    except ValueError:
        return None


def is_banned(ip):
    found = row("SELECT * FROM bans WHERE ip = ?", (ip,))
    if not found:
        return None
    if found["expires_at"] and found["expires_at"] <= now():
        write("DELETE FROM bans WHERE ip = ?", (ip,))
        return None
    return found


def ban_ip(ip, reason="", seconds=None):
    normalized = valid_ip(ip)
    if not normalized:
        return False
    expires = now() + int(seconds) if seconds else None
    write(
        "INSERT INTO bans (ip, reason, created_at, expires_at) VALUES (?, ?, ?, ?)"
        " ON CONFLICT(ip) DO UPDATE SET reason = excluded.reason, created_at = excluded.created_at,"
        " expires_at = excluded.expires_at",
        (normalized, str(reason)[:300], now(), expires),
    )
    return True


def unban_ip(ip):
    write("DELETE FROM bans WHERE ip = ?", (ip,))


def list_bans():
    return rows("SELECT * FROM bans ORDER BY created_at DESC LIMIT 500")


def clean_hwid(value):
    text = str(value or "").strip()
    return text if DEVICE_RE.match(text) else ""


def is_hwid_banned(hwid):
    hwid = clean_hwid(hwid)
    if not hwid:
        return None
    found = row("SELECT * FROM hwid_bans WHERE hwid = ?", (hwid,))
    if not found:
        return None
    if found["expires_at"] and found["expires_at"] <= now():
        write("DELETE FROM hwid_bans WHERE hwid = ?", (hwid,))
        return None
    return found


def ban_hwid(hwid, reason="", seconds=None):
    hwid = clean_hwid(hwid)
    if not hwid:
        return False
    expires = now() + int(seconds) if seconds else None
    write(
        "INSERT INTO hwid_bans (hwid, reason, created_at, expires_at) VALUES (?, ?, ?, ?)"
        " ON CONFLICT(hwid) DO UPDATE SET reason = excluded.reason, created_at = excluded.created_at,"
        " expires_at = excluded.expires_at",
        (hwid, str(reason)[:300], now(), expires),
    )
    return True


def unban_hwid(hwid):
    hwid = clean_hwid(hwid)
    if not hwid:
        return False
    write("DELETE FROM hwid_bans WHERE hwid = ?", (hwid,))
    return True


def list_hwid_bans():
    return rows("SELECT * FROM hwid_bans ORDER BY created_at DESC LIMIT 500")


def revoke_sessions_for_hwid(hwid):
    hwid = clean_hwid(hwid)
    if hwid:
        write("UPDATE sessions SET revoked = 1 WHERE device_id = ? AND revoked = 0", (hwid,))


def add_geo_rule(country_code, country_name, region_key="", region_name=""):
    if not country_code:
        return False, "Choose a country."
    try:
        write(
            "INSERT INTO geo_rules (country_code, country_name, region_key, region_name, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (country_code.upper()[:2], country_name, region_key, region_name, now()),
        )
    except sqlite3.IntegrityError:
        return False, "That country/state is already locked."
    return True, None


def remove_geo_rule(rule_id):
    write("DELETE FROM geo_rules WHERE id = ?", (rule_id,))


def list_geo_rules():
    return rows("SELECT * FROM geo_rules ORDER BY country_name, region_name")


def geo_mode():
    return get_setting("geo.mode", "block")


def set_geo_mode(mode):
    set_setting("geo.mode", "allow" if mode == "allow" else "block")


def list_sessions(role=None):
    sql = "SELECT * FROM sessions WHERE revoked = 0 AND expires_at > ?"
    args = [now()]
    if role:
        sql += " AND role = ?"
        args.append(role)
    sql += " ORDER BY last_seen DESC LIMIT 300"
    return rows(sql, args)


def kill_session(session_id):
    write("UPDATE sessions SET revoked = 1 WHERE id = ?", (session_id,))


def recent_audit(limit=100):
    return rows("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (max(1, min(limit, 500)),))


def stats():
    maint = maintenance_state()
    reference = int(maint["started_at"]) if maint["on"] else now()
    counts = {}
    for label, query in {
        "keys_total": "SELECT COUNT(*) FROM keys",
        "keys_active": "SELECT COUNT(*) FROM keys WHERE status = 'active' AND expires_at > ?",
        "keys_unused": "SELECT COUNT(*) FROM keys WHERE status = 'unused'",
        "keys_revoked": "SELECT COUNT(*) FROM keys WHERE status = 'revoked'",
        "resellers": "SELECT COUNT(*) FROM resellers",
        "plans": "SELECT COUNT(*) FROM plans",
        "bans": "SELECT COUNT(*) FROM bans",
        "hwid_bans": "SELECT COUNT(*) FROM hwid_bans",
        "requests": "SELECT COUNT(*) FROM restock_requests WHERE status = 'open'",
        "revenue": "SELECT COALESCE(SUM(unit_price_cents), 0) FROM purchases",
        "sessions": "SELECT COUNT(*) FROM sessions WHERE revoked = 0 AND expires_at > ?",
    }.items():
        args = (reference,) if label in {"keys_active", "sessions"} else ()
        counts[label] = value(query, args, 0)
    counts["maintenance"] = maint["on"]
    return counts
