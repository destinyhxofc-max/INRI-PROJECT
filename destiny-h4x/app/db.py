import sqlite3
from contextlib import contextmanager

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS resellers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    pass_hash TEXT NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    age INTEGER,
    balance_cents INTEGER NOT NULL DEFAULT 0,
    photo TEXT NOT NULL DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    seconds INTEGER NOT NULL,
    price_cents INTEGER NOT NULL,
    stock INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    plan_id INTEGER REFERENCES plans(id) ON DELETE SET NULL,
    reseller_id INTEGER REFERENCES resellers(id) ON DELETE SET NULL,
    created_by TEXT NOT NULL DEFAULT 'admin',
    kind TEXT NOT NULL DEFAULT 'single' CHECK (kind IN ('single', 'unlimited')),
    validity_seconds INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'unused' CHECK (status IN ('unused', 'active', 'revoked')),
    hwid TEXT,
    first_used_at INTEGER,
    expires_at INTEGER,
    created_at INTEGER NOT NULL,
    note TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS key_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    ua TEXT NOT NULL DEFAULT '',
    first_seen INTEGER NOT NULL,
    UNIQUE (key_id, device_id)
);

CREATE TABLE IF NOT EXISTS purchases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reseller_id INTEGER REFERENCES resellers(id) ON DELETE SET NULL,
    plan_id INTEGER REFERENCES plans(id) ON DELETE SET NULL,
    unit_price_cents INTEGER NOT NULL,
    key_id INTEGER REFERENCES keys(id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS restock_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reseller_id INTEGER NOT NULL REFERENCES resellers(id) ON DELETE CASCADE,
    plan_id INTEGER NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
    note TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    created_at INTEGER NOT NULL,
    handled_at INTEGER
);

CREATE TABLE IF NOT EXISTS bans (
    ip TEXT PRIMARY KEY,
    reason TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    expires_at INTEGER
);

CREATE TABLE IF NOT EXISTS hwid_bans (
    hwid TEXT PRIMARY KEY,
    reason TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    expires_at INTEGER
);

CREATE TABLE IF NOT EXISTS geo_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    country_code TEXT NOT NULL,
    country_name TEXT NOT NULL,
    region_key TEXT NOT NULL DEFAULT '',
    region_name TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    UNIQUE (country_code, region_key)
);

CREATE TABLE IF NOT EXISTS geo_cache (
    ip TEXT PRIMARY KEY,
    ok INTEGER NOT NULL,
    country_code TEXT,
    country_name TEXT,
    region TEXT,
    ts INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    device_id TEXT NOT NULL DEFAULT '',
    token_hash TEXT NOT NULL UNIQUE,
    ip TEXT NOT NULL DEFAULT '',
    ua TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_keys_status ON keys(status);
CREATE INDEX IF NOT EXISTS idx_keys_code ON keys(code);
CREATE INDEX IF NOT EXISTS idx_keys_reseller ON keys(reseller_id);
CREATE INDEX IF NOT EXISTS idx_key_devices_key ON key_devices(key_id);
CREATE INDEX IF NOT EXISTS idx_sessions_hash ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_subject ON sessions(role, subject_id);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit(created_at);
CREATE INDEX IF NOT EXISTS idx_geo_cache_ts ON geo_cache(ts);
"""


def get_db():
    if "db" not in g:
        conn = sqlite3.connect(current_app.config["DATABASE_PATH"], timeout=20, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 20000")
        g.db = conn
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    app.config["DATABASE_PATH"] = str(app.config["DATABASE_PATH"])
    with app.app_context():
        db = get_db()
        db.executescript(SCHEMA)


def rows(sql, args=()):
    return [dict(row) for row in get_db().execute(sql, args).fetchall()]


def row(sql, args=()):
    found = get_db().execute(sql, args).fetchone()
    return dict(found) if found else None


def value(sql, args=(), default=None):
    found = get_db().execute(sql, args).fetchone()
    return found[0] if found else default


def write(sql, args=()):
    cur = get_db().execute(sql, args)
    return cur.lastrowid


@contextmanager
def transaction():
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        yield db
    except Exception:
        db.execute("ROLLBACK")
        raise
    else:
        db.execute("COMMIT")
