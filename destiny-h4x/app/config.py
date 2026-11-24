import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = Path(os.environ.get("INSTANCE_DIR") or (BASE_DIR / "instance")).resolve()
UPLOAD_DIR = INSTANCE_DIR / "uploads"
DB_PATH = Path(os.environ.get("DATABASE_PATH") or (INSTANCE_DIR / "destiny.sqlite3"))
ADMIN_PASSWORD_FILE = INSTANCE_DIR / "admin_password.txt"
SECRET_KEY_FILE = INSTANCE_DIR / "secret_key"

APP_NAME = "DESTINY H4X"


def load_dotenv():
    path = BASE_DIR / ".env"
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


load_dotenv()


def env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def trusted_proxy():
    if os.environ.get("TRUST_PROXY") is not None:
        return env_bool("TRUST_PROXY")
    return any(
        os.environ.get(name)
        for name in ("RENDER", "RAILWAY_ENVIRONMENT", "FLY_APP_NAME", "DYNO")
    )


def session_secure():
    if os.environ.get("SESSION_COOKIE_SECURE") is not None:
        return env_bool("SESSION_COOKIE_SECURE")
    return trusted_proxy()


def get_secret_key():
    value = os.environ.get("SECRET_KEY", "").strip()
    if value:
        return value
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    if SECRET_KEY_FILE.exists():
        stored = SECRET_KEY_FILE.read_text(encoding="utf-8").strip()
        if stored:
            return stored
    generated = secrets.token_urlsafe(48)
    SECRET_KEY_FILE.write_text(generated + "\n", encoding="utf-8")
    return generated


def admin_credentials():
    username = os.environ.get("ADMIN_USERNAME", "").strip() or "admin"
    password = os.environ.get("ADMIN_PASSWORD", "")
    if not password:
        INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
        if ADMIN_PASSWORD_FILE.exists():
            password = ADMIN_PASSWORD_FILE.read_text(encoding="utf-8").strip()
        if not password:
            password = secrets.token_urlsafe(12)
            ADMIN_PASSWORD_FILE.write_text(password + "\n", encoding="utf-8")
    return username, password


def admin_allowed_ips():
    raw = os.environ.get("ADMIN_ALLOWED_IPS", "")
    return [item.strip() for item in raw.split(",") if item.strip()]


PROXY_ENV = {
    "HAPP_PROTOCOL": "happ.protocol",
    "HAPP_HOST": "happ.host",
    "HAPP_PORT": "happ.port",
    "HAPP_UUID": "happ.uuid",
    "HAPP_PASSWORD": "happ.password",
    "HAPP_SNI": "happ.sni",
    "HAPP_PATH": "happ.path",
    "HAPP_NETWORK": "happ.network",
    "HAPP_SECURITY": "happ.security",
    "HAPP_FLOW": "happ.flow",
    "HAPP_FP": "happ.fp",
    "HAPP_REMARK": "happ.remark",
    "HAPP_CRYPTO_LINK": "happ.crypto_link",
    "HAPP_SS_METHOD": "happ.ss_method",
    "HAPP_ALPN": "happ.alpn",
    "HAPP_PBK": "happ.pbk",
    "HAPP_SID": "happ.sid",
}

SITE_ENV = {
    "BUY_URL": "site.buy_url",
    "SUPPORT_URL": "site.support_url",
    "CURRENCY": "site.currency",
    "PUBLIC_BASE_URL": "site.public_base_url",
    "SENTINEL": "sentinel.enabled",
}

DEFAULT_SETTINGS = {
    "maintenance": "0",
    "maintenance_started_at": "0",
    "geo.mode": "block",
    "geo.fail_open": "1",
    "geo.locked_note": "State locked",
    "sentinel.enabled": "1",
    "site.buy_url": "https://youtube.com/@destinyh4x",
    "site.support_url": "",
    "site.currency": "NGN",
    "site.public_base_url": "",
    "happ.protocol": "vless",
    "happ.host": "",
    "happ.port": "443",
    "happ.uuid": "",
    "happ.password": "",
    "happ.sni": "",
    "happ.path": "/",
    "happ.network": "ws",
    "happ.security": "tls",
    "happ.flow": "",
    "happ.fp": "chrome",
    "happ.remark": "DESTINY H4X",
    "happ.crypto_link": "1",
    "happ.ss_method": "aes-256-gcm",
    "happ.alpn": "h2,http/1.1",
    "happ.pbk": "",
    "happ.sid": "",
    "test.target_url": "https://cp.cloudflare.com/generate_204",
}
