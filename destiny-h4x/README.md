# DESTINY H4X

Licensing site for the DESTINY H4X proxy keys: activation panel, admin console, reseller shop, GeoIP country/state lock, maintenance pause, IP bans, and a Happ subscription that shows the key timer inside the app.

All checks run on the server (Python/Flask + SQLite). Nothing is verified in the browser, so `/dashboard`, `/reseller` and `/admin` cannot be opened without the matching session, device and location checks.

## Run locally

```bash
python -m venv .venv
.venv/Scripts/activate        # Windows
pip install -r requirements.txt
copy .env.example .env        # edit values
waitress-serve --host=0.0.0.0 --port=8080 --call app:create_app
```

Open `http://127.0.0.1:8080` (verification passes locally when `ALLOW_GEO_TEST=1` is set).

## Hosting variables (Railway / any host)

| Variable | Required | Meaning |
| --- | --- | --- |
| `ADMIN_USERNAME` | yes | Admin panel username |
| `ADMIN_PASSWORD` | yes | Admin panel password. Re-applied on every start; redeploy after changing |
| `SECRET_KEY` | yes | Long random string (sessions, tokens, encryption) |
| `PUBLIC_BASE_URL` | yes | Public HTTPS address used inside Happ subscription links, no trailing slash |
| `BUY_URL` | no | "Need a key?" link on the activation page (e.g. WhatsApp) |
| `SUPPORT_URL` | no | Support link in the dashboard and Happ profile |
| `CURRENCY` | no | Currency label, default `NGN` |
| `HAPP_HOST` | yes | Proxy server host |
| `HAPP_PORT` | no | Server port, default 443 |
| `HAPP_UUID` | VLESS | VLESS UUID |
| `HAPP_PASSWORD` | trojan/ss | Trojan or Shadowsocks password |
| `HAPP_PROTOCOL` | no | `vless`, `trojan` or `ss` |
| `HAPP_NETWORK` | no | `ws`, `tcp` or `grpc` |
| `HAPP_SECURITY` | no | `tls`, `reality` or `none` |
| `HAPP_SNI`, `HAPP_PATH`, `HAPP_FP`, `HAPP_ALPN`, `HAPP_FLOW` | no | Transport details |
| `HAPP_PBK`, `HAPP_SID` | reality | Reality public key / short id |
| `HAPP_REMARK` | no | Happ profile title, default `DESTINY H4X` |
| `HAPP_CRYPTO_LINK` | no | `1` sends encrypted `happ://crypt…` links (default on) |
| `ADMIN_ALLOWED_IPS` | no | Comma-separated IPs/CIDRs allowed to reach `/admin` |
| `SENTINEL` | no | `1` (default) turns on the auto-ban shield; `0` disables it |
| `INSTANCE_DIR` | no | Data folder (SQLite + reseller photos). Use a mounted volume in production |
| `TRUST_PROXY` | no | `1` behind Railway/Render/Fly so real client IPs are read |
| `ALLOW_GEO_TEST` | test only | Accepts `X-Test-Country` / `X-Test-Region` headers for local testing |
| `GEO_OVERRIDE_COUNTRY`, `GEO_OVERRIDE_REGION` | test only | Force location for a single test deployment |

Environment values for `HAPP_*`, `BUY_URL`, `SUPPORT_URL`, `CURRENCY` and `PUBLIC_BASE_URL` are authoritative: they overwrite stored values at every start and the admin UI shows them locked.

## How the pieces fit

- **Activation** (`/`): verifying screen → activation panel → key check → device binding for single keys.
- **Keys**: minutes/seconds/hours/days/months; single (locks to first web device or Happ HWID) or unlimited. Expiry shows in Happ via `subscription-userinfo expire=` and the profile remark (`… | N left`). Expired or revoked keys return HTTP 410 so Happ drops the subscription on refresh.
- **Maintenance**: pauses every timer by shifting `expires_at` on resume; activation, reseller and Happ subscription show the maintenance notice.
- **Geo lock**: blocks (or allow-only) countries/states before the activation page opens; lookups cached 24h; fail-open is configurable.
- **Admin**: keys, plans + stock, resellers (photo, balance, password), bans (IP + device ID), geo rules, Happ config + test URI, sessions, audit.
- **Reseller**: buys plan keys from balance; sold-out plans cannot be bought; restock requests reach the admin.
- **Sheriff shield**: on by default. Decoy login pages (`/wp-login.php`, `/wp-admin`, …), `.env`/`.git`/backup probe paths, attack payloads (SQLi, traversal, shell, JNDI) and scanner user agents are trapped; the request bans its IP and, when the client sends a device ID, that device too. Repeat requests over 600/minute also ban. Local IPs and IPs holding an admin session are spared so the owner can test safely.

Data lives in SQLite under `INSTANCE_DIR` (default `instance/`). On Railway attach a volume and set `INSTANCE_DIR=/data`. An admin password generated because `ADMIN_PASSWORD` was missing is written to `instance/admin_password.txt`; always set the variable instead.

## Notes

- A browser cannot create a VPN tunnel. The dashboard opens Happ with the owner's subscription (admin-configured server), which is the "web proxy" connection.
- Encrypted links use the official Happ crypto endpoint (`crypto.happ.su`). If it is unreachable, the dashboard keeps the copyable subscription link visible instead of navigating away.
- The test button in **Keys** creates a 10-minute single key; **TEST CONFIG** builds a sample URI without touching real keys.

## Tests

```bash
.venv/Scripts/python.exe -m unittest discover -s tests -v
```
