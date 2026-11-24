import io
import os
import tempfile
import time
import unittest
import urllib.parse

TEST_DIR = tempfile.mkdtemp(prefix="dh4x-test-")
os.environ.update(
    {
        "INSTANCE_DIR": TEST_DIR,
        "ADMIN_USERNAME": "admin",
        "ADMIN_PASSWORD": "admin-pass-123",
        "SECRET_KEY": "test-secret-key-destiny-h4x-0123456789abcdef",
        "SESSION_COOKIE_SECURE": "0",
        "PUBLIC_BASE_URL": "https://destiny.test",
        "HAPP_HOST": "server.example.com",
        "HAPP_PORT": "443",
        "HAPP_UUID": "11111111-2222-4333-8444-555555555555",
        "HAPP_NETWORK": "ws",
        "HAPP_SECURITY": "tls",
        "HAPP_CRYPTO_LINK": "0",
        "GEO_OVERRIDE_COUNTRY": "NG",
        "GEO_OVERRIDE_REGION": "Abia",
    }
)

from app import create_app  # noqa: E402
from app import db, security  # noqa: E402

JPEG = b"\xff\xd8\xff\xe0" + b"0" * 40


class DestinyFlowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app({"TESTING": True})

    def new_client(self):
        return self.app.test_client()

    def csrf(self, client, path="/"):
        client.get(path)
        cookie = client.get_cookie("dh4x_csrf")
        self.assertIsNotNone(cookie, "csrf cookie missing")
        return cookie.value.split(".")[0]

    def headers(self, token):
        return {"X-CSRF-Token": token}

    def verify_geo(self, client, expect=200):
        token = self.csrf(client, "/")
        response = client.post("/api/geo/check", json={}, headers=self.headers(token))
        self.assertEqual(response.status_code, expect)
        return response, token

    def admin(self):
        client = self.new_client()
        token = self.csrf(client, "/admin")
        response = client.post(
            "/admin/login",
            data={"_csrf": token, "username": "admin", "password": "admin-pass-123"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/admin/dashboard", response.headers["Location"])
        return client, token

    def test_01_public_verify_and_activation(self):
        client = self.new_client()
        page = client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Verifying location", page.data)

        response, _token = self.verify_geo(client)
        self.assertTrue(response.get_json()["ok"])
        activate = client.get("/activate")
        self.assertEqual(activate.status_code, 200)
        self.assertIn(b"PREMIUM ACCESS PANEL", activate.data)
        self.assertNotIn(b"SUPABASE", activate.data.upper())

    def test_02_admin_guard_login_and_config(self):
        anonymous = self.new_client()
        blocked = anonymous.get("/admin/dashboard")
        self.assertEqual(blocked.status_code, 302)
        self.assertIn("/admin", blocked.headers["Location"])

        client, token = self.admin()
        dashboard = client.get("/admin/dashboard")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b"Generate keys", dashboard.data)

        saved = client.post(
            "/admin/api/config",
            json={"remark": "DESTINY H4X"},
            headers=self.headers(token),
        )
        self.assertEqual(saved.status_code, 200)
        self.assertEqual(saved.get_json()["errors"], [])

        test = client.post("/admin/api/config/test", json={}, headers=self.headers(token))
        self.assertEqual(test.status_code, 200)
        self.assertTrue(test.get_json()["test"]["uri"].startswith("vless://"))

    def test_03_key_generation_and_activation(self):
        admin, token = self.admin()
        created = admin.post(
            "/admin/api/keys",
            json={"value": 10, "unit": "minutes", "kind": "single", "count": 1},
            headers=self.headers(token),
        )
        self.assertEqual(created.status_code, 200)
        self.__class__.key_code = created.get_json()["codes"][0]
        self.assertTrue(self.key_code.startswith("DYH4X-"))

        client = self.new_client()
        _response, token = self.verify_geo(client)
        activated = client.post(
            "/api/activate",
            json={"key": self.key_code, "device": "device-alpha-0001"},
            headers=self.headers(token),
        )
        self.assertEqual(activated.status_code, 200, activated.data)
        self.assertEqual(activated.get_json()["redirect"], "/dashboard")

        dashboard = client.get("/dashboard")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b"DESTINY H4X ACTIVATED", dashboard.data)
        self.assertIn(b'id="expiryLine"', dashboard.data)
        self.assertIn(b"data-expires=", dashboard.data)

        status = client.get("/api/status").get_json()
        self.assertTrue(status["ok"])
        self.assertEqual(status["state"], "active")
        self.assertTrue(0 < status["remaining"] <= 600)
        self.__class__.user_client = client

    def test_04_second_device_rejected(self):
        other = self.new_client()
        _response, token = self.verify_geo(other)
        response = other.post(
            "/api/activate",
            json={"key": self.key_code, "device": "device-beta-0002"},
            headers=self.headers(token),
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["error"], "other_device")

    def test_05_connect_and_subscription(self):
        client = self.user_client
        token = self.csrf(client, "/dashboard")
        response = client.post("/api/connect", json={}, headers=self.headers(token))
        self.assertEqual(response.status_code, 200, response.data)
        payload = response.get_json()
        self.assertFalse(payload["encrypted"])
        self.assertTrue(payload["subscription_url"].startswith("https://destiny.test/sub/"))

        path = urllib.parse.urlparse(payload["subscription_url"]).path
        sub = client.get(path)
        self.assertEqual(sub.status_code, 200)
        self.assertEqual(sub.headers.get("profile-title"), "DESTINY H4X")
        self.assertIn("expire=", sub.headers.get("subscription-userinfo"))
        body = sub.data.decode()
        import base64

        uri = base64.b64decode(body).decode()
        self.assertTrue(uri.startswith("vless://11111111-2222-4333-8444-555555555555@server.example.com:443"))
        self.assertIn("left", urllib.parse.unquote(uri))

    def test_06_expiry_stops_subscription(self):
        admin, token = self.admin()
        created = admin.post(
            "/admin/api/keys",
            json={"value": 10, "unit": "seconds", "kind": "single", "count": 1},
            headers=self.headers(token),
        )
        code = created.get_json()["codes"][0]

        client = self.new_client()
        _response, csrf = self.verify_geo(client)
        activated = client.post(
            "/api/activate",
            json={"key": code, "device": "device-gamma-0003"},
            headers=self.headers(csrf),
        )
        self.assertEqual(activated.status_code, 200)

        payload = client.post("/api/connect", json={}, headers=self.headers(csrf)).get_json()
        path = urllib.parse.urlparse(payload["subscription_url"]).path

        with self.app.app_context():
            db.write(
                "UPDATE keys SET expires_at = ? WHERE code = ?",
                (security.now() - 5, code),
            )

        status = client.get("/api/status").get_json()
        self.assertFalse(status["ok"])
        self.assertEqual(status["state"], "expired")
        sub = client.get(path)
        self.assertEqual(sub.status_code, 410)

    def test_07_maintenance_pauses_timers(self):
        client = self.user_client
        admin, token = self.admin()
        before = client.get("/api/status").get_json()["remaining"]

        turned_on = admin.post(
            "/admin/api/maintenance", json={"on": True}, headers=self.headers(token)
        )
        self.assertTrue(turned_on.get_json()["maintenance"]["on"])
        first = client.get("/api/status").get_json()
        self.assertTrue(first["maintenance"])
        time.sleep(1.2)
        second = client.get("/api/status").get_json()
        self.assertLessEqual(abs(first["remaining"] - second["remaining"]), 1)
        self.assertLessEqual(second["remaining"], before)

        visitor = self.new_client()
        self.verify_geo(visitor)
        maintenance_page = visitor.get("/activate")
        self.assertEqual(maintenance_page.status_code, 200)
        self.assertIn(b"On maintenance", maintenance_page.data)

        turned_off = admin.post(
            "/admin/api/maintenance", json={"on": False}, headers=self.headers(token)
        )
        self.assertFalse(turned_off.get_json()["maintenance"]["on"])

    def test_08_ip_ban_blocks_valid_key(self):
        admin, token = self.admin()
        banned = admin.post(
            "/admin/api/bans",
            json={"ip": "203.0.113.9", "reason": "abuse"},
            headers=self.headers(token),
        )
        self.assertEqual(banned.status_code, 200)

        attacker = self.new_client()
        response = attacker.get("/", environ_base={"REMOTE_ADDR": "203.0.113.9"})
        self.assertEqual(response.status_code, 403)
        self.assertIn(b"ACCESS DENIED", response.data)

        unbanned = admin.delete(
            "/admin/api/bans/203.0.113.9", headers=self.headers(token)
        )
        self.assertEqual(unbanned.status_code, 200)
        allowed = attacker.get("/", environ_base={"REMOTE_ADDR": "203.0.113.9"})
        self.assertEqual(allowed.status_code, 200)

    def test_09_plan_stock_reseller_buy_and_restock(self):
        admin, token = self.admin()
        plan = admin.post(
            "/admin/api/plans",
            json={"name": "2 Minute Test", "value": 2, "unit": "minutes", "price": "100", "stock": 1},
            headers=self.headers(token),
        )
        self.assertEqual(plan.status_code, 200)
        plan_id = plan.get_json()["id"]

        created = admin.post(
            "/admin/api/resellers",
            data={
                "username": "buyer1",
                "password": "buyerpass1",
                "first_name": "Ada",
                "last_name": "Obi",
                "age": "24",
                "balance": "500",
                "photo": (io.BytesIO(JPEG), "ada.jpg"),
            },
            headers=self.headers(token),
            content_type="multipart/form-data",
        )
        self.assertEqual(created.status_code, 200, created.data)
        reseller_id = created.get_json()["id"]

        reseller = self.new_client()
        csrf = self.csrf(reseller, "/reseller")
        login = reseller.post(
            "/reseller/login",
            data={"_csrf": csrf, "username": "buyer1", "password": "buyerpass1"},
            headers=self.headers(csrf),
        )
        self.assertEqual(login.status_code, 302)
        self.assertIn("welcome=1", login.headers["Location"])

        dashboard = reseller.get("/reseller/dashboard?welcome=1")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b"Welcome, Ada Obi", dashboard.data)
        self.assertIn(("reseller/photo/%d" % reseller_id).encode(), dashboard.data)

        photo = reseller.get("/reseller/photo/%d" % reseller_id)
        self.assertEqual(photo.status_code, 200)
        self.assertEqual(photo.mimetype, "image/jpeg")

        bought = reseller.post(
            "/reseller/buy", json={"plan_id": plan_id}, headers=self.headers(csrf)
        )
        self.assertEqual(bought.status_code, 200, bought.data)
        self.assertEqual(bought.get_json()["balance_cents"], 40000)

        sold_out = reseller.post(
            "/reseller/buy", json={"plan_id": plan_id}, headers=self.headers(csrf)
        )
        self.assertEqual(sold_out.status_code, 409)
        self.assertIn("sold", sold_out.get_json()["error"].lower())

        restock = reseller.post(
            "/reseller/restock", json={"plan_id": plan_id, "note": "more please"},
            headers=self.headers(csrf),
        )
        self.assertEqual(restock.status_code, 200)

        requests = admin.get("/admin/api/requests").get_json()["requests"]
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["status"], "open")
        closed = admin.post(
            "/admin/api/requests/%d/close" % requests[0]["id"],
            json={"status": "done"},
            headers=self.headers(token),
        )
        self.assertEqual(closed.status_code, 200)

    def test_10_geo_lock_blocks_state(self):
        admin, token = self.admin()
        added = admin.post(
            "/admin/api/geo/rules",
            json={"country_code": "NG", "region": "Abia"},
            headers=self.headers(token),
        )
        self.assertEqual(added.status_code, 200)

        visitor = self.new_client()
        blocked, _token = self.verify_geo(visitor, expect=403)
        self.assertTrue(blocked.get_json()["locked"])
        self.assertEqual(blocked.get_json()["message"], "State locked")

        rules = admin.get("/admin/api/geo").get_json()["rules"]
        self.assertEqual(len(rules), 1)
        removed = admin.delete(
            "/admin/api/geo/rules/%d" % rules[0]["id"], headers=self.headers(token)
        )
        self.assertEqual(removed.status_code, 200)

        reopened, _token = self.verify_geo(self.new_client())
        self.assertTrue(reopened.get_json()["ok"])

    def test_11_security_headers(self):
        client = self.new_client()
        response = client.get("/")
        self.assertIn("script-src 'self'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("noindex", response.headers["X-Robots-Tag"])
        self.assertEqual(client.get("/healthz").data, b"ok")
        self.assertIn(b"Disallow", client.get("/robots.txt").data)

    def test_12_sheriff_bans_probe_ip(self):
        incident_ip = "45.33.32.156"
        admin, token = self.admin()
        attacker = self.new_client()
        probe = attacker.get("/.env", environ_base={"REMOTE_ADDR": incident_ip})
        self.assertEqual(probe.status_code, 404)
        bans = admin.get("/admin/api/bans").get_json()["bans"]
        self.assertTrue(any(item["ip"] == incident_ip for item in bans))
        blocked = attacker.get("/", environ_base={"REMOTE_ADDR": incident_ip})
        self.assertEqual(blocked.status_code, 403)
        self.assertIn(b"ACCESS DENIED", blocked.data)
        audit = admin.get("/admin/api/audit").get_json()["audit"]
        self.assertTrue(any(item["actor"] == "sheriff" for item in audit))
        unbanned = admin.delete("/admin/api/bans/" + incident_ip, headers=self.headers(token))
        self.assertEqual(unbanned.status_code, 200)

    def test_13_decoy_and_device_ban(self):
        probe_ip = "45.33.32.157"
        admin, token = self.admin()
        attacker = self.new_client()
        page = attacker.get("/wp-login.php", environ_base={"REMOTE_ADDR": probe_ip})
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Log In", page.data)
        self.assertIn(b'name="pwd"', page.data)

        device = "device-evil-0001"
        hunter = self.new_client()
        hunter.get(
            "/.git/config",
            headers={"X-HWID": device},
            environ_base={"REMOTE_ADDR": "45.33.32.158"},
        )
        hwid_bans = admin.get("/admin/api/bans").get_json()["hwid_bans"]
        self.assertTrue(any(item["hwid"] == device for item in hwid_bans))

        visitor = self.new_client()
        _response, csrf = self.verify_geo(visitor)
        refused = visitor.post(
            "/api/activate",
            json={"key": "DYH4X-NONE-NONE-NONE", "device": device},
            headers=self.headers(csrf),
        )
        self.assertEqual(refused.status_code, 403)
        self.assertEqual(refused.get_json()["error"], "banned")

        unbanned = admin.delete("/admin/api/hwid-bans/" + device, headers=self.headers(token))
        self.assertEqual(unbanned.status_code, 200)
        for address in (probe_ip, "45.33.32.158"):
            admin.delete("/admin/api/bans/" + address, headers=self.headers(token))

    def test_14_sheriff_toggle(self):
        ip = "45.33.32.160"
        admin, token = self.admin()
        self.assertTrue(admin.get("/admin/api/sentinel").get_json()["enabled"])
        off = admin.post(
            "/admin/api/sentinel", json={"enabled": False}, headers=self.headers(token)
        )
        self.assertFalse(off.get_json()["enabled"])
        try:
            probe = self.new_client().get("/.git/config", environ_base={"REMOTE_ADDR": ip})
            self.assertEqual(probe.status_code, 404)
            bans = admin.get("/admin/api/bans").get_json()["bans"]
            self.assertFalse(any(item["ip"] == ip for item in bans))
        finally:
            admin.post(
                "/admin/api/sentinel", json={"enabled": True}, headers=self.headers(token)
            )


if __name__ == "__main__":
    unittest.main()
