# test_subscription.py
# ══════════════════════════════════════════════════════════════════════════════
# نمایش حجم، زمان و نام VPN داخل ساب / v2rayNG
#
# اجرا:  python3 test_subscription.py
# ══════════════════════════════════════════════════════════════════════════════

import base64
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from urllib.parse import unquote

TMP = tempfile.mkdtemp(prefix="xr-sub-")
os.environ["DATA_DIR"] = TMP
os.environ["NODE_API_TOKEN"] = "test-node-token"
os.environ["ADMIN_PASSWORD"] = "secret"
os.environ["SECRET_KEY"] = "unit-test-secret"

from fastapi.testclient import TestClient

import main


def _decode_sub(body: str) -> str:
    return base64.b64decode(body).decode("utf-8")


class SubscriptionUserinfoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)
        login = cls.client.post("/api/login", json={"password": "secret"})
        assert login.status_code == 200, login.text

    def _make_link(self, **kwargs):
        payload = {
            "label": kwargs.get("label", "کاربر علی"),
            "limit_value": kwargs.get("limit_value", 10),
            "limit_unit": kwargs.get("limit_unit", "GB"),
            "expires_days": kwargs.get("expires_days", 30),
            "location": kwargs.get("location", "آلمان"),
            "protocol": kwargs.get("protocol", "vless-ws"),
        }
        r = self.client.post("/api/links", json=payload)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def test_helpers_userinfo_and_remarks(self):
        exp = (datetime.now() + timedelta(days=12)).isoformat()
        link = {
            "label": "علی",
            "location": "آلمان",
            "used_bytes": 2 * 1024 ** 3,
            "limit_bytes": 10 * 1024 ** 3,
            "expires_at": exp,
        }
        info = main.subscription_userinfo_header([link])
        self.assertIn("upload=0", info)
        self.assertIn(f"download={2 * 1024 ** 3}", info)
        self.assertIn(f"total={10 * 1024 ** 3}", info)
        self.assertIn("expire=", info)
        expire_val = int(info.split("expire=")[1])
        self.assertGreater(expire_val, 0)

        extras, nxt = main.sub_info_lines_for_link(link, 1)
        self.assertEqual(len(extras), 2)
        self.assertEqual(nxt, 3)
        joined_extras = "\n".join(unquote(x) for x in extras)
        self.assertIn("📦", joined_extras)
        self.assertIn("📅", joined_extras)
        self.assertIn("🌐", joined_extras)
        self.assertIn("آلمان", joined_extras)
        self.assertNotIn("علی |", joined_extras)

        title = main.profile_title_header("علی")
        self.assertTrue(title.startswith("base64:"))
        decoded = base64.b64decode(title.split(":", 1)[1]).decode("utf-8")
        self.assertEqual(decoded, "علی")

        headers = main.build_subscription_headers("علی", [link], "https://example.com/subinfo/x")
        # هدر HTTP باید latin-1 باشد — متن فارسی خام نباید داخلش برود
        for k, v in headers.items():
            v.encode("latin-1")
        self.assertIn("subscription-userinfo", headers)
        self.assertEqual(headers["profile-update-interval"], "1")
        self.assertEqual(headers["profile-web-page-url"], "https://example.com/subinfo/x")

        lines = main.sub_info_lines([link])
        self.assertEqual(len(lines), 2)
        joined = "\n".join(unquote(x) for x in lines)
        self.assertIn("📦", joined)
        self.assertIn("📅", joined)
        self.assertIn("🌐 لوکیشن", joined)
        self.assertIn("آلمان", joined)

    def test_customer_sub_protocols_order(self):
        from protocols import customer_sub_protocols
        self.assertEqual(
            customer_sub_protocols("vless-ws"),
            ["vless-ws", "xhttp-stream-one", "trojan-ws", "vmess-ws"],
        )
        self.assertEqual(
            customer_sub_protocols("trojan-ws"),
            ["trojan-ws", "vless-ws", "xhttp-stream-one", "vmess-ws"],
        )
        self.assertEqual(
            customer_sub_protocols("xhttp-packet-up"),
            ["xhttp-packet-up", "vless-ws", "trojan-ws", "vmess-ws"],
        )
        self.assertEqual(len(customer_sub_protocols("nope")), 4)

        link = {"label": "علی", "protocol": "vless-ws"}
        lines = main.share_links_for_customer(link, "11111111-2222-3333-4444-555555555555", "cdn.example.com")
        self.assertEqual(len(lines), 4)
        self.assertTrue(lines[0].startswith("vless://"))
        self.assertIn("type=xhttp", lines[1])
        self.assertTrue(lines[2].startswith("trojan://"))
        self.assertTrue(lines[3].startswith("vmess://"))
        joined = unquote("\n".join(lines))
        self.assertIn("علی · VLESS-WS", joined)
        self.assertIn("علی · XHTTP", joined)
        self.assertIn("علی · Trojan", joined)
        # remark در لینک VMess داخل base64/JSON است
        import base64 as _b64, json as _json
        vmess_ps = _json.loads(_b64.b64decode(lines[3][len("vmess://"):]).decode())["ps"]
        self.assertIn("علی · VMess", vmess_ps)

    def test_unlimited_userinfo(self):
        link = {"used_bytes": 123, "limit_bytes": 0, "expires_at": None}
        info = main.subscription_userinfo_header([link])
        self.assertEqual(info, "upload=0; download=123; total=0; expire=0")
        remark = main.usage_remark_suffix(link)
        self.assertIn("∞", remark)

    def test_single_sub_headers_and_body(self):
        data = self._make_link()
        uid = data["uuid"]
        # مصرف ساختگی تا در ساب دیده شود
        main.LINKS[uid]["used_bytes"] = 512 * 1024 ** 2

        r = self.client.get(f"/sub/{uid}")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn("subscription-userinfo", r.headers)
        userinfo = r.headers["subscription-userinfo"]
        self.assertIn("upload=0", userinfo)
        self.assertIn(f"download={512 * 1024 ** 2}", userinfo)
        self.assertIn(f"total={10 * 1024 ** 3}", userinfo)
        self.assertTrue(r.headers["profile-title"].startswith("base64:"))
        self.assertEqual(r.headers["profile-update-interval"], "1")
        self.assertIn("/subinfo/", r.headers.get("profile-web-page-url", ""))

        body = unquote(_decode_sub(r.text))
        parts = [p for p in body.split("\n") if p.strip()]
        self.assertGreaterEqual(len(parts), 5)
        self.assertIn("کاربر علی", parts[0])
        self.assertNotIn("📦", parts[0])
        self.assertNotIn("🌐", parts[0])
        # چهار پروتکل واقعی از همان UUID، بعد ردیف حجم و لوکیشن
        real = parts[:4]
        self.assertTrue(any("type=ws" in p and p.startswith("vless://") for p in real))
        self.assertTrue(any("type=xhttp" in p for p in real))
        self.assertTrue(any(p.startswith("trojan://") for p in real))
        self.assertTrue(any(p.startswith("vmess://") for p in real))
        for p in real:
            if p.startswith("vmess://"):
                import base64 as _b64, json as _json
                cfg = _json.loads(_b64.b64decode(p[len("vmess://"):]).decode())
                self.assertIn("کاربر علی", cfg.get("ps", ""))
            else:
                self.assertIn("کاربر علی", p)
            self.assertNotIn("📦", p)
        self.assertIn("📦 حجم", parts[4])
        self.assertIn("📅 زمان", parts[4])
        self.assertIn("🌐 لوکیشن", parts[5])
        self.assertIn("آلمان", parts[5])

    def test_group_sub_aggregates_usage(self):
        a = self._make_link(label="سرور ۱", limit_value=5, expires_days=10)
        b = self._make_link(label="سرور ۲", limit_value=5, expires_days=20)
        main.LINKS[a["uuid"]]["used_bytes"] = 1024 ** 3
        main.LINKS[b["uuid"]]["used_bytes"] = 2 * 1024 ** 3

        created = self.client.post("/api/subs", json={"name": "گروه تست"})
        self.assertEqual(created.status_code, 200, created.text)
        sub = created.json()
        self.client.patch(
            f"/api/subs/{sub['sub_id']}",
            json={"link_ids": [a["uuid"], b["uuid"]]},
        )
        main.LINKS[a["uuid"]]["sub_id"] = sub["sub_id"]
        main.LINKS[b["uuid"]]["sub_id"] = sub["sub_id"]

        r = self.client.get(f"/sub-group/{sub['uuid_key']}")
        self.assertEqual(r.status_code, 200, r.text)
        userinfo = r.headers["subscription-userinfo"]
        self.assertIn(f"download={3 * 1024 ** 3}", userinfo)
        self.assertIn(f"total={10 * 1024 ** 3}", userinfo)
        body = unquote(_decode_sub(r.text))
        self.assertIn("سرور ۱", body)
        self.assertIn("سرور ۲", body)
        self.assertIn("📦 حجم", body)
        self.assertIn("🌐 لوکیشن", body)
        self.assertEqual(body.count("📦 حجم"), 2)
        self.assertEqual(body.count("🌐 لوکیشن"), 2)
        self.assertEqual(body.count("سرور ۱ ·"), 3)
        self.assertEqual(body.count("سرور ۲ ·"), 3)
        self.assertIn("trojan://", body)
        self.assertIn("type=xhttp", body)

    def test_node_api_subscription_has_userinfo(self):
        self._make_link(label="نود-ساب")
        r = self.client.get(
            "/api/node/v1/subscription",
            headers={"Authorization": "Bearer test-node-token"},
        )
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn("subscription-userinfo", r.headers)
        self.assertIn("vless://", _decode_sub(r.text))


if __name__ == "__main__":
    unittest.main()
