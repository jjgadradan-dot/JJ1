# test_shop.py
# ══════════════════════════════════════════════════════════════════════════════
# 🛒 فروش خودکار اشتراک — تست کل چرخه‌ی فروش
#
# پلن‌سازی از API ادمین، ساخت سفارش، درگاه آزمایشی (test)، callback پرداخت،
# صدور خودکار کانفیگ با مشخصات پلن، درگاه زرین‌پال با HTTP ماک‌شده و آمار فروش.
#
# اجرا:  python3 test_shop.py
# ══════════════════════════════════════════════════════════════════════════════

import os
import tempfile
import unittest

TMP = tempfile.mkdtemp(prefix="xr-shop-")
os.environ["DATA_DIR"] = TMP
os.environ["NODE_API_TOKEN"] = "test-node-token"
os.environ["ADMIN_PASSWORD"] = "secret"
os.environ["SECRET_KEY"] = "unit-test-secret"

from fastapi.testclient import TestClient

import main
import shop


class ShopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)
        login = cls.client.post("/api/login", json={"password": "secret"})
        assert login.status_code == 200, login.text

    def setUp(self):
        # هر تست با فروشگاهِ تمیز شروع می‌شود (تست‌ها به ترتیب الفبا اجرا می‌شوند)
        shop.SHOP.update({
            "enabled": True,
            "gateway": "test",
            "merchant_id": "",
            "sandbox": False,
            "public_base": "",
            "plans": {},
            "orders": {},
        })
        # قفل‌های async ممکن است به لوپِ تست/پورتال قبلی مقید شده و خطای
        # "bound to a different event loop" بدهند — اینجا تازه‌سازی می‌شوند
        # (فقط در تست؛ در پروداکشن همه‌چیز در یک لوپ اجرا می‌شود)
        import asyncio as _aio
        main.SAVE_LOCK = _aio.Lock()
        main.LINKS_LOCK = _aio.Lock()
        main.SUBS_LOCK = _aio.Lock()
        shop.SHOP_LOCK = _aio.Lock()

    # ── API پلن‌ها ────────────────────────────────────────────────────────────

    def test_shop_api_requires_auth(self):
        c = TestClient(main.app)
        r = c.get("/api/shop")
        self.assertIn(r.status_code, (401, 403))

    def test_plan_crud_and_validation(self):
        # قیمت زیر حداقل → خطا
        r = self.client.post("/api/shop/plans", json={"name": "ارزان", "price_toman": 100})
        self.assertEqual(r.status_code, 400, r.text)

        # پلن جدید
        r = self.client.post("/api/shop/plans", json={
            "name": "پلن طلایی", "price_toman": 50000,
            "limit_gb": 30, "days": 30, "speed_mbps": 20, "ip_limit": 2,
        })
        self.assertEqual(r.status_code, 200, r.text)
        plan = r.json()["plan"]
        pid = plan["id"]

        # لیست پلن‌ها داخل وضعیت فروشگاه
        r = self.client.get("/api/shop")
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertTrue(d["enabled"])
        self.assertEqual(d["gateway"], "test")
        self.assertEqual(len(d["plans"]), 1)
        self.assertEqual(d["stats"]["plans_count"], 1)

        # ویرایش
        r = self.client.post(f"/api/shop/plans/{pid}", json={
            "name": "پلن طلایی+", "price_toman": 60000, "limit_gb": 40, "days": 45,
            "speed_mbps": 0, "ip_limit": 0, "protocol": "vless-ws",
        })
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["plan"]["price_toman"], 60000)

        # خاموش/روشن
        r = self.client.post(f"/api/shop/plans/{pid}/toggle")
        self.assertFalse(r.json()["plan"]["active"])
        r = self.client.post(f"/api/shop/plans/{pid}/toggle")
        self.assertTrue(r.json()["plan"]["active"])

        # حذف
        r = self.client.delete(f"/api/shop/plans/{pid}")
        self.assertTrue(r.json()["ok"])
        self.assertIsNone(shop.get_plan(pid))

    # ── چرخه‌ی کامل درگاه آزمایشی ────────────────────────────────────────────

    def test_gateway_full_flow(self):
        import asyncio
        r = self.client.post("/api/shop/plans", json={
            "name": "ماهانه", "price_toman": 80000,
            "limit_gb": 50, "days": 30, "speed_mbps": 10, "ip_limit": 3,
        })
        self.assertEqual(r.status_code, 200, r.text)
        plan = r.json()["plan"]
        pid = plan["id"]

        links_before = len(main.LINKS)

        # ساخت سفارش از طرف خریدار
        order, pay_url, err = asyncio.run(shop.create_order(plan, chat_id=111, username="ali", fullname="علی"))
        self.assertFalse(err, err)
        oid = order["id"]
        self.assertTrue(pay_url.endswith(f"/pay/test/{oid}"))
        self.assertEqual(order["status"], "pending")

        # صفحه پرداخت آزمایشی در دسترس است
        r = self.client.get(f"/pay/test/{oid}")
        self.assertEqual(r.status_code, 200)
        self.assertIn("درگاه آزمایشی", r.text)

        # شبیه‌سازی پرداخت موفق → callback → ریدایرکت به صفحه مشتری کانفیگ
        r = self.client.get(f"/pay/test/{oid}/simulate?result=ok", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn("/pay/callback/", r.headers["location"])
        r = self.client.get(f"/pay/callback/{oid}", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn("/subinfo/", r.headers["location"])

        # سفارش paid شده و کانفیگ با مشخصات پلن صادر شده
        order = shop.SHOP["orders"][oid]
        self.assertEqual(order["status"], "paid")
        self.assertTrue(order["link_uid"])
        self.assertTrue(order["ref_id"])
        link = main.LINKS[order["link_uid"]]
        self.assertEqual(len(main.LINKS), links_before + 1)
        self.assertEqual(link["limit_bytes"], 50 * 1024 ** 3)
        self.assertEqual(link["ip_limit"], 3)
        self.assertEqual(link["speed_limit_bytes"], int(10 * 1024 * 1024 / 8))
        self.assertTrue(link["label"].startswith("ماهانه"))
        self.assertIn("فروش خودکار", link["note"])
        import datetime as _dt
        exp = _dt.datetime.fromisoformat(link["expires_at"])
        self.assertGreater(exp, _dt.datetime.now() + _dt.timedelta(days=29))

        # پیام تحویل خریدار ساخته می‌شود
        msg = shop.delivery_message(order)
        self.assertIn("پرداخت تأیید شد", msg)
        self.assertIn(order["link_uid"], msg)

        # idempotent: تایید دوباره کانفیگ جدید نمی‌سازد
        res = asyncio.run(shop.verify_and_finalize(oid))
        self.assertEqual(res["status"], "paid")
        self.assertEqual(len(main.LINKS), links_before + 1)

        # آمار فروش
        stats = shop.shop_stats()
        self.assertEqual(stats["total_sales"], 1)
        self.assertEqual(stats["revenue_total_toman"], 80000)
        self.assertEqual(shop.get_plan(pid)["sold_count"], 1)

        # سفارش‌های خریدار
        self.assertEqual(len(shop.orders_for_chat(111)), 1)
        self.assertEqual(shop.orders_for_chat(222), [])

    def test_gateway_fail_flow(self):
        import asyncio
        pid, plan = asyncio.run(shop.add_plan("ناموفق", 10000, 5, 7))
        order, pay_url, err = asyncio.run(shop.create_order(plan, chat_id=333, username="boo"))
        self.assertTrue(pay_url)
        oid = order["id"]
        r = self.client.get(f"/pay/test/{oid}/simulate?result=fail", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        r = self.client.get(f"/pay/callback/{oid}?status=NOK", follow_redirects=False)
        self.assertEqual(r.status_code, 200)  # صفحه‌ی خطا (نه ریدایرکت)
        self.assertEqual(shop.SHOP["orders"][oid]["status"], "failed")

    def test_expired_and_unknown_orders(self):
        import asyncio
        from datetime import datetime, timedelta
        res = asyncio.run(shop.verify_and_finalize("XR-NOPE"))
        self.assertEqual(res["status"], "notfound")

        pid, plan = asyncio.run(shop.add_plan("کهنه", 5000, 1, 1))
        order, pay_url, _ = asyncio.run(shop.create_order(plan, chat_id=9))
        order["created_at"] = (datetime.now() - timedelta(hours=5)).isoformat()
        res = asyncio.run(shop.verify_and_finalize(order["id"]))
        self.assertEqual(res["status"], "expired")

    # ── زرین‌پال با HTTP ماک‌شده ─────────────────────────────────────────────

    def test_zarinpal_mocked_flow(self):
        import asyncio

        calls = []

        async def fake_gw_post(url, json_body=None, headers=None):
            calls.append(url)
            if url.endswith("/payment/request.json"):
                self.assertIn("merchant_id", json_body)
                self.assertEqual(json_body["amount"], 20000 * 10)  # تومان → ریال
                return {"data": {"code": 100, "authority": "FAKE-AUTH-1"}}
            if url.endswith("/payment/verify.json"):
                self.assertEqual(json_body["authority"], "FAKE-AUTH-1")
                return {"data": {"code": 100, "ref_id": 987654}}
            return {}

        orig = shop._gw_post
        shop._gw_post = fake_gw_post
        try:
            shop.SHOP["gateway"] = "zarinpal"
            shop.SHOP["merchant_id"] = "M" * 36
            pid, plan = asyncio.run(shop.add_plan("زرین", 20000, 10, 15))
            order, pay_url, err = asyncio.run(shop.create_order(plan, chat_id=555, username="zar"))
            self.assertFalse(err, err)
            self.assertIn("StartPay/FAKE-AUTH-1", pay_url)

            # «پرداخت کردم» بدون callback → verify از API
            res = asyncio.run(shop.verify_and_finalize(order["id"]))
            self.assertEqual(res["status"], "paid", res)
            self.assertEqual(res["order"]["ref_id"], "987654")
            self.assertTrue(res["order"]["link_uid"])
            self.assertTrue(any("verify.json" in u for u in calls))

            # callback با Status=NOK برای سفارش معلق → failed بدون verify
            order2, pay_url2, _ = asyncio.run(shop.create_order(plan, chat_id=556))
            res = asyncio.run(shop.verify_and_finalize(order2["id"], {"Status": "NOK"}, from_callback=True))
            self.assertEqual(res["status"], "failed")
        finally:
            shop._gw_post = orig
            shop.SHOP["gateway"] = "test"
            shop.SHOP["merchant_id"] = ""

    def test_zarinpal_without_merchant_fails_gracefully(self):
        import asyncio
        shop.SHOP["gateway"] = "zarinpal"
        shop.SHOP["merchant_id"] = ""
        try:
            pid, plan = asyncio.run(shop.add_plan("بدون مرچنت", 3000, 1, 1))
            order, pay_url, err = asyncio.run(shop.create_order(plan, chat_id=7))
            self.assertIsNone(pay_url)
            self.assertIn("مرچنت", err)
            self.assertEqual(order["status"], "failed")
        finally:
            shop.SHOP["gateway"] = "test"

    # ── ذخیره/بازیابی وضعیت ─────────────────────────────────────────────────

    def test_manual_order_api_end_to_end(self):
        """ساخت سفارش دستی از پنل (بدون ربات) + پرداخت + صدور خودکار کانفیگ."""
        r = self.client.post("/api/shop/plans", json={"name": "وب", "price_toman": 30000, "limit_gb": 15, "days": 20})
        pid = r.json()["plan"]["id"]

        # پلن ناموجود → 404
        r = self.client.post("/api/shop/orders", json={"plan_id": "nope"})
        self.assertEqual(r.status_code, 404)

        # سفارش دستی
        r = self.client.post("/api/shop/orders", json={"plan_id": pid, "fullname": "مشتری وب"})
        self.assertEqual(r.status_code, 200, r.text)
        d = r.json()
        oid = d["order"]["id"]
        self.assertTrue(d["pay_url"])

        # خریدار لینک پرداخت را باز می‌کند → صفحه‌ی درگاه آزمایشی
        r = self.client.get(f"/pay/test/{oid}")
        self.assertEqual(r.status_code, 200)

        # پرداخت موفق → callback → ریدایرکت به صفحه‌ی مشتری
        r = self.client.get(f"/pay/callback/{oid}?status=OK", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn("/subinfo/", r.headers["location"])

        order = shop.SHOP["orders"][oid]
        self.assertEqual(order["status"], "paid")
        self.assertEqual(order["fullname"], "مشتری وب")
        link = main.LINKS[order["link_uid"]]
        self.assertEqual(link["limit_bytes"], 15 * 1024 ** 3)

        # لیست سفارش‌های ادمین
        r = self.client.get("/api/shop/orders")
        self.assertTrue(any(o["id"] == oid for o in r.json()["orders"]))

    def test_state_roundtrip(self):
        import asyncio
        pid, plan = asyncio.run(shop.add_plan("ماندگار", 1000, 2, 3))
        snap = shop.shop_serialize()
        self.assertEqual(snap["plans"][pid]["name"], "ماندگار")

        # شبیه‌سازی ری‌استارت: وضعیت خالی + بازیابی
        saved_orders = shop.SHOP["orders"]
        shop.SHOP["plans"] = {}
        shop.SHOP["orders"] = {}
        shop.SHOP["enabled"] = False
        shop.shop_load(snap)
        self.assertTrue(shop.SHOP["enabled"])
        self.assertIn(pid, shop.SHOP["plans"])
        self.assertEqual(shop.SHOP["orders"], saved_orders)

        # عدم وجود کلید shop نباید خطا بدهد
        shop.shop_load(None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
