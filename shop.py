# shop.py
# ══════════════════════════════════════════════════════════════════════════════
# 🛒 فروش خودکار اشتراک — فروشگاه داخل ربات تلگرام + اتصال به درگاه پرداخت
#
# چرخه‌ی کامل فروش:
#   ۱) خریدار توی ربات یکی از پلن‌ها رو انتخاب می‌کنه
#   ۲) برایش سفارش (Order) ساخته می‌شه و لینک پرداخت درگاه (زرین‌پال / آیدی‌پی)
#      تولید و ارسال می‌شود
#   ۳) بعد از پرداخت، درگاه مرورگر خریدار را به /pay/callback/{order_id}
#      برمی‌گرداند؛ پنل پرداخت را Verify کرده، کانفیگ (لینک + ساب) را با
#      مشخصات همان پلن به‌صورت خودکار صادر می‌کند و برای خریدار در تلگرام
#      می‌فرستد
#   ۴) ادمین‌ها هم پیام «فروش جدید» می‌گیرند
#
# درگاه‌ها: زرین‌پال (PG v4) · آیدی‌پی (v1.1) · درگاه «آزمایشی» برای تست کل
# چرخه بدون پول واقعی. همه‌ی وضعیت‌ها (پلن‌ها و سفارش‌ها) داخل همان فایل
# state اصلی پنل ذخیره می‌شوند و با ری‌استارت از بین نمی‌روند.
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import os
import secrets
from datetime import datetime, timedelta

import httpx

# ── وضعیت فروشگاه (در حافظه + ذخیره روی دیسک از طریق save_state اصلی) ──────────

def _env_truthy(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().lower() not in ("0", "false", "no", "off", "")

SHOP: dict = {
    # کلید فروشگاه: وقتی خاموش باشد ربات برای غیرادمین‌ها منوی خرید نشان نمی‌دهد
    "enabled": _env_truthy("SHOP_ENABLED", "0"),
    # درگاه فعال: zarinpal | idpay | test
    "gateway": (os.environ.get("SHOP_GATEWAY") or "zarinpal").strip().lower(),
    # مرچنت‌کد زرین‌پال یا API-Key آیدی‌پی (یک درگاه در هر لحظه فعال است)
    "merchant_id": (os.environ.get("SHOP_MERCHANT_ID") or "").strip(),
    # حالت سندباکس (تست درگاه بدون پول واقعی)
    "sandbox": _env_truthy("SHOP_SANDBOX", "0"),
    # اگر تنظیم شود callback درگاه با این آدرس ساخته می‌شود (وگرنه دامنه خود پنل)
    "public_base": (os.environ.get("SHOP_PUBLIC_BASE") or "").strip().rstrip("/"),
    "plans": {},   # plan_id -> {name, price_toman, limit_gb, days, speed_mbps, ip_limit, protocol, active, ...}
    "orders": {},  # order_id -> {status, plan snapshot, buyer, gateway, authority, ref_id, link_uid, ...}
}

SHOP_LOCK = asyncio.Lock()

# نام نمایشی درگاه‌ها (برای ربات و پنل)
GATEWAYS = {
    "zarinpal": "زرین‌پال",
    "idpay": "آیدی‌پی",
    "test": "آزمایشی (بدون پول واقعی)",
}

ORDER_TTL_MINUTES = 120  # سفارش‌های معلقِ پرداخت‌نشده بعد از این مدت منقضی می‌شوند


def _m():
    """دسترسی تنبل (lazy) به ماژول اصلی — تا shop قبل از main هم قابل ایمپورت باشد."""
    import main
    return main


# ── ذخیره/بازیابی وضعیت (توسط save_state / load_state اصلی صدا زده می‌شود) ──────

def shop_serialize() -> dict:
    return {
        "enabled": bool(SHOP.get("enabled")),
        "gateway": SHOP.get("gateway", "zarinpal"),
        "merchant_id": SHOP.get("merchant_id", ""),
        "sandbox": bool(SHOP.get("sandbox")),
        "public_base": SHOP.get("public_base", ""),
        "plans": dict(SHOP.get("plans", {})),
        "orders": dict(SHOP.get("orders", {})),
    }

def shop_load(data: dict | None):
    if not isinstance(data, dict):
        return
    if "enabled" in data:
        SHOP["enabled"] = bool(data["enabled"])
    gw = str(data.get("gateway") or "").strip().lower()
    if gw in GATEWAYS:
        SHOP["gateway"] = gw
    SHOP["merchant_id"] = str(data.get("merchant_id") or "").strip()
    SHOP["sandbox"] = bool(data.get("sandbox"))
    SHOP["public_base"] = str(data.get("public_base") or "").strip().rstrip("/")
    if isinstance(data.get("plans"), dict):
        SHOP["plans"].update(data["plans"])
    if isinstance(data.get("orders"), dict):
        SHOP["orders"].update(data["orders"])
    _m().logger.info(f"Shop state loaded: {len(SHOP['plans'])} plans, {len(SHOP['orders'])} orders")


# ── مدیریت پلن‌ها ─────────────────────────────────────────────────────────────

MIN_PRICE_TOMAN = 1000  # حداقل مبلغ قابل پرداخت در درگاه‌های ایرانی


def _new_id() -> str:
    return secrets.token_hex(4)

async def add_plan(
    name: str,
    price_toman: int,
    limit_gb: float = 0,
    days: int = 30,
    speed_mbps: float = 0,
    ip_limit: int = 0,
    protocol: str = "",
) -> tuple[str, dict]:
    name = (name or "").strip()[:60] or "پلن جدید"
    pid = _new_id()
    plan = {
        "id": pid,
        "name": name,
        "price_toman": max(0, int(price_toman)),
        "limit_gb": max(0.0, float(limit_gb or 0)),
        "days": max(0, int(days or 0)),
        "speed_mbps": max(0.0, float(speed_mbps or 0)),
        "ip_limit": max(0, int(ip_limit or 0)),
        "protocol": (protocol or "").strip(),
        "active": True,
        "sold_count": 0,
        "created_at": datetime.now().isoformat(),
    }
    async with SHOP_LOCK:
        SHOP["plans"][pid] = plan
    _m().log_activity("shop", f"پلن فروش «{name}» ساخته شد", "ok")
    await _save()
    return pid, plan

async def update_plan(pid: str, **fields) -> dict | None:
    async with SHOP_LOCK:
        plan = SHOP["plans"].get(pid)
        if not plan:
            return None
        if "name" in fields and str(fields["name"]).strip():
            plan["name"] = str(fields["name"]).strip()[:60]
        for key, cast in (("price_toman", int), ("days", int), ("ip_limit", int)):
            if key in fields and fields[key] is not None:
                plan[key] = max(0, cast(fields[key]))
        for key in ("limit_gb", "speed_mbps"):
            if key in fields and fields[key] is not None:
                plan[key] = max(0.0, float(fields[key] or 0))
        if "protocol" in fields:
            plan["protocol"] = str(fields["protocol"] or "").strip()
        updated = dict(plan)
    _m().log_activity("shop", f"پلن فروش «{updated['name']}» ویرایش شد", "info")
    await _save()
    return updated

async def remove_plan(pid: str) -> str | None:
    async with SHOP_LOCK:
        plan = SHOP["plans"].pop(pid, None)
        if not plan:
            return None
        name = plan["name"]
    _m().log_activity("shop", f"پلن فروش «{name}» حذف شد", "warn")
    await _save()
    return name

async def toggle_plan(pid: str) -> dict | None:
    async with SHOP_LOCK:
        plan = SHOP["plans"].get(pid)
        if not plan:
            return None
        plan["active"] = not plan.get("active", True)
        out = dict(plan)
    await _save()
    return out

def get_plan(pid: str) -> dict | None:
    return SHOP["plans"].get(pid)

def public_plans() -> list[dict]:
    """پلن‌های فعال، مرتب بر اساس قیمت — برای نمایش به خریدار."""
    plans = [p for p in SHOP["plans"].values() if p.get("active", True)]
    return sorted(plans, key=lambda p: p.get("price_toman", 0))


# ── سفارش‌ها ──────────────────────────────────────────────────────────────────

def callback_base() -> str:
    """آدرس پایه‌ی عمومی پنل برای ساخت callback درگاه."""
    base = SHOP.get("public_base", "")
    if base:
        return base
    try:
        return f"https://{_m().get_host()}"
    except Exception:
        return "https://localhost"

def callback_url(order_id: str) -> str:
    return f"{callback_base()}/pay/callback/{order_id}"

def _save():
    # ذخیره‌ی async وضعیت روی دیسک — در همه‌ی مسیرها داخل توابع async صدا زده می‌شود
    return _m().save_state()

async def _expire_stale_orders():
    """سفارش‌های معلق قدیمی‌تر از TTL را منقضی می‌کند (بدون حذف — برای گزارش می‌مانند)."""
    now = datetime.now()
    changed = False
    for o in SHOP["orders"].values():
        if o.get("status") != "pending":
            continue
        try:
            created = datetime.fromisoformat(o.get("created_at") or "")
        except ValueError:
            continue
        if now - created > timedelta(minutes=ORDER_TTL_MINUTES):
            o["status"] = "expired"
            changed = True
    if changed:
        await _save()

async def create_order(plan: dict, chat_id: int, username: str = "", fullname: str = "") -> tuple[dict, str | None, str]:
    """سفارش جدید + گرفتن لینک پرداخت از درگاه فعال.

    خروجی: (order, pay_url, error) — اگر pay_url خالی باشد error پیام دلیل است.
    """
    await _expire_stale_orders()
    gw = SHOP.get("gateway", "zarinpal")
    order_id = f"XR-{secrets.token_hex(4).upper()}"
    order = {
        "id": order_id,
        "plan_id": plan.get("id", ""),
        "plan_name": plan.get("name", "پلن"),
        "amount_toman": int(plan.get("price_toman", 0)),
        "limit_gb": plan.get("limit_gb", 0),
        "days": plan.get("days", 0),
        "speed_mbps": plan.get("speed_mbps", 0),
        "ip_limit": plan.get("ip_limit", 0),
        "protocol": plan.get("protocol", ""),
        "chat_id": chat_id,
        "username": (username or "").strip()[:64],
        "fullname": (fullname or "").strip()[:80],
        "gateway": gw,
        "status": "pending",
        "authority": "",
        "ref_id": "",
        "link_uid": "",
        "fail_reason": "",
        "created_at": datetime.now().isoformat(),
        "paid_at": "",
    }
    pay_url, authority, err = await _gateway_request(order)
    order["authority"] = authority or ""
    if not pay_url:
        order["status"] = "failed"
        order["fail_reason"] = err or "خطای درگاه پرداخت"
        async with SHOP_LOCK:
            SHOP["orders"][order_id] = order
        await _save()
        return order, None, order["fail_reason"]
    order["pay_url"] = pay_url
    async with SHOP_LOCK:
        SHOP["orders"][order_id] = order
    _m().log_activity("shop", f"سفارش {order_id} برای «{order['plan_name']}» ساخته شد ({order['amount_toman']:,} تومان)", "info")
    await _save()
    return order, pay_url, ""

def orders_for_chat(chat_id: int) -> list[dict]:
    out = [o for o in SHOP["orders"].values() if o.get("chat_id") == chat_id]
    return sorted(out, key=lambda o: o.get("created_at", ""), reverse=True)

def orders_recent(limit: int = 50) -> list[dict]:
    out = sorted(SHOP["orders"].values(), key=lambda o: o.get("created_at", ""), reverse=True)
    return out[:limit]

def shop_stats() -> dict:
    orders = list(SHOP["orders"].values())
    paid = [o for o in orders if o.get("status") == "paid"]
    today = datetime.now().date().isoformat()
    paid_today = [o for o in paid if (o.get("paid_at") or "").startswith(today)]
    return {
        "total_sales": len(paid),
        "sales_today": len(paid_today),
        "revenue_total_toman": sum(o.get("amount_toman", 0) for o in paid),
        "revenue_today_toman": sum(o.get("amount_toman", 0) for o in paid_today),
        "pending_orders": sum(1 for o in orders if o.get("status") == "pending"),
        "plans_count": len(SHOP["plans"]),
    }


# ── لایه‌ی درگاه‌ها ────────────────────────────────────────────────────────────
# همه‌ی تماس‌های HTTP با درگاه از داخل _gw_post می‌گذرند تا در تست‌ها قابل
# جایگزینی (mock) باشند و شبکه‌ی واقعی صدا زده نشود.

async def _gw_post(url: str, json_body: dict | None = None, headers: dict | None = None) -> dict:
    async with httpx.AsyncClient(timeout=25.0) as client:
        r = await client.post(url, json=json_body, headers=headers)
        return r.json()

def _toman_to_rial(toman: int) -> int:
    return int(toman) * 10

# ── زرین‌پال (PG v4) ──────────────────────────────────────────────────────────

def _zarinpal_base() -> str:
    return "https://sandbox.zarinpal.com" if SHOP.get("sandbox") else "https://payment.zarinpal.com"

async def _zarinpal_request(order: dict) -> tuple[str | None, str | None, str]:
    merchant = SHOP.get("merchant_id", "")
    if not merchant:
        return None, None, "مرچنت‌کد زرین‌پال تنظیم نشده (تنظیمات فروشگاه)"
    try:
        resp = await _gw_post(
            f"{_zarinpal_base()}/pg/v4/payment/request.json",
            {
                "merchant_id": merchant,
                "amount": _toman_to_rial(order["amount_toman"]),
                "callback_url": callback_url(order["id"]),
                "description": f"خرید اشتراک {order['plan_name']} — سفارش {order['id']}",
            },
        )
        data = resp.get("data") or {}
        authority = data.get("authority") or ""
        if str(data.get("code")) == "100" and authority:
            return f"{_zarinpal_base()}/pg/StartPay/{authority}", authority, ""
        errs = resp.get("errors") or data
        return None, None, f"خطای زرین‌پال: {errs}"
    except Exception as e:
        return None, None, f"ارتباط با زرین‌پال برقرار نشد: {e}"

async def _zarinpal_verify(order: dict) -> tuple[str, str, str]:
    """خروجی: (state, ref_id, message) — state یکی از paid/pending/failed"""
    merchant = SHOP.get("merchant_id", "")
    if not merchant or not order.get("authority"):
        return "pending", "", "اطلاعات پرداخت ناقص است"
    try:
        resp = await _gw_post(
            f"{_zarinpal_base()}/pg/v4/payment/verify.json",
            {
                "merchant_id": merchant,
                "amount": _toman_to_rial(order["amount_toman"]),
                "authority": order["authority"],
            },
        )
        data = resp.get("data") or {}
        code = data.get("code")
        if code in (100, 101):
            return "paid", str(data.get("ref_id") or ""), "پرداخت تأیید شد"
        if isinstance(code, int) and code < 0:
            # کدهای منفی معمولاً یعنی هنوز پرداختی روی این authority ثبت نشده
            return "pending", "", "پرداخت هنوز در زرین‌پال ثبت نشده؛ چند لحظه دیگر دوباره تلاش کنید"
        return "failed", "", f"تأیید پرداخت ناموفق بود (کد {code})"
    except Exception as e:
        return "pending", "", f"ارتباط با زرین‌پال برقرار نشد: {e}"

# ── آیدی‌پی (v1.1) ────────────────────────────────────────────────────────────

def _idpay_headers() -> dict:
    h = {"X-API-KEY": SHOP.get("merchant_id", ""), "Content-Type": "application/json"}
    if SHOP.get("sandbox"):
        h["X-SANDBOX"] = "1"
    return h

async def _idpay_request(order: dict) -> tuple[str | None, str | None, str]:
    if not SHOP.get("merchant_id"):
        return None, None, "API-Key آیدی‌پی تنظیم نشده (تنظیمات فروشگاه)"
    try:
        resp = await _gw_post(
            "https://api.idpay.ir/v1.1/payment",
            {
                "order_id": order["id"],
                "amount": _toman_to_rial(order["amount_toman"]),
                "callback": callback_url(order["id"]),
            },
            headers=_idpay_headers(),
        )
        pay_id = resp.get("id") or ""
        link = resp.get("link") or ""
        if pay_id and link:
            return link, pay_id, ""
        return None, None, f"خطای آیدی‌پی: {resp.get('error_message') or resp}"
    except Exception as e:
        return None, None, f"ارتباط با آیدی‌پی برقرار نشد: {e}"

async def _idpay_verify(order: dict) -> tuple[str, str, str]:
    if not SHOP.get("merchant_id") or not order.get("authority"):
        return "pending", "", "اطلاعات پرداخت ناقص است"
    try:
        resp = await _gw_post(
            "https://api.idpay.ir/v1.1/payment/verify",
            {"id": order["authority"], "order_id": order["id"]},
            headers=_idpay_headers(),
        )
        status = resp.get("status")
        try:
            status = int(status)
        except (TypeError, ValueError):
            status = -1
        if status in (100, 101):
            return "paid", str(resp.get("track_id") or ""), "پرداخت تأیید شد"
        if status in (1, 2, 7):  # در انتظار پرداخت/تأیید
            return "pending", "", "پرداخت هنوز تأیید نشده؛ چند لحظه دیگر دوباره تلاش کنید"
        return "failed", "", f"تأیید پرداخت ناموفق بود (وضعیت {status})"
    except Exception as e:
        return "pending", "", f"ارتباط با آیدی‌پی برقرار نشد: {e}"

# ── درگاه آزمایشی (کل چرخه بدون پول واقعی — برای تست و دمو) ───────────────────

async def _test_request(order: dict) -> tuple[str | None, str | None, str]:
    """صفحه‌ی پرداخت ساختگی روی خود پنل — بعد از «پرداخت» به همان callback برمی‌گردد."""
    authority = f"TEST-{secrets.token_hex(4).upper()}"
    return f"{callback_base()}/pay/test/{order['id']}", authority, ""

# ── دیسپچر درگاه فعال ─────────────────────────────────────────────────────────

async def _gateway_request(order: dict) -> tuple[str | None, str | None, str]:
    gw = order.get("gateway")
    if gw == "idpay":
        return await _idpay_request(order)
    if gw == "test":
        return await _test_request(order)
    return await _zarinpal_request(order)


# ── تأیید پرداخت + صدور خودکار کانفیگ ─────────────────────────────────────────

async def verify_and_finalize(order_id: str, params: dict | None = None, from_callback: bool = False) -> dict:
    """وضعیت سفارش را از درگاه می‌پرسد؛ اگر پرداخت شده باشد کانفیگ صادر می‌کند.

    خروجی: {"status": paid|pending|failed|expired|canceled|notfound,
            "order": ..., "link_uid": ..., "message": ...}
    """
    params = params or {}
    order = SHOP["orders"].get(order_id)
    if not order:
        return {"status": "notfound", "order": None, "link_uid": "", "message": "سفارش پیدا نشد"}
    await _expire_stale_orders()

    if order["status"] == "paid":
        return {"status": "paid", "order": order, "link_uid": order.get("link_uid", ""), "message": "این سفارش قبلاً تحویل شده"}
    if order["status"] in ("expired", "canceled"):
        return {"status": order["status"], "order": order, "link_uid": "", "message": "این سفارش منقضی/لغو شده؛ سفارش جدید ثبت کنید"}

    gw = order.get("gateway")
    state, ref_id, msg = "pending", "", ""

    if gw == "test":
        # درگاه آزمایشی: پارامتر status=NOK یعنی شبیه‌سازی پرداخت ناموفق
        if str(params.get("status", "OK")).upper() in ("NOK", "FAIL", "2"):
            state, msg = "failed", "پرداخت (آزمایشی) لغو/ناموفق بود"
        else:
            state, ref_id, msg = "paid", f"TEST-{secrets.token_hex(3).upper()}", "پرداخت آزمایشی موفق"
    elif gw == "idpay":
        state, ref_id, msg = await _idpay_verify(order)
    else:  # zarinpal
        if from_callback and str(params.get("Status", "OK")).upper() != "OK":
            state, msg = "failed", "پرداخت در زرین‌پال ناموفق/لغو شد"
        else:
            state, ref_id, msg = await _zarinpal_verify(order)

    if state == "paid":
        link_uid = await finalize_order(order, ref_id)
        return {"status": "paid", "order": order, "link_uid": link_uid, "message": msg or "پرداخت تأیید شد"}
    if state == "failed":
        order["status"] = "failed"
        order["fail_reason"] = msg
        await _save()
    return {"status": state, "order": order, "link_uid": "", "message": msg}


async def finalize_order(order: dict, ref_id: str = "") -> str:
    """پرداخت تأییدشده → ساخت کانفیگ با مشخصات پلن + اطلاع‌رسانی خریدار و ادمین‌ها.

    Idempotent است: اگر برای این سفارش قبلاً کانفیگ صادر شده، همان uid برمی‌گرداند.
    """
    async with SHOP_LOCK:
        if order.get("link_uid"):
            return order["link_uid"]
        order["status"] = "paid"
        order["paid_at"] = datetime.now().isoformat()
        order["ref_id"] = ref_id or order.get("ref_id", "")

    main = _m()
    expires_at = (datetime.now() + timedelta(days=int(order.get("days") or 0))).isoformat() if (order.get("days") or 0) > 0 else None
    limit_bytes = main.parse_size_to_bytes(float(order.get("limit_gb") or 0), "GB") if (order.get("limit_gb") or 0) > 0 else 0
    speed_limit_bytes = main.parse_speed_to_bytes(float(order.get("speed_mbps") or 0), "MBIT") if (order.get("speed_mbps") or 0) > 0 else 0
    buyer = order.get("username") or order.get("fullname") or str(order.get("chat_id", ""))
    label = f"{order.get('plan_name', 'پلن')} — {buyer}"[:60]

    uid, link = await main.make_link(
        label=label,
        limit_bytes=limit_bytes,
        expires_at=expires_at,
        note=f"🛒 فروش خودکار — سفارش {order.get('id')} (کد پیگیری {order.get('ref_id') or '—'})",
        protocol=order.get("protocol") or "",
        ip_limit=int(order.get("ip_limit") or 0),
        speed_limit_bytes=speed_limit_bytes,
    )

    async with SHOP_LOCK:
        order["link_uid"] = uid
        plan = SHOP["plans"].get(order.get("plan_id", ""))
        if plan is not None:
            plan["sold_count"] = int(plan.get("sold_count", 0)) + 1

    main.log_activity("shop", f"💰 فروش خودکار: «{order.get('plan_name')}» به {buyer} ({order.get('amount_toman', 0):,} تومان)", "ok")
    await _save()

    await _notify_everyone(order, uid, link)
    return uid


async def _notify_everyone(order: dict, uid: str, link: dict):
    """پیام تحویل کانفیگ به خریدار + پیام فروش جدید به ادمین‌ها (بی‌صدا اگر ربات خاموش است)."""
    try:
        from telegram_bot import send_buyer_message, send_admin_notification
    except Exception:
        return
    main = _m()
    buyer_text = delivery_message(order)
    if buyer_text:
        try:
            await send_buyer_message(int(order.get("chat_id") or 0), buyer_text)
        except Exception as e:
            main.logger.warning(f"Shop: could not notify buyer: {e}")

    admin_text = (
        f"💰 فروش جدید!\n\n"
        f"📦 پلن: {order.get('plan_name')}\n"
        f"💵 مبلغ: {order.get('amount_toman', 0):,} تومان\n"
        f"👤 خریدار: {order.get('fullname') or '—'} (@{order.get('username') or '—'}) [{order.get('chat_id')}]\n"
        f"🧾 سفارش: {order.get('id')} · پیگیری: {order.get('ref_id') or '—'}\n"
        f"🏷 کانفیگ صادرشده: «{link.get('label')}»"
    )
    try:
        await send_admin_notification(admin_text)
    except Exception:
        pass


def delivery_message(order: dict) -> str:
    """متن HTML پیام تحویل کانفیگ به خریدار (برای ارسال اولیه و ارسال مجدد از ربات)."""
    main = _m()
    uid = order.get("link_uid") or ""
    link = main.LINKS.get(uid)
    if not link:
        return ""
    host = main.get_host()
    vless = main.vless_link_for_link(link, uid, host)
    volume_txt = "نامحدود" if not order.get("limit_gb") else f"{order.get('limit_gb'):g} گیگابایت"
    days_txt = "نامحدود" if not order.get("days") else f"{order.get('days')} روز"
    return (
        f"🎉 پرداخت تأیید شد! کانفیگ شما به‌صورت خودکار ساخته شد.\n\n"
        f"📦 پلن: <b>{order.get('plan_name')}</b>\n"
        f"📊 حجم: {volume_txt} · ⏳ مدت: {days_txt}\n"
        f"🧾 کد پیگیری پرداخت: <code>{order.get('ref_id') or '—'}</code>\n\n"
        f"🔗 لینک اتصال مستقیم:\n<code>{vless}</code>\n\n"
        f"📄 لینک ساب (پیشنهادی — شامل ۳ پروتکل):\n<code>https://{host}/sub/{uid}</code>\n\n"
        f"🌐 صفحه‌ی مشتری (مصرف، انقضا و تمدید):\nhttps://{host}/subinfo/{uid}\n\n"
        f"برای دیدن دوباره‌ی این کانفیگ، از «📦 خریدهای من» استفاده کن."
    )
