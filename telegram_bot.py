# telegram_bot.py
# ══════════════════════════════════════════════════════════════════════════════
# ربات مدیریت تلگرام — ساخت/حذف/فعال‌غیرفعال/مشاهده‌ی کانفیگ‌ها، فقط برای ادمین‌های
# مجاز (TELEGRAM_ADMIN_IDS). با long polling کار می‌کنه، نیازی به دامنه/webhook نداره.
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import os
import re

import httpx

from datetime import datetime, timedelta

from main import (
    LINKS,
    make_link,
    remove_link,
    set_link_active,
    vless_link_for_link,
    get_host,
    fmt_bytes,
    is_link_allowed,
    logger,
    PROTOCOLS,
    DEFAULT_PROTOCOL,
    FINGERPRINTS,
    DEFAULT_FINGERPRINT,
    DEFAULT_ALPN_BY_PROTOCOL,
    DEFAULT_PORT,
    DEFAULT_SPEED_LIMIT,
    MIN_PORT,
    MAX_PORT,
    parse_size_to_bytes,
    parse_speed_to_bytes,
    SUBS,
    create_sub_group,
    set_link_sub,
    remove_sub_group,
    CONFIG,
)

from shop import (
    SHOP as SHOP_STATE,
    GATEWAYS as SHOP_GATEWAYS,
    MIN_PRICE_TOMAN,
    add_plan as shop_add_plan,
    remove_plan as shop_remove_plan,
    toggle_plan as shop_toggle_plan,
    get_plan as shop_get_plan,
    public_plans as shop_public_plans,
    create_order as shop_create_order,
    verify_and_finalize as shop_verify_finalize,
    orders_for_chat as shop_orders_for_chat,
    orders_recent as shop_orders_recent,
    shop_stats as shop_stats,
    delivery_message as shop_delivery_message,
)

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
_admin_ids_raw = os.environ.get("TELEGRAM_ADMIN_IDS", "").strip()
ADMIN_IDS = {int(x) for x in _admin_ids_raw.replace(" ", "").split(",") if x.isdigit()} if _admin_ids_raw else set()

API_BASE = f"https://api.telegram.org/bot{BOT_TOKEN}"
PAGE_SIZE = 6

_client: httpx.AsyncClient | None = None
_poll_task: asyncio.Task | None = None
_running = False
_pending: dict = {}   # chat_id -> {"action": "wizard", "step": "...", "data": {...}}

# ── Config creation wizard ────────────────────────────────────────────────────
# مراحل ساخت کانفیگ جدید، دقیقاً هم‌راستا با فیلدهایی که پنل وب موقع ساخت کاربر می‌گیره:
# برچسب، پروتکل، fingerprint، ALPN، پورت، محدودیت حجم، محدودیت سرعت، محدودیت آی‌پی، روز انقضا.
WIZARD_STEPS = ["label", "protocol", "fingerprint", "alpn", "port", "volume", "speed", "iplimit", "days"]

PROTOCOL_LABELS = {
    "vless-ws": "VLESS + WebSocket",
    "xhttp-packet-up": "XHTTP (packet-up)",
    "xhttp-stream-up": "XHTTP (stream-up)",
    "xhttp-stream-one": "XHTTP (stream-one)",
}

def _protocol_label(p: str) -> str:
    return PROTOCOL_LABELS.get(p, p)

def _fp_label(fp: str) -> str:
    return fp.capitalize()

_VOLUME_RE = re.compile(r"^([\d.]+)\s*(GB|MB|KB)?$", re.IGNORECASE)
_SPEED_RE = re.compile(r"^([\d.]+)\s*(MBIT|MBPS|MB|KB)?$", re.IGNORECASE)

def _parse_volume_text(text: str):
    """ورودی مثل '10GB' یا '500 MB' رو به بایت تبدیل می‌کنه. اگه نامعتبر بود None برمی‌گردونه."""
    m = _VOLUME_RE.match(text.strip())
    if not m:
        return None
    try:
        value = float(m.group(1))
    except ValueError:
        return None
    if value <= 0:
        return 0
    unit = (m.group(2) or "GB").upper()
    return parse_size_to_bytes(value, unit)

def _parse_speed_text(text: str):
    """ورودی مثل '20' یا '20Mbit' رو به بایت‌بر‌ثانیه تبدیل می‌کنه (پیش‌فرض واحد Mbit)."""
    m = _SPEED_RE.match(text.strip())
    if not m:
        return None
    try:
        value = float(m.group(1))
    except ValueError:
        return None
    if value <= 0:
        return 0
    unit_raw = (m.group(2) or "MBIT").upper()
    unit = "MBIT" if unit_raw in ("MBIT", "MBPS") else unit_raw
    return parse_speed_to_bytes(value, unit)

def _parse_nonneg_int(text: str):
    try:
        n = int(text.strip())
    except ValueError:
        return None
    return max(0, n)

# ── Telegram API helpers ────────────────────────────────────────────────────
async def _call(method: str, **params):
    if _client is None:
        return None
    try:
        r = await _client.post(f"{API_BASE}/{method}", json=params, timeout=40)
        data = r.json()
        if not data.get("ok"):
            logger.warning(f"Telegram API {method} failed: {data}")
        return data
    except Exception as e:
        logger.warning(f"Telegram API {method} error: {e}")
        return None

async def _send(chat_id: int, text: str, kb: dict | None = None):
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
    if kb:
        payload["reply_markup"] = kb
    return await _call("sendMessage", **payload)

async def _edit(chat_id: int, message_id: int, text: str, kb: dict | None = None):
    payload = {"chat_id": chat_id, "message_id": message_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
    if kb:
        payload["reply_markup"] = kb
    res = await _call("editMessageText", **payload)
    if res is None or not res.get("ok"):
        # اگه ادیت به هر دلیلی نشد (مثلاً پیام قدیمی/حذف‌شده)، پیام جدید بفرست
        await _send(chat_id, text, kb)

async def _answer_cb(cb_id: str, text: str = ""):
    await _call("answerCallbackQuery", callback_query_id=cb_id, text=text)

def _is_admin(chat_id: int) -> bool:
    return chat_id in ADMIN_IDS

async def send_admin_notification(text: str) -> int:
    """ارسال پیام به همه ادمین‌های مجاز (مثل sendAdminNotification در Nyx Panel).

    برای هشدارهای خودکار مثل سوئیچ SNI توسط دیمون Auto-Failover استفاده می‌شود.
    اگر ربات غیرفعال باشد یا ادمینی تعریف نشده باشد، بی‌صدا برمی‌گردد.
    """
    if _client is None or not ADMIN_IDS:
        return 0
    sent = 0
    for cid in ADMIN_IDS:
        try:
            res = await _send(cid, text)
            if res and res.get("ok"):
                sent += 1
        except Exception as e:
            logger.warning(f"Telegram send_admin_notification -> {cid} failed: {e}")
    return sent

async def send_admin_document(payload: bytes, filename: str, caption: str = "") -> int:
    """ارسال یک فایل (مثل بکاپ دیتابیس) به همه ادمین‌های مجاز.

    از multipart/form-data استفاده می‌کند چون sendDocument فایل باینری می‌خواهد.
    خروجی: تعداد ادمین‌هایی که فایل با موفقیت برایشان ارسال شد.
    """
    if _client is None or not ADMIN_IDS:
        return 0
    sent = 0
    for cid in ADMIN_IDS:
        try:
            r = await _client.post(
                f"{API_BASE}/sendDocument",
                data={"chat_id": str(cid), "caption": caption[:1024], "parse_mode": "HTML"},
                files={"document": (filename, payload, "application/json")},
                timeout=120,
            )
            if r.json().get("ok"):
                sent += 1
            else:
                logger.warning(f"Telegram sendDocument -> {cid}: {r.text[:200]}")
        except Exception as e:
            logger.warning(f"Telegram sendDocument -> {cid} failed: {e}")
    return sent


async def send_buyer_message(chat_id: int, text: str, kb: dict | None = None):
    """ارسال پیام به خریدار (فروشگاه) — اگر ربات خاموش باشد بی‌صدا برمی‌گرداند."""
    if _client is None or not chat_id:
        return 0
    res = await _send(chat_id, text, kb)
    return 1 if (res and res.get("ok")) else 0


async def _download_file(file_id: str) -> bytes | None:
    """دانلود فایل آپلودشده توسط ادمین (برای بازیابی بکاپ)."""
    if _client is None:
        return None
    try:
        info = await _call("getFile", file_id=file_id)
        if not info or not info.get("ok"):
            return None
        path = info["result"]["file_path"]
        r = await _client.get(f"https://api.telegram.org/file/bot{BOT_TOKEN}/{path}", timeout=120)
        if r.status_code != 200:
            return None
        return r.content
    except Exception as e:
        logger.warning(f"Telegram _download_file failed: {e}")
        return None


async def _handle_document(msg: dict):
    """دریافت فایل بکاپ از ادمین و بازیابی ۱-کلیک (مثل Nyx)."""
    chat_id = msg.get("chat", {}).get("id")
    doc = msg.get("document") or {}
    if chat_id is None:
        return
    if not _is_admin(chat_id):
        await _send(chat_id, "⛔ شما اجازه‌ی دسترسی به این ربات رو ندارید.")
        return

    name = str(doc.get("file_name") or "")
    if not name.lower().endswith(".json"):
        await _send(chat_id, "📎 فقط فایل بکاپ با پسوند <b>.json</b> پذیرفته می‌شود.")
        return
    if int(doc.get("file_size") or 0) > 20 * 1024 * 1024:
        await _send(chat_id, "⚠️ حجم فایل بیش از ۲۰ مگابایت است.")
        return

    await _send(chat_id, f"⏳ در حال دریافت و بررسی <b>{name}</b>…")
    raw = await _download_file(doc.get("file_id"))
    if raw is None:
        await _send(chat_id, "❌ دانلود فایل از تلگرام ناموفق بود.")
        return

    try:
        from backup_service import restore_backup
        result = await restore_backup(raw)
    except ValueError as e:
        await _send(chat_id, f"❌ بازیابی انجام نشد:\n<code>{str(e)[:300]}</code>")
        return
    except Exception as e:
        logger.warning(f"Telegram restore failed: {e}")
        await _send(chat_id, f"❌ خطای غیرمنتظره در بازیابی:\n<code>{str(e)[:300]}</code>")
        return

    await _send(
        chat_id,
        "✅ <b>بازیابی با موفقیت انجام شد!</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔗 کانفیگ‌ها: <b>{result['links_restored']}</b>\n"
        f"👥 گروه‌ها: <b>{result['subs_restored']}</b>\n"
        f"🖥️ نودها: <b>{result['nodes_restored']}</b>\n"
        f"🔐 اعتبارسنجی SHA-256: <b>{'انجام شد ✅' if result['checksum_verified'] else 'نداشت ⚠️'}</b>\n"
        f"🔑 رمز پنل: <b>{'بازگردانی شد' if result['password_restored'] else 'دست‌نخورده'}</b>\n"
        f"📅 تاریخ بکاپ: {result.get('backup_created_at') or '—'}\n\n"
        "<i>یک نسخهٔ ایمنی از وضعیت قبلی هم ذخیره شد.</i>",
        _main_menu_kb(),
    )


# ── Keyboards ────────────────────────────────────────────────────────────────
def _main_menu_kb():
    return {"inline_keyboard": [
        [{"text": "📋 لیست کانفیگ‌ها", "callback_data": "list:0"}],
        [{"text": "➕ ساخت کانفیگ جدید", "callback_data": "newcfg"}],
        [{"text": "🗂 گروه‌های ساب (لینک حرفه‌ای)", "callback_data": "subs:0"}],
        [{"text": "🛡️ سوئیچ خودکار SNI", "callback_data": "autofailover"}],
        [{"text": "🛒 فروشگاه (فروش خودکار)", "callback_data": "shmenu"}],
        [{"text": "🔄 رفرش", "callback_data": "menu"}],
    ]}

def _links_list_kb(page: int):
    items = sorted(LINKS.items(), key=lambda kv: kv[1].get("created_at", ""), reverse=True)
    total = len(items)
    start = page * PAGE_SIZE
    chunk = items[start:start + PAGE_SIZE]
    rows = []
    for uid, l in chunk:
        dot = "🟢" if is_link_allowed(l) else "🔴"
        rows.append([{"text": f"{dot} {l.get('label','?')[:28]}", "callback_data": f"view:{uid}"}])
    nav = []
    if start > 0:
        nav.append({"text": "◀ قبلی", "callback_data": f"list:{page-1}"})
    if start + PAGE_SIZE < total:
        nav.append({"text": "بعدی ▶", "callback_data": f"list:{page+1}"})
    if nav:
        rows.append(nav)
    rows.append([{"text": "➕ ساخت کانفیگ جدید", "callback_data": "newcfg"}])
    rows.append([{"text": "⬅ منوی اصلی", "callback_data": "menu"}])
    return {"inline_keyboard": rows}

def _link_detail_kb(uid: str, active: bool):
    return {"inline_keyboard": [
        [{"text": "🔗 نمایش لینک اتصال", "callback_data": f"link:{uid}"}],
        [{"text": "🗂 گروه ساب (لینک حرفه‌ای)", "callback_data": f"cfggroup:{uid}"}],
        [{"text": ("⛔ غیرفعال‌سازی" if active else "✅ فعال‌سازی"), "callback_data": f"toggle:{uid}"}],
        [{"text": "🗑 حذف کانفیگ", "callback_data": f"del:{uid}"}],
        [{"text": "⬅ بازگشت به لیست", "callback_data": "list:0"}],
    ]}

def _confirm_delete_kb(uid: str):
    return {"inline_keyboard": [
        [{"text": "✅ بله، حذف کن", "callback_data": f"delok:{uid}"},
         {"text": "❌ انصراف", "callback_data": f"view:{uid}"}],
    ]}

# ── Wizard keyboards ─────────────────────────────────────────────────────────
def _wizard_cancel_kb():
    return {"inline_keyboard": [[{"text": "❌ انصراف", "callback_data": "w:cancel"}]]}

def _wizard_protocol_kb():
    rows = [[{"text": _protocol_label(p), "callback_data": f"w:proto:{p}"}] for p in PROTOCOLS]
    rows.append([{"text": "❌ انصراف", "callback_data": "w:cancel"}])
    return {"inline_keyboard": rows}

def _wizard_fp_kb():
    rows, row = [], []
    for fp in FINGERPRINTS:
        row.append({"text": _fp_label(fp), "callback_data": f"w:fp:{fp}"})
        if len(row) == 3:
            rows.append(row); row = []
    if row:
        rows.append(row)
    rows.append([{"text": "❌ انصراف", "callback_data": "w:cancel"}])
    return {"inline_keyboard": rows}

def _wizard_skip_kb(step_key: str, label: str):
    return {"inline_keyboard": [
        [{"text": label, "callback_data": f"w:skip:{step_key}"}],
        [{"text": "❌ انصراف", "callback_data": "w:cancel"}],
    ]}

ALPN_PRESET_MAP = {"p1": "http/1.1", "p2": "h2,http/1.1", "p3": "h2"}

def _wizard_alpn_kb():
    return {"inline_keyboard": [
        [{"text": "🔤 http/1.1 (پیشنهادی)", "callback_data": "w:alpnpreset:p1"}],
        [{"text": "🔤 h2,http/1.1", "callback_data": "w:alpnpreset:p2"}],
        [{"text": "🔤 h2", "callback_data": "w:alpnpreset:p3"}],
        [{"text": "⏭ پیش‌فرض پروتکل", "callback_data": "w:skip:alpn"}],
        [{"text": "❌ انصراف", "callback_data": "w:cancel"}],
    ]}

def _wizard_unlimited_kb(step_key: str):
    return _wizard_skip_kb(step_key, "♾ نامحدود")

def _wizard_confirm_kb():
    return {"inline_keyboard": [
        [{"text": "✅ ساخت کانفیگ", "callback_data": "w:confirm"}],
        [{"text": "❌ انصراف", "callback_data": "w:cancel"}],
    ]}

def _wizard_prompt(step: str, data: dict) -> str:
    n = WIZARD_STEPS.index(step) + 1 if step in WIZARD_STEPS else len(WIZARD_STEPS)
    head = f"🧩 ساخت کانفیگ جدید — مرحله {n}/{len(WIZARD_STEPS)}\n\n"
    if step == "label":
        return head + "✏️ اسم/برچسب کانفیگ رو بفرست:"
    if step == "protocol":
        return head + "🌐 پروتکل رو از دکمه‌های زیر انتخاب کن:"
    if step == "fingerprint":
        return head + "🖐 Fingerprint (uTLS) رو انتخاب کن:"
    if step == "alpn":
        return head + ("🔤 ALPN رو از دکمه‌های زیر انتخاب کن (پیشنهادی: <code>http/1.1</code>)\n"
                        "یا خودت هر مقدار دلخواهی رو تایپ و ارسال کن (مثلاً h2,http/1.1):")
    if step == "port":
        return head + f"🔌 شماره پورت (بین {MIN_PORT} تا {MAX_PORT}) رو بفرست\nیا پیش‌فرض ({DEFAULT_PORT}) رو انتخاب کن:"
    if step == "volume":
        return head + "📦 محدودیت حجم مصرفی رو بفرست، مثلاً:\n<code>10GB</code> یا <code>500MB</code>\nیا دکمه‌ی نامحدود رو بزن:"
    if step == "speed":
        return head + "🚀 محدودیت سرعت رو به مگابیت‌بر‌ثانیه بفرست، مثلاً <code>20</code>\nیا دکمه‌ی نامحدود رو بزن:"
    if step == "iplimit":
        return head + "👥 حداکثر تعداد آی‌پی/کاربر هم‌زمان مجاز رو بفرست\nیا دکمه‌ی نامحدود رو بزن:"
    if step == "days":
        return head + "📅 تعداد روزهای اعتبار کانفیگ رو بفرست\nیا دکمه‌ی نامحدود (بدون انقضا) رو بزن:"
    return head

def _wizard_summary(data: dict) -> str:
    limit = "نامحدود" if not data.get("limit_bytes") else fmt_bytes(data["limit_bytes"])
    speed = "نامحدود" if not data.get("speed_limit_bytes") else f"{data['speed_limit_bytes']*8/1024/1024:.1f} Mbps"
    iplim = data.get("ip_limit", 0) or "نامحدود"
    days = data.get("expires_days", 0)
    days_txt = "بدون انقضا" if not days else f"{days} روز"
    proto = data.get("protocol", DEFAULT_PROTOCOL)
    alpn = data.get("alpn") or f"پیش‌فرض ({DEFAULT_ALPN_BY_PROTOCOL.get(proto, 'http/1.1')})"
    return (
        "🧩 خلاصه‌ی کانفیگ جدید — تایید کن:\n\n"
        f"برچسب: <b>{data.get('label','?')}</b>\n"
        f"پروتکل: {_protocol_label(proto)}\n"
        f"Fingerprint: {_fp_label(data.get('fingerprint', DEFAULT_FINGERPRINT))}\n"
        f"ALPN: {alpn}\n"
        f"پورت: {data.get('port', DEFAULT_PORT)}\n"
        f"محدودیت حجم: {limit}\n"
        f"محدودیت سرعت: {speed}\n"
        f"محدودیت آی‌پی: {iplim}\n"
        f"انقضا: {days_txt}"
    )

# ── View builders ────────────────────────────────────────────────────────────
def _format_detail(uid: str, l: dict) -> str:
    status = "🟢 فعال" if is_link_allowed(l) else "🔴 غیرفعال/منقضی"
    limit = "نامحدود" if not l.get("limit_bytes") else fmt_bytes(l["limit_bytes"])
    speed = "نامحدود" if not l.get("speed_limit_bytes") else f"{l['speed_limit_bytes']*8/1024/1024:.1f} Mbps"
    exp = l.get("expires_at")
    exp_txt = exp.split("T")[0] if exp else "بدون انقضا"
    proto = l.get("protocol", DEFAULT_PROTOCOL)
    alpn = l.get("alpn") or f"پیش‌فرض ({DEFAULT_ALPN_BY_PROTOCOL.get(proto, 'http/1.1')})"
    return (
        f"<b>{l.get('label','?')}</b>\n"
        f"وضعیت: {status}\n"
        f"مصرف: {fmt_bytes(l.get('used_bytes',0))} / {limit}\n"
        f"محدودیت سرعت: {speed}\n"
        f"محدودیت آی‌پی: {l.get('ip_limit',0) or 'نامحدود'}\n"
        f"پروتکل: {_protocol_label(proto)}\n"
        f"Fingerprint: {_fp_label(l.get('fingerprint', DEFAULT_FINGERPRINT))}\n"
        f"ALPN: {alpn}\n"
        f"پورت: {l.get('port', DEFAULT_PORT)}\n"
        f"انقضا: {exp_txt}\n"
        f"UUID: <code>{uid}</code>"
    )

# ── Sub-group (لینک ساب حرفه‌ای) view builders ────────────────────────────────
def _group_public_url(s: dict) -> str:
    host = get_host()
    return f"https://{host}/p/{s.get('uuid_key','')}"

def _subs_list_kb(page: int):
    items = sorted(SUBS.items(), key=lambda kv: kv[1].get("created_at", ""), reverse=True)
    total = len(items)
    start = page * PAGE_SIZE
    chunk = items[start:start + PAGE_SIZE]
    rows = []
    for sid, s in chunk:
        cnt = len(s.get("link_ids", []))
        rows.append([{"text": f"🗂 {s.get('name','?')[:26]} ({cnt})", "callback_data": f"subview:{sid}"}])
    nav = []
    if start > 0:
        nav.append({"text": "◀ قبلی", "callback_data": f"subs:{page-1}"})
    if start + PAGE_SIZE < total:
        nav.append({"text": "بعدی ▶", "callback_data": f"subs:{page+1}"})
    if nav:
        rows.append(nav)
    rows.append([{"text": "➕ ساخت گروه جدید", "callback_data": "newsub"}])
    rows.append([{"text": "⬅ منوی اصلی", "callback_data": "menu"}])
    return {"inline_keyboard": rows}

def _format_sub_detail(sid: str, s: dict) -> str:
    cnt = len(s.get("link_ids", []))
    pw = "🔒 دارد" if s.get("password_hash") else "بدون رمز"
    desc = s.get("desc") or "—"
    return (
        f"🗂 <b>{s.get('name','?')}</b>\n"
        f"توضیحات: {desc}\n"
        f"تعداد کانفیگ‌های داخل گروه: {cnt}\n"
        f"رمز عبور: {pw}\n\n"
        f"🔗 لینک ساب حرفه‌ای این گروه:\n<code>{_group_public_url(s)}</code>"
    )

def _sub_detail_kb(sid: str):
    return {"inline_keyboard": [
        [{"text": "➕ افزودن کانفیگ به این گروه", "callback_data": f"subaddlink:{sid}:0"}],
        [{"text": "🗑 حذف گروه", "callback_data": f"subdel:{sid}"}],
        [{"text": "⬅ بازگشت به لیست گروه‌ها", "callback_data": "subs:0"}],
    ]}

def _confirm_subdel_kb(sid: str):
    return {"inline_keyboard": [
        [{"text": "✅ بله، حذف کن", "callback_data": f"subdelok:{sid}"},
         {"text": "❌ انصراف", "callback_data": f"subview:{sid}"}],
    ]}

def _pick_link_for_group_kb(sid: str, page: int):
    """لیست همه‌ی کانفیگ‌ها برای انتخاب و افزودن به یک گروه ساب مشخص."""
    items = sorted(LINKS.items(), key=lambda kv: kv[1].get("created_at", ""), reverse=True)
    total = len(items)
    start = page * PAGE_SIZE
    chunk = items[start:start + PAGE_SIZE]
    rows = []
    for uid, l in chunk:
        in_this = "✅ " if l.get("sub_id") == sid else ""
        rows.append([{"text": f"{in_this}{l.get('label','?')[:28]}", "callback_data": f"subaddlinkdo:{uid}"}])
    nav = []
    if start > 0:
        nav.append({"text": "◀ قبلی", "callback_data": f"subaddlink:{sid}:{page-1}"})
    if start + PAGE_SIZE < total:
        nav.append({"text": "بعدی ▶", "callback_data": f"subaddlink:{sid}:{page+1}"})
    if nav:
        rows.append(nav)
    rows.append([{"text": "⬅ بازگشت به گروه", "callback_data": f"subview:{sid}"}])
    return {"inline_keyboard": rows}

# ── Per-config "group" (ساب لینک حرفه‌ای) view builders ───────────────────────
def _cfg_group_kb(uid: str):
    link = LINKS.get(uid, {})
    sid = link.get("sub_id")
    if sid and sid in SUBS:
        return {"inline_keyboard": [
            [{"text": "➖ خارج کردن از گروه", "callback_data": f"cfgungroup:{uid}"}],
            [{"text": "⬅ بازگشت", "callback_data": f"view:{uid}"}],
        ]}
    rows = []
    for sid2, s in sorted(SUBS.items(), key=lambda kv: kv[1].get("created_at", ""), reverse=True)[:8]:
        rows.append([{"text": f"➕ افزودن به «{s.get('name','?')[:24]}»", "callback_data": f"cfgaddgroup:{sid2}"}])
    rows.append([{"text": "🆕 ساخت گروه جدید و افزودن", "callback_data": f"cfgnewgroup:{uid}"}])
    rows.append([{"text": "⬅ بازگشت", "callback_data": f"view:{uid}"}])
    return {"inline_keyboard": rows}

def _format_cfg_group(uid: str) -> str:
    link = LINKS.get(uid, {})
    sid = link.get("sub_id")
    if sid and sid in SUBS:
        s = SUBS[sid]
        return (
            f"🗂 کانفیگ «{link.get('label','?')}» توی گروه «{s.get('name','?')}» هست.\n\n"
            f"🔗 لینک ساب حرفه‌ای این گروه:\n<code>{_group_public_url(s)}</code>"
        )
    return (
        f"کانفیگ «{link.get('label','?')}» توی هیچ گروهی نیست، یعنی فقط لینک ساب ساده داره.\n\n"
        "برای گرفتن لینک ساب حرفه‌ای (صفحه‌ی زیبا)، این کانفیگ رو به یک گروه اضافه کن یا یه گروه جدید بساز:"
    )

# ── 🛒 فروشگاه: جریان خریدار (غیرادمین) ───────────────────────────────────────
# خریدار /start می‌زند → لیست پلن‌ها → پرداخت آنلاین در درگاه → بعد از تأیید،
# کانفیگ خودکار صادر و همین‌جا تحویل داده می‌شود.

SHOP_ORDER_TTL_TEXT = "۲ ساعت"

def _shop_open() -> tuple[bool, str]:
    if not SHOP_STATE.get("enabled"):
        return False, "فروشگاه فعلاً بسته است. بعداً سر بزن! 🙏"
    if not shop_public_plans():
        return False, "فعلاً پلنی برای فروش تعریف نشده. بعداً سر بزن! 🙏"
    return True, ""

def _buyer_hub_text() -> str:
    brand = (CONFIG.get("branding") or {}).get("brand_name") or "XR"
    return (
        f"👋 به فروشگاه <b>{brand}</b> خوش اومدی!\n\n"
        "📡 اینترنت آزاد و پرسرعت، خرید کاملاً خودکار:\n"
        "پلن رو انتخاب می‌کنی → آنلاین پرداخت می‌کنی → کانفیگ همین‌جا تحویل می‌گیری. 🚀\n\n"
        "از دکمه‌های زیر استفاده کن:"
    )

def _buyer_hub_kb():
    return {"inline_keyboard": [
        [{"text": "🛍 خرید اشتراک", "callback_data": "bplans"}],
        [{"text": "📦 خریدهای من", "callback_data": "bmy"}],
        [{"text": "💬 پشتیبانی", "callback_data": "bsupport"}],
    ]}

def _plan_volume_txt(p: dict) -> str:
    gb = float(p.get("limit_gb") or 0)
    return "♾ نامحدود" if gb <= 0 else f"{gb:g} گیگابایت"

def _plan_days_txt(p: dict) -> str:
    d = int(p.get("days") or 0)
    return "♾ نامحدود" if d <= 0 else f"{d} روز"

def _format_plan_card(p: dict) -> str:
    speed = float(p.get("speed_mbps") or 0)
    ip = int(p.get("ip_limit") or 0)
    proto = p.get("protocol") or ""
    lines = [
        f"📦 پلن <b>«{p.get('name')}»</b>",
        "",
        f"💵 مبلغ: <b>{int(p.get('price_toman') or 0):,} تومان</b>",
        f"📊 حجم: {_plan_volume_txt(p)}",
        f"⏳ مدت: {_plan_days_txt(p)}",
        f"🚀 سرعت: {'♾ نامحدود' if speed <= 0 else f'{speed:g} Mbps'}",
        f"👥 آی‌پی هم‌زمان: {'♾ نامحدود' if ip <= 0 else str(ip)}",
    ]
    if proto:
        lines.append(f"🔌 پروتکل: {_protocol_label(proto)}")
    lines += [
        "",
        "✨ بعد از پرداخت، کانفیگ به‌صورت خودکار ساخته و همین‌جا ارسال می‌شود",
        "(لینک اتصال + ساب ۳ پروتکله + صفحه‌ی مشتری با حجم و انقضا).",
    ]
    return "\n".join(lines)

def _buyer_plans_text() -> str:
    plans = shop_public_plans()
    rows = "\n\n".join(
        f"▫️ <b>{p['name']}</b> — {int(p.get('price_toman') or 0):,} تومان\n"
        f"   {_plan_volume_txt(p)} · {_plan_days_txt(p)}"
        for p in plans
    )
    return "🛍 پلن‌های فروش:\n\n" + rows + "\n\nبرای جزئیات و خرید، یکی رو انتخاب کن:"

def _buyer_plans_kb():
    rows = [[{"text": f"📦 {p['name']} — {int(p.get('price_toman') or 0):,} تومان", "callback_data": f"bplan:{p['id']}"}]
            for p in shop_public_plans()]
    rows.append([{"text": "🏠 خانه", "callback_data": "bstart"}])
    return {"inline_keyboard": rows}

def _plan_detail_kb(pid: str):
    return {"inline_keyboard": [
        [{"text": "💳 خرید و پرداخت", "callback_data": f"bbuy:{pid}"}],
        [{"text": "⬅ بازگشت به پلن‌ها", "callback_data": "bplans"}],
    ]}

def _order_pay_kb(oid: str, url: str, amount: int):
    rows = [[{"text": f"💳 پرداخت آنلاین ({amount:,} تومان)", "url": url}]]
    rows.append([{"text": "✅ پرداخت کردم", "callback_data": f"bpaid:{oid}"}])
    rows.append([{"text": "⬅ بازگشت به پلن‌ها", "callback_data": "bplans"}])
    return {"inline_keyboard": rows}

_ORDER_STATUS_TXT = {
    "pending": "⏳ در انتظار پرداخت",
    "paid": "✅ پرداخت و تحویل شده",
    "failed": "❌ ناموفق",
    "expired": "🕓 منقضی‌شده",
    "canceled": "🚫 لغو‌شده",
}

def _my_buys_kb(chat_id: int):
    rows = []
    for o in shop_orders_for_chat(chat_id)[:10]:
        st = o.get("status")
        label = f"{_ORDER_STATUS_TXT.get(st, st)} — {o.get('plan_name','?')[:24]}"
        cb = f"bcfg:{o['id']}" if st == "paid" else f"bpaid:{o['id']}"
        rows.append([{"text": label, "callback_data": cb}])
    if not rows:
        return None
    rows.append([{"text": "🏠 خانه", "callback_data": "bstart"}])
    return {"inline_keyboard": rows}

def _buyer_support_text() -> str:
    sup = (CONFIG.get("branding") or {}).get("support_telegram") or ""
    txt = "💬 پشتیبانی:\n\n"
    if sup:
        txt += f"برای پیگیری سفارش و سؤالات، به پشتیبانی پیام بده:\n{sup}"
    else:
        txt += "با ادمین فروشگاه در همین ربات در تماس باش؛ به‌زودی لینک پشتیبانی اینجا قرار می‌گیرد."
    return txt

async def _send_buyer_hub(chat_id: int):
    await _send(chat_id, _buyer_hub_text(), _buyer_hub_kb())

async def _handle_buyer_message(msg: dict):
    chat_id = msg.get("chat", {}).get("id")
    if chat_id is None:
        return
    text = (msg.get("text") or "").strip()
    if text in ("/cancel",):
        _pending.pop(chat_id, None)
    open_, closed_msg = _shop_open()
    if not open_:
        await _send(chat_id, f"🙏 {closed_msg}")
        return
    if text in ("/start", "/menu"):
        await _send_buyer_hub(chat_id)
        return
    # بقیه‌ی تعامل‌ها با دکمه‌های شیشه‌ای است؛ هر متنی زده شد، هاب رو نشون بده
    await _send(chat_id, "از دکمه‌های زیر استفاده کن:", _buyer_hub_kb())

async def _handle_buyer_callback(cb: dict):
    chat_id = cb.get("message", {}).get("chat", {}).get("id")
    message_id = cb.get("message", {}).get("message_id")
    data = cb.get("data", "")
    cb_id = cb.get("id")
    frm = cb.get("from") or {}
    username = (frm.get("username") or "").strip()
    fullname = " ".join(filter(None, [frm.get("first_name"), frm.get("last_name")])).strip()

    async def _deny():
        await _answer_cb(cb_id, "⛔ این دکمه مال شما نیست")

    open_, closed_msg = _shop_open()
    if not open_ and data not in ("bstart", "bsupport", "bmy"):
        await _answer_cb(cb_id, closed_msg)
        return

    if data == "bstart":
        await _answer_cb(cb_id)
        await _edit(chat_id, message_id, _buyer_hub_text(), _buyer_hub_kb())
        return

    if data == "bsupport":
        await _answer_cb(cb_id)
        await _edit(chat_id, message_id, _buyer_support_text(), _buyer_hub_kb())
        return

    if data == "bplans":
        await _answer_cb(cb_id)
        await _edit(chat_id, message_id, _buyer_plans_text(), _buyer_plans_kb())
        return

    if data.startswith("bplan:"):
        pid = data.split(":", 1)[1]
        p = shop_get_plan(pid)
        if not p or not p.get("active", True):
            await _answer_cb(cb_id, "این پلن دیگه موجود نیست")
            await _edit(chat_id, message_id, _buyer_plans_text(), _buyer_plans_kb())
            return
        await _answer_cb(cb_id)
        await _edit(chat_id, message_id, _format_plan_card(p), _plan_detail_kb(pid))
        return

    if data.startswith("bbuy:"):
        pid = data.split(":", 1)[1]
        p = shop_get_plan(pid)
        if not p or not p.get("active", True):
            await _answer_cb(cb_id, "این پلن دیگه موجود نیست")
            return
        await _answer_cb(cb_id, "🧾 در حال ساخت فاکتور...")
        order, pay_url, err = await shop_create_order(p, chat_id, username, fullname)
        if not pay_url:
            await _send(chat_id, f"❌ فعلاً نمی‌شه سفارش ثبت کرد:\n{err}\n\nبه پشتیبانی اطلاع بده: {_buyer_support_text()}")
            return
        amount = int(order.get("amount_toman") or 0)
        txt = (
            f"🧾 فاکتور سفارش <code>{order['id']}</code>\n\n"
            f"📦 پلن: <b>{order['plan_name']}</b>\n"
            f"💵 مبلغ: <b>{amount:,} تومان</b>\n\n"
            "۱) روی «💳 پرداخت آنلاین» بزن و در درگاه پرداخت کن.\n"
            "۲) بعد از پرداخت، دکمه‌ی «✅ پرداخت کردم» همین پیام رو بزن.\n"
            "۳) کانفیگت خودکار ساخته و همین‌جا ارسال می‌شود. 🚀"
        )
        await _send(chat_id, txt, _order_pay_kb(order["id"], pay_url, amount))
        return

    if data.startswith("bpaid:"):
        oid = data.split(":", 1)[1]
        o = SHOP_STATE["orders"].get(oid)
        if not o or o.get("chat_id") != chat_id:
            await _deny()
            return
        if o.get("status") == "paid":
            await _answer_cb(cb_id, "✅ این سفارش قبلاً تحویل شده")
            msg = shop_delivery_message(o)
            if msg:
                await _send(chat_id, msg)
            return
        await _answer_cb(cb_id, "⏳ در حال استعلام از درگاه...")
        res = await shop_verify_finalize(oid)
        st = res["status"]
        if st == "paid":
            await _send(chat_id, "✅ پرداخت تأیید شد! کانفیگت در پیام جداگانه ارسال شد 🎉\n(همیشه از «📦 خریدهای من» قابل دسترسیه)")
        elif st == "pending":
            await _send(chat_id, f"⏳ {res.get('message') or 'پرداخت هنوز ثبت نشده؛ چند لحظه دیگه دوباره «✅ پرداخت کردم» رو بزن.'}\nاگر مبلغ کم شده، معمولاً تا چند دقیقه ثبت می‌شود.")
        else:
            await _send(chat_id, f"❌ {res.get('message') or 'پرداخت تأیید نشد'}\nاگر مبلغی کم شده باشد تا ۷۲ ساعت بازمی‌گردد. برای تلاش دوباره از «🛍 خرید اشتراک» شروع کن.")
        return

    if data == "bmy":
        await _answer_cb(cb_id)
        orders = shop_orders_for_chat(chat_id)
        if not orders:
            await _edit(chat_id, message_id, "📦 هنوز سفارشی ثبت نکردی.\nاز «🛍 خرید اشتراک» شروع کن!", _buyer_hub_kb())
            return
        lines = ["📦 سفارش‌های تو:\n"]
        for o in orders[:10]:
            lines.append(f"▫️ {_ORDER_STATUS_TXT.get(o.get('status'), o.get('status'))} — {o.get('plan_name','?')} ({int(o.get('amount_toman') or 0):,} تومان)")
        kb = _my_buys_kb(chat_id)
        await _edit(chat_id, message_id, "\n".join(lines), kb or _buyer_hub_kb())
        return

    if data.startswith("bcfg:"):
        oid = data.split(":", 1)[1]
        o = SHOP_STATE["orders"].get(oid)
        if not o or o.get("chat_id") != chat_id:
            await _deny()
            return
        if o.get("status") != "paid" or not o.get("link_uid"):
            await _answer_cb(cb_id, "این سفارش هنوز پرداخت نشده")
            return
        await _answer_cb(cb_id)
        msg = shop_delivery_message(o)
        await _send(chat_id, msg or "کانفیگ این سفارش دیگر روی سرور وجود ندارد؛ با پشتیبانی در تماس باش.")
        return

    await _answer_cb(cb_id, "دکمه ناشناخته است")

# ── 🛒 فروشگاه: مدیریت توسط ادمین ────────────────────────────────────────────

SHOP_PLAN_WIZARD_STEPS = ["name", "price", "volume", "days", "speed", "iplimit", "confirm"]

_FA_DIGITS = str.maketrans("۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩", "01234567890123456789")

def _to_en_digits(text: str) -> str:
    return (text or "").translate(_FA_DIGITS)

_PRICE_RE = re.compile(r"^([\d.,]+)\s*(k|هزار|ت)?$|(^([\d.,]+)\s*(میلیون|م))$", re.IGNORECASE)

def _parse_price_text(text: str):
    """قیمت به تومان — '50000'، '50k'، '۵۰هزار' یا '۲ میلیون'."""
    t = _to_en_digits(text.strip()).lower().replace(",", "").replace("،", "")
    if not t:
        return None
    m = re.match(r"^([\d.]+)\s*(k|هزار|ت)?$", t)
    if m:
        try:
            v = float(m.group(1))
        except ValueError:
            return None
        if m.group(2):
            v *= 1_000
        return int(v)
    m = re.match(r"^([\d.]+)\s*(میلیون|م)$", t)
    if m:
        try:
            return int(float(m.group(1)) * 1_000_000)
        except ValueError:
            return None
    return None

def _parse_gb_text(text: str):
    """حجم پلن به گیگابایت — '30' یا '30GB'؛ 0 یعنی نامحدود."""
    t = _to_en_digits(text.strip())
    if t in ("0", "نامحدود", "infinity", "inf"):
        return 0
    m = re.match(r"^([\d.]+)\s*(gb|گیگ|گ)?$", t, re.IGNORECASE)
    if not m:
        return None
    try:
        v = float(m.group(1))
    except ValueError:
        return None
    return v if v > 0 else None

def _parse_mbit_text(text: str):
    t = _to_en_digits(text.strip())
    if t in ("0", "نامحدود", "infinity", "inf"):
        return 0
    m = re.match(r"^([\d.]+)\s*(mbit|mbps|m)?$", t, re.IGNORECASE)
    if not m:
        return None
    try:
        v = float(m.group(1))
    except ValueError:
        return None
    return v if v > 0 else None

def _shop_menu_kb():
    return {"inline_keyboard": [
        [{"text": "📦 پلن‌ها", "callback_data": "shpl:0"}],
        [{"text": "➕ پلن جدید", "callback_data": "shnew"}],
        [{"text": "🧾 سفارش‌ها و آمار فروش", "callback_data": "shord"}],
        [{"text": "⚙️ تنظیمات (درگاه پرداخت)", "callback_data": "shcfg"}],
        [{"text": "⬅ منوی اصلی", "callback_data": "menu"}],
    ]}

def _shop_admin_text() -> str:
    st = shop_stats()
    gw = SHOP_GATEWAYS.get(SHOP_STATE.get("gateway"), SHOP_STATE.get("gateway"))
    return (
        "🛒 <b>فروشگاه — فروش خودکار اشتراک</b>\n\n"
        f"وضعیت: {'✅ روشن' if SHOP_STATE.get('enabled') else '⛔ خاموش'}\n"
        f"درگاه پرداخت: {gw}\n"
        f"تعداد پلن: {st['plans_count']} · فروش موفق: {st['total_sales']} · درآمد کل: {st['revenue_total_toman']:,} تومان\n\n"
        "خریدارها توی همین ربات پلن می‌خرن و کانفیگ خودکار تحویل می‌گیرن.\n"
        "مدیریت کامل هم از تب «فروشگاه» توی پنل وب ممکنه."
    )

def _format_plan_admin(p: dict) -> str:
    speed = float(p.get("speed_mbps") or 0)
    ip = int(p.get("ip_limit") or 0)
    proto = p.get("protocol") or ""
    return (
        f"📦 پلن «<b>{p.get('name')}</b>» {'🟢 فعال' if p.get('active', True) else '🔴 غیرفعال'}\n\n"
        f"💵 قیمت: {int(p.get('price_toman') or 0):,} تومان\n"
        f"📊 حجم: {_plan_volume_txt(p)}\n"
        f"⏳ مدت: {_plan_days_txt(p)}\n"
        f"🚀 سرعت: {'♾ نامحدود' if speed <= 0 else f'{speed:g} Mbps'}\n"
        f"👥 آی‌پی هم‌زمان: {'♾ نامحدود' if ip <= 0 else str(ip)}\n"
        f"🔌 پروتکل: {_protocol_label(proto) if proto else 'پیش‌فرض پنل'}\n"
        f"🧾 فروش‌کرده: {int(p.get('sold_count') or 0)}"
    )

def _shop_plans_kb(page: int):
    plans = sorted(SHOP_STATE["plans"].values(), key=lambda p: p.get("price_toman", 0))
    total = len(plans)
    chunk = plans[page * PAGE_SIZE:(page + 1) * PAGE_SIZE]
    rows = [[{"text": f"{'🟢' if p.get('active', True) else '🔴'} {p['name'][:28]} — {int(p.get('price_toman') or 0):,} ت", "callback_data": f"shview:{p['id']}"}]
            for p in chunk]
    nav = []
    if page > 0:
        nav.append({"text": "◀ قبلی", "callback_data": f"shpl:{page-1}"})
    if (page + 1) * PAGE_SIZE < total:
        nav.append({"text": "بعدی ▶", "callback_data": f"shpl:{page+1}"})
    if nav:
        rows.append(nav)
    rows.append([{"text": "⬅ فروشگاه", "callback_data": "shmenu"}])
    return {"inline_keyboard": rows}

def _shop_plan_kb(pid: str, active: bool):
    return {"inline_keyboard": [
        [{"text": ("⛔ غیرفعال‌سازی" if active else "✅ فعال‌سازی"), "callback_data": f"shtgl:{pid}"}],
        [{"text": "🗑 حذف پلن", "callback_data": f"shdel:{pid}"}],
        [{"text": "⬅ بازگشت به پلن‌ها", "callback_data": "shpl:0"}],
    ]}

def _shop_confirm_del_kb(pid: str):
    return {"inline_keyboard": [
        [{"text": "✅ بله، حذف کن", "callback_data": f"shdelok:{pid}"},
         {"text": "❌ انصراف", "callback_data": f"shview:{pid}"}],
    ]}

def _shop_cfg_text() -> str:
    gw = SHOP_STATE.get("gateway", "zarinpal")
    merch = SHOP_STATE.get("merchant_id") or ""
    merch_txt = f"<code>{merch[:6]}…{merch[-4:]}</code>" if len(merch) > 12 else (f"<code>{merch}</code>" if merch else "تنظیم نشده ⚠️")
    cb = f"https://{get_host()}/pay/callback/{{order_id}}"
    ready = bool(merch) or gw == "test"
    return (
        "⚙️ <b>تنظیمات فروشگاه</b>\n\n"
        f"وضعیت فروشگاه: {'✅ روشن' if SHOP_STATE.get('enabled') else '⛔ خاموش'}\n"
        f"درگاه فعال: <b>{SHOP_GATEWAYS.get(gw, gw)}</b>\n"
        f"🧪 سندباکس (تست بدون پول): {'روشن' if SHOP_STATE.get('sandbox') else 'خاموش'}\n"
        f"🔑 مرچنت‌کد / API-Key: {merch_txt}\n\n"
        f"🔗 آدرس بازگشت از درگاه (Callback):\n<code>{cb}</code>\n\n"
        + ("" if ready else "⚠️ برای درگاه واقعی، اول مرچنت‌کد را تنظیم کن.\n\n")
        + "با دکمه‌های زیر تغییر بده:"
    )

def _shop_cfg_kb():
    gw = SHOP_STATE.get("gateway", "zarinpal")
    def gw_btn(key: str):
        return {"text": ("✅ " if gw == key else "") + SHOP_GATEWAYS[key], "callback_data": f"shgw:{key}"}
    return {"inline_keyboard": [
        [{"text": ("⛔ خاموش کردن فروشگاه" if SHOP_STATE.get("enabled") else "✅ روشن کردن فروشگاه"), "callback_data": "shonoff"}],
        [gw_btn("zarinpal"), gw_btn("idpay")],
        [gw_btn("test")],
        [{"text": f"🧪 سندباکس: {'روشن ✅' if SHOP_STATE.get('sandbox') else 'خاموش'}", "callback_data": "shsbx"}],
        [{"text": "🔑 تنظیم مرچنت‌کد / API-Key", "callback_data": "shmerch"}],
        [{"text": "⬅ فروشگاه", "callback_data": "shmenu"}],
    ]}

def _shop_orders_text() -> str:
    st = shop_stats()
    orders = shop_orders_recent(10)
    lines = [
        "📊 <b>آمار فروش</b>\n",
        f"💰 درآمد کل: <b>{st['revenue_total_toman']:,} تومان</b> ({st['total_sales']} فروش)",
        f"📅 امروز: {st['revenue_today_toman']:,} تومان ({st['sales_today']} فروش)",
        f"⏳ در انتظار پرداخت: {st['pending_orders']}",
        "",
        "🧾 <b>آخرین سفارش‌ها</b>\n",
    ]
    if not orders:
        lines.append("هنوز سفارشی ثبت نشده.")
    for o in orders:
        buyer = f"@{o['username']}" if o.get("username") else (o.get("fullname") or o.get("chat_id"))
        lines.append(f"▫️ <code>{o['id']}</code> — {o.get('plan_name','?')} — {int(o.get('amount_toman') or 0):,} ت — {_ORDER_STATUS_TXT.get(o.get('status'), o.get('status'))} — {buyer}")
    return "\n".join(lines)

def _shop_wizard_prompt(step: str, data: dict) -> str:
    n = SHOP_PLAN_WIZARD_STEPS.index(step) + 1
    total = len(SHOP_PLAN_WIZARD_STEPS)
    if step == "name":
        return f"➕ پلن جدید ({n}/{total})\n\nنام پلن رو بفرست:\nمثلاً: <code>پلن طلایی ۳۰ گیگ</code>"
    if step == "price":
        return f"➕ پلن «{data.get('name')}» ({n}/{total})\n\nقیمت به تومان رو بفرست (حداقل {MIN_PRICE_TOMAN:,}):\nمثلاً: <code>50000</code> یا <code>50k</code> یا <code>۵۰هزار</code>"
    if step == "volume":
        return f"➕ پلن «{data.get('name')}» ({n}/{total})\n\nحجم پلن به گیگابایت (۰ = نامحدود):\nمثلاً: <code>30</code> یا <code>30GB</code>"
    if step == "days":
        return f"➕ پلن «{data.get('name')}» ({n}/{total})\n\nمدت اعتبار به روز (۰ = نامحدود):\nمثلاً: <code>30</code>"
    if step == "speed":
        return f"➕ پلن «{data.get('name')}» ({n}/{total})\n\nمحدودیت سرعت به Mbps (۰ = نامحدود):\nمثلاً: <code>20</code>"
    if step == "iplimit":
        return f"➕ پلن «{data.get('name')}» ({n}/{total})\n\nحداکثر آی‌پی/دستگاه هم‌زمان (۰ = نامحدود):\nمثلاً: <code>3</code>"
    return ""

def _shop_wizard_summary(data: dict) -> str:
    speed = float(data.get("speed_mbps") or 0)
    ip = int(data.get("ip_limit") or 0)
    volume_txt = "♾ نامحدود" if not data.get("limit_gb") else f"{float(data.get('limit_gb')):g} گیگابایت"
    days_txt = "♾ نامحدود" if not data.get("days") else f"{int(data.get('days'))} روز"
    return (
        "✅ خلاصه‌ی پلن جدید:\n\n"
        f"📦 نام: <b>{data.get('name')}</b>\n"
        f"💵 قیمت: {int(data.get('price_toman') or 0):,} تومان\n"
        f"📊 حجم: {volume_txt}\n"
        f"⏳ مدت: {days_txt}\n"
        f"🚀 سرعت: {'♾ نامحدود' if speed <= 0 else f'{speed:g} Mbps'}\n"
        f"👥 آی‌پی هم‌زمان: {'♾ نامحدود' if ip <= 0 else str(ip)}\n"
        f"🔌 پروتکل: پیش‌فرض پنل\n\n"
        "ساخته بشه؟"
    )

def _shop_wizard_unlimited_kb(step_key: str):
    return {"inline_keyboard": [
        [{"text": "♾ نامحدود", "callback_data": f"shskip:{step_key}"}],
        [{"text": "❌ انصراف", "callback_data": "shcancel"}],
    ]}

def _shop_wizard_cancel_kb():
    return {"inline_keyboard": [[{"text": "❌ انصراف", "callback_data": "shcancel"}]]}

def _shop_wizard_confirm_kb():
    return {"inline_keyboard": [
        [{"text": "✅ ساخت پلن", "callback_data": "shconf"}],
        [{"text": "❌ انصراف", "callback_data": "shcancel"}],
    ]}

async def _handle_shop_callback(chat_id: int, message_id: int, data: str, cb_id: str):
    """هندلر دکمه‌های مدیریت فروشگاه (فقط ادمین — فراخوانی از _handle_callback)."""
    if data == "shmenu":
        await _answer_cb(cb_id)
        await _edit(chat_id, message_id, _shop_admin_text(), _shop_menu_kb())
        return

    if data.startswith("shpl:"):
        await _answer_cb(cb_id)
        plans = SHOP_STATE["plans"]
        if not plans:
            await _edit(chat_id, message_id, "📦 هنوز پلنی تعریف نشده.\nاز «➕ پلن جدید» شروع کن!", _shop_menu_kb())
            return
        await _edit(chat_id, message_id, "📦 پلن‌های فروش (مرتب بر اساس قیمت):\nبرای مدیریت، یکی رو انتخاب کن:", _shop_plans_kb(int(data.split(":", 1)[1] or 0)))
        return

    if data.startswith("shview:"):
        pid = data.split(":", 1)[1]
        p = shop_get_plan(pid)
        if not p:
            await _answer_cb(cb_id, "این پلن حذف شده")
            await _edit(chat_id, message_id, _shop_admin_text(), _shop_menu_kb())
            return
        await _answer_cb(cb_id)
        await _edit(chat_id, message_id, _format_plan_admin(p), _shop_plan_kb(pid, p.get("active", True)))
        return

    if data.startswith("shtgl:"):
        pid = data.split(":", 1)[1]
        p = await shop_toggle_plan(pid)
        if not p:
            await _answer_cb(cb_id, "این پلن حذف شده")
            return
        await _answer_cb(cb_id, "تغییر کرد")
        await _edit(chat_id, message_id, _format_plan_admin(p), _shop_plan_kb(pid, p.get("active", True)))
        return

    if data.startswith("shdel:"):
        pid = data.split(":", 1)[1]
        p = shop_get_plan(pid)
        if not p:
            await _answer_cb(cb_id, "این پلن حذف شده")
            return
        await _answer_cb(cb_id)
        await _edit(chat_id, message_id, f"❗️ از حذف پلن «{p['name']}» مطمئنی؟ (سفارش‌های قبلی دست‌نخورده می‌مونن)", _shop_confirm_del_kb(pid))
        return

    if data.startswith("shdelok:"):
        pid = data.split(":", 1)[1]
        name = await shop_remove_plan(pid)
        await _answer_cb(cb_id, "حذف شد" if name else "پیدا نشد")
        await _edit(chat_id, message_id, f"🗑 پلن «{name}» حذف شد." if name else "این پلن قبلاً حذف شده بود.", _shop_menu_kb())
        return

    if data == "shnew":
        await _answer_cb(cb_id)
        _pending[chat_id] = {"action": "shopplan", "step": "name", "data": {}}
        await _send(chat_id, _shop_wizard_prompt("name", {}), _shop_wizard_cancel_kb())
        return

    if data.startswith("shskip:"):
        step = data.split(":", 1)[1]
        pending = _pending.get(chat_id)
        if not pending or pending.get("action") != "shopplan":
            await _answer_cb(cb_id, "این دکمه دیگه معتبر نیست")
            return
        await _answer_cb(cb_id)
        wdata = pending["data"]
        step_defaults = {"volume": "limit_gb", "days": "days", "speed": "speed_mbps", "iplimit": "ip_limit"}
        wdata[step_defaults[step]] = 0
        nxt = SHOP_PLAN_WIZARD_STEPS[SHOP_PLAN_WIZARD_STEPS.index(step) + 1]
        pending["step"] = nxt
        if nxt == "confirm":
            await _edit(chat_id, message_id, _shop_wizard_summary(wdata), _shop_wizard_confirm_kb())
        else:
            await _edit(chat_id, message_id, _shop_wizard_prompt(nxt, wdata), _shop_wizard_unlimited_kb(nxt))
        return

    if data == "shconf":
        pending = _pending.pop(chat_id, None)
        if not pending or pending.get("action") != "shopplan":
            await _answer_cb(cb_id, "این دکمه دیگه معتبر نیست")
            return
        await _answer_cb(cb_id)
        wdata = pending["data"]
        pid, plan = await shop_add_plan(
            name=wdata.get("name") or "پلن جدید",
            price_toman=int(wdata.get("price_toman") or 0),
            limit_gb=float(wdata.get("limit_gb") or 0),
            days=int(wdata.get("days") or 0),
            speed_mbps=float(wdata.get("speed_mbps") or 0),
            ip_limit=int(wdata.get("ip_limit") or 0),
        )
        await _edit(chat_id, message_id, f"✅ پلن ساخته شد!\n\n{_format_plan_admin(plan)}", _shop_plan_kb(pid, True))
        return

    if data == "shcancel":
        _pending.pop(chat_id, None)
        await _answer_cb(cb_id, "لغو شد")
        await _edit(chat_id, message_id, _shop_admin_text(), _shop_menu_kb())
        return

    if data == "shord":
        await _answer_cb(cb_id)
        await _edit(chat_id, message_id, _shop_orders_text(), _shop_menu_kb())
        return

    if data == "shcfg":
        await _answer_cb(cb_id)
        await _edit(chat_id, message_id, _shop_cfg_text(), _shop_cfg_kb())
        return

    if data == "shonoff":
        SHOP_STATE["enabled"] = not SHOP_STATE.get("enabled", False)
        from main import save_state
        await save_state()
        await _answer_cb(cb_id, "روشن شد ✅" if SHOP_STATE["enabled"] else "خاموش شد ⛔")
        await _edit(chat_id, message_id, _shop_cfg_text(), _shop_cfg_kb())
        return

    if data.startswith("shgw:"):
        gw = data.split(":", 1)[1]
        if gw in SHOP_GATEWAYS:
            SHOP_STATE["gateway"] = gw
            from main import save_state
            await save_state()
        await _answer_cb(cb_id, f"درگاه: {SHOP_GATEWAYS.get(gw, gw)}")
        await _edit(chat_id, message_id, _shop_cfg_text(), _shop_cfg_kb())
        return

    if data == "shsbx":
        SHOP_STATE["sandbox"] = not SHOP_STATE.get("sandbox", False)
        from main import save_state
        await save_state()
        await _answer_cb(cb_id)
        await _edit(chat_id, message_id, _shop_cfg_text(), _shop_cfg_kb())
        return

    if data == "shmerch":
        await _answer_cb(cb_id)
        _pending[chat_id] = {"action": "shopmerchant"}
        await _send(chat_id, "🔑 مرچنت‌کد جدید (زرین‌پال) یا API-Key (آیدی‌پی) رو بفرست:\n\nبرای زرین‌پال: کد ۳۶ کاراکتری از پنل زرین‌پال\nبرای آیدی‌پی: کلید از پنل آیدی‌پی\n\n(/cancel برای انصراف)", _shop_wizard_cancel_kb())
        return

    await _answer_cb(cb_id, "دکمه ناشناخته است")

# ── Update handling ──────────────────────────────────────────────────────────
async def _handle_message(msg: dict):
    chat_id = msg.get("chat", {}).get("id")
    text = (msg.get("text") or "").strip()
    if chat_id is None:
        return
    if not _is_admin(chat_id):
        # 🛒 غیرادمین‌ها = خریدارهای فروشگاه
        await _handle_buyer_message(msg)
        return

    if text in ("/start", "/menu"):
        _pending.pop(chat_id, None)
        await _send(chat_id, "👋 به ربات مدیریت XR خوش اومدی.\nاز دکمه‌های زیر برای مدیریت کانفیگ‌ها استفاده کن:", _main_menu_kb())
        return

    if text == "/cancel":
        _pending.pop(chat_id, None)
        await _send(chat_id, "لغو شد.", _main_menu_kb())
        return

    pending = _pending.get(chat_id)

    if pending and pending.get("action") == "newsub" and pending.get("step") == "name" and text:
        name = text[:60]
        sid, s = await create_sub_group(name=name)
        link_uid = pending.get("link_uid")
        _pending.pop(chat_id, None)
        if link_uid and link_uid in LINKS:
            await set_link_sub(link_uid, sid)
            await _send(chat_id, f"✅ گروه ساخته شد و کانفیگ به اون اضافه شد.\n\n{_format_cfg_group(link_uid)}", _cfg_group_kb(link_uid))
        else:
            await _send(chat_id, f"✅ گروه ساخته شد.\n\n{_format_sub_detail(sid, s)}", _sub_detail_kb(sid))
        return

    if pending and pending.get("action") == "shopmerchant" and text:
        _pending.pop(chat_id, None)
        merch = text.strip()[:128]
        if len(merch) < 8:
            await _send(chat_id, "❗️ مقدار واردشده معتبر به نظر نمی‌رسه (کوتاه‌تر از حد).\nدوباره از «⚙️ تنظیمات → 🔑 تنظیم مرچنت‌کد» تلاش کن.", _shop_menu_kb())
            return
        SHOP_STATE["merchant_id"] = merch
        from main import save_state
        await save_state()
        await _send(chat_id, "✅ مرچنت‌کد / API-Key ذخیره شد.", _shop_cfg_kb())
        return

    if pending and pending.get("action") == "shopplan" and text:
        step = pending["step"]
        data = pending["data"]

        if step == "name":
            data["name"] = text[:60] or "پلن جدید"
            pending["step"] = "price"
            await _send(chat_id, _shop_wizard_prompt("price", data), _shop_wizard_cancel_kb())
            return

        if step == "price":
            v = _parse_price_text(text)
            if v is None or v < MIN_PRICE_TOMAN:
                await _send(chat_id, f"❗️ قیمت نامعتبره. یه عدد بفرست (حداقل {MIN_PRICE_TOMAN:,}):\nمثلاً <code>50000</code> یا <code>50k</code> یا <code>۵۰هزار</code>", _shop_wizard_cancel_kb())
                return
            data["price_toman"] = v
            pending["step"] = "volume"
            await _send(chat_id, _shop_wizard_prompt("volume", data), _shop_wizard_unlimited_kb("volume"))
            return

        if step == "volume":
            v = _parse_gb_text(text)
            if v is None:
                await _send(chat_id, "❗️ فرمت درست نیست. مثلاً <code>30</code> یا <code>30GB</code> (۰ = نامحدود)", _shop_wizard_unlimited_kb("volume"))
                return
            data["limit_gb"] = v
            pending["step"] = "days"
            await _send(chat_id, _shop_wizard_prompt("days", data), _shop_wizard_unlimited_kb("days"))
            return

        if step == "days":
            n = _parse_nonneg_int(_to_en_digits(text))
            if n is None:
                await _send(chat_id, "❗️ یه عدد صحیح بفرست (تعداد روز، ۰ = نامحدود):", _shop_wizard_unlimited_kb("days"))
                return
            data["days"] = n
            pending["step"] = "speed"
            await _send(chat_id, _shop_wizard_prompt("speed", data), _shop_wizard_unlimited_kb("speed"))
            return

        if step == "speed":
            v = _parse_mbit_text(text)
            if v is None:
                await _send(chat_id, "❗️ فرمت درست نیست. مثلاً <code>20</code> (Mbps، ۰ = نامحدود)", _shop_wizard_unlimited_kb("speed"))
                return
            data["speed_mbps"] = v
            pending["step"] = "iplimit"
            await _send(chat_id, _shop_wizard_prompt("iplimit", data), _shop_wizard_unlimited_kb("iplimit"))
            return

        if step == "iplimit":
            n = _parse_nonneg_int(_to_en_digits(text))
            if n is None:
                await _send(chat_id, "❗️ یه عدد صحیح بفرست (۰ = نامحدود):", _shop_wizard_unlimited_kb("iplimit"))
                return
            data["ip_limit"] = n
            pending["step"] = "confirm"
            await _send(chat_id, _shop_wizard_summary(data), _shop_wizard_confirm_kb())
            return

    if pending and pending.get("action") == "wizard" and text:
        step = pending["step"]
        data = pending["data"]

        if step == "label":
            data["label"] = text[:60] or "کانفیگ جدید"
            pending["step"] = "protocol"
            await _send(chat_id, _wizard_prompt("protocol", data), _wizard_protocol_kb())
            return

        if step in ("protocol", "fingerprint"):
            # این دو مرحله فقط با دکمه انتخاب می‌شن
            kb = _wizard_protocol_kb() if step == "protocol" else _wizard_fp_kb()
            await _send(chat_id, "لطفاً از دکمه‌های بالا یکی رو انتخاب کن 👆", kb)
            return

        if step == "alpn":
            data["alpn"] = text.strip()[:100]
            pending["step"] = "port"
            await _send(chat_id, _wizard_prompt("port", data), _wizard_skip_kb("port", f"⏭ پیش‌فرض ({DEFAULT_PORT})"))
            return

        if step == "port":
            try:
                p = int(text.strip())
            except ValueError:
                p = None
            if p is None or not (MIN_PORT <= p <= MAX_PORT):
                await _send(chat_id, f"❗️ عدد پورت نامعتبره. یه عدد بین {MIN_PORT} تا {MAX_PORT} بفرست:", _wizard_skip_kb("port", f"⏭ پیش‌فرض ({DEFAULT_PORT})"))
                return
            data["port"] = p
            pending["step"] = "volume"
            await _send(chat_id, _wizard_prompt("volume", data), _wizard_unlimited_kb("volume"))
            return

        if step == "volume":
            parsed = _parse_volume_text(text)
            if parsed is None:
                await _send(chat_id, "❗️ فرمت درست نیست. مثلاً بفرست: <code>10GB</code> یا <code>500MB</code>", _wizard_unlimited_kb("volume"))
                return
            data["limit_bytes"] = parsed
            pending["step"] = "speed"
            await _send(chat_id, _wizard_prompt("speed", data), _wizard_unlimited_kb("speed"))
            return

        if step == "speed":
            parsed = _parse_speed_text(text)
            if parsed is None:
                await _send(chat_id, "❗️ فرمت درست نیست. یه عدد بفرست، مثلاً <code>20</code> (Mbps)", _wizard_unlimited_kb("speed"))
                return
            data["speed_limit_bytes"] = parsed
            pending["step"] = "iplimit"
            await _send(chat_id, _wizard_prompt("iplimit", data), _wizard_unlimited_kb("iplimit"))
            return

        if step == "iplimit":
            n = _parse_nonneg_int(text)
            if n is None:
                await _send(chat_id, "❗️ یه عدد صحیح بفرست:", _wizard_unlimited_kb("iplimit"))
                return
            data["ip_limit"] = n
            pending["step"] = "days"
            await _send(chat_id, _wizard_prompt("days", data), _wizard_unlimited_kb("days"))
            return

        if step == "days":
            n = _parse_nonneg_int(text)
            if n is None:
                await _send(chat_id, "❗️ یه عدد صحیح بفرست (تعداد روز):", _wizard_unlimited_kb("days"))
                return
            data["expires_days"] = n
            pending["step"] = "confirm"
            await _send(chat_id, _wizard_summary(data), _wizard_confirm_kb())
            return

    # پیام ناشناخته → منو رو نشون بده
    await _send(chat_id, "از دکمه‌های زیر استفاده کن:", _main_menu_kb())

async def _handle_callback(cb: dict):
    chat_id = cb.get("message", {}).get("chat", {}).get("id")
    message_id = cb.get("message", {}).get("message_id")
    data = cb.get("data", "")
    cb_id = cb.get("id")

    if chat_id is None:
        return
    if not _is_admin(chat_id):
        # 🛒 دکمه‌های خرید (b*) برای همه‌ی کاربران بازه
        await _handle_buyer_callback(cb)
        return

    # 🛒 مدیریت فروشگاه (sh*) — هندلر خودش callback رو جواب میده
    if data == "shmenu" or data == "shnew" or data.startswith(("shpl:", "shview:", "shtgl:", "shdel:", "shdelok:", "shskip:", "shgw:", "shord", "shcfg", "shonoff", "shsbx", "shmerch", "shconf", "shcancel")):
        await _handle_shop_callback(chat_id, message_id, data, cb_id)
        return

    await _answer_cb(cb_id)

    if data == "menu":
        _pending.pop(chat_id, None)
        await _edit(chat_id, message_id, "منوی مدیریت XR:", _main_menu_kb())
        return

    if data == "autofailover":
        # دکمهٔ «سوئیچ خودکار SNI» — مثل دکمهٔ Auto-Failover در ربات Nyx
        try:
            from auto_failover import auto_failover_manager
            await _edit(chat_id, message_id, "⏳ در حال پایش و تست اتصال TLS دامنه‌ها... چند ثانیه شکیبا باشید...")
            result = await auto_failover_manager.check_and_failover()
            checked = result.get("checked_count", 0)
            switched = result.get("switched_count", 0)
            msg = (
                "✅ <b>گزارش سوئیچ هوشمند و پایش SNI (Auto-Failover):</b>\n\n"
                f"🔹 کانفیگ‌های بررسی‌شده: {checked}\n"
                f"⚡ سوئیچ‌های انجام‌شده: {switched}\n\n"
            )
            if switched == 0:
                msg += "🟢 تمام دامنه‌های SNI فعال، باثبات و سالم هستند! نیازی به سوئیچ نبود."
            else:
                msg += "⚠️ <b>جزئیات سوئیچ هوشمند:</b>\n"
                for ev in result.get("events", []):
                    who = ", ".join(ev.get("labels") or ev.get("links") or [])
                    msg += f"• {who}: {ev['old_sni']} ➡️ <code>{ev['new_sni']}</code> ({ev['latency_ms']}ms)\n"
            await _edit(chat_id, message_id, msg, _main_menu_kb())
        except Exception as e:
            logger.warning(f"Auto-Failover bot trigger error: {e}")
            await _edit(chat_id, message_id, "❌ خطا در اجرای سوئیچ هوشمند SNI.", _main_menu_kb())
        return

    if data.startswith("list:"):
        page = int(data.split(":", 1)[1] or 0)
        if not LINKS:
            await _edit(chat_id, message_id, "هنوز هیچ کانفیگی ساخته نشده.", _main_menu_kb())
            return
        await _edit(chat_id, message_id, f"📋 لیست کانفیگ‌ها ({len(LINKS)} مورد):", _links_list_kb(page))
        return

    # ── گروه‌های ساب (لینک حرفه‌ای) ────────────────────────────────────────────
    if data.startswith("subs:"):
        page = int(data.split(":", 1)[1] or 0)
        if not SUBS:
            await _edit(chat_id, message_id, "هنوز هیچ گروهی ساخته نشده.\n\nبرای گرفتن لینک ساب حرفه‌ای (صفحه‌ی زیبا)، اول یه گروه بساز و کانفیگ مورد نظرت رو داخلش بذار.", _subs_list_kb(0))
            return
        await _edit(chat_id, message_id, f"🗂 گروه‌های ساب ({len(SUBS)} مورد):", _subs_list_kb(page))
        return

    if data == "newsub":
        _pending[chat_id] = {"action": "newsub", "step": "name", "link_uid": None}
        await _edit(chat_id, message_id, "✏️ اسم گروه رو بفرست (این اسم فقط برای خودت توی مدیریت گروه‌هاست):", _wizard_cancel_kb())
        return

    if data.startswith("subview:"):
        sid = data.split(":", 1)[1]
        s = SUBS.get(sid)
        if not s:
            await _edit(chat_id, message_id, "این گروه دیگه وجود نداره.", _main_menu_kb())
            return
        await _edit(chat_id, message_id, _format_sub_detail(sid, s), _sub_detail_kb(sid))
        return

    if data.startswith("subaddlink:"):
        _, sid, page_s = data.split(":", 2)
        if sid not in SUBS:
            await _edit(chat_id, message_id, "این گروه دیگه وجود نداره.", _main_menu_kb())
            return
        if not LINKS:
            await _edit(chat_id, message_id, "هنوز هیچ کانفیگی نداری که به گروه اضافه کنی.", _sub_detail_kb(sid))
            return
        _pending[chat_id] = {"action": "subaddlink_ctx", "sid": sid}
        await _edit(chat_id, message_id, "کدوم کانفیگ رو به این گروه اضافه کنم؟\n(کانفیگ‌هایی که علامت ✅ دارن همین الان توی این گروهن)", _pick_link_for_group_kb(sid, int(page_s or 0)))
        return

    if data.startswith("subaddlinkdo:"):
        uid = data.split(":", 1)[1]
        ctx = _pending.get(chat_id) or {}
        sid = ctx.get("sid") if ctx.get("action") == "subaddlink_ctx" else None
        if not sid or sid not in SUBS:
            await _answer_cb(cb_id, "این عملیات منقضی شده، از منوی گروه‌ها دوباره امتحان کن.")
            return
        ok = await set_link_sub(uid, sid)
        if not ok:
            await _answer_cb(cb_id, "این کانفیگ دیگه وجود نداره")
            return
        _pending.pop(chat_id, None)
        s = SUBS.get(sid)
        await _edit(chat_id, message_id, f"✅ کانفیگ به گروه اضافه شد.\n\n{_format_sub_detail(sid, s)}", _sub_detail_kb(sid))
        return

    if data.startswith("subdel:"):
        sid = data.split(":", 1)[1]
        s = SUBS.get(sid)
        if not s:
            await _edit(chat_id, message_id, "این گروه دیگه وجود نداره.", _main_menu_kb())
            return
        await _edit(chat_id, message_id, f"❗️ از حذف گروه «{s.get('name')}» مطمئنی؟ لینک ساب حرفه‌ای‌اش دیگه کار نمی‌کنه (کانفیگ‌ها حذف نمی‌شن، فقط از گروه خارج می‌شن).", _confirm_subdel_kb(sid))
        return

    if data.startswith("subdelok:"):
        sid = data.split(":", 1)[1]
        name = await remove_sub_group(sid)
        if name is None:
            await _edit(chat_id, message_id, "این گروه قبلاً حذف شده بود.", _main_menu_kb())
        else:
            await _edit(chat_id, message_id, f"🗑 گروه «{name}» حذف شد.", _main_menu_kb())
        return

    # ── گروه یک کانفیگ خاص (از صفحه‌ی جزئیات کانفیگ) ───────────────────────────
    if data.startswith("cfggroup:"):
        uid = data.split(":", 1)[1]
        if uid not in LINKS:
            await _edit(chat_id, message_id, "این کانفیگ دیگه وجود نداره.", _main_menu_kb())
            return
        _pending[chat_id] = {"action": "cfg_group_ctx", "uid": uid}
        await _edit(chat_id, message_id, _format_cfg_group(uid), _cfg_group_kb(uid))
        return

    if data.startswith("cfgungroup:"):
        uid = data.split(":", 1)[1]
        await set_link_sub(uid, None)
        l = LINKS.get(uid)
        if not l:
            await _edit(chat_id, message_id, "این کانفیگ دیگه وجود نداره.", _main_menu_kb())
            return
        await _edit(chat_id, message_id, _format_detail(uid, l), _link_detail_kb(uid, l["active"]))
        return

    if data.startswith("cfgaddgroup:"):
        sid = data.split(":", 1)[1]
        ctx = _pending.get(chat_id) or {}
        uid = ctx.get("uid") if ctx.get("action") == "cfg_group_ctx" else None
        if not uid or uid not in LINKS:
            await _answer_cb(cb_id, "این عملیات منقضی شده، از روی کانفیگ دوباره وارد این بخش شو.")
            return
        ok = await set_link_sub(uid, sid)
        if not ok:
            await _answer_cb(cb_id, "این گروه دیگه وجود نداره")
            return
        _pending.pop(chat_id, None)
        await _edit(chat_id, message_id, f"✅ کانفیگ به گروه اضافه شد.\n\n{_format_cfg_group(uid)}", _cfg_group_kb(uid))
        return

    if data.startswith("cfgnewgroup:"):
        uid = data.split(":", 1)[1]
        if uid not in LINKS:
            await _edit(chat_id, message_id, "این کانفیگ دیگه وجود نداره.", _main_menu_kb())
            return
        _pending[chat_id] = {"action": "newsub", "step": "name", "link_uid": uid}
        await _edit(chat_id, message_id, "✏️ اسم گروه جدید رو بفرست؛ بعد از ساخته شدن، همین کانفیگ خودکار داخلش قرار می‌گیره:", _wizard_cancel_kb())
        return

    if data == "newcfg":
        _pending[chat_id] = {"action": "wizard", "step": "label", "data": {}}
        await _edit(chat_id, message_id, _wizard_prompt("label", {}), _wizard_cancel_kb())
        return

    if data == "w:cancel":
        _pending.pop(chat_id, None)
        await _edit(chat_id, message_id, "ساخت کانفیگ لغو شد.", _main_menu_kb())
        return

    if data.startswith("w:"):
        pending = _pending.get(chat_id)
        if not pending or pending.get("action") != "wizard":
            await _edit(chat_id, message_id, "این مرحله دیگه معتبر نیست، از منوی زیر دوباره شروع کن.", _main_menu_kb())
            return

        step = pending["step"]
        wdata = pending["data"]

        if data.startswith("w:proto:") and step == "protocol":
            proto = data.split(":", 2)[2]
            wdata["protocol"] = proto if proto in PROTOCOLS else DEFAULT_PROTOCOL
            pending["step"] = "fingerprint"
            await _edit(chat_id, message_id, _wizard_prompt("fingerprint", wdata), _wizard_fp_kb())
            return

        if data.startswith("w:fp:") and step == "fingerprint":
            fp = data.split(":", 2)[2]
            wdata["fingerprint"] = fp if fp in FINGERPRINTS else DEFAULT_FINGERPRINT
            pending["step"] = "alpn"
            await _edit(chat_id, message_id, _wizard_prompt("alpn", wdata), _wizard_alpn_kb())
            return

        if data.startswith("w:alpnpreset:") and step == "alpn":
            code = data.split(":", 2)[2]
            wdata["alpn"] = ALPN_PRESET_MAP.get(code, "")
            pending["step"] = "port"
            await _edit(chat_id, message_id, _wizard_prompt("port", wdata), _wizard_skip_kb("port", f"⏭ پیش‌فرض ({DEFAULT_PORT})"))
            return

        if data == "w:skip:alpn" and step == "alpn":
            wdata["alpn"] = ""
            pending["step"] = "port"
            await _edit(chat_id, message_id, _wizard_prompt("port", wdata), _wizard_skip_kb("port", f"⏭ پیش‌فرض ({DEFAULT_PORT})"))
            return

        if data == "w:skip:port" and step == "port":
            wdata["port"] = DEFAULT_PORT
            pending["step"] = "volume"
            await _edit(chat_id, message_id, _wizard_prompt("volume", wdata), _wizard_unlimited_kb("volume"))
            return

        if data == "w:skip:volume" and step == "volume":
            wdata["limit_bytes"] = 0
            pending["step"] = "speed"
            await _edit(chat_id, message_id, _wizard_prompt("speed", wdata), _wizard_unlimited_kb("speed"))
            return

        if data == "w:skip:speed" and step == "speed":
            wdata["speed_limit_bytes"] = 0
            pending["step"] = "iplimit"
            await _edit(chat_id, message_id, _wizard_prompt("iplimit", wdata), _wizard_unlimited_kb("iplimit"))
            return

        if data == "w:skip:iplimit" and step == "iplimit":
            wdata["ip_limit"] = 0
            pending["step"] = "days"
            await _edit(chat_id, message_id, _wizard_prompt("days", wdata), _wizard_unlimited_kb("days"))
            return

        if data == "w:skip:days" and step == "days":
            wdata["expires_days"] = 0
            pending["step"] = "confirm"
            await _edit(chat_id, message_id, _wizard_summary(wdata), _wizard_confirm_kb())
            return

        if data == "w:confirm" and step == "confirm":
            expires_days = wdata.get("expires_days", 0)
            expires_at = (datetime.now() + timedelta(days=expires_days)).isoformat() if expires_days > 0 else None
            uid, link = await make_link(
                label=wdata.get("label") or "کانفیگ جدید",
                limit_bytes=wdata.get("limit_bytes", 0),
                expires_at=expires_at,
                protocol=wdata.get("protocol", DEFAULT_PROTOCOL),
                fingerprint=wdata.get("fingerprint", DEFAULT_FINGERPRINT),
                alpn=wdata.get("alpn", ""),
                port=wdata.get("port", DEFAULT_PORT),
                ip_limit=wdata.get("ip_limit", 0),
                speed_limit_bytes=wdata.get("speed_limit_bytes", 0),
            )
            _pending.pop(chat_id, None)
            await _edit(chat_id, message_id, f"✅ کانفیگ ساخته شد.\n\n{_format_detail(uid, link)}", _link_detail_kb(uid, link["active"]))
            return

        # هیچ‌کدوم از حالت‌های بالا مچ نشد (مثلاً روی دکمه‌ی مرحله‌ی قبلی که دیگه معتبر نیست زده)
        await _answer_cb(cb_id, "این دکمه دیگه معتبر نیست.")
        return

    if data.startswith("view:"):
        uid = data.split(":", 1)[1]
        l = LINKS.get(uid)
        if not l:
            await _edit(chat_id, message_id, "این کانفیگ دیگه وجود نداره.", _main_menu_kb())
            return
        await _edit(chat_id, message_id, _format_detail(uid, l), _link_detail_kb(uid, l["active"]))
        return

    if data.startswith("toggle:"):
        uid = data.split(":", 1)[1]
        l = await set_link_active(uid, not LINKS.get(uid, {}).get("active", True))
        if not l:
            await _edit(chat_id, message_id, "این کانفیگ دیگه وجود نداره.", _main_menu_kb())
            return
        await _edit(chat_id, message_id, _format_detail(uid, l), _link_detail_kb(uid, l["active"]))
        return

    if data.startswith("link:"):
        uid = data.split(":", 1)[1]
        l = LINKS.get(uid)
        if not l:
            await _answer_cb(cb_id, "کانفیگ پیدا نشد")
            return
        host = get_host()
        vless = vless_link_for_link(l, uid, host)
        sub_url = f"https://{host}/sub/{uid}"
        msg = (
            f"🔗 لینک اتصال «{l.get('label')}»:\n\n<code>{vless}</code>\n\n"
            f"لینک ساب مشتری (۳ پروتکل + حجم و زمان):\n<code>{sub_url}</code>"
        )
        sid = l.get("sub_id")
        if sid and sid in SUBS:
            msg += f"\n\n✨ لینک ساب حرفه‌ای گروه «{SUBS[sid].get('name','?')}»:\n<code>{_group_public_url(SUBS[sid])}</code>"
        else:
            msg += "\n\nℹ️ این کانفیگ توی هیچ گروهی نیست. برای گرفتن لینک ساب حرفه‌ای، از دکمه‌ی «🗂 گروه ساب» توی صفحه‌ی کانفیگ استفاده کن."
        await _send(chat_id, msg)
        return

    if data.startswith("del:"):
        uid = data.split(":", 1)[1]
        l = LINKS.get(uid)
        if not l:
            await _edit(chat_id, message_id, "این کانفیگ دیگه وجود نداره.", _main_menu_kb())
            return
        await _edit(chat_id, message_id, f"❗️ از حذف «{l.get('label')}» مطمئنی؟ این عمل برگشت‌ناپذیره.", _confirm_delete_kb(uid))
        return

    if data.startswith("delok:"):
        uid = data.split(":", 1)[1]
        label = await remove_link(uid)
        if label is None:
            await _edit(chat_id, message_id, "این کانفیگ قبلاً حذف شده بود.", _main_menu_kb())
        else:
            await _edit(chat_id, message_id, f"🗑 کانفیگ «{label}» حذف شد.", _main_menu_kb())
        return

# ── Polling loop ─────────────────────────────────────────────────────────────
async def _poll_loop():
    global _running
    offset = 0
    logger.info(f"🤖 Telegram bot polling started (admins: {len(ADMIN_IDS)})")
    while _running:
        try:
            res = await _call("getUpdates", offset=offset, timeout=30, allowed_updates=["message", "callback_query"])
            if not res or not res.get("ok"):
                await asyncio.sleep(3)
                continue
            for upd in res.get("result", []):
                offset = upd["update_id"] + 1
                try:
                    if "message" in upd:
                        _m = upd["message"]
                        if _m.get("document"):
                            await _handle_document(_m)
                        else:
                            await _handle_message(_m)
                    elif "callback_query" in upd:
                        await _handle_callback(upd["callback_query"])
                except Exception as e:
                    logger.warning(f"Telegram update handling error: {e}")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.warning(f"Telegram poll loop error: {e}")
            await asyncio.sleep(3)

# ── Lifecycle ────────────────────────────────────────────────────────────────
async def start_bot():
    global _client, _poll_task, _running
    if not BOT_TOKEN:
        logger.info("Telegram bot: TELEGRAM_BOT_TOKEN تنظیم نشده، ربات غیرفعاله.")
        return
    if not ADMIN_IDS:
        logger.warning("Telegram bot: TELEGRAM_ADMIN_IDS تنظیم نشده، هیچ‌کس اجازه‌ی مدیریت نداره (ربات روشنه ولی همه رد می‌شن).")
    _client = httpx.AsyncClient(timeout=httpx.Timeout(40.0, connect=10.0))
    _running = True
    _poll_task = asyncio.create_task(_poll_loop())

async def stop_bot():
    global _running, _client
    _running = False
    if _poll_task:
        _poll_task.cancel()
    if _client:
        await _client.aclose()
        _client = None
