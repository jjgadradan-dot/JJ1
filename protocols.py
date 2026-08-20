# protocols.py
# ══════════════════════════════════════════════════════════════════════════════
#  🚀 XR — پروتکل‌ها و تنظیمات پکت فرگمنت  (پورت‌شده از Nyx Panel)
#
#   ۱) پروتکل Trojan روی ترابرد WebSocket — کنار VLESS موجود
#   ۲) تنظیمات دقیق پکت فرگمنت با پریست‌های تست‌شدهٔ اپراتورهای ایران
#
#  این ماژول عمداً از main.py چیزی ایمپورت نمی‌کند تا حلقهٔ ایمپورت ایجاد نشود.
# ══════════════════════════════════════════════════════════════════════════════

import hashlib
from urllib.parse import quote

# ══════════════════════════════════════════════════════════════════════════════
# پروتکل‌ها
# ══════════════════════════════════════════════════════════════════════════════

# پروتکل‌های مبتنی بر VLESS (ترابرد WS و سه مد XHTTP)
VLESS_PROTOCOLS = ("vless-ws", "xhttp-packet-up", "xhttp-stream-up", "xhttp-stream-one")
# پروتکل Trojan روی ترابرد WebSocket (رله‌ی واقعی در relay_trojan.py)
TROJAN_PROTOCOLS = ("trojan-ws",)

ALL_PROTOCOLS = VLESS_PROTOCOLS + TROJAN_PROTOCOLS

PROTOCOL_LABELS = {
    "vless-ws": "VLESS + WebSocket",
    "xhttp-packet-up": "VLESS + XHTTP (packet-up)",
    "xhttp-stream-up": "VLESS + XHTTP (stream-up)",
    "xhttp-stream-one": "VLESS + XHTTP (stream-one)",
    "trojan-ws": "Trojan + WebSocket",
}

# اسم کوتاه داخل لیست v2rayNG تا سه پروتکل یک مشتری قاطی نشوند
PROTOCOL_SHORT_LABELS = {
    "vless-ws": "VLESS-WS",
    "xhttp-packet-up": "XHTTP-packet",
    "xhttp-stream-up": "XHTTP-stream",
    "xhttp-stream-one": "XHTTP",
    "trojan-ws": "Trojan",
}


def customer_sub_protocols(primary: str | None) -> list[str]:
    """سه پروتکل جدا برای ساب مشتری از روی همان UUID.

    ترتیب: پروتکل انتخاب‌شدهٔ ادمین اول، بعد دو خانوادهٔ دیگر
    (VLESS-WS، یک مد XHTTP، Trojan) تا اگر یکی فیلتر شد بقیه وصل شوند.
    """
    primary = (primary or "").strip().lower()
    if primary not in ALL_PROTOCOLS:
        primary = "vless-ws"
    xhttp = primary if primary.startswith("xhttp-") else "xhttp-stream-one"
    out: list[str] = []
    for p in (primary, "vless-ws", xhttp, "trojan-ws"):
        if p not in out:
            out.append(p)
    return out[:3]


def is_trojan(protocol: str) -> bool:
    return (protocol or "") in TROJAN_PROTOCOLS


def trojan_password(uuid: str) -> str:
    """رمز Trojan هر کانفیگ = همان UUID آن (یکتا و بدون نیاز به مدیریت جداگانه)."""
    return uuid


def trojan_password_hash(uuid: str) -> str:
    """هش SHA-224 هگزادسیمال ۵۶ کاراکتری — دقیقاً همان چیزی که کلاینت Trojan می‌فرستد."""
    return hashlib.sha224(trojan_password(uuid).encode("utf-8")).hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# ⚡ پکت فرگمنت (Packet Fragment Tuning)
# ══════════════════════════════════════════════════════════════════════════════
#
# با شکستن بستهٔ ClientHello در TLS، سامانه‌های DPI نمی‌توانند SNI را بخوانند و
# اتصال را ببندند. مقادیر زیر روی شبکه‌های ایران تست شده‌اند (از Nyx Panel).

FRAGMENT_PRESETS = {
    "mci": {
        "id": "mci",
        "label": "📱 همراه اول (MCI)",
        "length": "100-200",
        "interval": "10-20",
        "packets": "tlshello",
        "hint": "بهترین پایداری روی نت همراه اول",
    },
    "irancell": {
        "id": "irancell",
        "label": "📡 ایرانسل (Irancell)",
        "length": "50-150",
        "interval": "5-15",
        "packets": "tlshello",
        "hint": "عبور مؤثر از فیلترینگ ایرانسل",
    },
    "intranet": {
        "id": "intranet",
        "label": "⚡ ترافیک داخلی / اینترانت",
        "length": "10-60",
        "interval": "2-10",
        "packets": "tlshello",
        "hint": "مناسب شبکهٔ ملی و ترافیک داخل کشور",
    },
    "custom": {
        "id": "custom",
        "label": "🛠️ دستی (Custom)",
        "length": "100-200",
        "interval": "10-20",
        "packets": "tlshello",
        "hint": "مقادیر دلخواه خودتان را وارد کنید",
    },
}

DEFAULT_FRAGMENT_PRESET = "mci"
# حالت‌های مجاز برای اینکه کدام بسته‌ها تکه‌تکه شوند
FRAGMENT_PACKET_MODES = ("tlshello", "1-1", "1-2", "1-3", "1-5")


def _clean_range(value: str, fallback: str) -> str:
    """اعتبارسنجی مقادیری مثل «100-200» یا «120». ورودی نامعتبر → مقدار پیش‌فرض."""
    v = str(value or "").strip().replace(" ", "")
    if not v:
        return fallback
    parts = v.split("-")
    if len(parts) > 2:
        return fallback
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return fallback
    if any(n < 0 or n > 100000 for n in nums):
        return fallback
    if len(nums) == 2:
        lo, hi = sorted(nums)
        return f"{lo}-{hi}"
    return str(nums[0])


def normalize_fragment(raw: dict | None) -> dict:
    """تنظیمات فرگمنت یک کانفیگ را تمیز و کامل می‌کند.

    خروجی همیشه شامل enabled / preset / length / interval / packets است.
    اگر پریست آماده انتخاب شده باشد، مقادیر آن پریست اعمال می‌شود؛ فقط در حالت
    «custom» مقادیر دستی کاربر خوانده می‌شوند.
    """
    raw = raw if isinstance(raw, dict) else {}
    preset = str(raw.get("preset") or DEFAULT_FRAGMENT_PRESET).strip().lower()
    if preset not in FRAGMENT_PRESETS:
        preset = DEFAULT_FRAGMENT_PRESET
    base = FRAGMENT_PRESETS[preset]

    if preset == "custom":
        length = _clean_range(raw.get("length"), base["length"])
        interval = _clean_range(raw.get("interval"), base["interval"])
        packets = str(raw.get("packets") or base["packets"]).strip().lower()
        if packets not in FRAGMENT_PACKET_MODES:
            packets = base["packets"]
    else:
        length, interval, packets = base["length"], base["interval"], base["packets"]

    return {
        "enabled": bool(raw.get("enabled", False)),
        "preset": preset,
        "length": length,
        "interval": interval,
        "packets": packets,
    }


def fragment_query_value(frag: dict | None) -> str:
    """مقدار پارامتر fragment در لینک اشتراک: «packets,length,interval».

    این قالب را کلاینت‌های Hiddify، NekoBox، Streisand و v2rayNG (نسخه‌های جدید)
    می‌شناسند. اگر فرگمنت خاموش باشد رشتهٔ خالی برمی‌گردد و پارامتری اضافه نمی‌شود.
    """
    f = normalize_fragment(frag)
    if not f["enabled"]:
        return ""
    return f"{f['packets']},{f['length']},{f['interval']}"


def fragment_summary_fa(frag: dict | None) -> str:
    """توضیح خوانا برای نمایش در پنل و ربات تلگرام."""
    f = normalize_fragment(frag)
    if not f["enabled"]:
        return "غیرفعال"
    label = FRAGMENT_PRESETS[f["preset"]]["label"]
    return f"{label} · طول {f['length']} · فاصله {f['interval']}"


# ══════════════════════════════════════════════════════════════════════════════
# ساخت لینک اشتراک Trojan
# ══════════════════════════════════════════════════════════════════════════════

def build_trojan_link(
    uuid: str,
    host: str,
    remark: str = "",
    port: int = 443,
    sni: str = "",
    fingerprint: str = "chrome",
    alpn: str = "http/1.1",
    fragment: dict | None = None,
) -> str:
    """لینک اشتراک Trojan روی ترابرد WebSocket.

    قالب: trojan://<password>@<host>:<port>?security=tls&type=ws&...#<remark>
    مسیر WS همان /trojan/{uuid} است که relay_trojan.py سرو می‌کند.
    """
    params = {
        "security": "tls",
        "type": "ws",
        "host": host,
        "path": f"/trojan/{uuid}",
        "sni": (sni or "").strip() or host,
        "fp": (fingerprint or "chrome").strip() or "chrome",
        "alpn": (alpn or "").strip() or "http/1.1",
    }
    frag = fragment_query_value(fragment)
    if frag:
        params["fragment"] = frag
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"trojan://{quote(trojan_password(uuid))}@{host}:{port}?{query}#{quote(remark)}"
