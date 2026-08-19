# multipath.py
# ══════════════════════════════════════════════════════════════════════════════
#  ⚛️  XR — Quantum MultiPath Engine  (پورت‌شده از Nyx Panel v2.3.0)
#      Nyx: backend/src/services/multiPathService.ts
#           backend/src/services/panicModeService.ts
#           backend/src/services/loadBalancerService.ts
#
#  سه سامانه در یک ماژول:
#
#   ۱) موتور پایش ۴ مسیره (Quantum MultiPath Engine)
#      هر ۱۵ ثانیه به‌صورت موازی ۴ مسیر ارتباطی مستقل تست می‌شوند:
#        🛡️  Route 1 — Direct TLS (VLESS + REALITY مستقیم)
#        ☁️  Route 2 — CDN داخلی ایران (ابر آروان / PoP داخل کشور)
#        🌐  Route 3 — امکان تونل DNS روی پورت ۵۳
#        📡  Route 4 — تونل ICMP لایه ۳ (پینگ خام)
#      بهترین مسیر بر اساس امتیاز ۰ تا ۱۰۰ انتخاب می‌شود.
#
#   ۲) حالت اضطراری (Panic Mode) با منطق Hysteresis
#      برای جلوگیری از آلارم کاذب، فقط پس از ۳ چک متوالی ناموفق فعال می‌شود و
#      پس از ۲ چک متوالی موفق رفع می‌گردد. هشدار و پیام رفع بحران (با مدت دقیق
#      قطعی) به ربات تلگرام ادمین ارسال می‌شود.
#
#   ۳) لودبالانسر هوشمند (Smart Health Load Balancer)
#      هر ۳۰ ثانیه همه کانفیگ‌های فعال بر اساس تاخیر، پایداری و آپتایم نمره
#      می‌گیرند (۰ تا ۱۰۰) تا سالم‌ترین سرور همیشه در ردیف اول سابسکریپشن باشد.
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import os
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
from collections import deque
from datetime import datetime

from main import (
    CONFIG,
    IRAN_TZ,
    LINKS,
    LINKS_LOCK,
    is_link_allowed,
    log_activity,
    logger,
)

# ══════════════════════════════════════════════════════════════════════════════
# ثابت‌ها و متادیتای ۴ مسیر
# ══════════════════════════════════════════════════════════════════════════════

PATH_TYPES = ("DIRECT_TLS", "CDN_IRAN", "DNS_TUNNEL", "ICMP_PING")

PATH_META = {
    "DIRECT_TLS": {
        "label": "Direct TLS / VLESS Reality",
        "label_fa": "مسیر مستقیم TLS / ریلیتی",
        "desc_fa": "اتصال مستقیم به SNI کانفیگ — مسیر استاندارد و سریع‌ترین حالت",
        "emoji": "🛡️",
    },
    "CDN_IRAN": {
        "label": "CDN Iran Gateway (ArvanCloud PoP)",
        "label_fa": "دروازه CDN داخلی (ابر آروان)",
        "desc_fa": "وقتی DPI مسیر مستقیم را می‌بندد، CDN داخل ایران هنوز پاسخ می‌دهد",
        "emoji": "☁️",
    },
    "DNS_TUNNEL": {
        "label": "DNS Tunnel Viability (Port 53)",
        "label_fa": "امکان تونل DNS (پورت ۵۳)",
        "desc_fa": "پورت ۵۳ تقریباً هیچ‌وقت بسته نمی‌شود — راه نجات قطعی‌های سنگین",
        "emoji": "🌐",
    },
    "ICMP_PING": {
        "label": "ICMP Ping Path (L3 Bypass)",
        "label_fa": "مسیر پینگ ICMP (دور زدن لایه ۳)",
        "desc_fa": "اگر بسته خام لایه ۳ عبور کند، تونل ICMP در حالت اضطراری ممکن است",
        "emoji": "📡",
    },
}

# دامنه‌ی پیش‌فرض تست مسیر مستقیم (وقتی هیچ SNI سراسری تنظیم نشده باشد)
DEFAULT_PROBE_SNI = "ebanking.banksepah.ir"
# دروازه CDN داخل ایران برای مسیر دوم
CDN_IRAN_HOST = "arvancloud.ir"
# رزولورهای DNS برای مسیر سوم
DNS_SERVERS = ("8.8.8.8", "1.1.1.1", "4.2.2.4")
# هدف پینگ برای مسیر چهارم
ICMP_TARGET = "8.8.8.8"

HEALTH_LEVELS = ("EXCELLENT", "GOOD", "DEGRADED", "CRITICAL", "PANIC")

HEALTH_FA = {
    "EXCELLENT": "عالی",
    "GOOD": "خوب",
    "DEGRADED": "افت‌کرده",
    "CRITICAL": "بحرانی",
    "PANIC": "اضطراری",
}


def _now_iso() -> str:
    return datetime.now(IRAN_TZ).isoformat()


def _now_fa_time() -> str:
    return datetime.now(IRAN_TZ).strftime("%H:%M:%S")


def _default_probe_sni() -> str:
    """SNI ای که مسیر ۱ با آن تست می‌شود: SNI سراسری Auto-Failover → دامنه CDN → پیش‌فرض."""
    sni = (CONFIG.get("auto_failover", {}) or {}).get("default_sni") or ""
    sni = str(sni).strip()
    if sni:
        return sni
    cdn = str(CONFIG.get("cdn_domain") or "").strip()
    if cdn:
        return cdn.split(":")[0]
    return DEFAULT_PROBE_SNI


def _mp_cfg() -> dict:
    """تنظیمات موتور از CONFIG (با مقادیر پیش‌فرض امن)."""
    cfg = CONFIG.setdefault("multipath", {})
    cfg.setdefault("enabled", True)
    cfg.setdefault("interval", 15)
    cfg.setdefault("lb_enabled", True)
    cfg.setdefault("lb_interval", 30)
    cfg.setdefault("panic_alerts", True)
    return cfg


# ══════════════════════════════════════════════════════════════════════════════
# محاسبهٔ امتیاز سلامت (calcScore در Nyx)
# ══════════════════════════════════════════════════════════════════════════════

def calc_score(healthy: bool, latency_ms: float, consecutive_failures: int) -> int:
    """امتیاز ۰ تا ۱۰۰ برای یک مسیر — دقیقاً مطابق منطق Nyx."""
    if not healthy:
        return 0
    if latency_ms < 80:
        score = 100
    elif latency_ms < 200:
        score = 90
    elif latency_ms < 400:
        score = 75
    elif latency_ms < 800:
        score = 55
    elif latency_ms < 1500:
        score = 35
    else:
        score = 15
    # پاداش پایداری — مسیری که اخیراً هیچ خطایی نداشته
    if consecutive_failures == 0:
        score = min(100, score + 5)
    return score


def calc_inbound_score(healthy: bool, latency_ms: float, cf: int, uptime: int) -> int:
    """امتیاز سلامت یک کانفیگ برای لودبالانسر (calcInboundScore در Nyx)."""
    if not healthy:
        return 0
    if latency_ms < 80:
        base = 100
    elif latency_ms < 180:
        base = 92
    elif latency_ms < 350:
        base = 80
    elif latency_ms < 600:
        base = 62
    elif latency_ms < 1000:
        base = 42
    else:
        base = 22
    # وزن آپتایم: سروری با ۹۵٪+ آپتایم پاداش می‌گیرد
    if uptime >= 95:
        uptime_bonus = 8
    elif uptime >= 80:
        uptime_bonus = 4
    elif uptime >= 60:
        uptime_bonus = 0
    else:
        uptime_bonus = -5
    stability_bonus = 3 if cf == 0 else 0
    return max(0, min(100, base + uptime_bonus + stability_bonus))


# ══════════════════════════════════════════════════════════════════════════════
# تست‌کننده‌های ۴ مسیر
# ══════════════════════════════════════════════════════════════════════════════

def _tls_probe_sync(host: str, port: int = 443, timeout_ms: int = 4500) -> dict:
    """TLS handshake واقعی روی پورت ۴۴۳ (معادل tls.connect در Nyx)."""
    timeout = max(0.5, timeout_ms / 1000)
    start = time.monotonic()
    raw = None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        with ctx.wrap_socket(raw, server_hostname=host) as sock:
            sock.do_handshake()
            return {"healthy": True, "latency_ms": round((time.monotonic() - start) * 1000, 1)}
    except socket.timeout:
        return {"healthy": False, "latency_ms": timeout_ms, "error": f"TLS Timeout (>{timeout:.1f}s)"}
    except Exception as e:  # noqa: BLE001 — هر خطای شبکه یعنی مسیر ناسالم
        return {"healthy": False, "latency_ms": 9999, "error": str(e)[:100] or "TLS failed"}
    finally:
        try:
            if raw is not None:
                raw.close()
        except Exception:
            pass


async def test_direct_tls(sni: str, timeout_ms: int = 4500) -> dict:
    """مسیر ۱ — دست‌دادن واقعی TLS با SNI کانفیگ (اثبات کارکرد VLESS/Reality)."""
    return await asyncio.to_thread(_tls_probe_sync, sni, 443, timeout_ms)


async def test_cdn_iran(timeout_ms: int = 4000) -> dict:
    """مسیر ۲ — ابر آروان PoP داخل ایران دارد؛ اگر جواب دهد تونل CDN‌محور ممکن است."""
    return await asyncio.to_thread(_tls_probe_sync, CDN_IRAN_HOST, 443, timeout_ms)


def _dns_query_sync(server: str, qname: str = "google.com", timeout_ms: int = 3000) -> dict:
    """یک کوئری خام DNS/UDP روی پورت ۵۳ (بدون وابستگی خارجی).

    اگر پاسخ معتبر با حداقل یک رکورد A برگردد، یعنی پورت ۵۳ باز است و تونل DNS
    در شرایط قطعی سنگین قابل استفاده خواهد بود.
    """
    timeout = max(0.5, timeout_ms / 1000)
    start = time.monotonic()
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)  # RD=1، ۱ سؤال
    qbytes = b"".join(bytes([len(p)]) + p.encode("ascii") for p in qname.split(".")) + b"\x00"
    packet = header + qbytes + struct.pack(">HH", 1, 1)  # QTYPE=A، QCLASS=IN

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(1024)
        latency = round((time.monotonic() - start) * 1000, 1)
        if len(data) < 12:
            return {"healthy": False, "latency_ms": latency, "error": "پاسخ DNS ناقص"}
        resp_id, flags, _qd, ancount = struct.unpack(">HHHH", data[:8])
        if resp_id != tid:
            return {"healthy": False, "latency_ms": latency, "error": "شناسه پاسخ DNS نامعتبر"}
        rcode = flags & 0x000F
        if rcode != 0:
            return {"healthy": False, "latency_ms": latency, "error": f"DNS RCODE={rcode}"}
        if ancount < 1:
            return {"healthy": False, "latency_ms": latency, "error": "پاسخ DNS خالی"}
        return {"healthy": True, "latency_ms": latency, "server": server}
    except socket.timeout:
        return {"healthy": False, "latency_ms": timeout_ms, "error": f"DNS Timeout (>{timeout:.1f}s)"}
    except Exception as e:  # noqa: BLE001
        return {"healthy": False, "latency_ms": 9999, "error": str(e)[:100] or "DNS failed"}
    finally:
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass


async def test_dns_tunnel(timeout_ms: int = 3000) -> dict:
    """مسیر ۳ — رزولوشن DNS روی پورت ۵۳ (چند رزولور، اولین موفقیت کافی است)."""
    last = {"healthy": False, "latency_ms": 9999, "error": "هیچ رزولوری پاسخ نداد"}
    per_server = max(800, int(timeout_ms / len(DNS_SERVERS)))
    for server in DNS_SERVERS:
        res = await asyncio.to_thread(_dns_query_sync, server, "google.com", per_server)
        if res.get("healthy"):
            return res
        last = res
    return last


_PING_RTT_RE = re.compile(r"time[=<]\s*(\d+\.?\d*)\s*ms", re.IGNORECASE)
_PING_ANY_MS_RE = re.compile(r"(\d+\.?\d*)\s*ms", re.IGNORECASE)


def _icmp_ping_sync(target: str = ICMP_TARGET, timeout_ms: int = 3500) -> dict:
    """مسیر ۴ — پینگ ICMP خام (اثبات عبور بسته در لایه ۳)."""
    start = time.monotonic()
    secs = max(1, int(round(timeout_ms / 1000)))
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), target]
    else:
        cmd = ["ping", "-c", "1", "-W", str(secs), target]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=secs + 2,
            text=True,
        )
        elapsed = round((time.monotonic() - start) * 1000, 1)
        if proc.returncode != 0:
            return {"healthy": False, "latency_ms": elapsed, "error": "بسته ICMP بی‌پاسخ ماند"}
        out = proc.stdout or ""
        m = _PING_RTT_RE.search(out) or _PING_ANY_MS_RE.search(out)
        return {"healthy": True, "latency_ms": round(float(m.group(1)), 1) if m else elapsed}
    except subprocess.TimeoutExpired:
        return {"healthy": False, "latency_ms": timeout_ms, "error": "ICMP Timeout"}
    except FileNotFoundError:
        return {"healthy": False, "latency_ms": 9999, "error": "دستور ping روی سرور موجود نیست"}
    except Exception as e:  # noqa: BLE001
        return {"healthy": False, "latency_ms": 9999, "error": str(e)[:100] or "ICMP failed"}


async def test_icmp_ping(target: str = ICMP_TARGET, timeout_ms: int = 3500) -> dict:
    return await asyncio.to_thread(_icmp_ping_sync, target, timeout_ms)


# ══════════════════════════════════════════════════════════════════════════════
# ⚛️ موتور اصلی — Quantum MultiPath Engine
# ══════════════════════════════════════════════════════════════════════════════

class MultiPathEngine:
    """پایش موازی ۴ مسیر و انتخاب خودکار بهترین مسیر (MultiPathEngine در Nyx)."""

    def __init__(self):
        self.snapshot = self._initial_snapshot()
        self._task: asyncio.Task | None = None
        self._running = False
        self.check_count = 0
        self.history: deque = deque(maxlen=60)  # آخرین ۶۰ چک برای نمودار زنده

    # ── وضعیت اولیه ───────────────────────────────────────────────────────────
    def _initial_snapshot(self) -> dict:
        paths = {}
        for p in PATH_TYPES:
            paths[p] = {
                "path": p,
                **PATH_META[p],
                "healthy": False,
                "latency_ms": 9999,
                "error": None,
                "timestamp": _now_iso(),
                "consecutive_failures": 0,
                "score": 0,
            }
        return {
            "overall_health": "DEGRADED",
            "overall_health_fa": HEALTH_FA["DEGRADED"],
            "paths": paths,
            "best_path": None,
            "panic_mode": False,
            "healthy_count": 0,
            "avg_score": 0,
            "recommendation_fa": "در حال راه‌اندازی موتور مسیریابی چندگانه کوانتومی...",
            "last_update": _now_iso(),
            "check_count": 0,
        }

    @property
    def enabled(self) -> bool:
        return bool(_mp_cfg().get("enabled", True))

    @property
    def interval(self) -> int:
        try:
            return max(5, int(_mp_cfg().get("interval", 15)))
        except (TypeError, ValueError):
            return 15

    # ── اجرای همزمان هر ۴ تست (Promise.allSettled در Nyx) ────────────────────
    async def check_all_paths(self) -> dict:
        self.check_count += 1
        sni = _default_probe_sni()

        results = await asyncio.gather(
            test_direct_tls(sni),
            test_cdn_iran(),
            test_dns_tunnel(),
            test_icmp_ping(),
            return_exceptions=True,
        )

        raw = {}
        for key, res in zip(PATH_TYPES, results):
            if isinstance(res, BaseException):
                raw[key] = {"healthy": False, "latency_ms": 9999, "error": str(res)[:100] or "تست ناموفق"}
            else:
                raw[key] = res

        paths = {}
        for p in PATH_TYPES:
            prev = self.snapshot["paths"].get(p, {})
            res = raw[p]
            cf = 0 if res.get("healthy") else int(prev.get("consecutive_failures", 0)) + 1
            paths[p] = {
                "path": p,
                **PATH_META[p],
                "healthy": bool(res.get("healthy")),
                "latency_ms": res.get("latency_ms", 9999),
                "error": res.get("error"),
                "timestamp": _now_iso(),
                "consecutive_failures": cf,
                "score": calc_score(bool(res.get("healthy")), float(res.get("latency_ms", 9999)), cf),
            }
        # مسیر ۱ همیشه SNI واقعی در حال استفاده را نشان دهد
        paths["DIRECT_TLS"]["target"] = sni

        healthy = [p for p in paths.values() if p["healthy"]]
        healthy_count = len(healthy)
        avg_score = round(sum(p["score"] for p in paths.values()) / len(PATH_TYPES), 1)
        panic = healthy_count == 0

        if healthy_count == 4 and avg_score >= 80:
            overall = "EXCELLENT"
        elif healthy_count >= 3 and avg_score >= 55:
            overall = "GOOD"
        elif healthy_count == 2:
            overall = "DEGRADED"
        elif healthy_count == 1:
            overall = "CRITICAL"
        else:
            overall = "PANIC"

        best = max(healthy, key=lambda p: p["score"])["path"] if healthy else None

        self.snapshot = {
            "overall_health": overall,
            "overall_health_fa": HEALTH_FA[overall],
            "paths": paths,
            "best_path": best,
            "panic_mode": panic,
            "healthy_count": healthy_count,
            "avg_score": avg_score,
            "recommendation_fa": self._recommendation(overall, best, paths, healthy_count),
            "last_update": _now_iso(),
            "check_count": self.check_count,
        }

        self.history.appendleft({
            "time": self.snapshot["last_update"],
            "overall_health": overall,
            "healthy_count": healthy_count,
            "avg_score": avg_score,
            "best_path": best,
        })

        summary = " | ".join(
            f"{p['emoji']}{int(p['latency_ms'])}ms" if p["healthy"] else f"{p['emoji']}FAIL"
            for p in paths.values()
        )
        line = f"[MultiPath] [{overall}] {summary} | بهترین: {best or 'هیچ'}"
        if overall in ("CRITICAL", "PANIC"):
            logger.warning(line)
        else:
            logger.info(line)

        return self.snapshot

    def _recommendation(self, health: str, best: str | None, paths: dict, healthy_count: int) -> str:
        lat = f"{int(paths[best]['latency_ms'])}ms" if best else "—"
        best_fa = PATH_META[best]["label_fa"] if best else "—"
        if health == "EXCELLENT":
            return f"✅ هر ۴ مسیر سالم هستند. بهترین مسیر: {best_fa} ({lat})"
        if health == "GOOD":
            return f"🟢 شبکه پایدار است. مسیر بهینه {best_fa} ({lat}) فعال است."
        if health == "DEGRADED":
            return f"⚠️ اختلال DPI روی {4 - healthy_count} مسیر. فال‌بک خودکار روی {best_fa} ({lat}) فعال شد."
        if health == "CRITICAL":
            return f"🚨 بحرانی: ۳ مسیر مسدود شد! فقط {best_fa} ({lat}) پاسخگوست. پروتکل اضطراری فعال."
        return "🔴 حالت اضطراری — قطعی کامل اینترنت بین‌الملل تشخیص داده شد. همه مسیرها بی‌پاسخ هستند."

    def get_snapshot(self) -> dict:
        return self.snapshot

    # ── چرخهٔ دیمون ───────────────────────────────────────────────────────────
    async def _loop(self):
        try:
            await asyncio.sleep(6)  # مثل Nyx: اولین چک ۶ ثانیه بعد از بالا آمدن
        except asyncio.CancelledError:
            return
        while self._running:
            try:
                await self.check_all_paths()
                await panic_manager.tick()
            except asyncio.CancelledError:
                break
            except Exception as e:  # noqa: BLE001
                logger.warning(f"[MultiPath] خطای دیمون: {e}")
            try:
                await asyncio.sleep(self.interval)
            except asyncio.CancelledError:
                break

    def start(self):
        if self._running or (self._task and not self._task.done()):
            return
        if not self.enabled:
            logger.info("[MultiPath] موتور مسیریابی چندگانه غیرفعال است.")
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info(f"[MultiPath] ⚛️ موتور کوانتومی ۴ مسیره شروع شد (هر {self.interval} ثانیه).")

    def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None
        logger.info("[MultiPath] موتور متوقف شد.")

    def apply_settings(self):
        if self.enabled and not self._running:
            self.start()
        elif not self.enabled and self._running:
            self.stop()

    def get_status(self) -> dict:
        snap = dict(self.snapshot)
        snap["enabled"] = self.enabled
        snap["running"] = self._running
        snap["interval"] = self.interval
        snap["probe_sni"] = _default_probe_sni()
        snap["history"] = list(self.history)[:30]
        return snap


# ══════════════════════════════════════════════════════════════════════════════
# 🚨 حالت اضطراری — Panic Mode Emergency Response
# ══════════════════════════════════════════════════════════════════════════════

class PanicModeManager:
    """تشخیص قطعی ۱۰۰٪ با منطق Hysteresis + اعلان تلگرام (PanicModeManager در Nyx)."""

    PANIC_THRESHOLD = 3      # ۳ چک متوالی ناموفق → فعال شدن
    RECOVERY_THRESHOLD = 2   # ۲ چک متوالی موفق → رفع بحران

    def __init__(self):
        self.is_active = False
        self.started_at: float | None = None
        self.started_at_iso: str | None = None
        self.consecutive_panic = 0
        self.consecutive_recovery = 0
        self.total_events = 0
        self.history: deque = deque(maxlen=10)
        self._critical_warned = False

    @property
    def alerts_enabled(self) -> bool:
        return bool(_mp_cfg().get("panic_alerts", True))

    async def _notify(self, text: str):
        """ارسال پیام به ادمین‌های تلگرام (اگر ربات فعال باشد)."""
        if not self.alerts_enabled:
            return
        try:
            from telegram_bot import send_admin_notification
            await send_admin_notification(text)
        except Exception as e:  # noqa: BLE001 — نبود ربات نباید موتور را بخواباند
            logger.debug(f"[Panic Mode] ارسال اعلان تلگرام ممکن نشد: {e}")

    async def tick(self):
        snap = multipath_engine.get_snapshot()

        if snap.get("panic_mode"):
            self.consecutive_panic += 1
            self.consecutive_recovery = 0
            if not self.is_active and self.consecutive_panic >= self.PANIC_THRESHOLD:
                await self._activate(snap)
        else:
            self.consecutive_recovery += 1
            self.consecutive_panic = max(0, self.consecutive_panic - 1)
            if self.is_active and self.consecutive_recovery >= self.RECOVERY_THRESHOLD:
                await self._resolve(snap)

        # هشدار زودهنگام در وضعیت CRITICAL (قبل از قطعی کامل)
        if not self.is_active and snap.get("overall_health") == "CRITICAL":
            if not self._critical_warned:
                self._critical_warned = True
                await self._warn_critical(snap)
        elif snap.get("overall_health") not in ("CRITICAL", "PANIC"):
            self._critical_warned = False

    async def _activate(self, snap: dict):
        self.is_active = True
        self.started_at = time.time()
        self.started_at_iso = _now_iso()
        self.total_events += 1

        lines = "\n".join(
            f"{p['emoji']} <b>{p['label_fa']}</b>: "
            + (f"✅ {int(p['latency_ms'])}ms" if p["healthy"] else f"❌ {(p.get('error') or 'قطع')[:50]}")
            for p in snap["paths"].values()
        )
        msg = (
            "🔴 <b>حالت اضطراری XR فعال شد!</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"⏰ زمان: {_now_fa_time()}\n"
            "🌐 وضعیت: <b>قطعی کامل اینترنت بین‌الملل</b>\n\n"
            "📊 <b>وضعیت ۴ مسیر اتصال:</b>\n"
            f"{lines}\n\n"
            "🛡️ <b>اقدامات خودکار:</b>\n"
            "• سابسکریپشن‌ها به سالم‌ترین مسیر موجود هدایت می‌شوند\n"
            "• پایش مداوم فعال است — بازیابی خودکار اعلام خواهد شد\n\n"
            "<i>XR Quantum MultiPath Engine — Emergency Protocol Active</i>"
        )
        logger.error(f"[Panic Mode] 🔴 فعال شد — {self.consecutive_panic} چک متوالی ناموفق")
        log_activity("panic", "حالت اضطراری فعال شد: قطعی کامل اینترنت بین‌الملل", level="error")

        self.history.appendleft({
            "id": f"panic-{int(time.time())}",
            "triggered_at": self.started_at_iso,
            "resolved_at": None,
            "duration_seconds": None,
            "peak_health": snap.get("overall_health"),
            "paths_down": 4,
        })
        await self._notify(msg)

    async def _resolve(self, snap: dict):
        if self.started_at is None:
            self.is_active = False
            return
        duration = time.time() - self.started_at
        mins, secs = int(duration // 60), int(duration % 60)

        self.is_active = False
        self.consecutive_panic = 0
        self.consecutive_recovery = 0

        if self.history:
            self.history[0]["resolved_at"] = _now_iso()
            self.history[0]["duration_seconds"] = int(duration)

        best = snap["paths"].get(snap["best_path"]) if snap.get("best_path") else None
        msg = (
            "✅ <b>اتصال XR بازگردانی شد!</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"⏱️ مدت قطعی: <b>{mins} دقیقه و {secs} ثانیه</b>\n"
            f"⚡ بهترین مسیر: <b>{best['label_fa'] if best else '—'}</b>"
            f" ({int(best['latency_ms']) if best else '?'}ms)\n"
            f"🔄 وضعیت شبکه: <b>{snap.get('overall_health_fa', '—')}</b>\n"
            f"⏰ زمان بازیابی: {_now_fa_time()}\n\n"
            "<i>سیستم به حالت عادی بازگشت. همه سابسکریپشن‌ها فعال هستند.</i>"
        )
        logger.info(f"[Panic Mode] ✅ رفع شد — مدت قطعی: {mins}m {secs}s")
        log_activity("panic", f"بحران رفع شد — مدت قطعی {mins} دقیقه و {secs} ثانیه", level="info")
        self.started_at = None
        await self._notify(msg)

    async def _warn_critical(self, snap: dict):
        msg = (
            "🚨 <b>هشدار بحرانی XR</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"⚠️ فقط <b>{snap.get('healthy_count', 0)} از ۴ مسیر</b> پاسخگوست\n"
            "📉 وضعیت: <b>CRITICAL</b>\n"
            f"⏰ {_now_fa_time()}\n\n"
            "در صورت ادامه، حالت اضطراری کامل فعال خواهد شد."
        )
        logger.warning("[Panic Mode] 🚨 هشدار بحرانی ارسال شد")
        await self._notify(msg)

    def get_status(self) -> dict:
        return {
            "is_active": self.is_active,
            "started_at": self.started_at_iso if self.is_active else None,
            "active_for_seconds": int(time.time() - self.started_at) if (self.is_active and self.started_at) else 0,
            "consecutive_fail_checks": self.consecutive_panic,
            "panic_threshold": self.PANIC_THRESHOLD,
            "recovery_threshold": self.RECOVERY_THRESHOLD,
            "alerts_enabled": self.alerts_enabled,
            "total_events": self.total_events,
            "history": list(self.history)[:5],
        }


# ══════════════════════════════════════════════════════════════════════════════
# ⚖️ لودبالانسر هوشمند — Smart Health Load Balancer
# ══════════════════════════════════════════════════════════════════════════════

class LoadBalancer:
    """نمره‌دهی زندهٔ کانفیگ‌ها تا سالم‌ترین سرور همیشه ردیف اول ساب باشد."""

    def __init__(self):
        self.health: dict[str, dict] = {}
        self._task: asyncio.Task | None = None
        self._running = False
        self.last_check: str | None = None

    @property
    def enabled(self) -> bool:
        return bool(_mp_cfg().get("lb_enabled", True))

    @property
    def interval(self) -> int:
        try:
            return max(10, int(_mp_cfg().get("lb_interval", 30)))
        except (TypeError, ValueError):
            return 30

    def _target_for(self, link: dict) -> str:
        """دامنه‌ای که سلامت این کانفیگ با آن سنجیده می‌شود."""
        for key in ("sni", "cdn_host"):
            val = str(link.get(key) or "").strip()
            if val:
                return val.split(":")[0]
        gsni = str((CONFIG.get("auto_failover", {}) or {}).get("default_sni") or "").strip()
        if gsni:
            return gsni.split(":")[0]
        cdn = str(CONFIG.get("cdn_domain") or "").strip()
        if cdn:
            return cdn.split(":")[0]
        return DEFAULT_PROBE_SNI

    async def refresh(self) -> dict:
        async with LINKS_LOCK:
            snapshot = {uid: dict(l) for uid, l in LINKS.items() if is_link_allowed(l)}

        if not snapshot:
            self.last_check = _now_iso()
            return {"checked": 0, "healthy": 0}

        async def probe(uid: str, link: dict):
            target = self._target_for(link)
            res = await asyncio.to_thread(_tls_probe_sync, target, 443, 3500)
            prev = self.health.get(uid, {})
            checks_total = int(prev.get("checks_total", 0)) + 1
            checks_healthy = int(prev.get("checks_healthy", 0)) + (1 if res.get("healthy") else 0)
            cf = 0 if res.get("healthy") else int(prev.get("consecutive_failures", 0)) + 1
            cs = int(prev.get("consecutive_successes", 0)) + 1 if res.get("healthy") else 0
            uptime = round((checks_healthy / checks_total) * 100)
            self.health[uid] = {
                "uid": uid,
                "label": str(link.get("label") or "").strip() or uid[:8],
                "target": target,
                "port": link.get("port"),
                "protocol": link.get("protocol"),
                "healthy": bool(res.get("healthy")),
                "latency_ms": res.get("latency_ms", 9999),
                "error": res.get("error"),
                "score": calc_inbound_score(bool(res.get("healthy")), float(res.get("latency_ms", 9999)), cf, uptime),
                "uptime": uptime,
                "consecutive_failures": cf,
                "consecutive_successes": cs,
                "checks_total": checks_total,
                "checks_healthy": checks_healthy,
                "last_checked": _now_iso(),
            }

        await asyncio.gather(*(probe(uid, l) for uid, l in snapshot.items()), return_exceptions=True)

        # پاک‌سازی کانفیگ‌های حذف‌شده
        for uid in list(self.health):
            if uid not in snapshot:
                self.health.pop(uid, None)

        healthy = sum(1 for h in self.health.values() if h["healthy"])
        self.last_check = _now_iso()
        logger.info(f"[Load Balancer] ⚖️ پایش سلامت: {healthy}/{len(snapshot)} کانفیگ سالم")
        return {"checked": len(snapshot), "healthy": healthy}

    def sort_uids(self, uids: list[str]) -> list[str]:
        """مرتب‌سازی شناسه‌ها بر اساس امتیاز سلامت (بهترین اول).

        کانفیگ‌های بدون داده امتیاز خنثی ۵۰ می‌گیرند تا جریمه نشوند. ترتیب
        اولیه برای هم‌امتیازها حفظ می‌شود (مرتب‌سازی پایدار پایتون).
        """
        if not self.enabled or not self.health:
            return list(uids)
        return sorted(uids, key=lambda u: -int(self.health.get(u, {}).get("score", 50)))

    def get_all_health(self) -> list[dict]:
        return sorted(self.health.values(), key=lambda h: -h["score"])

    async def _loop(self):
        try:
            await asyncio.sleep(8)  # مثل Nyx: تاخیر اولیه تا آماده شدن state
        except asyncio.CancelledError:
            return
        while self._running:
            try:
                await self.refresh()
            except asyncio.CancelledError:
                break
            except Exception as e:  # noqa: BLE001
                logger.warning(f"[Load Balancer] خطای دیمون: {e}")
            try:
                await asyncio.sleep(self.interval)
            except asyncio.CancelledError:
                break

    def start(self):
        if self._running or (self._task and not self._task.done()):
            return
        if not self.enabled:
            logger.info("[Load Balancer] لودبالانسر غیرفعال است.")
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info(f"[Load Balancer] ⚖️ لودبالانسر هوشمند شروع شد (هر {self.interval} ثانیه).")

    def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None
        logger.info("[Load Balancer] لودبالانسر متوقف شد.")

    def apply_settings(self):
        if self.enabled and not self._running:
            self.start()
        elif not self.enabled and self._running:
            self.stop()

    def get_status(self) -> dict:
        items = self.get_all_health()
        return {
            "enabled": self.enabled,
            "running": self._running,
            "interval": self.interval,
            "last_check": self.last_check,
            "total": len(items),
            "healthy": sum(1 for h in items if h["healthy"]),
            "items": items,
        }


# ── نمونه‌های سراسری (مثل export const در Nyx) ────────────────────────────────
multipath_engine = MultiPathEngine()
panic_manager = PanicModeManager()
load_balancer = LoadBalancer()


def start_all():
    """راه‌اندازی هر سه سامانه — از رویداد startup در main.py صدا زده می‌شود."""
    multipath_engine.apply_settings()
    load_balancer.apply_settings()


def stop_all():
    multipath_engine.stop()
    load_balancer.stop()


def get_full_status() -> dict:
    """وضعیت کامل برای داشبورد زنده."""
    return {
        "multipath": multipath_engine.get_status(),
        "panic": panic_manager.get_status(),
        "load_balancer": load_balancer.get_status(),
    }
