# auto_failover.py
# ══════════════════════════════════════════════════════════════════════════════
# سامانه هوشمند سوئیچ خودکار SNI در زمان قطعی نت (Smart Auto-Failover Daemon)
# ── پورت‌شده از Nyx Panel (backend/src/services/autoFailoverService.ts) ──
#
# دیمون پس‌زمینه که هر N ثانیه (پیش‌فرض ۶۰) اتصال TLS دامنه‌های SNI فعال را
# زنده تست می‌کند؛ اگر یک SNI مسدود/فیلتر شده باشد، سالم‌ترین دامنه از
# لیست سفید (FALLBACK_SNI_POOL) را جایگزین می‌کند — بدون تغییر لینک کاربران
# (لینک‌ها و ساب‌ها با همان UUID می‌مانند و فقط SNI داخلشان عوض می‌شود).
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import os
import socket
import ssl
import time
from collections import deque

from main import (
    LINKS,
    LINKS_LOCK,
    CONFIG,
    save_state,
    is_link_allowed,
    log_activity,
    logger,
)

# ── لیست سفید SNI های پراطمینان برای شرایط شبکه ایران (از Nyx) ──────────────
FALLBACK_SNI_POOL = [
    {"domain": "ebanking.banksepah.ir", "label": "💳 Shaparak / Bank Sepah (Whitelist)"},
    {"domain": "bmi.ir", "label": "💳 Bank Melli (Whitelist)"},
    {"domain": "arvancloud.ir", "label": "☁️ ArvanCloud CDN"},
    {"domain": "divar.ir", "label": "🚗 Essential Apps"},
    {"domain": "digikala.com", "label": "🛒 E-Commerce"},
    {"domain": "pypi.org", "label": "📦 Software Repos"},
    {"domain": "archive.ubuntu.com", "label": "📦 Ubuntu Repo"},
    {"domain": "yahoo.com", "label": "🌐 Global Mask"},
]

DEFAULT_TIMEOUT_MS = 3000          # تست SNI فعلی
CANDIDATE_TIMEOUT_MS = 2500        # تست هر کاندیدای جایگزین (مثل Nyx)


def _tls_handshake_sync(domain: str, port: int = 443, timeout_ms: int = 3000) -> dict:
    """تست زندهٔ TLS handshake روی پورت 443 برای یک دامنهٔ SNI (همان tls.connect در Nyx).

    اگر دامنه سالم باشد latency برمی‌گرداند؛ اگر مسدود/بی‌پاسخ باشد خطا.
    verify غیرفعال است چون فقط می‌خواهیم بدانیم handshake جواب می‌دهد یا نه.
    """
    timeout = max(0.5, timeout_ms / 1000)
    start = time.monotonic()
    raw = None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((domain, port), timeout=timeout)
        raw.settimeout(timeout)
        with ctx.wrap_socket(raw, server_hostname=domain) as sock:
            sock.do_handshake()
            latency_ms = round((time.monotonic() - start) * 1000, 1)
            return {"domain": domain, "healthy": True, "latency_ms": latency_ms}
    except socket.timeout:
        if raw:
            raw.close()
        return {"domain": domain, "healthy": False, "latency_ms": 9999, "error": "Connection Timeout (>3s)"}
    except (ssl.SSLError, OSError, ValueError) as e:
        if raw:
            raw.close()
        return {"domain": domain, "healthy": False, "latency_ms": 9999, "error": str(e)[:120]}
    except Exception as e:
        if raw:
            raw.close()
        return {"domain": domain, "healthy": False, "latency_ms": 9999, "error": str(e)[:120]}


async def test_sni_domain(domain: str, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> dict:
    """نسخهٔ async تست TLS — مثل testSniDomain در Nyx."""
    return await asyncio.to_thread(_tls_handshake_sync, domain, 443, timeout_ms)


def _settings() -> dict:
    """تنظیمات فعلی دیمون از CONFIG (که از state.json و متغیرهای محیطی پر شده)."""
    return CONFIG.get("auto_failover", {})


def _default_sni() -> str:
    return (_settings().get("default_sni") or "").strip()


class AutoFailoverManager:
    """مدیریت دیمون پایش و سوئیچ خودکار SNI — مطابق AutoFailoverManager در Nyx."""

    def __init__(self):
        self._task: asyncio.Task | None = None
        self._running = False
        self.last_check: str | None = None
        self.last_checked_count = 0
        self.last_switched_count = 0
        self.last_error: str | None = None
        self.history: deque = deque(maxlen=50)

    # ── وضعیت ────────────────────────────────────────────────────────────────
    @property
    def enabled(self) -> bool:
        return bool(_settings().get("enabled", True))

    @property
    def interval(self) -> int:
        try:
            return max(10, int(_settings().get("interval", 60)))
        except (TypeError, ValueError):
            return 60

    # ── هستهٔ پایش و سوئیچ (checkAndFailoverInbounds در Nyx) ────────────────
    async def check_and_failover(self) -> dict:
        events = []
        switched = 0
        checked = 0
        try:
            async with LINKS_LOCK:
                snap = {
                    uid: dict(l) for uid, l in LINKS.items()
                    if is_link_allowed(l) and l.get("active", True)
                }

            # SNI مؤثر هر کانفیگ: sni اختصاصی → default_sni سراسری → بدون SNI (رد شدن)
            by_sni: dict[str, list[str]] = {}
            for uid, link in snap.items():
                sni = (link.get("sni") or "").strip() or _default_sni()
                if not sni:
                    continue
                by_sni.setdefault(sni, []).append(uid)

            for sni, uids in by_sni.items():
                logger.info(f"[Auto-Failover] تست زنده SNI «{sni}» ...")
                health = await test_sni_domain(sni, DEFAULT_TIMEOUT_MS)
                checked += 1
                if health["healthy"]:
                    logger.info(f"[Auto-Failover] ✅ SNI «{sni}» سالم است ({health['latency_ms']}ms)")
                    continue

                logger.warning(
                    f"[Auto-Failover] ⚠️ SNI «{sni}» مسدود/ناموفق شد "
                    f"({health.get('error') or 'Blocked'}). در حال جستجوی SNI جایگزین سالم..."
                )

                # جستجوی سالم‌ترین کاندیدای لیست سفید (مثل Nyx)
                candidate = None
                for cand in FALLBACK_SNI_POOL:
                    if cand["domain"] == sni:
                        continue
                    ch = await test_sni_domain(cand["domain"], CANDIDATE_TIMEOUT_MS)
                    if ch["healthy"]:
                        candidate = ch
                        break

                if candidate is None:
                    self.last_error = f"No healthy fallback for {sni}"
                    logger.error(
                        f"[Auto-Failover] ❌ هیچ SNI جایگزین سالمی برای «{sni}» پیدا نشد."
                    )
                    continue

                new_sni = candidate["domain"]
                labels = []
                async with LINKS_LOCK:
                    for uid in uids:
                        if uid in LINKS:
                            LINKS[uid]["sni"] = new_sni
                            labels.append(str(LINKS[uid].get("label") or uid))
                await save_state()

                switched += 1
                event = {
                    "links": uids,
                    "labels": labels[:5],
                    "old_sni": sni,
                    "new_sni": new_sni,
                    "latency_ms": candidate["latency_ms"],
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                }
                events.append(event)
                self.history.appendleft(event)

                log_activity(
                    "system",
                    f"Auto-Failover: SNI «{sni}» مسدود شد → سوئیچ به «{new_sni}» "
                    f"({candidate['latency_ms']}ms) برای {len(uids)} کانفیگ",
                    "warn",
                )
                logger.info(
                    f"[Auto-Failover] ⚡ سوئیچ خودکار SNI: {sni} -> {new_sni} "
                    f"({candidate['latency_ms']}ms) برای {len(uids)} کانفیگ"
                )
                await self._notify_admin(event)

            self.last_check = time.strftime("%Y-%m-%dT%H:%M:%S")
            self.last_checked_count = checked
            self.last_switched_count = switched
            self.last_error = None
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.last_error = str(e)[:200]
            logger.error(f"[Auto-Failover] خطا در اجرای پایش: {e}")

        return {
            "checked_count": checked,
            "switched_count": switched,
            "events": events,
            "last_check": self.last_check,
        }

    # ── هشدار تلگرام به ادمین (مثل sendAdminNotification در Nyx) ─────────────
    async def _notify_admin(self, event: dict):
        try:
            from telegram_bot import send_admin_notification
            msg = (
                "⚠️ <b>[هشدار Auto-Failover / سوئیچ اتوماتیک SNI]</b>\n"
                f"🔹 <b>کانفیگ:</b> {', '.join(event.get('labels') or event.get('links') or [])}\n"
                f"❌ <b>SNI مسدودشده:</b> <code>{event['old_sni']}</code>\n"
                f"✅ <b>SNI جدید فعال:</b> <code>{event['new_sni']}</code>\n"
                f"⚡ <b>تاخیر پاسخ:</b> {event['latency_ms']}ms\n"
                f"📅 <b>زمان:</b> {time.strftime('%H:%M:%S')}\n\n"
                "<i>لینک‌های ساب کاربران بدون تغییر به‌روز می‌شوند!</i>"
            )
            await send_admin_notification(msg)
        except Exception as e:
            logger.warning(f"[Auto-Failover] ارسال هشدار تلگرام ناموفق بود: {e}")

    # ── چرخهٔ دیمون ──────────────────────────────────────────────────────────
    async def _loop(self):
        # اولین چک ۱۰ ثانیه بعد از بالا آمدن سرور (مثل Nyx)
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            return
        while self._running:
            try:
                await self.check_and_failover()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"[Auto-Failover] خطای دیمون: {e}")
            try:
                await asyncio.sleep(self.interval)
            except asyncio.CancelledError:
                break

    def start(self):
        if self._running or (self._task and not self._task.done()):
            return
        if not self.enabled:
            logger.info("[Auto-Failover] دیمون غیرفعال است (AUTO_FAILOVER_ENABLED=0 یا از پنل خاموش شده).")
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info(f"[Auto-Failover] دیمون پایش خودکار SNI شروع شد (هر {self.interval} ثانیه).")

    def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None
        logger.info("[Auto-Failover] دیمون متوقف شد.")

    def apply_settings(self):
        """پس از تغییر تنظیمات (enable/disable/interval) دیمون را هماهنگ می‌کند."""
        if self.enabled and not self._running:
            self.start()
        elif not self.enabled and self._running:
            self.stop()

    # ── خروجی وضعیت (getStatus در Nyx) ───────────────────────────────────────
    def get_status(self) -> dict:
        return {
            "enabled": self.enabled,
            "running": self._running,
            "interval": self.interval,
            "default_sni": _default_sni(),
            "last_check": self.last_check,
            "last_checked_count": self.last_checked_count,
            "last_switched_count": self.last_switched_count,
            "last_error": self.last_error,
            "history": list(self.history)[:10],
            "pool": FALLBACK_SNI_POOL,
        }


auto_failover_manager = AutoFailoverManager()
