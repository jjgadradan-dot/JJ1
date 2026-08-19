# backup_service.py
# ══════════════════════════════════════════════════════════════════════════════
#  💾 XR — بکاپ‌گیری خودکار دیتابیس در تلگرام و بازیابی ۱-کلیک
#      (پورت‌شده از Nyx Panel — backend/src/services/backupService.ts)
#
#   • هر ۲۴ ساعت (قابل تنظیم) فایل state پنل را با کد اعتبارسنجی SHA-256
#     به تلگرام ادمین می‌فرستد
#   • با ارسال دوباره‌ی همان فایل به ربات، همه کانفیگ‌ها و تنظیمات در چند
#     ثانیه بازگردانی می‌شوند
#   • قبل از هر بازیابی، یک نسخهٔ ایمنی از وضعیت فعلی گرفته می‌شود
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import hashlib
import json
import os
import time
from collections import deque
from datetime import datetime

from main import (
    AUTH,
    CONFIG,
    DATA_FILE,
    IRAN_TZ,
    LINKS,
    LINKS_LOCK,
    MASTER,
    NODES,
    NODE_API,
    SUBS,
    SUBS_LOCK,
    fmt_bytes,
    log_activity,
    logger,
    save_state,
)

BACKUP_VERSION = 1


def _cfg() -> dict:
    c = CONFIG.setdefault("backup", {})
    c.setdefault("enabled", os.environ.get("BACKUP_ENABLED", "1").strip()
                 not in ("0", "false", "no", ""))
    try:
        c.setdefault("interval_hours", max(1, int(os.environ.get("BACKUP_INTERVAL_HOURS", "24") or 24)))
    except (TypeError, ValueError):
        c.setdefault("interval_hours", 24)
    return c


def _now_iso() -> str:
    return datetime.now(IRAN_TZ).isoformat()


def compute_checksum(payload: bytes) -> str:
    """کد اعتبارسنجی SHA-256 برای اطمینان از سالم بودن فایل بکاپ."""
    return hashlib.sha256(payload).hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# ساخت و بازیابی بستهٔ بکاپ
# ══════════════════════════════════════════════════════════════════════════════

async def build_backup() -> tuple[bytes, dict]:
    """یک بستهٔ کامل JSON از وضعیت پنل می‌سازد.

    خروجی: (بایت‌های فایل، متادیتا شامل checksum و آمار)
    """
    await save_state()  # مطمئن شو آخرین تغییرات روی دیسک است

    async with LINKS_LOCK:
        links = {k: dict(v) for k, v in LINKS.items()}
    async with SUBS_LOCK:
        subs = {k: dict(v) for k, v in SUBS.items()}

    body = {
        "links": links,
        "subs": subs,
        "nodes": dict(NODES),
        "node_api": dict(NODE_API),
        "master": dict(MASTER),
        "password_hash": AUTH.get("password_hash"),
        "cdn_domain": CONFIG.get("cdn_domain", ""),
        "auto_failover": dict(CONFIG.get("auto_failover", {})),
        "multipath": dict(CONFIG.get("multipath", {})),
        "branding": dict(CONFIG.get("branding", {})),
        "warp": dict(CONFIG.get("warp", {})),
        "backup": dict(CONFIG.get("backup", {})),
    }
    body_bytes = json.dumps(body, ensure_ascii=False, sort_keys=True).encode("utf-8")
    checksum = compute_checksum(body_bytes)

    total_used = sum(int(l.get("used_bytes", 0)) for l in links.values())
    meta = {
        "backup_version": BACKUP_VERSION,
        "brand": "XR",
        "created_at": _now_iso(),
        "checksum_sha256": checksum,
        "links_count": len(links),
        "subs_count": len(subs),
        "nodes_count": len(NODES),
        "total_used_bytes": total_used,
        "total_used_fmt": fmt_bytes(total_used),
    }
    envelope = {"meta": meta, "data": body}
    return json.dumps(envelope, ensure_ascii=False, indent=2).encode("utf-8"), meta


def _validate_envelope(raw: bytes) -> tuple[dict, dict]:
    """بستهٔ بکاپ را می‌خواند و صحت checksum را بررسی می‌کند."""
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"فایل بکاپ خوانا نیست: {e}") from e

    if not isinstance(envelope, dict) or "data" not in envelope:
        raise ValueError("ساختار فایل بکاپ نامعتبر است (کلید data پیدا نشد)")

    meta = envelope.get("meta") or {}
    body = envelope["data"]
    if not isinstance(body, dict):
        raise ValueError("بخش data باید یک شیء JSON باشد")

    expected = str(meta.get("checksum_sha256") or "")
    if expected:
        actual = compute_checksum(
            json.dumps(body, ensure_ascii=False, sort_keys=True).encode("utf-8")
        )
        if actual != expected:
            raise ValueError("کد اعتبارسنجی SHA-256 نمی‌خواند — فایل دستکاری یا خراب شده است")
    return meta, body


async def restore_backup(raw: bytes, keep_password: bool = False) -> dict:
    """بازیابی کامل از فایل بکاپ.

    قبل از جایگزینی، یک نسخهٔ ایمنی از وضعیت فعلی کنار فایل state ذخیره می‌شود
    تا اگر بکاپ اشتباهی بازیابی شد، بشود برگشت.
    """
    meta, body = _validate_envelope(raw)

    # ── نسخهٔ ایمنی قبل از بازیابی ────────────────────────────────────────────
    safety_path = None
    try:
        safety_bytes, _ = await build_backup()
        safety_path = DATA_FILE.with_name(
            f"pre-restore-{datetime.now(IRAN_TZ).strftime('%Y%m%d-%H%M%S')}.json"
        )
        safety_path.write_bytes(safety_bytes)
    except Exception as e:  # noqa: BLE001 — نبود نسخهٔ ایمنی نباید جلوی بازیابی را بگیرد
        logger.warning(f"[Backup] ساخت نسخهٔ ایمنی ممکن نشد: {e}")

    # ── جایگزینی وضعیت ────────────────────────────────────────────────────────
    async with LINKS_LOCK:
        LINKS.clear()
        LINKS.update(body.get("links", {}) or {})
    async with SUBS_LOCK:
        SUBS.clear()
        SUBS.update(body.get("subs", {}) or {})

    NODES.clear()
    NODES.update(body.get("nodes", {}) or {})
    if body.get("node_api"):
        NODE_API.update(body["node_api"])
    if body.get("master"):
        MASTER.update(body["master"])

    if not keep_password and body.get("password_hash"):
        AUTH["password_hash"] = body["password_hash"]

    if "cdn_domain" in body:
        CONFIG["cdn_domain"] = str(body.get("cdn_domain") or "").strip()
    for key in ("auto_failover", "multipath", "branding", "warp", "backup"):
        if isinstance(body.get(key), dict):
            CONFIG.setdefault(key, {}).update(body[key])

    await save_state()

    result = {
        "links_restored": len(LINKS),
        "subs_restored": len(SUBS),
        "nodes_restored": len(NODES),
        "password_restored": (not keep_password) and bool(body.get("password_hash")),
        "backup_created_at": meta.get("created_at"),
        "checksum_verified": bool(meta.get("checksum_sha256")),
        "safety_copy": str(safety_path) if safety_path else None,
    }
    logger.info(f"[Backup] ✅ بازیابی انجام شد: {result['links_restored']} کانفیگ، "
                f"{result['subs_restored']} گروه")
    log_activity("backup",
                 f"بازیابی از بکاپ: {result['links_restored']} کانفیگ و "
                 f"{result['subs_restored']} گروه بازگردانی شد", "ok")
    return result


# ══════════════════════════════════════════════════════════════════════════════
# دیمون بکاپ خودکار
# ══════════════════════════════════════════════════════════════════════════════

class BackupManager:
    def __init__(self):
        self._task: asyncio.Task | None = None
        self._running = False
        self.last_backup: str | None = None
        self.last_checksum: str | None = None
        self.last_error: str | None = None
        self.total_backups = 0
        self.history: deque = deque(maxlen=10)

    @property
    def enabled(self) -> bool:
        return bool(_cfg().get("enabled", True))

    @property
    def interval_hours(self) -> int:
        try:
            return max(1, int(_cfg().get("interval_hours", 24)))
        except (TypeError, ValueError):
            return 24

    async def send_backup(self, reason: str = "خودکار") -> dict:
        """ساخت بکاپ و ارسال آن به تلگرام ادمین."""
        try:
            payload, meta = await build_backup()
        except Exception as e:  # noqa: BLE001
            self.last_error = str(e)[:200]
            logger.warning(f"[Backup] ساخت بکاپ ناموفق: {e}")
            return {"ok": False, "error": self.last_error}

        stamp = datetime.now(IRAN_TZ).strftime("%Y-%m-%d_%H-%M")
        filename = f"xr-backup-{stamp}.json"

        caption = (
            "💾 <b>بکاپ خودکار پنل XR</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📅 تاریخ: {datetime.now(IRAN_TZ).strftime('%Y/%m/%d — %H:%M')}\n"
            f"🔖 نوع: {reason}\n"
            f"🔗 کانفیگ‌ها: <b>{meta['links_count']}</b>\n"
            f"👥 گروه‌ها: <b>{meta['subs_count']}</b>\n"
            f"🖥️ نودها: <b>{meta['nodes_count']}</b>\n"
            f"📊 مصرف کل: <b>{meta['total_used_fmt']}</b>\n"
            f"🔐 SHA-256: <code>{meta['checksum_sha256'][:16]}…</code>\n\n"
            "<i>برای بازیابی، همین فایل را دوباره برای ربات بفرستید.</i>"
        )

        sent = 0
        try:
            from telegram_bot import send_admin_document
            sent = await send_admin_document(payload, filename, caption)
        except Exception as e:  # noqa: BLE001
            self.last_error = str(e)[:200]
            logger.warning(f"[Backup] ارسال به تلگرام ناموفق: {e}")

        self.last_backup = _now_iso()
        self.last_checksum = meta["checksum_sha256"]
        self.total_backups += 1
        entry = {
            "time": self.last_backup,
            "reason": reason,
            "filename": filename,
            "size_bytes": len(payload),
            "size_fmt": fmt_bytes(len(payload)),
            "checksum": meta["checksum_sha256"][:16],
            "links": meta["links_count"],
            "sent_to": sent,
        }
        self.history.appendleft(entry)

        if sent:
            self.last_error = None
            logger.info(f"[Backup] 💾 بکاپ برای {sent} ادمین ارسال شد ({fmt_bytes(len(payload))})")
            log_activity("backup", f"بکاپ {reason} برای {sent} ادمین تلگرام ارسال شد", "ok")
        else:
            logger.info("[Backup] 💾 بکاپ ساخته شد ولی ادمین/رباتی برای ارسال نبود")

        return {"ok": True, "sent_to": sent, **entry, "meta": meta}

    async def _loop(self):
        try:
            await asyncio.sleep(120)  # اولین بکاپ ۲ دقیقه پس از بالا آمدن سرور
        except asyncio.CancelledError:
            return
        while self._running:
            try:
                await self.send_backup("خودکار")
            except asyncio.CancelledError:
                break
            except Exception as e:  # noqa: BLE001
                logger.warning(f"[Backup] خطای دیمون: {e}")
            try:
                await asyncio.sleep(self.interval_hours * 3600)
            except asyncio.CancelledError:
                break

    def start(self):
        if self._running or (self._task and not self._task.done()):
            return
        if not self.enabled:
            logger.info("[Backup] بکاپ خودکار غیرفعال است.")
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info(f"[Backup] 💾 بکاپ خودکار شروع شد (هر {self.interval_hours} ساعت).")

    def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None
        logger.info("[Backup] بکاپ خودکار متوقف شد.")

    def apply_settings(self):
        if self.enabled and not self._running:
            self.start()
        elif not self.enabled and self._running:
            self.stop()

    def get_status(self) -> dict:
        next_in = None
        if self._running and self.last_backup:
            try:
                elapsed = time.time() - datetime.fromisoformat(self.last_backup).timestamp()
                next_in = max(0, int(self.interval_hours * 3600 - elapsed))
            except (TypeError, ValueError):
                next_in = None
        return {
            "enabled": self.enabled,
            "running": self._running,
            "interval_hours": self.interval_hours,
            "last_backup": self.last_backup,
            "last_checksum": self.last_checksum,
            "last_error": self.last_error,
            "total_backups": self.total_backups,
            "next_in_seconds": next_in,
            "history": list(self.history),
        }


backup_manager = BackupManager()
