# warp_service.py
# ══════════════════════════════════════════════════════════════════════════════
#  🌐 XR — خروجی کلودفلر WARP  (Cloudflare WARP Outbound از Nyx Panel)
#
#  با فعال کردن WARP، ترافیک خروجی به مقصدهای انتخابی از شبکهٔ کلودفلر عبور
#  می‌کند. نتیجه:
#    • رفع تحریم OpenAI / ChatGPT / Netflix / Spotify و…
#    • مخفی ماندن IP واقعی سرور از دید مقصد
#
#  پیاده‌سازی: پنل XR رلهٔ پایتونی خودش را دارد (نه Xray)، بنابراین WARP اینجا
#  به‌صورت «مسیریابی خروجی از طریق یک پروکسی SOCKS5/HTTP» انجام می‌شود که
#  معمولاً همان wireproxy یا warp-svc محلی روی همان سرور است.
#  اگر پروکسی در دسترس نباشد، اتصال به‌صورت خودکار مستقیم برقرار می‌شود تا
#  هیچ‌وقت سرویس کاربران قطع نشود (fail-open).
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import os
import re
import socket
import struct
import time
from collections import deque
from datetime import datetime

from main import CONFIG, IRAN_TZ, log_activity, logger

# ⚡ سقف بافر خواندن جریان (پیش‌فرض asyncio=64KB). با مقدار بزرگ‌تر، backpressure
# کمتر و throughput بیشتری روی لینک‌های پرسرعت/پرتاخیر به دست می‌آید.
READ_LIMIT = int(os.environ.get("READ_LIMIT", str(2 * 1024 * 1024)))

# ── دامنه‌هایی که به‌طور پیش‌فرض از WARP عبور داده می‌شوند ─────────────────────
DEFAULT_WARP_DOMAINS = [
    "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
    "anthropic.com", "claude.ai",
    "netflix.com", "nflxvideo.net",
    "spotify.com", "scdn.co",
    "gemini.google.com", "bard.google.com",
    "intercom.io", "stripe.com",
]

# پیش‌فرض wireproxy: یک پروکسی SOCKS5 محلی روی 127.0.0.1:40000
DEFAULT_PROXY = os.environ.get("WARP_PROXY", "socks5://127.0.0.1:40000").strip()

_PROXY_RE = re.compile(r"^(?P<scheme>socks5h?|http)://(?:(?P<user>[^:@]+):(?P<pw>[^@]*)@)?"
                       r"(?P<host>[^:/]+):(?P<port>\d+)/?$", re.IGNORECASE)


def _cfg() -> dict:
    c = CONFIG.setdefault("warp", {})
    c.setdefault("enabled", os.environ.get("WARP_ENABLED", "0").strip()
                 not in ("0", "false", "no", ""))
    c.setdefault("proxy", DEFAULT_PROXY)
    c.setdefault("domains", list(DEFAULT_WARP_DOMAINS))
    c.setdefault("mode", "domains")  # domains = فقط لیست، all = همه ترافیک
    return c


def parse_proxy(url: str) -> dict | None:
    """رشتهٔ پروکسی را می‌شکافد. خروجی None یعنی نامعتبر."""
    m = _PROXY_RE.match((url or "").strip())
    if not m:
        return None
    port = int(m.group("port"))
    if not (1 <= port <= 65535):
        return None
    return {
        "scheme": m.group("scheme").lower(),
        "host": m.group("host"),
        "port": port,
        "user": m.group("user") or "",
        "password": m.group("pw") or "",
    }


def normalize_domains(raw) -> list[str]:
    """لیست دامنه‌ها را تمیز می‌کند (حروف کوچک، بدون تکرار، بدون پروتکل)."""
    if isinstance(raw, str):
        raw = re.split(r"[\s,\n]+", raw)
    if not isinstance(raw, list):
        return list(DEFAULT_WARP_DOMAINS)
    out, seen = [], set()
    for item in raw:
        d = str(item or "").strip().lower()
        for pre in ("https://", "http://"):
            if d.startswith(pre):
                d = d[len(pre):]
        d = d.split("/")[0].lstrip(".")
        if not d or d in seen or len(d) > 253:
            continue
        seen.add(d)
        out.append(d)
        if len(out) >= 300:
            break
    return out


def domain_matches(host: str, domains: list[str]) -> bool:
    """آیا این مقصد باید از WARP عبور کند؟ (تطابق دامنه و همه زیردامنه‌هایش)"""
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return False
    for d in domains:
        if h == d or h.endswith("." + d):
            return True
    return False


# ══════════════════════════════════════════════════════════════════════════════
# اتصال از طریق پروکسی
# ══════════════════════════════════════════════════════════════════════════════

async def _socks5_connect(proxy: dict, address: str, port: int, timeout: float):
    """دست‌دادن SOCKS5 (RFC 1928) و درخواست CONNECT به مقصد."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(proxy["host"], proxy["port"], limit=READ_LIMIT), timeout=timeout
    )
    try:
        use_auth = bool(proxy["user"])
        methods = b"\x00\x02" if use_auth else b"\x00"
        writer.write(b"\x05" + bytes([len(methods)]) + methods)
        await writer.drain()

        resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if resp[0] != 0x05:
            raise ConnectionError("پاسخ SOCKS5 نامعتبر است")
        method = resp[1]

        if method == 0x02:
            if not use_auth:
                raise ConnectionError("پروکسی نیاز به نام کاربری/رمز دارد")
            u = proxy["user"].encode()[:255]
            p = proxy["password"].encode()[:255]
            writer.write(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            await writer.drain()
            auth = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
            if auth[1] != 0x00:
                raise ConnectionError("احراز هویت پروکسی WARP رد شد")
        elif method != 0x00:
            raise ConnectionError(f"روش احراز هویت پشتیبانی‌نشده: {method}")

        # CONNECT با آدرس دامنه‌ای تا DNS هم سمت WARP حل شود
        ab = address.encode()[:255]
        writer.write(b"\x05\x01\x00\x03" + bytes([len(ab)]) + ab + struct.pack(">H", port))
        await writer.drain()

        rep = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        if rep[1] != 0x00:
            raise ConnectionError(f"پروکسی WARP اتصال را رد کرد (کد {rep[1]})")
        atyp = rep[3]
        if atyp == 0x01:
            await asyncio.wait_for(reader.readexactly(4 + 2), timeout=timeout)
        elif atyp == 0x03:
            ln = (await asyncio.wait_for(reader.readexactly(1), timeout=timeout))[0]
            await asyncio.wait_for(reader.readexactly(ln + 2), timeout=timeout)
        elif atyp == 0x04:
            await asyncio.wait_for(reader.readexactly(16 + 2), timeout=timeout)
        return reader, writer
    except Exception:
        writer.close()
        raise


async def _http_connect(proxy: dict, address: str, port: int, timeout: float):
    """تونل HTTP CONNECT برای پروکسی‌های HTTP."""
    import base64

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(proxy["host"], proxy["port"], limit=READ_LIMIT), timeout=timeout
    )
    try:
        req = f"CONNECT {address}:{port} HTTP/1.1\r\nHost: {address}:{port}\r\n"
        if proxy["user"]:
            token = base64.b64encode(
                f"{proxy['user']}:{proxy['password']}".encode()
            ).decode()
            req += f"Proxy-Authorization: Basic {token}\r\n"
        writer.write((req + "\r\n").encode())
        await writer.drain()

        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if b" 200 " not in line:
            raise ConnectionError(f"پروکسی HTTP پاسخ داد: {line.decode(errors='ignore').strip()}")
        while True:  # مصرف بقیه هدرها
            h = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if h in (b"\r\n", b"\n", b""):
                break
        return reader, writer
    except Exception:
        writer.close()
        raise


class WarpManager:
    """مدیریت خروجی WARP: تصمیم مسیریابی، اتصال و آمار."""

    def __init__(self):
        self.total_via_warp = 0
        self.total_direct = 0
        self.total_fallback = 0
        self.last_error: str | None = None
        self.last_check: str | None = None
        self.last_check_ok: bool | None = None
        self.last_check_latency: float | None = None
        self.recent: deque = deque(maxlen=20)

    # ── تنظیمات ───────────────────────────────────────────────────────────────
    @property
    def enabled(self) -> bool:
        return bool(_cfg().get("enabled", False))

    @property
    def mode(self) -> str:
        m = str(_cfg().get("mode", "domains")).lower()
        return m if m in ("domains", "all") else "domains"

    @property
    def domains(self) -> list[str]:
        return normalize_domains(_cfg().get("domains"))

    @property
    def proxy(self) -> dict | None:
        return parse_proxy(str(_cfg().get("proxy") or ""))

    # ── تصمیم مسیریابی ────────────────────────────────────────────────────────
    def should_use_warp(self, address: str) -> bool:
        if not self.enabled or self.proxy is None:
            return False
        if self.mode == "all":
            return True
        return domain_matches(address, self.domains)

    async def open_connection(self, address: str, port: int, timeout: float = 10.0):
        """اتصال به مقصد — در صورت نیاز از WARP، وگرنه مستقیم.

        اگر پروکسی WARP در دسترس نباشد، به اتصال مستقیم برمی‌گردد (fail-open)
        تا سرویس کاربران هیچ‌وقت به‌خاطر خرابی WARP قطع نشود.
        """
        if not self.should_use_warp(address):
            self.total_direct += 1
            return await asyncio.wait_for(
                asyncio.open_connection(address, port, limit=READ_LIMIT), timeout=timeout
            ), False

        proxy = self.proxy
        try:
            if proxy["scheme"].startswith("socks5"):
                conn = await _socks5_connect(proxy, address, port, timeout)
            else:
                conn = await _http_connect(proxy, address, port, timeout)
            self.total_via_warp += 1
            self.last_error = None
            self.recent.appendleft({"time": datetime.now(IRAN_TZ).isoformat(),
                                    "host": address, "via": "warp"})
            return conn, True
        except Exception as e:  # noqa: BLE001 — fail-open
            self.total_fallback += 1
            self.last_error = str(e)[:160]
            logger.warning(f"[WARP] اتصال به {address} از طریق WARP ناموفق بود "
                           f"({self.last_error}) — اتصال مستقیم برقرار شد")
            self.recent.appendleft({"time": datetime.now(IRAN_TZ).isoformat(),
                                    "host": address, "via": "fallback"})
            return await asyncio.wait_for(
                asyncio.open_connection(address, port, limit=READ_LIMIT), timeout=timeout
            ), False

    # ── تست سلامت ─────────────────────────────────────────────────────────────
    async def test(self) -> dict:
        """بررسی می‌کند پروکسی WARP بالا و قابل استفاده است یا نه."""
        proxy = self.proxy
        self.last_check = datetime.now(IRAN_TZ).isoformat()
        if proxy is None:
            self.last_check_ok = False
            self.last_check_latency = None
            return {"ok": False, "error": "آدرس پروکسی WARP نامعتبر است "
                                          "(نمونه درست: socks5://127.0.0.1:40000)"}
        start = time.monotonic()
        try:
            if proxy["scheme"].startswith("socks5"):
                reader, writer = await _socks5_connect(proxy, "cloudflare.com", 443, 6.0)
            else:
                reader, writer = await _http_connect(proxy, "cloudflare.com", 443, 6.0)
            latency = round((time.monotonic() - start) * 1000, 1)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            self.last_check_ok = True
            self.last_check_latency = latency
            self.last_error = None
            return {"ok": True, "latency_ms": latency,
                    "proxy": f"{proxy['scheme']}://{proxy['host']}:{proxy['port']}"}
        except Exception as e:  # noqa: BLE001
            self.last_check_ok = False
            self.last_check_latency = None
            self.last_error = str(e)[:160]
            return {"ok": False, "error": self.last_error}

    def get_status(self) -> dict:
        proxy = self.proxy
        return {
            "enabled": self.enabled,
            "mode": self.mode,
            "proxy": str(_cfg().get("proxy") or ""),
            "proxy_valid": proxy is not None,
            "domains": self.domains,
            "domains_count": len(self.domains),
            "default_domains": list(DEFAULT_WARP_DOMAINS),
            "total_via_warp": self.total_via_warp,
            "total_direct": self.total_direct,
            "total_fallback": self.total_fallback,
            "last_error": self.last_error,
            "last_check": self.last_check,
            "last_check_ok": self.last_check_ok,
            "last_check_latency": self.last_check_latency,
            "recent": list(self.recent)[:10],
        }


warp_manager = WarpManager()
