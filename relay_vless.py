# relay_vless.py
# بخش VLESS Relay — جدا شده از main.py
# تغییر: ثبت IP واقعی کلاینت (با احتساب هدر x-forwarded-for پشت پراکسی) در connections
#
# ⚡ بهینه‌سازی v9.15 — مسیر داغ بدون قفل و بدون I/O:
#   پیش از این، check_and_use به ازای هر چانک دادهٔ هر کاربر قفل سراسری LINKS_LOCK
#   می‌گرفت و در همان لحظه strftime هم انجام می‌داد؛ یعنی همهٔ اتصال‌ها در نقطهٔ
#   حسابداری مصرف سریال می‌شدند و داغ‌ترین مسیر رله، سنگین‌ترین مسیر بود.
#   حالا:
#     ۱) حسابداری مصرف با جمع‌زدن دسته‌ای (batch) هر ۱ ثانیه انجام می‌شود؛ در مسیر
#        داده فقط یک جمع ساده روی dict حافظه‌ای رخ می‌دهد (بدون قفل و بدون await —
#        در حلقهٔ رویداد تک‌رشته‌ای اتمی است).
#     ۲) کلید ساعت (برای نمودار ترافیک ساعتی) حداکثر ۱ بار در ثانیه ساخته می‌شود،
#        نه به ازای هر چانک.
#     ۳) بررسی انقضا/سهمیه برای هر کانفیگ حداکثر ۱ بار در ثانیه انجام می‌شود؛
#        بررسی «وجود و فعال بودن» که بسیار ارزان است همچنان برای هر چانک می‌ماند.
#        (حداکثر اضافه‌مصرف ممکن بعد از اتمام سهمیه ≈ ترافیک ۱ ثانیه است.)
#     ۴) اگر کانفیگ محدودیت سرعت نداشته باشد — که حالت رایج است — تابع throttle
#        اصلاً صدا زده نمی‌شود (صرفه‌جویی یک coroutine به ازای هر چانک).
#     ۵) سوکت TCP با TCP_NODELAY و بافرهای بزرگ‌تر تنظیم می‌شود.
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import os
import secrets
import socket
import time
from datetime import datetime

from fastapi import WebSocket, WebSocketDisconnect

from main import (
    LINKS,
    LINKS_LOCK,
    stats,
    hourly_traffic,
    connections,
    error_logs,
    logger,
    is_link_allowed,
    is_ip_allowed,
    save_state,
    log_activity,
    now_ir,
)
from speed_limit import throttle

# ══════════════════════════════════════════════════════════════════════════════
# VLESS Relay — بهینه‌شده برای حداکثر throughput
# ══════════════════════════════════════════════════════════════════════════════

RELAY_BUF = int(os.environ.get("RELAY_BUF", str(1024 * 1024)))   # 1 MB buffer
SOCK_BUF_SIZE = 4 * 1024 * 1024                                  # SO_SNDBUF / SO_RCVBUF

# ══════════════════════════════════════════════════════════════════════════════
# حسابداری مصرف — بدون قفل، با فلاش دسته‌ای هر ۱ ثانیه
# ══════════════════════════════════════════════════════════════════════════════

_PENDING: dict[str, int] = {}        # بایت‌های ثبت‌شده که هنوز اعمال نشده‌اند (per uuid)
_FLUSH_INTERVAL = 1.0                # بازهٔ فلاش دسته‌ای (ثانیه)
_flush_task: asyncio.Task | None = None
_last_full_check: dict[str, float] = {}   # زمان آخرین بررسی کامل (انقضا/سهمیه) هر کانفیگ
_hour_key_cache = ""                 # کلید ساعت تهران که در فلاش استفاده می‌شود
_last_hour_ts = 0.0


def _current_hour_key() -> str:
    """کلید ساعت جاری (مثل «14:00») با کش ۱ ثانیه‌ای — به‌جای strftime در هر چانک."""
    global _hour_key_cache, _last_hour_ts
    t = time.monotonic()
    if t - _last_hour_ts >= 1.0:
        _last_hour_ts = t
        _hour_key_cache = now_ir().strftime("%H:00")
    return _hour_key_cache


def add_usage(uid: str, n: int) -> None:
    """ثبت مصرف بدون قفل و بدون I/O.

    فقط یک جمع روی dict انجام می‌شود؛ چون این تابع هیچ await ندارد، در حلقهٔ
    رویداد تک‌رشته‌ای اتمی است و نیازی به قفل نیست.
    """
    _PENDING[uid] = _PENDING.get(uid, 0) + n


def flush_usage() -> None:
    """اعمال مصرف‌های معلق روی شمارنده‌های سراسری (link/stats/hourly).

    کاملاً همگام است (بدون await) پس اتمی است؛ هم توسط حلقهٔ پس‌زمینهٔ ۱ ثانیه‌ای
    و هم هنگام بسته شدن اتصال صدا زده می‌شود تا چیزی از قلم نیفتد.
    """
    global _PENDING
    pending = _PENDING
    if not pending:
        return
    _PENDING = {}
    # هرس کش بررسی کامل برای کانفیگ‌های حذف‌شده (جلوگیری از رشد بی‌نهایت)
    if len(_last_full_check) > 8192:
        live = set(LINKS)
        for k in [k for k in _last_full_check if k not in live]:
            del _last_full_check[k]
    hour = _current_hour_key()
    for uid, n in pending.items():
        link = LINKS.get(uid)
        if link is None:
            continue
        link["used_bytes"] += n
        stats["total_bytes"] += n
        hourly_traffic[hour] += n


async def _flush_loop() -> None:
    while True:
        await asyncio.sleep(_FLUSH_INTERVAL)
        flush_usage()


def ensure_flush_loop() -> None:
    """شروع (تنبل) حلقهٔ فلاش پس‌زمینه — از بسترهای async صدا زده می‌شود."""
    global _flush_task
    if _flush_task is None or _flush_task.done():
        _flush_task = asyncio.create_task(_flush_loop())


def check_and_use(uid: str, n: int) -> bool:
    """نسخهٔ بدون قفل و سبکِ بررسی سهمیه + ثبت مصرف.

    - بررسی «وجود/فعال بودن» کانفیگ: هر چانک (فقط یک dict.get).
    - بررسی کامل (انقضا، سهمیه): حداکثر ۱ بار در ثانیه برای هر کانفیگ —
      datetime.fromisoformat هر چانک از این مسیر حذف شده است.
    - ثبت مصرف: فقط جمع روی _PENDING؛ اعمال واقعی در flush دسته‌ای.
    """
    link = LINKS.get(uid)
    if link is None or link.get("active") is False:
        return False
    t = time.monotonic()
    last = _last_full_check.get(uid)
    if last is None or t - last >= 1.0:
        _last_full_check[uid] = t
        if not is_link_allowed(link):
            return False
        lb = link.get("limit_bytes", 0)
        if lb > 0 and link.get("used_bytes", 0) + _PENDING.get(uid, 0) >= lb:
            return False
    _PENDING[uid] = _PENDING.get(uid, 0) + n
    return True


def _tune_socket(writer: asyncio.StreamWriter) -> None:
    """تیونینگ سوکت سمت مقصد: نودلی + بافرهای بزرگ‌تر برای جریان‌های حجیم.

    - TCP_NODELAY: حذف الگوریتم Nagle (تأخیر تجمیع بسته‌های کوچک) — برای رلهٔ
      تعاملی حیاتی است.
    - بافرهای ۴ مگابایتی: به هسته اجازه می‌دهد پنجرهٔ دریافت/ارسال را بزرگ نگه
      دارد و در مسیرهای با پینگ بالا (مثل ایران ↔ اروپا) از استال BDP جلوگیری کند.
    - TCP_QUICKACK (فقط لینوکس): ACKها بلافاصله ارسال شوند — در الگوهای
      درخواست/پاسخ و دانلود، تأخیر ACK باعث افت لحظه‌ای توان عملیاتی می‌شود.
    - SO_KEEPALIVE: جلوگیری از قطع شدن اتصال‌های نیمه‌باز توسط NAT/فایروال میانی.
    """
    sock = writer.transport.get_extra_info("socket")
    if not sock:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUF_SIZE)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUF_SIZE)
        quickack = getattr(socket, "TCP_QUICKACK", None)
        if quickack is not None:
            sock.setsockopt(socket.IPPROTO_TCP, quickack, 1)
        keepalive = getattr(socket, "SO_KEEPALIVE", None)
        if keepalive is not None:
            sock.setsockopt(socket.SOL_SOCKET, keepalive, 1)
    except OSError:
        pass


def _ws_client_ip(ws: WebSocket) -> str:
    fwd = ws.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = ws.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return ws.client.host if ws.client else "نامشخص"

async def parse_vless_header(chunk: bytes):
    if len(chunk) < 24:
        raise ValueError("chunk too small")
    pos = 1
    pos += 16
    addon_len = chunk[pos]; pos += 1 + addon_len
    command = chunk[pos]; pos += 1
    port = int.from_bytes(chunk[pos:pos+2], "big"); pos += 2
    addr_type = chunk[pos]; pos += 1
    if addr_type == 1:
        address = ".".join(str(b) for b in chunk[pos:pos+4]); pos += 4
    elif addr_type == 2:
        dlen = chunk[pos]; pos += 1
        address = chunk[pos:pos+dlen].decode("utf-8", errors="ignore"); pos += dlen
    elif addr_type == 3:
        ab = chunk[pos:pos+16]; pos += 16
        address = ":".join(f"{ab[i]:02x}{ab[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown addr type: {addr_type}")
    return command, address, port, chunk[pos:]

async def relay_ws_to_tcp(ws: WebSocket, writer: asyncio.StreamWriter, conn_id: str, uid: str, speed_limited: bool = False):
    conn = connections[conn_id]  # یک بار لوک‌آپ، نه به‌ازای هر چانک
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue
            if not check_and_use(uid, len(data)):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            if speed_limited:
                await throttle(uid, len(data))
            stats["total_requests"] += 1
            conn["bytes"] += len(data)
            writer.write(data)
            if writer.transport.get_write_buffer_size() > RELAY_BUF:
                await writer.drain()
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        try:
            writer.write_eof()
        except Exception:
            pass

async def relay_tcp_to_ws(ws: WebSocket, reader: asyncio.StreamReader, conn_id: str, uid: str, speed_limited: bool = False):
    conn = connections[conn_id]  # یک بار لوک‌آپ، نه به‌ازای هر چانک
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break
            if not check_and_use(uid, len(data)):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            if speed_limited:
                await throttle(uid, len(data))
            conn["bytes"] += len(data)
            payload = (b"\x00\x00" + data) if first else data
            first = False
            await ws.send_bytes(payload)
    except Exception:
        pass

async def websocket_tunnel(ws: WebSocket, uuid: str):
    await ws.accept()
    ensure_flush_loop()

    async with LINKS_LOCK:
        link = LINKS.get(uuid)

    if not is_link_allowed(link):
        logger.warning(f"🚫 WS rejected uuid={uuid[:8]}… (not allowed)")
        await ws.close(code=1008, reason="not authorized")
        return

    ip = _ws_client_ip(ws)

    if not is_ip_allowed(link, uuid, ip):
        logger.warning(f"🚫 WS rejected uuid={uuid[:8]}… ip={ip} (ip limit reached)")
        log_activity("connection", f"اتصال {ip} به کانفیگ «{link.get('label','?')}» رد شد (محدودیت تعداد آی‌پی)", "warn")
        await ws.close(code=1008, reason="ip limit reached")
        return

    # ⚡ اگر کانفیگ محدودیت سرعت ندارد، throttle در مسیر داغ اصلاً صدا زده نمی‌شود
    speed_limited = int((link or {}).get("speed_limit_bytes", 0) or 0) > 0

    conn_id = secrets.token_urlsafe(6)
    connections[conn_id] = {
        "uuid": uuid,
        "ip": ip,
        "transport": "vless-ws",
        "connected_at": datetime.now().isoformat(),
        "bytes": 0,
    }
    logger.info(f"✅ WS [{conn_id}] uuid={uuid[:8]}… ip={ip} total={len(connections)}")
    log_activity("connection", f"اتصال جدید از {ip} (کانفیگ {link.get('label','?')})", "info")
    writer = None

    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect":
            return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk:
            return

        command, address, port, payload = await parse_vless_header(first_chunk)

        if not check_and_use(uuid, len(first_chunk)):
            await ws.close(code=1008, reason="quota/disabled")
            return

        stats["total_requests"] += 1
        connections[conn_id]["bytes"] += len(first_chunk)
        logger.info(f"➡️  [{conn_id}] → {address}:{port}")

        # 🌐 در صورت فعال بودن WARP و تطابق مقصد، از خروجی کلودفلر عبور می‌کند
        from warp_service import warp_manager
        (reader, writer), via_warp = await warp_manager.open_connection(address, port, timeout=10.0)
        if via_warp:
            connections[conn_id]["via"] = "warp"
        _tune_socket(writer)

        if payload:
            writer.write(payload)
            await writer.drain()

        done, pending = await asyncio.wait(
            {
                asyncio.create_task(relay_ws_to_tcp(ws, writer, conn_id, uuid, speed_limited)),
                asyncio.create_task(relay_tcp_to_ws(ws, reader, conn_id, uuid, speed_limited)),
            },
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass

        flush_usage()
        asyncio.create_task(save_state())

    except WebSocketDisconnect:
        pass
    except asyncio.TimeoutError:
        stats["total_errors"] += 1
        error_logs.append({"error": "connection timeout", "time": datetime.now().isoformat()})
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        logger.error(f"WS error [{conn_id}]: {exc}")
    finally:
        flush_usage()
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        connections.pop(conn_id, None)
        logger.info(f"🔌 WS closed [{conn_id}] total={len(connections)}")
