# relay_trojan.py
# ══════════════════════════════════════════════════════════════════════════════
#  🔐 XR — رلهٔ واقعی پروتکل Trojan روی ترابرد WebSocket
#
#  ساختار بستهٔ اول Trojan (طبق استاندارد trojan-gfw):
#
#      +-----------------------+---------+----------------+---------+----------+
#      | hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
#      +-----------------------+---------+----------------+---------+----------+
#      |          56           |    2    |    متغیر       |    2    |  متغیر   |
#      +-----------------------+---------+----------------+---------+----------+
#
#  و ساختار Trojan Request (شبیه SOCKS5):
#
#      +-----+------+----------+----------+
#      | CMD | ATYP | DST.ADDR | DST.PORT |
#      +-----+------+----------+----------+
#      |  1  |  1   |  متغیر   |    2     |
#      +-----+------+----------+----------+
#
#  برخلاف VLESS، پاسخ سرور هیچ هدری ندارد و داده خام برمی‌گردد.
#  رمز عبور هر کانفیگ همان UUID آن است (protocols.trojan_password).
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import secrets
import socket
from datetime import datetime

from fastapi import WebSocket, WebSocketDisconnect

from main import (
    LINKS,
    LINKS_LOCK,
    connections,
    error_logs,
    hourly_traffic,  # noqa: F401 — از طریق check_and_use به‌روزرسانی می‌شود
    is_ip_allowed,
    is_link_allowed,
    log_activity,
    logger,
    save_state,
    stats,
)
from protocols import trojan_password_hash
from relay_vless import RELAY_BUF, check_and_use
from speed_limit import throttle

CRLF = b"\r\n"
TROJAN_CMD_CONNECT = 0x01
TROJAN_CMD_UDP_ASSOCIATE = 0x03


class TrojanAuthError(Exception):
    """رمز عبور بستهٔ Trojan با کانفیگ نمی‌خواند."""


class TrojanParseError(Exception):
    """بستهٔ اول Trojan ناقص یا نامعتبر است."""


def _ws_client_ip(ws: WebSocket) -> str:
    fwd = ws.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = ws.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return ws.client.host if ws.client else "نامشخص"


def parse_trojan_header(chunk: bytes, expected_hash: str):
    """بستهٔ اول Trojan را می‌شکافد و (command, address, port, payload) برمی‌گرداند.

    در صورت نامعتبر بودن رمز، TrojanAuthError و در صورت ناقص بودن بسته
    TrojanParseError پرتاب می‌شود.
    """
    if len(chunk) < 60:
        raise TrojanParseError("بستهٔ Trojan خیلی کوتاه است")

    # ── ۱) رمز عبور: ۵۶ کاراکتر هگز + CRLF ────────────────────────────────────
    pw_hex = chunk[:56]
    if chunk[56:58] != CRLF:
        raise TrojanParseError("CRLF بعد از رمز عبور پیدا نشد")
    try:
        got = pw_hex.decode("ascii")
    except UnicodeDecodeError as e:
        raise TrojanParseError("رمز عبور غیر ASCII") from e
    # مقایسهٔ زمان‌ثابت برای جلوگیری از حملهٔ زمان‌سنجی
    if not secrets.compare_digest(got.lower(), expected_hash.lower()):
        raise TrojanAuthError("رمز عبور Trojan نادرست است")

    pos = 58

    # ── ۲) درخواست: CMD + ATYP + ADDR + PORT ─────────────────────────────────
    if len(chunk) < pos + 2:
        raise TrojanParseError("بخش درخواست ناقص است")
    command = chunk[pos]
    pos += 1
    atyp = chunk[pos]
    pos += 1

    if atyp == 0x01:  # IPv4
        if len(chunk) < pos + 4:
            raise TrojanParseError("آدرس IPv4 ناقص است")
        address = ".".join(str(b) for b in chunk[pos:pos + 4])
        pos += 4
    elif atyp == 0x03:  # Domain
        if len(chunk) < pos + 1:
            raise TrojanParseError("طول دامنه ناقص است")
        dlen = chunk[pos]
        pos += 1
        if len(chunk) < pos + dlen:
            raise TrojanParseError("نام دامنه ناقص است")
        address = chunk[pos:pos + dlen].decode("utf-8", errors="ignore")
        pos += dlen
    elif atyp == 0x04:  # IPv6
        if len(chunk) < pos + 16:
            raise TrojanParseError("آدرس IPv6 ناقص است")
        ab = chunk[pos:pos + 16]
        address = ":".join(f"{ab[i]:02x}{ab[i + 1]:02x}" for i in range(0, 16, 2))
        pos += 16
    else:
        raise TrojanParseError(f"نوع آدرس ناشناخته: {atyp}")

    if len(chunk) < pos + 2:
        raise TrojanParseError("پورت مقصد ناقص است")
    port = int.from_bytes(chunk[pos:pos + 2], "big")
    pos += 2

    # ── ۳) CRLF پایانی + محمولهٔ باقی‌مانده ──────────────────────────────────
    if chunk[pos:pos + 2] != CRLF:
        raise TrojanParseError("CRLF پایانی درخواست پیدا نشد")
    pos += 2

    return command, address, port, chunk[pos:]


async def _ws_to_tcp(ws: WebSocket, writer: asyncio.StreamWriter, conn_id: str, uid: str):
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue
            if not await check_and_use(uid, len(data)):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            await throttle(uid, len(data))
            stats["total_requests"] += 1
            connections[conn_id]["bytes"] += len(data)
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


async def _tcp_to_ws(ws: WebSocket, reader: asyncio.StreamReader, conn_id: str, uid: str):
    """برخلاف VLESS، Trojan هیچ هدر پاسخی ندارد — داده خام برمی‌گردد."""
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break
            if not await check_and_use(uid, len(data)):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            await throttle(uid, len(data))
            connections[conn_id]["bytes"] += len(data)
            await ws.send_bytes(data)
    except Exception:
        pass


async def trojan_tunnel(ws: WebSocket, uuid: str):
    """اندپوینت WebSocket پروتکل Trojan — مسیر /trojan/{uuid}."""
    await ws.accept()

    async with LINKS_LOCK:
        link = LINKS.get(uuid)

    if not is_link_allowed(link):
        logger.warning(f"🚫 Trojan rejected uuid={uuid[:8]}… (not allowed)")
        await ws.close(code=1008, reason="not authorized")
        return

    ip = _ws_client_ip(ws)

    if not is_ip_allowed(link, uuid, ip):
        logger.warning(f"🚫 Trojan rejected uuid={uuid[:8]}… ip={ip} (ip limit reached)")
        log_activity(
            "connection",
            f"اتصال Trojan از {ip} به کانفیگ «{link.get('label', '?')}» رد شد (محدودیت تعداد آی‌پی)",
            "warn",
        )
        await ws.close(code=1008, reason="ip limit reached")
        return

    conn_id = secrets.token_urlsafe(6)
    connections[conn_id] = {
        "uuid": uuid,
        "ip": ip,
        "transport": "trojan-ws",
        "connected_at": datetime.now().isoformat(),
        "bytes": 0,
    }
    logger.info(f"✅ Trojan [{conn_id}] uuid={uuid[:8]}… ip={ip} total={len(connections)}")
    log_activity("connection", f"اتصال Trojan جدید از {ip} (کانفیگ {link.get('label', '?')})", "info")
    writer = None

    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect":
            return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk:
            return

        expected = trojan_password_hash(uuid)
        try:
            command, address, port, payload = parse_trojan_header(first_chunk, expected)
        except TrojanAuthError:
            logger.warning(f"🚫 Trojan [{conn_id}] رمز عبور نادرست")
            log_activity("connection", f"تلاش اتصال Trojan با رمز نادرست از {ip}", "warn")
            await ws.close(code=1008, reason="bad password")
            return
        except TrojanParseError as e:
            logger.warning(f"🚫 Trojan [{conn_id}] بستهٔ نامعتبر: {e}")
            await ws.close(code=1008, reason="bad request")
            return

        if command == TROJAN_CMD_UDP_ASSOCIATE:
            # UDP over Trojan پشتیبانی نمی‌شود (رله فقط TCP است)
            logger.info(f"⚠️ Trojan [{conn_id}] درخواست UDP رد شد")
            await ws.close(code=1008, reason="udp not supported")
            return
        if command != TROJAN_CMD_CONNECT:
            await ws.close(code=1008, reason="unsupported command")
            return

        if not await check_and_use(uuid, len(first_chunk)):
            await ws.close(code=1008, reason="quota/disabled")
            return

        stats["total_requests"] += 1
        connections[conn_id]["bytes"] += len(first_chunk)
        logger.info(f"➡️  Trojan [{conn_id}] → {address}:{port}")

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=10.0
        )
        sock = writer.transport.get_extra_info("socket")
        if sock:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        if payload:
            writer.write(payload)
            await writer.drain()

        done, pending = await asyncio.wait(
            {
                asyncio.create_task(_ws_to_tcp(ws, writer, conn_id, uuid)),
                asyncio.create_task(_tcp_to_ws(ws, reader, conn_id, uuid)),
            },
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass

        asyncio.create_task(save_state())

    except WebSocketDisconnect:
        pass
    except asyncio.TimeoutError:
        stats["total_errors"] += 1
        error_logs.append({"error": "trojan connection timeout", "time": datetime.now().isoformat()})
    except Exception as exc:  # noqa: BLE001
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        logger.error(f"Trojan error [{conn_id}]: {exc}")
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        connections.pop(conn_id, None)
        logger.info(f"🔌 Trojan closed [{conn_id}] total={len(connections)}")
