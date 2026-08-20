# relay_vmess.py
# ══════════════════════════════════════════════════════════════════════════════
#  🚀 XR — رلهٔ واقعی پروتکل VMess روی ترابرد WebSocket
#
#  ساختار مشابه سایر رله‌ها (VLESS/Trojan) است: کلاینت از طریق WebSocket وصل
#  می‌شود، هدر VMess (با احراز هویت AEAD) خوانده می‌شود، مقصد باز می‌شود و
#  سپس داده به‌صورت دوطرفه با قطعه‌بندی AEAD رله می‌شود.
#
#  جزئیات ریاضی/رمز در vmess_crypto.py است تا این فایل فقط «رله» باشد.
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import secrets
import struct
from datetime import datetime

from fastapi import WebSocket, WebSocketDisconnect

from main import (
    LINKS,
    LINKS_LOCK,
    connections,
    error_logs,
    is_ip_allowed,
    is_link_allowed,
    log_activity,
    logger,
    save_state,
    stats,
)
from relay_vless import RELAY_BUF, _tune_socket, check_and_use, ensure_flush_loop, flush_usage
from speed_limit import throttle
from vmess_crypto import (
    ADDR_DOMAIN,
    SEC_NONE,
    SEC_ZERO,
    OPT_CHUNK_MASKING,
    OPT_GLOBAL_PADDING,
    ShakeStream,
    VmessCodec,
    build_response_header,
    cmd_key,
    decrypt_auth_id,
    decrypt_header,
    derive_response_keys,
    encode_chunk,
    encode_end_marker,
    kdf,
    kdf16,
    parse_header,
    verify_header_checksum,
)

VMESS_CMD_TCP = 0x01
HEADER_FIXED = 42  # EAuID(16) + ALength(18) + Nonce(8)


def _ws_client_ip(ws: WebSocket) -> str:
    fwd = ws.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = ws.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return ws.client.host if ws.client else "نامشخص"


def _uuid_bytes(uuid: str) -> bytes:
    try:
        import uuid as _uuid
        return _uuid.UUID(uuid).bytes
    except Exception:
        # در حالت نامعتبر، همان بایت‌های خام را برگردان تا احراز هویت شکست بخورد
        return uuid.replace("-", "").encode("ascii", "ignore")[:16].ljust(16, b"\x00")


def _try_decode_chunk(buf: bytearray, codec: VmessCodec):
    """از بافر، یک بستهٔ کامل را رمزگشایی می‌کند.

    خروجی: (plaintext|None, eof, consumed). اگر داده ناکافی باشد (None, False, 0).
    """
    if not codec.is_chunked:
        if not buf:
            return None, False, 0
        data = bytes(buf)
        return data, False, len(buf)

    if len(buf) < 2:
        return None, False, 0
    raw = bytes(buf[:2])
    length, pad = _read_size(codec, raw)

    if codec.is_aead:
        enc_size = length - pad
        if enc_size <= codec.overhead:
            # پایان جریان (فقط tag) — خود بسته را هم مصرف می‌کنیم
            total = 2 + length
            if len(buf) < total:
                return None, False, 0
            return b"", True, total
    else:
        # None: پایان = طول صفر
        if length == 0:
            return b"", True, 2

    total = 2 + length
    if len(buf) < total:
        return None, False, 0

    if codec.is_aead:
        payload = bytes(buf[2:2 + enc_size])
        plain = codec._decrypt_block(payload)
    else:
        plain = bytes(buf[2:2 + length])
    return plain, False, total


def _read_size(codec: VmessCodec, raw: bytes) -> tuple[int, int]:
    """(length, padding) — ترتیب shake: پدینگ اول، ماسک دوم (مطابق v2ray)."""
    pad = codec.padding.next_u16() % 64 if codec.padding is not None else 0
    raw_len = int.from_bytes(raw, "big")
    if codec.mask is not None:
        return raw_len ^ codec.mask.next_u16(), pad
    return raw_len, pad


async def _read_header_block(ws: WebSocket, buf: bytearray, n: int, conn_id: str):
    """تا رسیدن به n بایت از WS می‌خواند (پیام‌های اضافه در buf می‌مانند)."""
    while len(buf) < n:
        msg = await ws.receive()
        if msg["type"] == "websocket.disconnect":
            raise WebSocketDisconnect()
        data = msg.get("bytes") or (msg.get("text") or "").encode()
        if data:
            buf.extend(data)
    out = bytes(buf[:n])
    del buf[:n]
    return out


async def vmess_tunnel(ws: WebSocket, uuid: str):
    await ws.accept()
    ensure_flush_loop()

    async with LINKS_LOCK:
        link = LINKS.get(uuid)

    if not is_link_allowed(link):
        logger.warning(f"🚫 VMess rejected uuid={uuid[:8]}… (not allowed)")
        await ws.close(code=1008, reason="not authorized")
        return

    ip = _ws_client_ip(ws)

    if not is_ip_allowed(link, uuid, ip):
        logger.warning(f"🚫 VMess rejected uuid={uuid[:8]}… ip={ip} (ip limit reached)")
        log_activity("connection", f"اتصال VMess از {ip} به کانفیگ «{link.get('label','?')}» رد شد (محدودیت تعداد آی‌پی)", "warn")
        await ws.close(code=1008, reason="ip limit reached")
        return

    speed_limited = int((link or {}).get("speed_limit_bytes", 0) or 0) > 0

    conn_id = secrets.token_urlsafe(6)
    connections[conn_id] = {
        "uuid": uuid,
        "ip": ip,
        "transport": "vmess-ws",
        "connected_at": datetime.now().isoformat(),
        "bytes": 0,
    }
    logger.info(f"✅ VMess [{conn_id}] uuid={uuid[:8]}… ip={ip} total={len(connections)}")
    log_activity("connection", f"اتصال VMess جدید از {ip} (کانفیگ {link.get('label','?')})", "info")
    writer = None

    try:
        buf = bytearray()
        eauthid = await asyncio.wait_for(_read_header_block(ws, buf, 16, conn_id), timeout=15.0)
        alength = await asyncio.wait_for(_read_header_block(ws, buf, 18, conn_id), timeout=15.0)
        nonce = await asyncio.wait_for(_read_header_block(ws, buf, 8, conn_id), timeout=15.0)

        ckey = cmd_key(_uuid_bytes(uuid))
        _ts, auth_ok = decrypt_auth_id(ckey, eauthid)
        if not auth_ok:
            logger.warning(f"🚫 VMess [{conn_id}] احراز هویت AEAD نامعتبر")
            await ws.close(code=1008, reason="invalid auth id")
            return

        # طول هدر ساده را از ALength بیرون می‌کشیم
        len_key = kdf16(ckey, b"VMess Header AEAD Key_Length", eauthid, nonce)
        len_iv = kdf(ckey, b"VMess Header AEAD Nonce_Length", eauthid, nonce)[:12]
        try:
            from vmess_crypto import _gcm_decrypt
            y_bytes = _gcm_decrypt(len_key, len_iv, alength, eauthid)
        except Exception:
            logger.warning(f"🚫 VMess [{conn_id}] ALength نامعتبر")
            await ws.close(code=1008, reason="invalid header length")
            return
        y = struct.unpack(">H", y_bytes)[0]
        if not (36 <= y <= 4096):
            logger.warning(f"🚫 VMess [{conn_id}] طول هدر غیرعادی: {y}")
            await ws.close(code=1008, reason="invalid header length")
            return

        aheader_ct = await asyncio.wait_for(_read_header_block(ws, buf, y + 16, conn_id), timeout=15.0)
        try:
            plain_header = decrypt_header(ckey, eauthid, nonce, alength, aheader_ct)
        except Exception:
            logger.warning(f"🚫 VMess [{conn_id}] هدر AEAD نامعتبر")
            await ws.close(code=1008, reason="invalid header")
            return

        if not verify_header_checksum(plain_header):
            logger.warning(f"🚫 VMess [{conn_id}] FNV1a نادرست")
            await ws.close(code=1008, reason="bad checksum")
            return

        hdr = parse_header(plain_header)
        if hdr["command"] != VMESS_CMD_TCP:
            logger.info(f"⚠️ VMess [{conn_id}] فرمان غیر TCP (UDP/Mux) رد شد")
            await ws.close(code=1008, reason="only tcp supported")
            return

        address, port = hdr["address"], hdr["port"]
        sec = hdr["security"]
        opt = hdr["option"]

        resp_key, resp_iv = derive_response_keys(hdr["request_key"], hdr["request_iv"])

        # codec درخواست (کلاینت → سرور)
        req_mask = ShakeStream(hdr["request_iv"]) if opt & OPT_CHUNK_MASKING else None
        req_pad = req_mask if opt & OPT_GLOBAL_PADDING else None
        req_codec = VmessCodec(hdr["request_key"], hdr["request_iv"], sec, req_mask, req_pad)

        # codec پاسخ (سرور → کلاینت)
        resp_mask = ShakeStream(resp_iv) if opt & OPT_CHUNK_MASKING else None
        resp_pad = resp_mask if opt & OPT_GLOBAL_PADDING else None
        resp_codec = VmessCodec(resp_key, resp_iv, sec, resp_mask, resp_pad)

        if not check_and_use(uuid, 42 + y + 16):
            await ws.close(code=1008, reason="quota/disabled")
            return
        stats["total_requests"] += 1
        logger.info(f"➡️  VMess [{conn_id}] → {address}:{port} (sec=0x{sec:02x})")

        # 🌐 در صورت فعال بودن WARP و تطابق مقصد، از خروجی کلودفلر عبور می‌کند
        from warp_service import warp_manager
        (reader, writer), via_warp = await warp_manager.open_connection(address, port, timeout=10.0)
        if via_warp:
            connections[conn_id]["via"] = "warp"
        _tune_socket(writer)

        # هدر پاسخ را اول بفرست (کلاینت منتظر آن است)
        await ws.send_bytes(build_response_header(hdr["response_auth"], resp_key, resp_iv))

        # دادهٔ احتمالیِ همراهشده با هدر (بعد از AHeader) باید پردازش شود
        leftover = bytearray(buf)

        done, pending = await asyncio.wait(
            {
                asyncio.create_task(_ws_to_tcp(ws, writer, conn_id, uuid, req_codec, speed_limited, leftover)),
                asyncio.create_task(_tcp_to_ws(ws, reader, conn_id, uuid, resp_codec, speed_limited)),
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
        error_logs.append({"error": "vmess connection timeout", "time": datetime.now().isoformat()})
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        logger.error(f"VMess error [{conn_id}]: {exc}")
    finally:
        flush_usage()
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        connections.pop(conn_id, None)
        logger.info(f"🔌 VMess closed [{conn_id}] total={len(connections)}")


async def _ws_to_tcp(ws, writer, conn_id, uid, codec, speed_limited, leftover):
    buf = bytearray(leftover)
    try:
        while True:
            plain, eof, consumed = _try_decode_chunk(buf, codec)
            if plain is None and consumed == 0:
                if eof:
                    break
                # نیاز به دادهٔ بیشتر
                msg = await ws.receive()
                if msg["type"] == "websocket.disconnect":
                    break
                data = msg.get("bytes") or (msg.get("text") or "").encode()
                if data:
                    buf.extend(data)
                continue
            if consumed:
                del buf[:consumed]
            if plain:
                if not check_and_use(uid, len(plain)):
                    await ws.close(code=1008, reason="quota/disabled/unknown")
                    break
                if speed_limited:
                    await throttle(uid, len(plain))
                stats["total_requests"] += 1
                connections[conn_id]["bytes"] += len(plain)
                writer.write(plain)
                if writer.transport.get_write_buffer_size() > RELAY_BUF:
                    await writer.drain()
            if eof:
                break
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        try:
            writer.write_eof()
        except Exception:
            pass


async def _tcp_to_ws(ws, reader, conn_id, uid, codec, speed_limited):
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
            connections[conn_id]["bytes"] += len(data)
            await ws.send_bytes(encode_chunk(codec, data))
    except Exception:
        pass
    finally:
        try:
            await ws.send_bytes(encode_end_marker(codec))
        except Exception:
            pass
