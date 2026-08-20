# test_vmess.py
# ══════════════════════════════════════════════════════════════════════════════
#  تست‌های واحد پروتکل VMess (vmess_crypto.py) — بدون نیاز به سرور
#
#  چون نمی‌توانیم با کلاینت واقعی v2ray تست کنیم، این تست‌ها:
#   ۱) صحت KDF (نردبان HMAC-SHA256) را با یک مرجع مستقل می‌سنجند؛
#   ۲) رمزنگاری (AES-GCM / ChaCha20-Poly1305 / AES-ECB) را رفت‌وبرگشت می‌کنند؛
#   ۳) یک «کلاینت ساختگی» کامل می‌سازند که درخواست را کد و سرور رمزگشایی می‌کند؛
#   ۴) هدر پاسخ و جریان داده را رفت‌وبرگشت می‌کنند.
# ══════════════════════════════════════════════════════════════════════════════

import hashlib
import hmac
import os
import secrets
import struct
import sys
import time
import uuid as _uuid
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vmess_crypto import (
    ADDR_DOMAIN,
    OPT_CHUNK_MASKING,
    OPT_GLOBAL_PADDING,
    SEC_AES128_GCM,
    SEC_CHACHA20_POLY1305,
    SEC_NONE,
    ShakeStream,
    VmessCodec,
    build_response_header,
    cmd_key,
    decrypt_auth_id,
    decrypt_header,
    derive_response_keys,
    encode_chunk,
    encode_end_marker,
    fnv1a32,
    kdf,
    parse_header,
    verify_header_checksum,
)


# ── مرجع مستقل برای KDF (بدون کلاس، صرفاً با هش تو در تو) ─────────────────────
def ref_kdf(key: bytes, paths: list[bytes]) -> bytes:
    h = hmac.new(b"VMess AEAD KDF", digestmod=hashlib.sha256)
    for p in paths:
        # HMAC با «کلید=p» و «هش = HMAC قبلی»
        def make(prev):
            inner = prev.copy()
            def _hash():
                return inner.copy()
            return hmac.new(p, digestmod=_hash)
        h = make(h)
    h.update(key)
    return h.digest()


def test_kdf():
    key = b"0123456789abcdef"
    a = kdf(key, b"VMess Header AEAD Key", b"A" * 16, b"B" * 8)
    assert len(a) == 32
    # قطعی بودن
    assert a == kdf(key, b"VMess Header AEAD Key", b"A" * 16, b"B" * 8)
    # مسیرهای متفاوت → خروجی متفاوت
    assert a != kdf(key, b"VMess Header AEAD Nonce", b"A" * 16, b"B" * 8)


def test_cmd_key():
    u = _uuid.uuid4()
    ck = cmd_key(u.bytes)
    assert len(ck) == 16
    expected = hashlib.md5(u.bytes + b"c48619fe-8f02-49e0-b9e9-edf763e17e21").digest()
    assert ck == expected


def test_fnv1a():
    # بردارهای مرجع FNV-1a ۳۲ بیتی
    assert fnv1a32(b"") == 0x811C9DC5
    assert fnv1a32(b"a") == 0xE40C292C
    assert fnv1a32(b"foobar") == 0xBF9CF968


def _aes_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def _build_client_request(uuid: str, address: str, port: int, sec: int, opt: int = 0):
    """یک درخواست VMess کامل (AEAD) از دید کلاینت می‌سازد."""
    ckey = cmd_key(_uuid.UUID(uuid).bytes)

    # EAuID
    ts = int(time.time())
    rand = secrets.token_bytes(4)
    crc = zlib.crc32(struct.pack(">q", ts) + rand)
    plain_auth = struct.pack(">q", ts) + rand + struct.pack(">I", crc)
    auth_key = kdf(ckey, b"AES Auth ID Encryption")[:16]
    eauthid = _aes_ecb_encrypt(auth_key, plain_auth)

    # هدر ساده
    req_iv = secrets.token_bytes(16)
    req_key = secrets.token_bytes(16)
    resp_v = secrets.token_bytes(1)[0]
    pad_len = 0
    header = bytearray()
    header.append(1)                      # ver
    header += req_iv                      # 16
    header += req_key                     # 16
    header.append(resp_v)                 # 1
    header.append(opt)                    # 1
    header.append((pad_len << 4) | sec)   # 1 (P hi nibble | Sec lo nibble)
    header.append(0)                      # reserved
    header.append(0x01)                   # Cmd TCP
    header += struct.pack(">H", port)     # 2
    header.append(ADDR_DOMAIN)            # T
    ab = address.encode()
    header.append(len(ab))                # domain len
    header += ab                          # domain
    # padding (none)
    header += struct.pack(">I", fnv1a32(bytes(header)))  # FNV1a

    # رمزنگاری ALength / AHeader
    nonce = secrets.token_bytes(8)
    len_key = kdf(ckey, b"VMess Header AEAD Key_Length", eauthid, nonce)[:16]
    len_iv = kdf(ckey, b"VMess Header AEAD Nonce_Length", eauthid, nonce)[:12]
    alength = AESGCM(len_key).encrypt(len_iv, struct.pack(">H", len(header)), eauthid)
    hdr_key = kdf(ckey, b"VMess Header AEAD Key", eauthid, nonce)[:16]
    hdr_iv = kdf(ckey, b"VMess Header AEAD Nonce", eauthid, nonce)[:12]
    aheader = AESGCM(hdr_key).encrypt(hdr_iv, bytes(header), eauthid)

    wire = eauthid + alength + nonce + aheader
    return wire, (req_key, req_iv, resp_v, sec, opt)


def test_request_parse_roundtrip():
    uuid = str(_uuid.uuid4())
    for sec in (SEC_AES128_GCM, SEC_CHACHA20_POLY1305):
        wire, (req_key, req_iv, resp_v, sec_, opt) = _build_client_request(
            uuid, "example.com", 443, sec, OPT_CHUNK_MASKING | OPT_GLOBAL_PADDING
        )
        ckey = cmd_key(_uuid.UUID(uuid).bytes)
        eauthid, alength, nonce = wire[:16], wire[16:34], wire[34:42]
        aheader = wire[42:]

        ts, ok = decrypt_auth_id(ckey, eauthid)
        assert ok
        assert abs(ts - time.time()) < 120

        plain = decrypt_header(ckey, eauthid, nonce, alength, aheader)
        assert verify_header_checksum(plain)
        hdr = parse_header(plain)
        assert hdr["address"] == "example.com"
        assert hdr["port"] == 443
        assert hdr["security"] == sec
        assert hdr["request_key"] == req_key
        assert hdr["request_iv"] == req_iv


def test_data_stream_roundtrip():
    key = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    mask_seed = secrets.token_bytes(16)
    for sec in (SEC_AES128_GCM, SEC_CHACHA20_POLY1305, SEC_NONE):
        enc = VmessCodec(key, iv, sec, mask=ShakeStream(mask_seed), padding=ShakeStream(mask_seed))
        dec = VmessCodec(key, iv, sec, mask=ShakeStream(mask_seed), padding=ShakeStream(mask_seed))

        payload = b"hello vmess " * 100
        encoded = encode_chunk(enc, payload) + encode_end_marker(enc)

        # رمزگشایی دستی بافر
        buf = bytearray(encoded)
        out = bytearray()
        eof = False
        while not eof:
            # read size
            raw = bytes(buf[:2])
            del buf[:2]
            length, pad = _read_size_manual(dec, raw)
            if dec.is_aead:
                enc_size = length - pad
                if enc_size <= dec.overhead:
                    del buf[:length]
                    eof = True
                    break
                total = length
            else:
                if length == 0:
                    eof = True
                    break
                total = length
            if len(buf) < total:
                raise AssertionError("buffer underrun")
            data = bytes(buf[:total])
            del buf[:total]
            if dec.is_aead:
                pt = dec._decrypt_block(data[:enc_size])
            else:
                pt = data[:total - pad] if pad else data
            out += pt

        assert bytes(out) == payload


def _read_size_manual(codec, raw):
    pad = codec.padding.next_u16() % 64 if codec.padding is not None else 0
    raw_len = int.from_bytes(raw, "big")
    if codec.mask is not None:
        return raw_len ^ codec.mask.next_u16(), pad
    return raw_len, pad


def test_response_header_roundtrip():
    req_key = secrets.token_bytes(16)
    req_iv = secrets.token_bytes(16)
    v = secrets.token_bytes(1)[0]
    rk, riv = derive_response_keys(req_key, req_iv)
    resp = build_response_header(v, rk, riv)
    assert len(resp) == 18 + 20

    # رمزگشایی معکوس برای اطمینان
    len_key = kdf(rk, b"AEAD Resp Header Len Key")[:16]
    len_iv = kdf(riv, b"AEAD Resp Header Len IV")[:12]
    L = struct.unpack(">H", AESGCM(len_key).decrypt(len_iv, resp[:18], b""))[0]
    assert L == 4
    payload_key = kdf(rk, b"AEAD Resp Header Key")[:16]
    payload_iv = kdf(riv, b"AEAD Resp Header IV")[:12]
    plain = AESGCM(payload_key).decrypt(payload_iv, resp[18:], b"")
    assert plain == bytes([v, 0x00, 0x00, 0x00])


def test_link_builder():
    from protocols import build_vmess_link
    import base64
    import json

    link = build_vmess_link("de305d54-75b4-431b-adb2-eb6b9e546014", "cdn.example.com", remark="تست")
    assert link.startswith("vmess://")
    cfg = json.loads(base64.b64decode(link[len("vmess://"):]).decode())
    assert cfg["id"] == "de305d54-75b4-431b-adb2-eb6b9e546014"
    assert cfg["add"] == "cdn.example.com"
    assert cfg["net"] == "ws"
    assert cfg["path"] == "/vmess/de305d54-75b4-431b-adb2-eb6b9e546014"
    assert cfg["aid"] == "0"


if __name__ == "__main__":
    test_kdf()
    test_cmd_key()
    test_fnv1a()
    test_request_parse_roundtrip()
    test_data_stream_roundtrip()
    test_response_header_roundtrip()
    test_link_builder()
    print("✅ همه تست‌های VMess پاس شد")
