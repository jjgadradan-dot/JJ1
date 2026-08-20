# vmess_crypto.py
# ══════════════════════════════════════════════════════════════════════════════
#  🚀 XR — پروتکل VMess روی ترابرد WebSocket (پیاده‌سازی واقعی استاندارد v2ray)
#
#  این ماژول فقط «ریاضی» پروتکل VMess را پیاده می‌کند و هیچ وابستگی به
#  main.py / FastAPI ندارد تا هم قابل تست باشد و هم حلقهٔ ایمپورت ایجاد نشود.
#
#  مرجع: مشخصات رسمی VMess (v2fly.org/developer/protocols/vmess.html)
#  + سورس v2fly/v2ray-core (proxy/vmess/aead ، proxy/vmess/encoding).
#
#  فقط احراز هویت «AEAD» پیاده شده (که همه کلاینت‌های مدرن مثل v2rayNG،
#  Hiddify، NekoBox و Streisand به‌صورت پیش‌فرض از آن استفاده می‌کنند).
#  احراز قدیمی MD5 + AES-128-CFB (منسوخ‌شده) پشتیبانی نمی‌شود.
# ══════════════════════════════════════════════════════════════════════════════

import hashlib
import hmac
import struct
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# ── ثابت‌های KDF (دقیقاً مطابق proxy/vmess/aead/consts.go) ────────────────────
KDF_SALT_KDF = b"VMess AEAD KDF"
KDF_SALT_AUTH_ID = b"AES Auth ID Encryption"
KDF_SALT_HDR_KEY = b"VMess Header AEAD Key"
KDF_SALT_HDR_IV = b"VMess Header AEAD Nonce"
KDF_SALT_HDR_LEN_KEY = b"VMess Header AEAD Key_Length"
KDF_SALT_HDR_LEN_IV = b"VMess Header AEAD Nonce_Length"
KDF_SALT_RESP_LEN_KEY = b"AEAD Resp Header Len Key"
KDF_SALT_RESP_LEN_IV = b"AEAD Resp Header Len IV"
KDF_SALT_RESP_PAYLOAD_KEY = b"AEAD Resp Header Key"
KDF_SALT_RESP_PAYLOAD_IV = b"AEAD Resp Header IV"

UUID_CMD_KEY_SALT = b"c48619fe-8f02-49e0-b9e9-edf763e17e21"

# نوع رمزنگاری داده (نیم‌بایت Sec در هدر)
SEC_LEGACY_CFB = 0x01      # منسوخ — پشتیبانی نمی‌شود
SEC_AES128_GCM = 0x03
SEC_CHACHA20_POLY1305 = 0x04
SEC_NONE = 0x05
SEC_ZERO = 0x06

# بیت‌های Opt
OPT_CHUNK_STREAM = 0x01    # S — قالب استاندارد داده (پیش‌فرض)
OPT_CHUNK_MASKING = 0x04   # M — پنهان‌سازی طول بسته
OPT_GLOBAL_PADDING = 0x08  # P — پدینگ سراسری

ADDR_IPV4 = 0x01
ADDR_DOMAIN = 0x02
ADDR_IPV6 = 0x03

GCM_TAG = 16
CHACHA_TAG = 16


# ══════════════════════════════════════════════════════════════════════════════
# KDF (نردبان HMAC — مطابق proxy/vmess/aead/kdf.go)
# ══════════════════════════════════════════════════════════════════════════════

class _Creator:
    """معادل hMacCreator در Go: یک «سازندهٔ هش» که HMAC تو در تو می‌سازد."""

    __slots__ = ("value", "parent")

    def __init__(self, value, parent=None):
        self.value = value
        self.parent = parent

    def __call__(self):
        if self.parent is None:
            return hmac.new(self.value, digestmod=hashlib.sha256)
        return hmac.new(self.value, digestmod=self.parent)


def kdf(key: bytes, *paths: bytes) -> bytes:
    """KDF(key, path...) — HMAC-SHA256 تو در تو (مطابق v2ray)."""
    creator = _Creator(KDF_SALT_KDF)
    for p in paths:
        creator = _Creator(p if isinstance(p, bytes) else p.encode(), parent=creator)
    h = creator()
    h.update(key)
    return h.digest()


def kdf16(key: bytes, *paths: bytes) -> bytes:
    return kdf(key, *paths)[:16]


def cmd_key(uuid_bytes: bytes) -> bytes:
    """CmdKey = MD5(UUID + salt) — کلید ۱۶ بایتی هر کاربر."""
    return hashlib.md5(uuid_bytes + UUID_CMD_KEY_SALT).digest()


# ══════════════════════════════════════════════════════════════════════════════
# ابزارهای پایه
# ══════════════════════════════════════════════════════════════════════════════

def fnv1a32(data: bytes) -> int:
    """FNV-1a ۳۲ بیتی (مطابق hash/fnv در Go)."""
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def _aes_ecb_decrypt(key: bytes, block: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return decryptor.update(block) + decryptor.finalize()


def _gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def _gcm_decrypt(key: bytes, nonce: bytes, data: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(nonce, data, aad)


def _chacha_key(key16: bytes) -> bytes:
    """GenerateChacha20Poly1305Key: MD5(k) + MD5(MD5(k))."""
    first = hashlib.md5(key16).digest()
    return first + hashlib.md5(first).digest()


def _chacha_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def _chacha_decrypt(key: bytes, nonce: bytes, data: bytes, aad: bytes = b"") -> bytes:
    return ChaCha20Poly1305(key).decrypt(nonce, data, aad)


class ShakeStream:
    """جریان بی‌نهایت بایت از SHA3-Shake128 (برای پنهان‌سازی طول/پدینگ)."""

    def __init__(self, seed: bytes):
        self._shake = hashlib.shake_128(seed)
        self._buf = b""

    def read(self, n: int) -> bytes:
        while len(self._buf) < n:
            total = (len(self._buf) // 4096 + 2) * 4096
            self._buf = self._shake.digest(total)
        out = self._buf[:n]
        self._buf = self._buf[n:]
        return out

    def next_u16(self) -> int:
        return int.from_bytes(self.read(2), "big")


# ══════════════════════════════════════════════════════════════════════════════
# رمزگشایی EAuID (۱۶ بایت اول)
# ══════════════════════════════════════════════════════════════════════════════

def decrypt_auth_id(cmdkey: bytes, eauthid: bytes) -> tuple[int, bool]:
    """EAuID را رمزگشایی و CRC را می‌سنجد. → (timestamp, valid)."""
    plain = _aes_ecb_decrypt(kdf16(cmdkey, KDF_SALT_AUTH_ID), eauthid)
    timestamp = struct.unpack(">q", plain[:8])[0]
    rand = plain[8:12]
    crc = struct.unpack(">I", plain[12:16])[0]
    valid = zlib.crc32(plain[:12]) == crc
    return timestamp, valid


# ══════════════════════════════════════════════════════════════════════════════
# رمزگشایی هدر درخواست (AEAD)
# ══════════════════════════════════════════════════════════════════════════════

def decrypt_header(cmdkey: bytes, eauthid: bytes, nonce: bytes, alength: bytes, aheader: bytes) -> bytes:
    """ALength (۱۸ بایت) و AHeader (Y بایت) را رمزگشایی و هدر ساده را برمی‌گرداند."""
    len_key = kdf16(cmdkey, KDF_SALT_HDR_LEN_KEY, eauthid, nonce)
    len_iv = kdf(cmdkey, KDF_SALT_HDR_LEN_IV, eauthid, nonce)[:12]
    _len = _gcm_decrypt(len_key, len_iv, alength, eauthid)  # (ignored, already sized)
    hdr_key = kdf16(cmdkey, KDF_SALT_HDR_KEY, eauthid, nonce)
    hdr_iv = kdf(cmdkey, KDF_SALT_HDR_IV, eauthid, nonce)[:12]
    return _gcm_decrypt(hdr_key, hdr_iv, aheader, eauthid)


def parse_header(plain: bytes) -> dict:
    """هدر سادهٔ VMess را می‌شکافد (بدون FNV1a — بررسی جدا انجام می‌شود)."""
    if len(plain) < 38:
        raise ValueError("vmess header too short")
    ver = plain[0]
    if ver != 1:
        raise ValueError(f"vmess version {ver} not supported")
    req_iv = plain[1:17]
    req_key = plain[17:33]
    resp_v = plain[33]
    opt = plain[34]
    sec = plain[35] & 0x0F
    padding_len = plain[35] >> 4
    cmd = plain[37]
    port = struct.unpack(">H", plain[38:40])[0]
    atyp = plain[40]
    pos = 41
    if atyp == ADDR_IPV4:
        address = ".".join(str(b) for b in plain[pos:pos + 4])
        pos += 4
    elif atyp == ADDR_DOMAIN:
        dlen = plain[pos]
        pos += 1
        address = plain[pos:pos + dlen].decode("utf-8", errors="ignore")
        pos += dlen
    elif atyp == ADDR_IPV6:
        ab = plain[pos:pos + 16]
        address = ":".join(f"{ab[i]:02x}{ab[i + 1]:02x}" for i in range(0, 16, 2))
        pos += 16
    else:
        raise ValueError(f"unknown vmess addr type {atyp}")
    # padding + FNV1a (۴ بایت آخر)
    if padding_len:
        pos += padding_len
    return {
        "version": ver,
        "request_iv": req_iv,
        "request_key": req_key,
        "response_auth": resp_v,
        "option": opt,
        "security": sec,
        "command": cmd,
        "port": port,
        "address": address,
    }


def verify_header_checksum(plain: bytes) -> bool:
    """FNV1a روی همهٔ هدر به‌جز ۴ بایت آخر باید با فیلد F برابر باشد."""
    if len(plain) < 4:
        return False
    expected = struct.unpack(">I", plain[-4:])[0]
    return fnv1a32(plain[:-4]) == expected


def derive_response_keys(request_key: bytes, request_iv: bytes) -> tuple[bytes, bytes]:
    """responseBodyKey/IV = SHA256(request key/iv)[:16] (مطابق v2ray)."""
    return hashlib.sha256(request_key).digest()[:16], hashlib.sha256(request_iv).digest()[:16]


def build_response_header(response_auth: int, response_key: bytes, response_iv: bytes) -> bytes:
    """هدر پاسخ AEAD = [18 بایت طول رمزشده][20 بایت محتوا رمزشده].

    محتوای ساده ۴ بایت است: [V][Opt=0][Cmd=0][Len=0].
    """
    plain = bytes([response_auth, 0x00, 0x00, 0x00])
    len_key = kdf16(response_key, KDF_SALT_RESP_LEN_KEY)
    len_iv = kdf(response_iv, KDF_SALT_RESP_LEN_IV)[:12]
    enc_len = _gcm_encrypt(len_key, len_iv, struct.pack(">H", len(plain)))
    payload_key = kdf16(response_key, KDF_SALT_RESP_PAYLOAD_KEY)
    payload_iv = kdf(response_iv, KDF_SALT_RESP_PAYLOAD_IV)[:12]
    enc_payload = _gcm_encrypt(payload_key, payload_iv, plain)
    return enc_len + enc_payload


# ══════════════════════════════════════════════════════════════════════════════
# کدک جریان داده (AEAD قطعه‌بندی‌شده)
# ══════════════════════════════════════════════════════════════════════════════

class VmessCodec:
    """رمز/رمزگشایی جریان دادهٔ یک جهت (درخواست یا پاسخ) با شمارندهٔ nonce مستقل."""

    def __init__(self, key: bytes, iv: bytes, security: int, mask: ShakeStream | None = None, padding: ShakeStream | None = None):
        self.key = key
        self.iv = iv
        self.security = security
        self.mask = mask
        self.padding = padding
        self.count = 0
        if security == SEC_AES128_GCM:
            self._aead = ("gcm", key)
        elif security == SEC_CHACHA20_POLY1305:
            self._aead = ("chacha", _chacha_key(key))
        elif security in (SEC_NONE, SEC_ZERO):
            self._aead = ("none", None)
            self.padding = None  # None/Zero هرگز پدینگ ندارند
        else:
            raise ValueError(f"vmess security 0x{security:02x} not supported (legacy CFB)")

    @property
    def is_aead(self) -> bool:
        return self._aead[0] in ("gcm", "chacha")

    @property
    def is_chunked(self) -> bool:
        # Zero = جریان خام؛ None = قطعه‌بندی بدون رمز
        return self.security != SEC_ZERO

    @property
    def overhead(self) -> int:
        if self._aead[0] == "gcm":
            return GCM_TAG
        if self._aead[0] == "chacha":
            return CHACHA_TAG
        return 0

    def _nonce(self) -> bytes:
        return self.count.to_bytes(2, "big") + self.iv[2:12]

    def _decrypt_block(self, data: bytes) -> bytes:
        kind, key = self._aead
        nonce = self._nonce()
        self.count += 1
        if kind == "gcm":
            return _gcm_decrypt(key, nonce, data)
        if kind == "chacha":
            return _chacha_decrypt(key, nonce, data)
        return data  # none

    def _encrypt_block(self, plaintext: bytes) -> bytes:
        kind, key = self._aead
        nonce = self._nonce()
        self.count += 1
        if kind == "gcm":
            return _gcm_encrypt(key, nonce, plaintext)
        if kind == "chacha":
            return _chacha_encrypt(key, nonce, plaintext)
        return plaintext  # none


def _read_size(codec: VmessCodec, raw: bytes) -> tuple[int, int]:
    """(L, padding) را از ۲ بایت خام می‌خواند؛ ترتیب shake: اول پدینگ بعد ماسک."""
    pad = 0
    if codec.padding is not None:
        pad = codec.padding.next_u16() % 64
    raw_len = int.from_bytes(raw, "big")
    if codec.mask is not None:
        return raw_len ^ codec.mask.next_u16(), pad
    return raw_len, pad


def encode_chunk(codec: VmessCodec, plaintext: bytes) -> bytes:
    """یک بستهٔ داده را برای ارسال (پاسخ سرور) کد می‌کند.

    ترتیب مصرف shake دقیقاً مطابق AuthenticationWriter است: اول پدینگ، بعد ماسک.
    """
    if not codec.is_chunked:
        return plaintext  # Zero = جریان خام
    if codec.is_aead:
        ct = codec._encrypt_block(plaintext)  # encryptedSize = len(pt) + tag
        pad = codec.padding.next_u16() % 64 if codec.padding is not None else 0
        length = len(ct) + pad
        if codec.mask is not None:
            length = length ^ codec.mask.next_u16()
        return length.to_bytes(2, "big") + ct + bytes(pad)
    # None = قطعه‌بندی بدون رمز (بدون tag و پدینگ)
    length = len(plaintext)
    if codec.mask is not None:
        length = length ^ codec.mask.next_u16()
    return length.to_bytes(2, "big") + plaintext


def encode_end_marker(codec: VmessCodec) -> bytes:
    """بستهٔ پایان جریان (برای بستن سالم سمت پاسخ)."""
    if not codec.is_chunked:
        return b""
    if codec.is_aead:
        ct = codec._encrypt_block(b"")  # فقط tag
        pad = codec.padding.next_u16() % 64 if codec.padding is not None else 0
        length = len(ct) + pad
        if codec.mask is not None:
            length = length ^ codec.mask.next_u16()
        return length.to_bytes(2, "big") + ct + bytes(pad)
    length = 0
    if codec.mask is not None:
        length = length ^ codec.mask.next_u16()
    return length.to_bytes(2, "big")
