# test_backup_warp.py
# ══════════════════════════════════════════════════════════════════════════════
# تست بکاپ خودکار/بازیابی و خروجی کلودفلر WARP
#
# شامل یک سرور SOCKS5 واقعی (کوچک) که نقش پروکسی WARP را بازی می‌کند تا
# مسیریابی، دست‌دادن SOCKS5 و رفتار fail-open واقعاً سنجیده شوند.
#
# اجرا:  python3 test_backup_warp.py
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import contextlib
import json
import struct
import sys

import main
import backup_service
import warp_service
from backup_service import build_backup, compute_checksum, restore_backup
from warp_service import (
    DEFAULT_WARP_DOMAINS,
    domain_matches,
    normalize_domains,
    parse_proxy,
    warp_manager,
)

_failures = []


def check(name: str, condition: bool, detail: str = ""):
    if condition:
        print(f"  ✅ {name}")
    else:
        print(f"  ❌ {name} {detail}")
        _failures.append(name)


# ══════════════════════════════════════════════════════════════════════════════
# یک سرور SOCKS5 مینیمال که نقش پروکسی WARP را بازی می‌کند
# ══════════════════════════════════════════════════════════════════════════════

class FakeWarpProxy:
    def __init__(self):
        self.server = None
        self.port = 0
        self.requests = []   # مقصدهایی که از پروکسی عبور کردند

    async def _handle(self, reader, writer):
        try:
            # ── مذاکرهٔ روش احراز هویت ────────────────────────────────────────
            head = await reader.readexactly(2)
            nmethods = head[1]
            await reader.readexactly(nmethods)
            writer.write(b"\x05\x00")  # بدون احراز هویت
            await writer.drain()

            # ── درخواست CONNECT ───────────────────────────────────────────────
            req = await reader.readexactly(4)
            atyp = req[3]
            if atyp == 0x01:
                addr = ".".join(str(b) for b in await reader.readexactly(4))
            elif atyp == 0x03:
                ln = (await reader.readexactly(1))[0]
                addr = (await reader.readexactly(ln)).decode()
            else:
                await reader.readexactly(16)
                addr = "ipv6"
            port = struct.unpack(">H", await reader.readexactly(2))[0]
            self.requests.append(f"{addr}:{port}")

            # ── اتصال واقعی به مقصد و پاسخ موفق ──────────────────────────────
            try:
                up_r, up_w = await asyncio.wait_for(
                    asyncio.open_connection(addr, port), timeout=5
                )
            except Exception:
                writer.write(b"\x05\x05\x00\x01" + b"\x00" * 6)
                await writer.drain()
                writer.close()
                return

            writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
            await writer.drain()

            async def pump(r, w):
                try:
                    while True:
                        d = await r.read(4096)
                        if not d:
                            break
                        w.write(d)
                        await w.drain()
                except Exception:
                    pass

            await asyncio.gather(pump(reader, up_w), pump(up_r, writer),
                                 return_exceptions=True)
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self.port

    async def stop(self):
        if self.server:
            self.server.close()
            with contextlib.suppress(Exception):
                await self.server.wait_closed()


# ══════════════════════════════════════════════════════════════════════════════
# تست‌های بکاپ
# ══════════════════════════════════════════════════════════════════════════════

async def test_backup():
    print("\n▶ ساخت بستهٔ بکاپ")
    main.LINKS.clear()
    main.SUBS.clear()
    uid1, _ = await main.make_link(label="کانفیگ الف", location="آلمان")
    uid2, _ = await main.make_link(label="کانفیگ ب", protocol="trojan-ws")
    main.LINKS[uid1]["used_bytes"] = 5_000_000
    main.CONFIG["branding"] = {"brand_name": "فروشگاه تست"}

    payload, meta = await build_backup()
    check("بکاپ ساخته شد", len(payload) > 100, f"-> {len(payload)} بایت")
    check("تعداد کانفیگ‌ها درست است", meta["links_count"] == 2, f"-> {meta['links_count']}")
    check("کد اعتبارسنجی SHA-256 تولید شد", len(meta["checksum_sha256"]) == 64)
    check("مصرف کل محاسبه شد", meta["total_used_bytes"] == 5_000_000)

    env = json.loads(payload)
    check("ساختار meta/data درست است", "meta" in env and "data" in env)
    check("برندینگ داخل بکاپ هست",
          env["data"]["branding"]["brand_name"] == "فروشگاه تست")
    check("رمز پنل داخل بکاپ هست", bool(env["data"]["password_hash"]))

    print("\n▶ بازیابی از بکاپ")
    # همه‌چیز را پاک می‌کنیم تا بازیابی واقعاً سنجیده شود
    main.LINKS.clear()
    main.SUBS.clear()
    main.CONFIG["branding"] = {}
    check("وضعیت پاک شد", len(main.LINKS) == 0)

    result = await restore_backup(payload)
    check("کانفیگ‌ها بازگردانی شدند", result["links_restored"] == 2,
          f"-> {result['links_restored']}")
    check("اعتبارسنجی SHA-256 انجام شد", result["checksum_verified"] is True)
    check("داده‌ها دقیقاً برگشتند", main.LINKS[uid1]["label"] == "کانفیگ الف")
    check("مصرف حفظ شد", main.LINKS[uid1]["used_bytes"] == 5_000_000)
    check("پروتکل Trojan حفظ شد", main.LINKS[uid2]["protocol"] == "trojan-ws")
    check("برندینگ بازگردانی شد",
          main.CONFIG["branding"]["brand_name"] == "فروشگاه تست")
    check("نسخهٔ ایمنی قبل از بازیابی ساخته شد", bool(result["safety_copy"]))

    print("\n▶ امنیت بکاپ")
    tampered = json.loads(payload)
    tampered["data"]["links"][uid1]["limit_bytes"] = 999999999
    try:
        await restore_backup(json.dumps(tampered).encode())
        check("فایل دستکاری‌شده رد می‌شود", False, "-> پذیرفته شد!")
    except ValueError as e:
        check("فایل دستکاری‌شده رد می‌شود", "SHA-256" in str(e), f"-> {e}")

    try:
        await restore_backup(b"not json at all")
        check("فایل خراب رد می‌شود", False, "-> پذیرفته شد!")
    except ValueError:
        check("فایل خراب رد می‌شود", True)

    try:
        await restore_backup(b'{"hello":"world"}')
        check("ساختار نامعتبر رد می‌شود", False, "-> پذیرفته شد!")
    except ValueError:
        check("ساختار نامعتبر رد می‌شود", True)

    check("محاسبهٔ checksum پایدار است",
          compute_checksum(b"abc") == compute_checksum(b"abc")
          and compute_checksum(b"abc") != compute_checksum(b"abd"))

    print("\n▶ وضعیت دیمون بکاپ")
    st = backup_service.backup_manager.get_status()
    check("بازهٔ پیش‌فرض ۲۴ ساعت است", st["interval_hours"] == 24, f"-> {st['interval_hours']}")
    check("خروجی وضعیت کامل است",
          all(k in st for k in ("enabled", "running", "last_backup", "history")))


# ══════════════════════════════════════════════════════════════════════════════
# تست‌های WARP
# ══════════════════════════════════════════════════════════════════════════════

def test_warp_config():
    print("\n▶ WARP — تنظیمات و مسیریابی")
    check("پروکسی معتبر شکافته می‌شود",
          parse_proxy("socks5://127.0.0.1:40000") == {
              "scheme": "socks5", "host": "127.0.0.1", "port": 40000,
              "user": "", "password": ""})
    check("پروکسی با نام کاربری/رمز",
          parse_proxy("socks5://ali:pass@1.2.3.4:1080")["user"] == "ali")
    check("پروکسی HTTP هم پشتیبانی می‌شود",
          parse_proxy("http://127.0.0.1:8080")["scheme"] == "http")
    check("آدرس نامعتبر رد می‌شود", parse_proxy("چرت‌وپرت") is None)
    check("پورت نامعتبر رد می‌شود", parse_proxy("socks5://1.2.3.4:99999") is None)

    check("OpenAI در لیست پیش‌فرض هست", "openai.com" in DEFAULT_WARP_DOMAINS)
    check("Netflix در لیست پیش‌فرض هست", "netflix.com" in DEFAULT_WARP_DOMAINS)
    check("زیردامنه هم تطابق می‌خورد",
          domain_matches("api.openai.com", ["openai.com"]))
    check("دامنهٔ نامرتبط تطابق نمی‌خورد",
          not domain_matches("google.com", ["openai.com"]))
    check("تطابق فریبنده رد می‌شود",
          not domain_matches("notopenai.com", ["openai.com"]))
    check("دامنه‌ها تمیز می‌شوند",
          normalize_domains(["HTTPS://OpenAI.com/path", " netflix.com ", "openai.com"])
          == ["openai.com", "netflix.com"],
          f"-> {normalize_domains(['HTTPS://OpenAI.com/path', ' netflix.com ', 'openai.com'])}")
    check("رشتهٔ چندخطی هم پذیرفته می‌شود",
          normalize_domains("openai.com\nnetflix.com, spotify.com") ==
          ["openai.com", "netflix.com", "spotify.com"])


async def test_warp_routing():
    print("\n▶ WARP — تست زنده با پروکسی SOCKS5 واقعی")
    proxy = FakeWarpProxy()
    port = await proxy.start()

    # ── سرور مقصد (echo) ──────────────────────────────────────────────────────
    async def echo(reader, writer):
        with contextlib.suppress(Exception):
            data = await reader.read(1024)
            writer.write(b"OK:" + data)
            await writer.drain()
            writer.close()

    dest = await asyncio.start_server(echo, "127.0.0.1", 0)
    dest_port = dest.sockets[0].getsockname()[1]

    try:
        main.CONFIG["warp"] = {
            "enabled": True,
            "proxy": f"socks5://127.0.0.1:{port}",
            "mode": "domains",
            "domains": ["127.0.0.1", "openai.com"],
        }
        check("WARP فعال شناخته شد", warp_manager.enabled)
        check("مقصد داخل لیست از WARP رد می‌شود",
              warp_manager.should_use_warp("api.openai.com"))
        check("مقصد خارج از لیست مستقیم می‌رود",
              not warp_manager.should_use_warp("google.com"))

        before = warp_manager.total_via_warp
        (r, w), via = await warp_manager.open_connection("127.0.0.1", dest_port)
        w.write(b"PING")
        await w.drain()
        reply = await asyncio.wait_for(r.read(64), timeout=5)
        w.close()
        check("اتصال از طریق WARP برقرار شد", via is True)
        check("داده از مسیر WARP رفت‌وبرگشت", reply == b"OK:PING", f"-> {reply!r}")
        check("پروکسی درخواست را دید",
              f"127.0.0.1:{dest_port}" in proxy.requests, f"-> {proxy.requests}")
        check("شمارندهٔ WARP بالا رفت", warp_manager.total_via_warp == before + 1)

        # ── حالت all ──────────────────────────────────────────────────────────
        main.CONFIG["warp"]["mode"] = "all"
        check("حالت all همه مقصدها را از WARP می‌برد",
              warp_manager.should_use_warp("هر-دامنه-ای.com"))
        main.CONFIG["warp"]["mode"] = "domains"

        # ── fail-open: پروکسی خراب ────────────────────────────────────────────
        print("\n▶ WARP — رفتار fail-open (پروکسی خراب)")
        await proxy.stop()
        fb_before = warp_manager.total_fallback
        (r2, w2), via2 = await warp_manager.open_connection("127.0.0.1", dest_port)
        w2.write(b"HELLO")
        await w2.drain()
        reply2 = await asyncio.wait_for(r2.read(64), timeout=5)
        w2.close()
        check("با خرابی پروکسی، اتصال مستقیم برقرار شد", via2 is False)
        check("سرویس کاربر قطع نشد", reply2 == b"OK:HELLO", f"-> {reply2!r}")
        check("شمارندهٔ fallback ثبت شد",
              warp_manager.total_fallback == fb_before + 1)
        check("خطای آخر ثبت شد", bool(warp_manager.last_error))

        # ── خاموش بودن WARP ───────────────────────────────────────────────────
        main.CONFIG["warp"]["enabled"] = False
        check("وقتی WARP خاموش است هیچ مقصدی از آن رد نمی‌شود",
              not warp_manager.should_use_warp("api.openai.com"))

        st = warp_manager.get_status()
        check("خروجی وضعیت کامل است",
              all(k in st for k in ("enabled", "mode", "domains_count",
                                    "total_via_warp", "total_fallback")))
    finally:
        await proxy.stop()
        dest.close()
        with contextlib.suppress(Exception):
            await dest.wait_closed()


async def main_async():
    print("═" * 62)
    print("  تست بکاپ خودکار تلگرام و خروجی کلودفلر WARP (پورت‌شده از Nyx)")
    print("═" * 62)
    await test_backup()
    test_warp_config()
    await test_warp_routing()

    print("\n" + "═" * 62)
    if _failures:
        print(f"  ❌ {len(_failures)} تست ناموفق: {'، '.join(_failures)}")
        return 1
    print("  ✅ همه تست‌ها با موفقیت گذشتند")
    print("═" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main_async()))
