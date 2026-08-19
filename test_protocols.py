# test_protocols.py
# ══════════════════════════════════════════════════════════════════════════════
# تست پروتکل Trojan و تنظیمات پکت فرگمنت
#
# شامل یک تست سرتاسری واقعی: یک کلاینت Trojan ساختگی به رلهٔ پنل وصل می‌شود،
# از آن می‌خواهد به یک سرور echo محلی متصل شود و داده را رفت‌وبرگشت می‌کند.
#
# اجرا:  python3 test_protocols.py
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import hashlib
import sys

import main  # noqa: F401 — اول ایمپورت شود تا حلقهٔ ایمپورت پیش نیاید
import protocols
from protocols import (
    FRAGMENT_PRESETS,
    build_trojan_link,
    fragment_query_value,
    is_trojan,
    normalize_fragment,
    trojan_password_hash,
)
from relay_trojan import (
    TrojanAuthError,
    TrojanParseError,
    parse_trojan_header,
)

_failures = []


def check(name: str, condition: bool, detail: str = ""):
    if condition:
        print(f"  ✅ {name}")
    else:
        print(f"  ❌ {name} {detail}")
        _failures.append(name)


# ══════════════════════════════════════════════════════════════════════════════
# ساخت بستهٔ Trojan مثل یک کلاینت واقعی
# ══════════════════════════════════════════════════════════════════════════════

def build_trojan_request(password: str, address: str, port: int, payload: bytes = b"",
                         cmd: int = 0x01) -> bytes:
    pw = hashlib.sha224(password.encode()).hexdigest().encode("ascii")
    if all(part.isdigit() for part in address.split(".")) and address.count(".") == 3:
        atyp = b"\x01" + bytes(int(p) for p in address.split("."))
    else:
        ab = address.encode()
        atyp = b"\x03" + bytes([len(ab)]) + ab
    return pw + b"\r\n" + bytes([cmd]) + atyp + port.to_bytes(2, "big") + b"\r\n" + payload


def test_fragment():
    print("\n▶ پکت فرگمنت — پریست‌های اپراتورها")
    check("پریست همراه اول ۱۰۰-۲۰۰ / ۱۰-۲۰ است",
          FRAGMENT_PRESETS["mci"]["length"] == "100-200"
          and FRAGMENT_PRESETS["mci"]["interval"] == "10-20")
    check("پریست ایرانسل ۵۰-۱۵۰ / ۵-۱۵ است",
          FRAGMENT_PRESETS["irancell"]["length"] == "50-150"
          and FRAGMENT_PRESETS["irancell"]["interval"] == "5-15")
    check("پریست اینترانت ۱۰-۶۰ / ۲-۱۰ است",
          FRAGMENT_PRESETS["intranet"]["length"] == "10-60"
          and FRAGMENT_PRESETS["intranet"]["interval"] == "2-10")

    print("\n▶ پکت فرگمنت — اعتبارسنجی")
    f = normalize_fragment({"enabled": True, "preset": "irancell"})
    check("انتخاب پریست مقادیرش را اعمال می‌کند", f["length"] == "50-150")
    check("فرگمنت خاموش هیچ پارامتری تولید نمی‌کند",
          fragment_query_value({"enabled": False, "preset": "mci"}) == "")
    check("فرگمنت روشن قالب packets,length,interval می‌دهد",
          fragment_query_value({"enabled": True, "preset": "mci"}) == "tlshello,100-200,10-20",
          f"-> {fragment_query_value({'enabled': True, 'preset': 'mci'})}")
    check("پریست نامعتبر به پیش‌فرض برمی‌گردد",
          normalize_fragment({"preset": "چرت‌وپرت"})["preset"] == "mci")
    custom = normalize_fragment({"enabled": True, "preset": "custom",
                                 "length": "300-120", "interval": "9"})
    check("مقادیر دستی مرتب و پذیرفته می‌شوند",
          custom["length"] == "120-300" and custom["interval"] == "9",
          f"-> {custom}")
    bad = normalize_fragment({"enabled": True, "preset": "custom", "length": "abc"})
    check("ورودی نامعتبر دستی به مقدار امن برمی‌گردد", bad["length"] == "100-200")
    check("حالت بسته‌شکنی نامعتبر رد می‌شود",
          normalize_fragment({"preset": "custom", "packets": "hack"})["packets"] == "tlshello")


def test_link_building():
    print("\n▶ ساخت لینک اشتراک")
    check("تشخیص پروتکل Trojan", is_trojan("trojan-ws") and not is_trojan("vless-ws"))

    uid = "aaaabbbb-cccc-dddd-eeee-ffff00001111"
    link = build_trojan_link(uid, "cdn.example.com", remark="تست", port=443,
                             sni="digikala.com",
                             fragment={"enabled": True, "preset": "irancell"})
    check("لینک با trojan:// شروع می‌شود", link.startswith(f"trojan://{uid}@"))
    check("پورت و هاست درست است", "@cdn.example.com:443?" in link)
    check("مسیر WS اختصاصی Trojan است", f"path=/trojan/{uid}" in link, f"-> {link}")
    check("SNI اعمال شد", "sni=digikala.com" in link)
    check("فرگمنت ایرانسل داخل لینک آمد",
          "fragment=tlshello%2C50-150%2C5-15" in link, f"-> {link}")

    # لینک VLESS با فرگمنت
    v = main.generate_vless_link(uid, "example.com", remark="v",
                                 fragment={"enabled": True, "preset": "mci"})
    check("لینک VLESS هم فرگمنت می‌گیرد", "fragment=tlshello%2C100-200%2C10-20" in v)
    v2 = main.generate_vless_link(uid, "example.com", remark="v")
    check("بدون فرگمنت، لینک VLESS دست‌نخورده می‌ماند", "fragment=" not in v2)

    # مسیریابی از طریق generate_vless_link
    t = main.generate_vless_link(uid, "example.com", remark="t", protocol="trojan-ws")
    check("generate_vless_link پروتکل Trojan را درست مسیریابی می‌کند",
          t.startswith("trojan://"))


def test_header_parsing():
    print("\n▶ شکافتن بستهٔ Trojan")
    uid = "11112222-3333-4444-5555-666677778888"
    expected = trojan_password_hash(uid)

    pkt = build_trojan_request(uid, "example.com", 443, b"HELLO")
    cmd, addr, port, payload = parse_trojan_header(pkt, expected)
    check("دامنه درست خوانده شد", addr == "example.com", f"-> {addr}")
    check("پورت درست خوانده شد", port == 443)
    check("دستور CONNECT است", cmd == 0x01)
    check("محموله سالم منتقل شد", payload == b"HELLO", f"-> {payload!r}")

    pkt4 = build_trojan_request(uid, "8.8.4.4", 53)
    _, addr4, port4, _ = parse_trojan_header(pkt4, expected)
    check("آدرس IPv4 درست خوانده شد", addr4 == "8.8.4.4" and port4 == 53, f"-> {addr4}:{port4}")

    print("\n▶ امنیت رلهٔ Trojan")
    wrong = build_trojan_request("رمز-اشتباه", "example.com", 443)
    try:
        parse_trojan_header(wrong, expected)
        check("رمز اشتباه رد می‌شود", False, "-> استثنایی پرتاب نشد!")
    except TrojanAuthError:
        check("رمز اشتباه رد می‌شود", True)
    except Exception as e:
        check("رمز اشتباه رد می‌شود", False, f"-> استثنای نادرست {type(e).__name__}")

    try:
        parse_trojan_header(b"\x00" * 30, expected)
        check("بستهٔ ناقص رد می‌شود", False, "-> استثنایی پرتاب نشد!")
    except TrojanParseError:
        check("بستهٔ ناقص رد می‌شود", True)
    except Exception as e:
        check("بستهٔ ناقص رد می‌شود", False, f"-> {type(e).__name__}")

    broken = bytearray(build_trojan_request(uid, "example.com", 443))
    broken[56:58] = b"XX"  # خراب کردن CRLF
    try:
        parse_trojan_header(bytes(broken), expected)
        check("CRLF خراب رد می‌شود", False, "-> استثنایی پرتاب نشد!")
    except TrojanParseError:
        check("CRLF خراب رد می‌شود", True)


async def test_end_to_end():
    """تست واقعی: کلاینت Trojan → رلهٔ پنل → سرور echo محلی."""
    print("\n▶ تست سرتاسری رلهٔ Trojan (کلاینت واقعی)")
    import contextlib

    import httpx
    import uvicorn
    import websockets

    # ── سرور echo که هرچه بگیرد با پیشوند برمی‌گرداند ────────────────────────
    async def echo_handler(reader, writer):
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(b"ECHO:" + data)
                await writer.drain()
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    echo_server = await asyncio.start_server(echo_handler, "127.0.0.1", 0)
    echo_port = echo_server.sockets[0].getsockname()[1]

    # ── بالا آوردن پنل ────────────────────────────────────────────────────────
    config = uvicorn.Config(main.app, host="127.0.0.1", port=8099, log_level="critical")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    for _ in range(100):
        if server.started:
            break
        await asyncio.sleep(0.1)
    check("پنل بالا آمد", server.started)

    try:
        async with httpx.AsyncClient(base_url="http://127.0.0.1:8099") as c:
            r = await c.post("/api/login", json={"password": "X4GKING"})
            cookie = r.cookies
            r = await c.post("/api/links",
                             json={"label": "تروجان-تست", "protocol": "trojan-ws",
                                   "fragment": {"enabled": True, "preset": "mci"}},
                             cookies=cookie)
            data = r.json()
            uid = data["uuid"]
            check("کانفیگ Trojan ساخته شد", data.get("protocol") == "trojan-ws",
                  f"-> {data.get('protocol')}")
            check("لینک اشتراک Trojan تولید شد",
                  data["vless_link"].startswith("trojan://"), f"-> {data['vless_link'][:40]}")
            check("فرگمنت همراه اول در لینک هست",
                  "fragment=tlshello%2C100-200%2C10-20" in data["vless_link"])

        # ── کلاینت Trojan واقعی ──────────────────────────────────────────────
        async with websockets.connect(f"ws://127.0.0.1:8099/trojan/{uid}") as ws:
            await ws.send(build_trojan_request(uid, "127.0.0.1", echo_port, b"SALAM"))
            reply = await asyncio.wait_for(ws.recv(), timeout=5)
            check("داده از مقصد واقعی برگشت", reply == b"ECHO:SALAM", f"-> {reply!r}")
            await ws.send(b"DOVOM")
            reply2 = await asyncio.wait_for(ws.recv(), timeout=5)
            check("جریان دوطرفه ادامه دارد", reply2 == b"ECHO:DOVOM", f"-> {reply2!r}")

        # ── کلاینت با رمز اشتباه باید قطع شود ────────────────────────────────
        rejected = False
        try:
            async with websockets.connect(f"ws://127.0.0.1:8099/trojan/{uid}") as ws:
                await ws.send(build_trojan_request("رمز-غلط", "127.0.0.1", echo_port, b"HI"))
                await asyncio.wait_for(ws.recv(), timeout=5)
        except Exception:
            rejected = True
        check("کلاینت با رمز اشتباه قطع می‌شود", rejected)

        # ── مصرف ترافیک ثبت شده باشد ─────────────────────────────────────────
        # ⚡ v9.15: حسابداری مصرف دسته‌ای است (فلاش هر ۱ ثانیه یا هنگام بسته شدن
        # اتصال)؛ پس چند لحظه صبر می‌کنیم تا فلاش سرور-side اتصال بسته‌شده اجرا شود.
        for _ in range(30):
            if main.LINKS[uid]["used_bytes"] > 0:
                break
            await asyncio.sleep(0.1)
        check("مصرف ترافیک روی کانفیگ ثبت شد", main.LINKS[uid]["used_bytes"] > 0,
              f"-> {main.LINKS[uid]['used_bytes']} بایت")

    finally:
        server.should_exit = True
        with contextlib.suppress(Exception):
            await asyncio.wait_for(task, timeout=10)
        echo_server.close()
        with contextlib.suppress(Exception):
            await echo_server.wait_closed()


async def main_async():
    print("═" * 62)
    print("  تست پروتکل Trojan و پکت فرگمنت XR (پورت‌شده از Nyx)")
    print("═" * 62)
    test_fragment()
    test_link_building()
    test_header_parsing()
    await test_end_to_end()

    print("\n" + "═" * 62)
    if _failures:
        print(f"  ❌ {len(_failures)} تست ناموفق: {'، '.join(_failures)}")
        return 1
    print("  ✅ همه تست‌ها با موفقیت گذشتند")
    print("═" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main_async()))
