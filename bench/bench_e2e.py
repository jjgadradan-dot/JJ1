# bench_e2e.py
# ══════════════════════════════════════════════════════════════════════════════
#  بنچمارک سرتاسری رلهٔ VLESS/WS: کلاینت WS → رلهٔ پنل → سرور echo محلی
#  (قبل و بعد از بهینه‌سازی — همان اسکریپت، خروجی قابل مقایسه)
#
#  پیش‌نیاز: سرور پنل باید جداگانه بالا باشد، مثلاً:
#    DATA_DIR=/tmp/xrbench-data ADMIN_PASSWORD=X4GKING \
#      .venv/bin/python -m uvicorn main:app --host 127.0.0.1 --port 8931
#
#  استفاده:
#    .venv/bin/python bench/bench_e2e.py
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import os
import sys
import time
import uuid as uuid_mod
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx
import websockets

BASE = os.environ.get("BENCH_BASE", "http://127.0.0.1:8931")
WS_BASE = BASE.replace("http", "ws")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "X4GKING")
CONNS = int(os.environ.get("BENCH_CONNS", "4"))
MB_PER_CONN = float(os.environ.get("BENCH_MB_PER_CONN", "16"))
CHUNK = 128 * 1024
INFLIGHT = 8


def build_vless_header(uuid: str, host: str, port: int) -> bytes:
    """بستهٔ اول VLESS: version + uuid + addon + cmd + port + IPv4."""
    ip = bytes(int(p) for p in host.split("."))
    uid_bytes = uuid_mod.UUID(uuid).bytes  # ۱۶ بایت خام، مطابق پروتکل VLESS
    return (
        b"\x00" + uid_bytes + b"\x00" + b"\x01"
        + port.to_bytes(2, "big") + b"\x01" + ip
    )


async def echo_handler(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main():
    print(f"🚀 بنچمارک سرتاسری رله — {CONNS} اتصال × {MB_PER_CONN} MB رفت‌وبرگشت")
    echo = await asyncio.start_server(echo_handler, "127.0.0.1", 0)
    echo_port = echo.sockets[0].getsockname()[1]

    async with httpx.AsyncClient(base_url=BASE, timeout=30) as c:
        r = await c.post("/api/login", json={"password": ADMIN_PASSWORD})
        if r.status_code != 200:
            print(f"❌ ورود ناموفق ({r.status_code}) — رمز/آدرس را چک کنید")
            return
        r = await c.post("/api/links", json={
            "label": "bench", "limit_value": 0, "limit_unit": "GB",
            "expires_days": 0, "protocol": "vless-ws", "port": 443,
            "ip_limit": 0, "speed_limit_value": 0,
        })
        uid = r.json()["uuid"]
    print(f"   کانفیگ بنچمارک: {uid[:12]}…")

    header = build_vless_header(uid, "127.0.0.1", echo_port)
    target = int(MB_PER_CONN * 1024 * 1024)
    payload = os.urandom(CHUNK)
    results = []

    async def conn(i: int):
        sent = recved = 0
        inflight = 0
        first = True
        t0 = time.perf_counter()
        async with websockets.connect(f"{WS_BASE}/ws/{uid}", max_size=32 * 1024 * 1024) as ws:
            await ws.send(header)
            while recved < target:
                while inflight < INFLIGHT and sent < target:
                    await ws.send(payload)
                    sent += len(payload)
                    inflight += 1
                msg = await asyncio.wait_for(ws.recv(), timeout=60)
                if first:
                    msg = msg[2:]          # حذف پیشوند ‎\x00\x00 اولین فریم دانلینک
                    first = False
                recved += len(msg)
                inflight -= 1
        dt = time.perf_counter() - t0
        mb = (sent + recved) / 1e6
        results.append((dt, mb))
        print(f"   اتصال {i+1}: {mb:7.1f} MB در {dt:6.2f}s → {mb/dt:8.1f} MB/s")

    t0 = time.perf_counter()
    await asyncio.gather(*(conn(i) for i in range(CONNS)))
    wall = time.perf_counter() - t0
    total_mb = sum(m for _, m in results)
    print(f"\n   ───────────────────────────────────────")
    print(f"   مجموع: {total_mb:.1f} MB در {wall:.2f}s")
    print(f"   ⚡ توان عملیاتی کل: {total_mb/wall:.1f} MB/s")
    print(f"   (بیشترین اتصال: {max(m/dt for dt, m in results):.1f} MB/s)")

    echo.close()


if __name__ == "__main__":
    asyncio.run(main())
