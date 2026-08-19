# bench/bench_ws_echo.py — سقف کلاینت + لایه WS (بدون رله)
# یک سرور echo ساده با کتابخانه websockets و همان الگوی کلاینت bench_e2e
import asyncio
import os
import sys
import time

import websockets

CHUNK = 128 * 1024
INFLIGHT = 8
CONNS = 4
MB = 16


async def echo_server(ws):
    async for msg in ws:
        await ws.send(msg)


async def main():
    port = 8933
    server = await websockets.serve(echo_server, "127.0.0.1", port)
    payload = os.urandom(CHUNK)
    target = MB * 1024 * 1024

    async def conn(i):
        sent = recved = 0
        inflight = 0
        t0 = time.perf_counter()
        async with websockets.connect(f"ws://127.0.0.1:{port}", max_size=32 * 1024 * 1024) as ws:
            while recved < target:
                while inflight < INFLIGHT and sent < target:
                    await ws.send(payload)
                    sent += CHUNK
                    inflight += 1
                msg = await asyncio.wait_for(ws.recv(), timeout=60)
                recved += len(msg)
                inflight -= 1
        dt = time.perf_counter() - t0
        mb = (sent + recved) / 1e6
        print(f"   اتصال {i+1}: {mb:7.1f} MB در {dt:6.2f}s → {mb/dt:8.1f} MB/s")
        return dt, mb

    t0 = time.perf_counter()
    results = await asyncio.gather(*(conn(i) for i in range(CONNS)))
    wall = time.perf_counter() - t0
    total = sum(m for _, m in results)
    print(f"   مجموع: {total:.1f} MB در {wall:.2f}s → {total/wall:.1f} MB/s (سقف WS خالص)")
    server.close()


if __name__ == "__main__":
    asyncio.run(main())
