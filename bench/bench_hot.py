# bench_hot.py
# ══════════════════════════════════════════════════════════════════════════════
#  میکروبنچمارک «مسیر داغ» حسابداری ترافیک رله (قبل / بعد از بهینه‌سازی)
#
#  استفاده:
#    .venv/bin/python bench/bench_hot.py
#
#  نسخهٔ «قدیمی» کپی دقیق بدنهٔ check_and_use فعلی relay_vless.py است و
#  نسخهٔ «جدید» از relay_vless ایمپورت می‌شود — هر دو در یک پروسه و با
#  همان داده اجرا می‌شوند تا مقایسه منصفانه باشد.
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import inspect
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main  # noqa: F401
from main import LINKS, LINKS_LOCK, hourly_traffic, is_link_allowed, now_ir, stats

NCONN = 200            # اتصال هم‌زمان
NCHUNK = 4000          # چانک برای هر اتصال
CHUNK = 16 * 1024      # 16 KB

# ── نسخهٔ قدیمی: کپی ۱:۱ بدنهٔ فعلی check_and_use ─────────────────────────────
async def old_check_and_use(uid: str, n: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            return False
        if not is_link_allowed(link):
            return False
        link["used_bytes"] += n
        stats["total_bytes"] += n
        hourly_traffic[now_ir().strftime("%H:00")] += n
    return True


# ── نوع دوم: مثل قدیم ولی بدون strftime (فقط برای جداسازی سهم هر هزینه) ──────
_fixed_hour = "12:00"
async def old_no_strftime(uid: str, n: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            return False
        if not is_link_allowed(link):
            return False
        link["used_bytes"] += n
        stats["total_bytes"] += n
        hourly_traffic[_fixed_hour] += n
    return True


async def bench(label: str, fn, uids):
    async def worker(uid):
        for _ in range(NCHUNK):
            r = fn(uid, CHUNK)
            if inspect.isawaitable(r):
                r = await r
            if not r:
                raise RuntimeError("quota rejected")
    t0 = time.perf_counter()
    await asyncio.gather(*(worker(u) for u in uids))
    dt = time.perf_counter() - t0
    total = NCONN * NCHUNK * CHUNK
    print(f"  {label:<34} {dt:7.3f}s   {total/dt/1e6:8.1f} MB/s   "
          f"{NCONN*NCHUNK/dt:12,.0f} chunk/s")


async def main_bench():
    # آماده‌سازی لینک‌ها (بدون سهمیه و انقضا)
    uids = [f"u{i:03d}" for i in range(NCONN)]
    for u in uids:
        LINKS[u] = {"active": True, "used_bytes": 0, "limit_bytes": 0,
                    "expires_at": None, "speed_limit_bytes": 0}

    print(f"⚡ میکروبنچمارک مسیر داغ — {NCONN} اتصال × {NCHUNK} چانک {CHUNK//1024}KB")
    print(f"  ({NCONN*NCHUNK*CHUNK/1e6:.0f} MB دادهٔ کل)")

    await bench("قدیمی (قفل + strftime + ISO-parse)", old_check_and_use, uids)
    await bench("قدیمی بدون strftime", old_no_strftime, uids)

    # ── نسخهٔ جدید از relay_vless (بعد از بهینه‌سازی) ───────────────────────
    try:
        from relay_vless import add_usage, check_and_use, ensure_flush_loop, flush_usage
        if hasattr(ensure_flush_loop, "__call__"):
            try:
                ensure_flush_loop()
            except Exception:
                pass
        def new_check(uid, n):
            ok = check_and_use(uid, n)
            return ok
        await bench("جدید (بدون قفل، batch، کش ساعت)", new_check, uids)
        flush_usage()
        print("\n  ✓ شمارنده‌ها بعد از اجرا:")
        print(f"    stats.total_bytes = {stats['total_bytes']:,}")
        print(f"    مجموع used_bytes  = {sum(LINKS[u]['used_bytes'] for u in uids):,}")
    except Exception as e:
        print(f"\n  (نسخهٔ جدید هنوز قابل ایمپورت نیست: {e})")


if __name__ == "__main__":
    asyncio.run(main_bench())
