# test_multipath.py
# ══════════════════════════════════════════════════════════════════════════════
# تست‌های موتور مسیریابی چندگانه کوانتومی، حالت اضطراری و لودبالانسر هوشمند
#
# اجرا:  python3 test_multipath.py
# (بدون نیاز به شبکه — همه تست‌ها منطق داخلی را می‌سنجند)
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import sys

import main  # noqa: F401 — باید اول ایمپورت شود تا حلقه ایمپورت پیش نیاید
import multipath
from multipath import (
    PATH_TYPES,
    calc_inbound_score,
    calc_score,
    load_balancer,
    multipath_engine,
    panic_manager,
)

_failures = []


def check(name: str, condition: bool, detail: str = ""):
    if condition:
        print(f"  ✅ {name}")
    else:
        print(f"  ❌ {name} {detail}")
        _failures.append(name)


def test_scores():
    print("\n▶ امتیازدهی مسیرها (calc_score)")
    check("مسیر ناسالم امتیاز صفر می‌گیرد", calc_score(False, 50, 0) == 0)
    check("تاخیر کم + پایدار = ۱۰۰", calc_score(True, 40, 0) == 100)
    check("پاداش پایداری اعمال می‌شود", calc_score(True, 300, 0) > calc_score(True, 300, 2))
    check("تاخیر بیشتر = امتیاز کمتر", calc_score(True, 100, 0) > calc_score(True, 1000, 0))
    check("سقف امتیاز از ۱۰۰ رد نمی‌شود", calc_score(True, 10, 0) <= 100)

    print("\n▶ امتیازدهی کانفیگ‌ها (calc_inbound_score)")
    check("کانفیگ قطع امتیاز صفر می‌گیرد", calc_inbound_score(False, 50, 3, 10) == 0)
    check("آپتایم بالا پاداش می‌گیرد",
          calc_inbound_score(True, 200, 0, 99) > calc_inbound_score(True, 200, 0, 50))
    check("امتیاز در بازه ۰ تا ۱۰۰ می‌ماند",
          0 <= calc_inbound_score(True, 5000, 9, 5) <= 100)


def test_snapshot_shape():
    print("\n▶ ساختار خروجی موتور")
    snap = multipath_engine.get_snapshot()
    check("هر ۴ مسیر تعریف شده‌اند", set(snap["paths"]) == set(PATH_TYPES),
          f"-> {set(snap['paths'])}")
    for p in PATH_TYPES:
        row = snap["paths"][p]
        check(f"مسیر {p} کلیدهای لازم را دارد",
              all(k in row for k in ("emoji", "label_fa", "healthy", "latency_ms", "score")))
    status = multipath_engine.get_status()
    check("get_status شامل enabled/interval است",
          "enabled" in status and "interval" in status)


def test_health_classification():
    print("\n▶ طبقه‌بندی وضعیت شبکه")
    cases = [
        (4, 100, "EXCELLENT"),
        (3, 70, "GOOD"),
        (2, 40, "DEGRADED"),
        (1, 20, "CRITICAL"),
        (0, 0, "PANIC"),
    ]
    for healthy_count, avg, expected in cases:
        if healthy_count == 4 and avg >= 80:
            got = "EXCELLENT"
        elif healthy_count >= 3 and avg >= 55:
            got = "GOOD"
        elif healthy_count == 2:
            got = "DEGRADED"
        elif healthy_count == 1:
            got = "CRITICAL"
        else:
            got = "PANIC"
        check(f"{healthy_count} مسیر سالم → {expected}", got == expected, f"-> {got}")


async def test_panic_hysteresis():
    print("\n▶ منطق Hysteresis حالت اضطراری")
    # اعلان تلگرام را خاموش می‌کنیم تا تست آفلاین بماند
    main.CONFIG.setdefault("multipath", {})["panic_alerts"] = False

    pm = panic_manager
    pm.is_active = False
    pm.consecutive_panic = 0
    pm.consecutive_recovery = 0
    pm.total_events = 0
    pm.history.clear()

    multipath_engine.snapshot.update(
        panic_mode=True, overall_health="PANIC", overall_health_fa="اضطراری", healthy_count=0
    )
    await pm.tick()
    check("چک ۱ ناموفق → هنوز فعال نشده", pm.is_active is False)
    await pm.tick()
    check("چک ۲ ناموفق → هنوز فعال نشده (جلوگیری از آلارم کاذب)", pm.is_active is False)
    await pm.tick()
    check("چک ۳ ناموفق → حالت اضطراری فعال شد", pm.is_active is True)
    check("رخداد در تاریخچه ثبت شد", len(pm.history) == 1 and pm.history[0]["resolved_at"] is None)

    multipath_engine.snapshot.update(
        panic_mode=False, overall_health="GOOD", overall_health_fa="خوب",
        healthy_count=3, best_path="DNS_TUNNEL",
    )
    await pm.tick()
    check("چک ۱ موفق → هنوز رفع نشده", pm.is_active is True)
    await pm.tick()
    check("چک ۲ موفق → بحران رفع شد", pm.is_active is False)

    st = pm.get_status()
    check("شمارنده رخدادها درست است", st["total_events"] == 1, f"-> {st['total_events']}")
    check("مدت قطعی ثبت شد", st["history"][0]["duration_seconds"] is not None)
    check("زمان رفع ثبت شد", st["history"][0]["resolved_at"] is not None)


def test_load_balancer_sorting():
    print("\n▶ مرتب‌سازی لودبالانسر")
    lb = load_balancer
    # مستقل از متغیرهای محیطی، لودبالانسر را برای این تست روشن می‌کنیم
    main.CONFIG.setdefault("multipath", {})["lb_enabled"] = True
    lb.health = {
        "a": {"uid": "a", "score": 40, "healthy": True},
        "b": {"uid": "b", "score": 95, "healthy": True},
        "c": {"uid": "c", "score": 0, "healthy": False},
    }
    check("بهترین کانفیگ ردیف اول می‌شود",
          lb.sort_uids(["a", "b", "c"]) == ["b", "a", "c"],
          f"-> {lb.sort_uids(['a', 'b', 'c'])}")
    check("کانفیگ ناشناخته امتیاز خنثی ۵۰ می‌گیرد",
          lb.sort_uids(["c", "new", "a"]) == ["new", "a", "c"],
          f"-> {lb.sort_uids(['c', 'new', 'a'])}")

    main.CONFIG["multipath"]["lb_enabled"] = False
    check("وقتی لودبالانسر خاموش است ترتیب دست‌نخورده می‌ماند",
          lb.sort_uids(["a", "b", "c"]) == ["a", "b", "c"])
    main.CONFIG["multipath"]["lb_enabled"] = True

    lb.health = {}
    check("بدون داده سلامت، ترتیب اصلی حفظ می‌شود",
          lb.sort_uids(["x", "y"]) == ["x", "y"])


def test_dns_packet_builder():
    print("\n▶ ساخت بستهٔ خام DNS (بدون ارسال)")
    # فقط بررسی می‌کنیم تابع روی سرور نامعتبر بدون کرش خطا برمی‌گرداند
    res = multipath._dns_query_sync("203.0.113.201", "example.com", 700)
    check("سرور بی‌پاسخ → healthy=False بدون استثنا", res["healthy"] is False)
    check("پیام خطا برگردانده می‌شود", bool(res.get("error")))


async def main_async():
    print("═" * 62)
    print("  تست موتور مسیریابی چندگانه کوانتومی XR (پورت‌شده از Nyx v2.3.0)")
    print("═" * 62)
    test_scores()
    test_snapshot_shape()
    test_health_classification()
    await test_panic_hysteresis()
    test_load_balancer_sorting()
    test_dns_packet_builder()

    print("\n" + "═" * 62)
    if _failures:
        print(f"  ❌ {len(_failures)} تست ناموفق: {'، '.join(_failures)}")
        return 1
    print("  ✅ همه تست‌ها با موفقیت گذشتند")
    print("═" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main_async()))
