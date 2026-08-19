# ══════════════════════════════════════════════════════════════════════════════
# دستور اجرای پرووداکشن (Railway / Heroku و هر PaaS سازگار با Procfile)
# موتور حداکثر سرعت:
#   --loop uvloop        حلقهٔ رویداد C-محور
#   --http httptools     پارسر HTTP فوق‌سریع
#   --ws websockets      پیاده‌سازی WebSocket سریع
#   --no-access-log      حذف سربار لاگ هر درخواست (برای XHTTP هر چانک = یک درخواست)
#   --ws-max-size 64MB   پذیرش فریم‌های باینری بسیار بزرگ
#   --backlog 8192       جذب بهتر انفجار اتصال‌های هم‌زمان
# ══════════════════════════════════════════════════════════════════════════════
web: uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --loop uvloop --http httptools --ws websockets --no-access-log --ws-max-size 67108864 --backlog 8192
