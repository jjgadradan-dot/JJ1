# branding.py
# ══════════════════════════════════════════════════════════════════════════════
#  🎨 XR — شخصی‌سازی کامل صفحه ساب مشتری  (Sub Portal Custom Branding از Nyx)
#
#   • نام برند/فروشگاه و لوگوی اختصاصی
#   • دکمه‌های مستقیم پشتیبانی تلگرام و تمدید اشتراک
#   • کادر اعلان و پیام به مشتریان
#   • باکس دانلود ۱-کلیک نرم‌افزارهای کلاینت (اندروید/آیفون/ویندوز)
#
#  این ماژول از main.py چیزی ایمپورت نمی‌کند تا حلقهٔ ایمپورت ایجاد نشود.
# ══════════════════════════════════════════════════════════════════════════════

import html
import os

# ── نرم‌افزارهای کلاینت پیشنهادی (باکس دانلود ۱-کلیک) ─────────────────────────
DEFAULT_CLIENT_APPS = [
    {
        "id": "android",
        "name": "v2rayNG",
        "platform": "اندروید",
        "icon": "ti-brand-android",
        "color": "#3DDC84",
        "url": "https://github.com/2dust/v2rayNG/releases/latest",
    },
    {
        "id": "ios",
        "name": "Streisand",
        "platform": "آیفون / iOS",
        "icon": "ti-brand-apple",
        "color": "#A0A6B0",
        "url": "https://apps.apple.com/app/streisand/id6450534064",
    },
    {
        "id": "windows",
        "name": "v2rayN",
        "platform": "ویندوز",
        "icon": "ti-brand-windows",
        "color": "#00A4EF",
        "url": "https://github.com/2dust/v2rayN/releases/latest",
    },
    {
        "id": "hiddify",
        "name": "Hiddify",
        "platform": "همه‌ی سیستم‌عامل‌ها",
        "icon": "ti-shield-bolt",
        "color": "#7C5CFF",
        "url": "https://github.com/hiddify/hiddify-next/releases/latest",
    },
]

DEFAULT_BRANDING = {
    "enabled": True,
    "brand_name": os.environ.get("BRAND_NAME", "XR VPN").strip() or "XR VPN",
    "logo_url": os.environ.get("BRAND_LOGO_URL", "").strip(),
    "accent": os.environ.get("BRAND_ACCENT", "#3B7CF6").strip() or "#3B7CF6",
    "support_telegram": os.environ.get("BRAND_SUPPORT_TG", "").strip(),
    "renew_telegram": os.environ.get("BRAND_RENEW_TG", "").strip(),
    "notice": "",
    "footer": "",
    "show_apps": True,
    "apps": [],  # خالی = استفاده از لیست پیش‌فرض بالا
}

_HEX = set("0123456789abcdefABCDEF")


def _clean_color(raw: str, fallback: str = "#3B7CF6") -> str:
    c = str(raw or "").strip()
    if len(c) == 7 and c[0] == "#" and all(ch in _HEX for ch in c[1:]):
        return c
    if len(c) == 4 and c[0] == "#" and all(ch in _HEX for ch in c[1:]):
        return c
    return fallback


def _clean_url(raw: str) -> str:
    """فقط http/https پذیرفته می‌شود تا جلوی تزریق javascript: گرفته شود."""
    u = str(raw or "").strip()
    if not u:
        return ""
    low = u.lower()
    if low.startswith("http://") or low.startswith("https://"):
        return u[:500]
    return ""


def _clean_telegram(raw: str) -> str:
    """آیدی تلگرام را به لینک کامل https://t.me/... تبدیل می‌کند."""
    v = str(raw or "").strip()
    if not v:
        return ""
    low = v.lower()
    if low.startswith("http://") or low.startswith("https://"):
        return v[:300]
    return "https://t.me/" + v.lstrip("@")[:100]


def normalize_branding(raw: dict | None) -> dict:
    """تنظیمات برندینگ را تمیز، امن و کامل می‌کند."""
    raw = raw if isinstance(raw, dict) else {}
    out = dict(DEFAULT_BRANDING)
    out["enabled"] = bool(raw.get("enabled", True))
    out["brand_name"] = (str(raw.get("brand_name") or DEFAULT_BRANDING["brand_name"]).strip()[:60]
                         or DEFAULT_BRANDING["brand_name"])
    out["logo_url"] = _clean_url(raw.get("logo_url"))
    out["accent"] = _clean_color(raw.get("accent"), DEFAULT_BRANDING["accent"])
    out["support_telegram"] = _clean_telegram(raw.get("support_telegram"))
    out["renew_telegram"] = _clean_telegram(raw.get("renew_telegram"))
    out["notice"] = str(raw.get("notice") or "").strip()[:500]
    out["footer"] = str(raw.get("footer") or "").strip()[:200]
    out["show_apps"] = bool(raw.get("show_apps", True))

    apps = raw.get("apps")
    clean_apps = []
    if isinstance(apps, list):
        for a in apps[:8]:
            if not isinstance(a, dict):
                continue
            url = _clean_url(a.get("url"))
            name = str(a.get("name") or "").strip()[:40]
            if not url or not name:
                continue
            clean_apps.append({
                "id": str(a.get("id") or name).strip()[:20],
                "name": name,
                "platform": str(a.get("platform") or "").strip()[:40],
                "icon": str(a.get("icon") or "ti-download").strip()[:40],
                "color": _clean_color(a.get("color"), "#3B7CF6"),
                "url": url,
            })
    out["apps"] = clean_apps
    return out


def effective_apps(branding: dict) -> list:
    """اپ‌های نمایش‌داده‌شده: لیست سفارشی ادمین یا لیست پیش‌فرض."""
    b = normalize_branding(branding)
    return b["apps"] if b["apps"] else DEFAULT_CLIENT_APPS


# ══════════════════════════════════════════════════════════════════════════════
# صفحه اشتراک مشتری  —  /subinfo/{uuid}
# ══════════════════════════════════════════════════════════════════════════════

def get_subinfo_html(uuid: str, branding: dict) -> str:
    """صفحه شخصی‌سازی‌شدهٔ مشتری برای یک کانفیگ.

    داده‌ها با فراخوانی /api/subinfo/{uuid} به‌صورت زنده بارگذاری می‌شوند.
    """
    b = normalize_branding(branding)
    e = html.escape
    accent = b["accent"]
    brand = e(b["brand_name"])

    logo = (
        f'<img src="{e(b["logo_url"])}" alt="{brand}" class="logo-img">'
        if b["logo_url"] else
        f'<div class="logo-txt">{brand[:2]}</div>'
    )

    notice = (
        f'<div class="notice"><i class="ti ti-speakerphone"></i><div>{e(b["notice"])}</div></div>'
        if b["notice"] else ""
    )

    btns = []
    if b["support_telegram"]:
        btns.append(
            f'<a class="cta" href="{e(b["support_telegram"])}" target="_blank" rel="noopener">'
            f'<i class="ti ti-headset"></i> پشتیبانی</a>'
        )
    if b["renew_telegram"]:
        btns.append(
            f'<a class="cta renew" href="{e(b["renew_telegram"])}" target="_blank" rel="noopener">'
            f'<i class="ti ti-rocket"></i> تمدید اشتراک</a>'
        )
    cta_row = f'<div class="cta-row">{"".join(btns)}</div>' if btns else ""

    apps_html = ""
    if b["show_apps"]:
        cards = "".join(
            f'<a class="app" href="{e(a["url"])}" target="_blank" rel="noopener" '
            f'style="--ac:{e(a["color"])}">'
            f'<i class="ti {e(a["icon"])}"></i>'
            f'<div><b>{e(a["name"])}</b><small>{e(a["platform"])}</small></div>'
            f'<i class="ti ti-download dl"></i></a>'
            for a in effective_apps(b)
        )
        apps_html = (
            '<div class="sec-title"><i class="ti ti-device-mobile"></i> دانلود نرم‌افزار</div>'
            f'<div class="apps">{cards}</div>'
        )

    footer = f'<div class="footer">{e(b["footer"])}</div>' if b["footer"] else ""

    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<title>{brand} — اشتراک من</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.19.0/dist/tabler-icons.min.css">
<style>
*{{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}}
:root{{--ac:{accent};--bg:#060a14;--card:#0c1326;--cb:rgba(255,255,255,.09);
--t1:#EFF4FF;--t2:#8AA0C4;--t3:#48577A;--ok:#22c55e;--warn:#fbbf24;--err:#f87171}}
body{{background:var(--bg);color:var(--t1);font-family:'Vazirmatn',sans-serif;
min-height:100vh;padding:16px;display:flex;justify-content:center;
background-image:radial-gradient(circle at 15% 0%,color-mix(in srgb,var(--ac) 22%,transparent),transparent 45%),
radial-gradient(circle at 85% 100%,rgba(157,123,240,.14),transparent 45%)}}
.wrap{{width:100%;max-width:540px}}
/* ── سربرگ برند ── */
.head{{display:flex;align-items:center;gap:13px;margin-bottom:18px;padding:16px 18px;
background:var(--card);border:1px solid var(--cb);border-radius:20px}}
.logo-img{{width:48px;height:48px;border-radius:14px;object-fit:cover;flex-shrink:0}}
.logo-txt{{width:48px;height:48px;border-radius:14px;flex-shrink:0;display:flex;
align-items:center;justify-content:center;font-weight:900;font-size:18px;color:#fff;
background:linear-gradient(135deg,var(--ac),color-mix(in srgb,var(--ac) 45%,#9D7BF0))}}
.head h1{{font-size:17px;font-weight:800;letter-spacing:-.01em}}
.head p{{font-size:11px;color:var(--t3);margin-top:2px}}
/* ── اعلان ── */
.notice{{display:flex;gap:9px;background:color-mix(in srgb,var(--warn) 12%,transparent);
border:1px solid color-mix(in srgb,var(--warn) 35%,transparent);border-radius:16px;
padding:13px 15px;font-size:12px;line-height:1.85;color:#fde68a;margin-bottom:16px}}
.notice i{{font-size:17px;flex-shrink:0;margin-top:1px}}
/* ── کارت‌ها ── */
.card{{background:var(--card);border:1px solid var(--cb);border-radius:20px;
padding:18px;margin-bottom:16px}}
.sec-title{{font-size:12px;font-weight:800;color:var(--t2);margin:20px 4px 10px;
display:flex;align-items:center;gap:7px}}
.sec-title i{{color:var(--ac);font-size:16px}}
/* ── حجم ── */
.qbar{{height:9px;border-radius:20px;background:rgba(255,255,255,.07);overflow:hidden;margin:11px 0 8px}}
.qbar span{{display:block;height:100%;border-radius:20px;transition:width .6s ease;
background:linear-gradient(90deg,var(--ac),color-mix(in srgb,var(--ac) 40%,#22c55e))}}
.qbar span.hi{{background:linear-gradient(90deg,#fbbf24,#f87171)}}
.qrow{{display:flex;justify-content:space-between;font-size:11.5px;color:var(--t2)}}
.qrow b{{color:var(--t1);font-weight:700}}
.stats{{display:grid;grid-template-columns:repeat(3,1fr);gap:9px;margin-top:14px}}
.stat{{background:rgba(0,0,0,.24);border:1px solid var(--cb);border-radius:13px;padding:11px}}
.stat small{{display:block;font-size:9px;color:var(--t3);font-weight:700;margin-bottom:4px}}
.stat b{{font-size:13px;font-weight:800}}
.pill{{display:inline-flex;align-items:center;gap:4px;font-size:10px;font-weight:800;
padding:4px 11px;border-radius:20px}}
.pill.on{{background:rgba(34,197,94,.16);color:var(--ok)}}
.pill.off{{background:rgba(248,113,113,.16);color:var(--err)}}
/* ── لینک ── */
.linkbox{{background:rgba(0,0,0,.3);border:1px solid var(--cb);border-radius:13px;
padding:12px;font-family:ui-monospace,monospace;font-size:10px;direction:ltr;
word-break:break-all;color:var(--t2);max-height:96px;overflow:auto;line-height:1.65}}
.linkbox.blur{{filter:blur(5px);user-select:none}}
.btn{{width:100%;border:none;border-radius:13px;padding:13px;font-family:inherit;
font-size:12.5px;font-weight:800;cursor:pointer;color:#fff;margin-top:10px;
display:flex;align-items:center;justify-content:center;gap:7px;
background:linear-gradient(135deg,var(--ac),color-mix(in srgb,var(--ac) 55%,#9D7BF0))}}
.btn:active{{transform:scale(.985)}}
.btn.ghost{{background:rgba(255,255,255,.06);border:1px solid var(--cb);color:var(--t1)}}
.qr{{background:#fff;border-radius:16px;padding:13px;margin-top:12px;display:none;text-align:center}}
.qr img{{width:100%;max-width:230px;border-radius:8px}}
/* ── دکمه‌های پشتیبانی ── */
.cta-row{{display:flex;gap:9px;margin-bottom:16px}}
.cta{{flex:1;display:flex;align-items:center;justify-content:center;gap:7px;
padding:14px 10px;border-radius:16px;text-decoration:none;font-size:12.5px;font-weight:800;
color:#fff;background:linear-gradient(135deg,#229ED9,#1c7fb0)}}
.cta.renew{{background:linear-gradient(135deg,var(--ac),color-mix(in srgb,var(--ac) 45%,#22c55e))}}
.cta:active{{transform:scale(.985)}}
/* ── اپ‌ها ── */
.apps{{display:grid;gap:9px}}
.app{{display:flex;align-items:center;gap:12px;background:var(--card);
border:1px solid var(--cb);border-radius:16px;padding:13px 15px;text-decoration:none;color:var(--t1)}}
.app:active{{transform:scale(.99)}}
.app>i:first-child{{font-size:23px;color:var(--ac);width:26px;text-align:center}}
.app div{{flex:1;min-width:0}}
.app b{{display:block;font-size:13px;font-weight:800}}
.app small{{font-size:10px;color:var(--t3)}}
.app .dl{{font-size:16px;color:var(--t3)}}
.footer{{text-align:center;font-size:10.5px;color:var(--t3);padding:18px 0 8px;line-height:1.9}}
.msg{{text-align:center;padding:44px 20px;color:var(--t3);font-size:13px}}
.toast{{position:fixed;bottom:22px;left:50%;transform:translateX(-50%) translateY(90px);
background:var(--ok);color:#04140b;padding:11px 22px;border-radius:14px;font-weight:800;
font-size:12.5px;transition:.3s;z-index:99}}
.toast.on{{transform:translateX(-50%) translateY(0)}}
</style>
</head>
<body>
<div class="wrap">
  <div class="head">
    {logo}
    <div>
      <h1>{brand}</h1>
      <p>پنل اشتراک شما</p>
    </div>
  </div>
  {notice}
  {cta_row}
  <div id="app"><div class="msg"><i class="ti ti-loader-2"></i> در حال بارگذاری اطلاعات اشتراک...</div></div>
  {apps_html}
  {footer}
</div>
<div class="toast" id="toast">کپی شد ✓</div>
<script>
const UUID={uuid!r};
let SHOWN=false, DATA=null;
const fa=n=>String(n).replace(/[0-9]/g,d=>'۰۱۲۳۴۵۶۷۸۹'[d]);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}})[c]);
function toast(t){{const el=document.getElementById('toast');el.textContent=t;el.classList.add('on');
  setTimeout(()=>el.classList.remove('on'),1900)}}
async function copyTxt(t){{
  try{{await navigator.clipboard.writeText(t)}}
  catch(e){{const a=document.createElement('textarea');a.value=t;document.body.appendChild(a);
    a.select();document.execCommand('copy');a.remove()}}
  toast('کپی شد ✓');
}}
function toggleLink(){{
  SHOWN=!SHOWN;
  document.getElementById('lb').classList.toggle('blur',!SHOWN);
  document.getElementById('eye').className='ti '+(SHOWN?'ti-eye-off':'ti-eye');
  document.getElementById('eyet').textContent=SHOWN?'مخفی کردن':'نمایش کانفیگ';
}}
function toggleQr(){{
  const q=document.getElementById('qr');
  const on=q.style.display==='block';
  q.style.display=on?'none':'block';
  if(!on&&!q.dataset.l){{
    q.innerHTML='<img src="https://api.qrserver.com/v1/create-qr-code/?size=460x460&data='
      +encodeURIComponent(DATA.vless_link)+'" alt="QR">';
    q.dataset.l='1';
  }}
}}
function render(d){{
  DATA=d;
  const pct=d.limit_bytes>0?Math.min(100,Math.round(d.used_bytes/d.limit_bytes*100)):0;
  document.getElementById('app').innerHTML=
   '<div class="card">'
   +'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">'
   +'<b style="font-size:14px">'+esc(d.label)+'</b>'
   +'<span class="pill '+(d.active?'on':'off')+'">'+(d.active?'فعال ✅':'غیرفعال ⛔')+'</span></div>'
   +'<div class="qbar"><span class="'+(pct>85?'hi':'')+'" style="width:'+(d.limit_bytes>0?pct:100)+'%"></span></div>'
   +'<div class="qrow"><span>مصرف: <b>'+fa(d.used_fmt)+'</b></span>'
   +'<span>'+(d.limit_bytes>0?'از <b>'+fa(d.limit_fmt)+'</b> ('+fa(pct)+'٪)':'<b>نامحدود ∞</b>')+'</span></div>'
   +'<div class="stats">'
   +'<div class="stat"><small>انقضا</small><b>'+fa(d.expires_fa||'∞')+'</b></div>'
   +'<div class="stat"><small>لوکیشن</small><b>'+esc(d.location||'—')+'</b></div>'
   +'<div class="stat"><small>اتصال فعال</small><b>'+fa(d.connections||0)+'</b></div>'
   +'</div></div>'
   +'<div class="sec-title"><i class="ti ti-link"></i> کانفیگ اتصال</div>'
   +'<div class="card">'
   +'<div class="linkbox blur" id="lb">'+esc(d.vless_link)+'</div>'
   +'<button class="btn" onclick="copyTxt(DATA.vless_link)"><i class="ti ti-copy"></i> کپی کانفیگ</button>'
   +'<button class="btn ghost" onclick="copyTxt(DATA.sub_url)"><i class="ti ti-cloud-download"></i> کپی لینک سابسکریپشن</button>'
   +'<button class="btn ghost" onclick="toggleLink()"><i class="ti ti-eye" id="eye"></i> <span id="eyet">نمایش کانفیگ</span></button>'
   +'<button class="btn ghost" onclick="toggleQr()"><i class="ti ti-qrcode"></i> کد QR</button>'
   +'<div class="qr" id="qr"></div>'
   +'</div>';
}}
async function load(){{
  try{{
    const r=await fetch('/api/subinfo/'+UUID);
    if(!r.ok){{
      document.getElementById('app').innerHTML=
        '<div class="msg"><i class="ti ti-alert-triangle" style="font-size:34px;display:block;margin-bottom:12px"></i>'
        +'اشتراک پیدا نشد یا غیرفعال است.<br>لطفاً با پشتیبانی تماس بگیرید.</div>';
      return;
    }}
    render(await r.json());
  }}catch(e){{
    document.getElementById('app').innerHTML='<div class="msg">خطا در ارتباط با سرور</div>';
  }}
}}
load();
setInterval(load,30000);
</script>
</body>
</html>"""
