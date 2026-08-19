import asyncio
import json
import os
import hashlib
import secrets
import time
import aiofiles
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from urllib.parse import quote
from collections import deque, defaultdict
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging

from panel_nodes import MasterClient, NodeError, PanelNodeClient, extract_bearer_token, normalize_base_url

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
# نام برند/پنل و پیشوند ثابت اسم کانفیگ‌ها — برای تغییر نام، فقط همین مقدار را عوض کنید
BRAND = "RVG"
VERSION = "9.7"

logger = logging.getLogger(BRAND)

IRAN_TZ = ZoneInfo("Asia/Tehran")

app = FastAPI(title=BRAND, docs_url=None, redoc_url=None)

# ── Persistence ───────────────────────────────────────────────────────────────
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DATA_FILE = DATA_DIR / "x4g_state.json"
SECRET_FILE = DATA_DIR / "x4g_secret.key"
SAVE_LOCK = asyncio.Lock()

def _load_or_create_secret() -> str:
    """SECRET_KEY را روی دیسک ذخیره و ثابت نگه می‌دارد.
    قبلاً وقتی متغیر محیطی SECRET_KEY تنظیم نشده بود، با هر ری‌استارت سرویس
    (که روی Railway هر چند ساعت یک‌بار اتفاق می‌افتد) یک مقدار تصادفی جدید
    ساخته می‌شد. چون هش پسورد بر پایه‌ی همین secret ساخته می‌شود، تغییر آن
    باعث می‌شد پسورد درست هم دیگر قبول نشود. حالا secret یک‌بار ساخته و در
    فایل ذخیره می‌شود و در ری‌استارت‌های بعدی همان مقدار خوانده می‌شود."""
    env_secret = os.environ.get("SECRET_KEY")
    if env_secret:
        return env_secret
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if SECRET_FILE.exists():
            existing = SECRET_FILE.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        new_secret = secrets.token_urlsafe(32)
        SECRET_FILE.write_text(new_secret, encoding="utf-8")
        return new_secret
    except Exception as e:
        logger.warning(f"Could not persist SECRET_KEY, sessions/password may reset on restart: {e}")
        return secrets.token_urlsafe(32)

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": _load_or_create_secret(),
    "host": os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost"),
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def load_state():
    global LINKS, AUTH, SUBS, NODES, NODE_API, MASTER
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if DATA_FILE.exists():
            async with aiofiles.open(DATA_FILE, "r", encoding="utf-8") as f:
                raw = await f.read()
            data = json.loads(raw)
            LINKS.update(data.get("links", {}))
            SUBS.update(data.get("subs", {}))
            NODES.update(data.get("nodes", {}))
            if data.get("node_api"):
                NODE_API.update(data["node_api"])
            if data.get("master"):
                MASTER.update(data["master"])
            if "password_hash" in data:
                AUTH["password_hash"] = data["password_hash"]
            logger.info(f"State loaded: {len(LINKS)} links, {len(SUBS)} subs")
    except Exception as e:
        logger.warning(f"Could not load state: {e}")

async def save_state():
    async with SAVE_LOCK:
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            data = {
                "links": dict(LINKS),
                "subs": dict(SUBS),
                "nodes": dict(NODES),
                "node_api": dict(NODE_API),
                "master": dict(MASTER),
                "password_hash": AUTH["password_hash"],
                "saved_at": datetime.now().isoformat(),
            }
            tmp = DATA_FILE.with_suffix(".tmp")
            async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
                await f.write(json.dumps(data, ensure_ascii=False, indent=2))
            tmp.replace(DATA_FILE)
        except Exception as e:
            logger.warning(f"Could not save state: {e}")

# ── In-memory state ───────────────────────────────────────────────────────────
connections: dict = {}
stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}
error_logs: deque = deque(maxlen=50)
activity_logs: deque = deque(maxlen=200)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None
LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()
SUBS: dict = {}
SUBS_LOCK = asyncio.Lock()
NODES: dict = {}
NODES_LOCK = asyncio.Lock()
NODE_API: dict = {}
NODE_API_LOCK = asyncio.Lock()
MASTER: dict = {}
MASTER_LOCK = asyncio.Lock()
_heartbeat_task: asyncio.Task | None = None

# پروتکل‌های پشتیبانی‌شده برای هر کانفیگ
PROTOCOLS = ("vless-ws", "xhttp-packet-up", "xhttp-stream-up", "xhttp-stream-one")
DEFAULT_PROTOCOL = "vless-ws"

# Fingerprint (uTLS) های قابل انتخاب برای هر کانفیگ
FINGERPRINTS = ("chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized")
DEFAULT_FINGERPRINT = "chrome"

# پیش‌فرض ALPN بر اساس نوع ترابرد (اگر کاربر مقدار دستی نده)
DEFAULT_ALPN_BY_PROTOCOL = {
    "vless-ws": "http/1.1",
    "xhttp-packet-up": "h2,http/1.1",
    "xhttp-stream-up": "h2,http/1.1",
    "xhttp-stream-one": "h2,http/1.1",
}
DEFAULT_PORT = 443
MIN_PORT, MAX_PORT = 1, 65535

# محدودیت سرعت (0 = نامحدود). واحد ذخیره‌سازی داخلی همیشه بایت‌بر‌ثانیه است.
DEFAULT_SPEED_LIMIT = 0

def log_activity(kind: str, message: str, level: str = "info"):
    """ثبت یک رخداد در لاگ فعالیت‌ها (ساخت/حذف/ویرایش کانفیگ، ورود، و...)."""
    activity_logs.append({
        "kind": kind,
        "level": level,
        "message": message,
        "time": datetime.now().isoformat(),
    })

# ── Auth ──────────────────────────────────────────────────────────────────────
SESSION_COOKIE = "x4g_session"
SESSION_TTL = 60 * 60 * 24 * 365

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {"password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "X4GKING"))}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None:
            return False
        if exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token: str | None):
    if not token:
        return
    async with SESSIONS_LOCK:
        SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token


async def require_auth_or_node(request: Request):
    """Dashboard session or this node's API token — used so a peer RVG can register us."""
    token = request.cookies.get(SESSION_COOKIE)
    if await is_valid_session(token):
        return token
    api_token = current_node_api_token()
    supplied = extract_bearer_token(
        request.headers.get("authorization", ""),
        request.headers.get("x-api-token") or request.headers.get("x-node-token") or "",
    )
    if api_token and supplied and secrets.compare_digest(supplied, api_token):
        return supplied
    raise HTTPException(status_code=401, detail="unauthorized")

def env_node_api_token() -> str:
    return os.environ.get("NODE_API_TOKEN", "").strip()


def current_node_api_token() -> str:
    """Env token wins so Railway/ops can pin it; otherwise the persisted one."""
    return env_node_api_token() or str(NODE_API.get("token") or "")


def new_node_api_token() -> str:
    return secrets.token_urlsafe(32)


async def ensure_node_api_token() -> str:
    token = current_node_api_token()
    if token:
        return token
    async with NODE_API_LOCK:
        token = current_node_api_token()
        if token:
            return token
        token = new_node_api_token()
        NODE_API["token"] = token
        NODE_API["created_at"] = datetime.now().isoformat()
        NODE_API["source"] = "generated"
    await save_state()
    log_activity("api", "توکن API نود ساخته شد", "ok")
    return token


def public_node_api(request: Request | None = None, reveal: bool = False) -> dict:
    token = current_node_api_token()
    host = get_host(request)
    scheme = "https" if host not in {"localhost", "127.0.0.1"} else "http"
    base = f"{scheme}://{host}/api/node/v1"
    return {
        "role": "node",
        "version": VERSION,
        "enabled": bool(token),
        "token_from_env": bool(env_node_api_token()),
        "has_token": bool(token),
        "token": token if reveal else None,
        "token_preview": (token[:4] + "…" + token[-4:]) if token and len(token) > 8 else ("••••" if token else ""),
        "created_at": NODE_API.get("created_at"),
        "base_url": f"{scheme}://{host}",
        "api_base": base,
        "endpoints": {
            "info": f"{base}/info",
            "health": f"{base}/health",
            "overview": f"{base}/overview",
            "stats": f"{base}/stats",
            "connections": f"{base}/connections",
            "configs": f"{base}/configs",
            "subscription": f"{base}/subscription",
            "subs": f"{base}/subs",
        },
    }


def public_master() -> dict:
    return {
        "connected": bool(MASTER.get("enabled") and MASTER.get("url")),
        "url": MASTER.get("url") or "",
        "name": MASTER.get("name") or "",
        "panel_type": MASTER.get("panel_type") or "rvg",
        "auth_type": MASTER.get("auth_type") or "credentials",
        "verify_ssl": bool(MASTER.get("verify_ssl", True)),
        "has_token": bool(MASTER.get("token")),
        "has_password": bool(MASTER.get("password")),
        "last_check": MASTER.get("last_check"),
        "last_ok": MASTER.get("last_ok"),
        "last_error": MASTER.get("last_error"),
        "registered": bool(MASTER.get("registered")),
    }


async def require_node_api(request: Request):
    """Authenticate the master panel without exposing the dashboard session."""
    expected = current_node_api_token()
    supplied = extract_bearer_token(
        request.headers.get("authorization", ""),
        request.headers.get("x-api-token") or request.headers.get("x-node-token") or "",
    )
    if not expected or not supplied or not secrets.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="invalid node API token")
    return supplied

# ── Startup / Shutdown ────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(
        limits=limits, timeout=timeout, follow_redirects=True,
    )
    await load_state()
    await ensure_node_api_token()
    await _tg_start_bot()
    global _heartbeat_task
    _heartbeat_task = asyncio.create_task(_master_heartbeat_loop())
    log_activity("system", "سرور راه‌اندازی شد", "ok")
    logger.info(f"{BRAND} v{VERSION} started on port {CONFIG['port']} (node mode)")

@app.on_event("shutdown")
async def shutdown():
    global _heartbeat_task
    if _heartbeat_task:
        _heartbeat_task.cancel()
        try:
            await _heartbeat_task
        except (asyncio.CancelledError, Exception):
            pass
        _heartbeat_task = None
    await save_state()
    await _tg_stop_bot()
    if http_client:
        await http_client.aclose()

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_host(request: Request | None = None) -> str:
    """آدرس دامنه رو ترجیحاً از خودِ درخواست HTTP می‌گیره (هدر Host/X-Forwarded-Host)
    چون این همیشه دقیقاً همون دامنه‌ایه که کاربر واقعاً بهش وصل شده. متغیر محیطی
    RAILWAY_PUBLIC_DOMAIN فقط به‌عنوان fallback استفاده می‌شه، چون گاهی موقع بالا اومدن
    کانتینر هنوز مقداردهی نشده و باعث می‌شد لینک‌ها گاهی با "localhost" ساخته بشن."""
    if request is not None:
        h = request.headers.get("x-forwarded-host") or request.headers.get("host")
        if h:
            h = h.split(":")[0]
            CONFIG["host"] = h  # کش آخرین دامنه‌ی واقعی دیده‌شده، برای جاهایی که request نداریم (مثل ربات تلگرام)
            return h
    return os.environ.get("RAILWAY_PUBLIC_DOMAIN", CONFIG["host"])

def generate_uuid() -> str:
    h = secrets.token_hex(16)
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
    
def now_ir() -> datetime:
    return datetime.now(IRAN_TZ)

def generate_vless_link(
    uuid: str,
    host: str,
    remark: str = BRAND,
    protocol: str = DEFAULT_PROTOCOL,
    fingerprint: str | None = None,
    alpn: str | None = None,
    port: int | None = None,
) -> str:
    """می‌سازد VLESS share-link متناسب با پروتکل انتخاب‌شده (WS کلاسیک یا یکی از مدهای XHTTP).
    fingerprint / alpn / port در صورت ندادن، از پیش‌فرض‌های خود پروتکل استفاده می‌شوند."""
    fp = (fingerprint or DEFAULT_FINGERPRINT).strip() or DEFAULT_FINGERPRINT
    if fp not in FINGERPRINTS:
        fp = DEFAULT_FINGERPRINT
    alpn_val = (alpn or "").strip() or DEFAULT_ALPN_BY_PROTOCOL.get(protocol, "http/1.1")
    port_val = port or DEFAULT_PORT
    if not (MIN_PORT <= port_val <= MAX_PORT):
        port_val = DEFAULT_PORT

    if protocol == "vless-ws":
        path = f"/ws/{uuid}"
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "ws",
            "host": host,
            "path": path,
            "sni": host,
            "fp": fp,
            "alpn": alpn_val,
        }
    else:
        # xhttp-packet-up / xhttp-stream-up / xhttp-stream-one
        mode = protocol.replace("xhttp-", "")  # packet-up | stream-up | stream-one
        path = f"/xhttp-siz10/{mode}/{uuid}"
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "xhttp",
            "mode": mode,
            "host": host,
            "path": path,
            "sni": host,
            "fp": fp,
            "alpn": alpn_val,
        }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{host}:{port_val}?{query}#{quote(remark)}"

def vless_link_for_link(link: dict, uid: str, host: str) -> str:
    """generate_vless_link رو با تنظیمات دستی همون کانفیگ (fingerprint/alpn/port) صدا می‌زنه."""
    proto = link.get("protocol", DEFAULT_PROTOCOL)
    return generate_vless_link(
        uid, host,
        remark=f"{BRAND}-{link.get('label','')}",
        protocol=proto,
        fingerprint=link.get("fingerprint"),
        alpn=link.get("alpn"),
        port=link.get("port"),
    )

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 ** 3)
    if unit == "MB": return int(value * 1024 ** 2)
    if unit == "KB": return int(value * 1024)
    return int(value)

def parse_speed_to_bytes(value: float, unit: str) -> int:
    """محدودیت سرعت رو به بایت‌بر‌ثانیه تبدیل می‌کنه.
    واحدهای پشتیبانی‌شده: MBIT (مگابیت‌بر‌ثانیه، رایج‌ترین)، KB (کیلوبایت‌بر‌ثانیه)، MB (مگابایت‌بر‌ثانیه)."""
    if value <= 0:
        return 0
    unit = (unit or "MBIT").upper()
    if unit == "MBIT":
        return int(value * 1024 * 1024 / 8)
    if unit == "KB":
        return int(value * 1024)
    if unit == "MB":
        return int(value * 1024 * 1024)
    return int(value)

def is_link_expired(link: dict) -> bool:
    exp = link.get("expires_at")
    if not exp:
        return False
    try:
        return datetime.now() > datetime.fromisoformat(exp)
    except Exception:
        return False

def is_link_allowed(link: dict | None) -> bool:
    if link is None:
        return False
    if not link.get("active", True):
        return False
    if is_link_expired(link):
        return False
    lb = link.get("limit_bytes", 0)
    if lb > 0 and link.get("used_bytes", 0) >= lb:
        return False
    return True

def fmt_bytes(b: int) -> str:
    if b < 1024: return f"{b} B"
    if b < 1024**2: return f"{b/1024:.1f} KB"
    if b < 1024**3: return f"{b/1024**2:.2f} MB"
    return f"{b/1024**3:.2f} GB"

def unique_ips_for_uuid(uuid: str) -> set:
    """آی‌پی‌های یکتای همین لحظه متصل به یک UUID خاص (بر اساس dict اتصالات زنده)."""
    return {c.get("ip") for c in connections.values() if c.get("uuid") == uuid and c.get("ip")}

def is_ip_allowed(link: dict | None, uuid: str, ip: str) -> bool:
    """محدودیت تعداد آی‌پی/کاربر هم‌زمان برای هر کانفیگ. ip_limit=0 یعنی نامحدود.
    اگر همین آی‌پی از قبل روی این کانفیگ سشن باز داشته باشه، همیشه مجازه (برای چند اتصال
    هم‌زمان از یک دستگاه/مرورگر مشکلی پیش نمیاد)."""
    if link is None:
        return False
    limit = int(link.get("ip_limit", 0) or 0)
    if limit <= 0:
        return True
    ips = unique_ips_for_uuid(uuid)
    if ip in ips:
        return True
    return len(ips) < limit

def client_ip(request: Request) -> str:
    """آی‌پی واقعی کلاینت رو با احتساب هدرهای پراکسی (Railway/Cloudflare) برمی‌گردونه."""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "نامشخص"

# ── Default link ──────────────────────────────────────────────────────────────
_default_link_created = False

async def ensure_default_link():
    global _default_link_created
    if _default_link_created:
        return
    async with LINKS_LOCK:
        if not any(l.get("is_default") for l in LINKS.values()):
            uid = hashlib.sha256(f"default{CONFIG['secret']}".encode()).hexdigest()
            uid = f"{uid[:8]}-{uid[8:12]}-{uid[12:16]}-{uid[16:20]}-{uid[20:32]}"
            if uid not in LINKS:
                LINKS[uid] = {
                    "label": "لینک پیش‌فرض",
                    "limit_bytes": 0,
                    "used_bytes": 0,
                    "created_at": datetime.now().isoformat(),
                    "active": True,
                    "expires_at": None,
                    "note": "",
                    "is_default": True,
                    "sub_id": None,
                    "protocol": DEFAULT_PROTOCOL,
                    "fingerprint": DEFAULT_FINGERPRINT,
                    "alpn": "",
                    "port": DEFAULT_PORT,
                    "ip_limit": 0,
                    "speed_limit_bytes": DEFAULT_SPEED_LIMIT,
                }
                asyncio.create_task(save_state())
        _default_link_created = True

# ── Basic endpoints ───────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"service": BRAND, "version": VERSION, "role": "hybrid", "roles": ["master", "node"], "status": "active", "channel": "https://t.me/Farajian2004f"}

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

# ── Subscription (single link) ────────────────────────────────────────────────
@app.get("/sub/{uuid}")
async def subscription_single(uuid: str, request: Request):
    import base64
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    if not link or not is_link_allowed(link):
        raise HTTPException(status_code=404, detail="not found or inactive")
    host = get_host(request)
    vless = vless_link_for_link(link, uuid, host)
    content = base64.b64encode(vless.encode()).decode()
    return Response(content=content, media_type="text/plain",
                    headers={"profile-title": quote(link["label"]), "support-url": "https://t.me/Farajian2004f"})

@app.get("/sub-all")
async def subscription_all(request: Request, _=Depends(require_auth)):
    import base64
    host = get_host(request)
    async with LINKS_LOCK:
        lines = [
            vless_link_for_link(d, uid, host)
            for uid, d in LINKS.items()
            if is_link_allowed(d)
        ]
    content = base64.b64encode("\n".join(lines).encode()).decode()
    return Response(content=content, media_type="text/plain")

# ══════════════════════════════════════════════════════════════════════════════
# SUB GROUP endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/subs")
async def create_sub(request: Request, _=Depends(require_auth)):
    body = await request.json()
    name = (body.get("name") or "گروه جدید").strip()[:60]
    desc = (body.get("desc") or "").strip()[:200]
    password = (body.get("password") or "").strip()
    sub_id = generate_uuid()
    uuid_key = secrets.token_urlsafe(16)
    async with SUBS_LOCK:
        SUBS[sub_id] = {
            "name": name,
            "desc": desc,
            "password_hash": hash_password(password) if password else None,
            "uuid_key": uuid_key,
            "created_at": datetime.now().isoformat(),
            "link_ids": [],
        }
    asyncio.create_task(save_state())
    log_activity("sub", f"گروه «{name}» ساخته شد", "ok")
    host = get_host(request)
    return {
        "sub_id": sub_id,
        **SUBS[sub_id],
        "public_url": f"https://{host}/p/{uuid_key}",
        "sub_url": f"https://{host}/sub-group/{uuid_key}",
    }

@app.get("/api/subs")
async def list_subs(request: Request, _=Depends(require_auth)):
    host = get_host(request)
    async with SUBS_LOCK:
        snap_subs = dict(SUBS)
    async with LINKS_LOCK:
        snap_links = dict(LINKS)
    result = []
    for sid, s in snap_subs.items():
        link_ids = s.get("link_ids", [])
        active_count = sum(1 for lid in link_ids if is_link_allowed(snap_links.get(lid)))
        total_used = sum(snap_links[lid].get("used_bytes", 0) for lid in link_ids if lid in snap_links)
        result.append({
            "sub_id": sid,
            **s,
            "password_hash": None,
            "has_password": s.get("password_hash") is not None,
            "links_count": len(link_ids),
            "active_count": active_count,
            "total_used_bytes": total_used,
            "total_used_fmt": fmt_bytes(total_used),
            "public_url": f"https://{host}/p/{s['uuid_key']}",
            "sub_url": f"https://{host}/sub-group/{s['uuid_key']}",
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"subs": result}

@app.patch("/api/subs/{sub_id}")
async def update_sub(sub_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        s = SUBS[sub_id]
        if "name" in body:
            s["name"] = str(body["name"])[:60]
        if "desc" in body:
            s["desc"] = str(body["desc"])[:200]
        if "password" in body:
            pw = str(body["password"]).strip()
            s["password_hash"] = hash_password(pw) if pw else None
        if "link_ids" in body:
            s["link_ids"] = list(body["link_ids"])
    asyncio.create_task(save_state())
    return {"ok": True}

@app.delete("/api/subs/{sub_id}")
async def delete_sub(sub_id: str, _=Depends(require_auth)):
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        name = SUBS[sub_id].get("name", sub_id)
        del SUBS[sub_id]
    async with LINKS_LOCK:
        for link in LINKS.values():
            if link.get("sub_id") == sub_id:
                link["sub_id"] = None
    asyncio.create_task(save_state())
    log_activity("sub", f"گروه «{name}» حذف شد", "warn")
    return {"ok": True, "deleted": sub_id}

@app.post("/api/subs/{sub_id}/links")
async def assign_link_to_sub(sub_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    link_id = str(body.get("link_id", ""))
    action = str(body.get("action", "add"))
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        s = SUBS[sub_id]
        ids = s.setdefault("link_ids", [])
        if action == "add":
            if link_id not in ids:
                ids.append(link_id)
        else:
            if link_id in ids:
                ids.remove(link_id)
    async with LINKS_LOCK:
        if link_id in LINKS:
            LINKS[link_id]["sub_id"] = sub_id if action == "add" else None
    asyncio.create_task(save_state())
    return {"ok": True}

# ── Public sub-group subscription file ───────────────────────────────────────
@app.get("/sub-group/{uuid_key}")
async def sub_group_subscription(uuid_key: str, request: Request):
    import base64
    async with SUBS_LOCK:
        sub = next((s for s in SUBS.values() if s.get("uuid_key") == uuid_key), None)
    if not sub:
        raise HTTPException(status_code=404, detail="not found")

    if sub.get("password_hash"):
        pw = request.query_params.get("pw", "")
        if hash_password(pw) != sub["password_hash"]:
            raise HTTPException(status_code=403, detail="wrong password")

    host = get_host(request)
    link_ids = sub.get("link_ids", [])
    async with LINKS_LOCK:
        lines = []
        for lid in link_ids:
            link = LINKS.get(lid)
            if link and is_link_allowed(link):
                lines.append(vless_link_for_link(link, lid, host))

    content = base64.b64encode("\n".join(lines).encode()).decode()
    return Response(
        content=content,
        media_type="text/plain",
        headers={
            "profile-title": quote(sub["name"]),
            "support-url": "https://t.me/Farajian2004f",
            "profile-update-interval": "12",
        }
    )

# ── Auth endpoints ────────────────────────────────────────────────────────────
@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    ip = client_ip(request)
    if hash_password(str(body.get("password", ""))) != AUTH["password_hash"]:
        log_activity("auth", f"تلاش ورود ناموفق از {ip}", "err")
        raise HTTPException(status_code=401, detail="رمز عبور اشتباه است")
    token = await create_session()
    log_activity("auth", f"ورود موفق به پنل از {ip}", "ok")
    resp = JSONResponse({"ok": True})
    resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    await destroy_session(request.cookies.get(SESSION_COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    return {"authenticated": await is_valid_session(request.cookies.get(SESSION_COOKIE))}

@app.post("/api/change-password")
async def api_change_password(request: Request, token=Depends(require_auth)):
    body = await request.json()
    if hash_password(str(body.get("current_password", ""))) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="رمز فعلی اشتباه است")
    new = str(body.get("new_password", ""))
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="رمز جدید باید حداقل ۴ کاراکتر باشد")
    AUTH["password_hash"] = hash_password(new)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        SESSIONS[token] = time.time() + SESSION_TTL
    await save_state()
    log_activity("auth", "رمز عبور پنل تغییر کرد", "ok")
    return {"ok": True}

# ── Stats ─────────────────────────────────────────────────────────────────────
@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    async with LINKS_LOCK:
        snap = dict(LINKS)
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 ** 2), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "hourly": dict(hourly_traffic),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(snap),
        "active_links": sum(1 for l in snap.values() if is_link_allowed(l)),
        "expired_links": sum(1 for l in snap.values() if is_link_expired(l)),
        "subs_count": len(SUBS),
    }

# ── Activity Logs ─────────────────────────────────────────────────────────────
@app.get("/api/activity")
async def get_activity(_=Depends(require_auth)):
    return {"logs": list(activity_logs)[-150:]}

# ── Live connections (with IP) ────────────────────────────────────────────────
@app.get("/api/connections")
async def get_connections(_=Depends(require_auth)):
    """
    خروجی این endpoint حالا بر اساس IP گروه‌بندی شده:
    هر آی‌پی فقط یک آیتم نمایش داده می‌شود، با جمع بایت‌های تمام سشن‌های
    باز روی همان آی‌پی و تعداد سشن‌های فعال آن آی‌پی.
    raw_count همچنان تعداد واقعی اتصالات باز (سشن‌های خام، مثلاً ۴۰ تا
    اتصال هم‌زمان یک موبایل) را برمی‌گرداند.
    """
    async with LINKS_LOCK:
        snap = dict(LINKS)

    grouped: dict[str, dict] = {}
    for conn_id, c in connections.items():
        ip = c.get("ip", "نامشخص")
        link = snap.get(c.get("uuid"))
        label = link.get("label") if link else "نامشخص"
        g = grouped.get(ip)
        if g is None:
            g = {
                "ip": ip,
                "sessions": 0,
                "bytes": 0,
                "labels": set(),
                "transports": set(),
                "first_connected_at": c.get("connected_at"),
                "last_connected_at": c.get("connected_at"),
            }
            grouped[ip] = g
        g["sessions"] += 1
        g["bytes"] += c.get("bytes", 0)
        g["labels"].add(label)
        g["transports"].add(c.get("transport", "vless-ws"))
        ca = c.get("connected_at")
        if ca:
            if not g["first_connected_at"] or ca < g["first_connected_at"]:
                g["first_connected_at"] = ca
            if not g["last_connected_at"] or ca > g["last_connected_at"]:
                g["last_connected_at"] = ca

    result = []
    for ip, g in grouped.items():
        result.append({
            "ip": ip,
            "sessions": g["sessions"],
            "labels": sorted(g["labels"]),
            "label": " · ".join(sorted(g["labels"])) if g["labels"] else "نامشخص",
            "transports": sorted(g["transports"]),
            "bytes": g["bytes"],
            "bytes_fmt": fmt_bytes(g["bytes"]),
            "connected_at": g["first_connected_at"],
            "last_connected_at": g["last_connected_at"],
        })
    result.sort(key=lambda x: x.get("last_connected_at") or "", reverse=True)

    return {
        "connections": result,
        "count": len(result),          # تعداد آی‌پی‌های یکتا
        "raw_count": len(connections), # تعداد کل اتصالات باز (بدون گروه‌بندی)
    }

# ── Shared link create/delete helpers (استفاده مشترک API و ربات تلگرام) ───────
async def make_link(
    label: str = "لینک جدید",
    limit_bytes: int = 0,
    expires_at: str | None = None,
    note: str = "",
    sub_id: str | None = None,
    protocol: str = DEFAULT_PROTOCOL,
    fingerprint: str = DEFAULT_FINGERPRINT,
    alpn: str = "",
    port: int = DEFAULT_PORT,
    ip_limit: int = 0,
    speed_limit_bytes: int = 0,
) -> tuple[str, dict]:
    if protocol not in PROTOCOLS:
        protocol = DEFAULT_PROTOCOL
    fingerprint = (fingerprint or DEFAULT_FINGERPRINT).strip().lower()
    if fingerprint not in FINGERPRINTS:
        fingerprint = DEFAULT_FINGERPRINT
    if not (MIN_PORT <= port <= MAX_PORT):
        port = DEFAULT_PORT
    uid = generate_uuid()
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": (label or "لینک جدید").strip()[:60] or "لینک جدید",
            "limit_bytes": max(0, limit_bytes),
            "used_bytes": 0,
            "created_at": datetime.now().isoformat(),
            "active": True,
            "expires_at": expires_at,
            "note": (note or "").strip()[:200],
            "is_default": False,
            "sub_id": sub_id,
            "protocol": protocol,
            "fingerprint": fingerprint,
            "alpn": (alpn or "").strip()[:100],
            "port": port,
            "ip_limit": max(0, ip_limit),
            "speed_limit_bytes": max(0, speed_limit_bytes),
        }
    if sub_id:
        async with SUBS_LOCK:
            if sub_id in SUBS:
                ids = SUBS[sub_id].setdefault("link_ids", [])
                if uid not in ids:
                    ids.append(uid)
    asyncio.create_task(save_state())
    log_activity("link", f"کانفیگ «{LINKS[uid]['label']}» ساخته شد", "ok")
    return uid, LINKS[uid]

async def remove_link(uid: str) -> str | None:
    async with LINKS_LOCK:
        if uid not in LINKS:
            return None
        label = LINKS[uid].get("label", uid)
        sub_id = LINKS[uid].get("sub_id")
        del LINKS[uid]
    if sub_id:
        async with SUBS_LOCK:
            if sub_id in SUBS:
                ids = SUBS[sub_id].get("link_ids", [])
                if uid in ids:
                    ids.remove(uid)
    asyncio.create_task(save_state())
    log_activity("link", f"کانفیگ «{label}» حذف شد", "err")
    return label

async def set_link_active(uid: str, active: bool) -> dict | None:
    async with LINKS_LOCK:
        if uid not in LINKS:
            return None
        LINKS[uid]["active"] = bool(active)
        label = LINKS[uid]["label"]
    log_activity("link", f"کانفیگ «{label}» {'فعال' if active else 'غیرفعال'} شد", "ok" if active else "warn")
    asyncio.create_task(save_state())
    return LINKS[uid]

# ── Sub-group helpers (reusable — هم API وب هم ربات تلگرام از همین‌ها استفاده می‌کنن) ──
async def create_sub_group(name: str = "گروه جدید", desc: str = "", password: str = "") -> tuple[str, dict]:
    name = (name or "گروه جدید").strip()[:60]
    desc = (desc or "").strip()[:200]
    password = (password or "").strip()
    sub_id = generate_uuid()
    uuid_key = secrets.token_urlsafe(16)
    async with SUBS_LOCK:
        SUBS[sub_id] = {
            "name": name,
            "desc": desc,
            "password_hash": hash_password(password) if password else None,
            "uuid_key": uuid_key,
            "created_at": datetime.now().isoformat(),
            "link_ids": [],
        }
    asyncio.create_task(save_state())
    log_activity("sub", f"گروه «{name}» ساخته شد", "ok")
    return sub_id, SUBS[sub_id]

async def set_link_sub(uid: str, sub_id: str | None) -> bool:
    """یک کانفیگ رو به یک گروه ساب اضافه/منتقل می‌کنه؛ با sub_id=None از گروه فعلیش خارجش می‌کنه."""
    async with LINKS_LOCK:
        if uid not in LINKS:
            return False
        old_sub = LINKS[uid].get("sub_id")
        label = LINKS[uid].get("label", uid)
    if sub_id is not None:
        async with SUBS_LOCK:
            if sub_id not in SUBS:
                return False
    async with SUBS_LOCK:
        if old_sub and old_sub in SUBS:
            ids = SUBS[old_sub].get("link_ids", [])
            if uid in ids:
                ids.remove(uid)
        if sub_id and sub_id in SUBS:
            ids = SUBS[sub_id].setdefault("link_ids", [])
            if uid not in ids:
                ids.append(uid)
    async with LINKS_LOCK:
        if uid in LINKS:
            LINKS[uid]["sub_id"] = sub_id
    asyncio.create_task(save_state())
    log_activity("link", f"کانفیگ «{label}» {'به گروه اضافه شد' if sub_id else 'از گروه خارج شد'}", "info")
    return True

async def remove_sub_group(sub_id: str) -> str | None:
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            return None
        name = SUBS[sub_id].get("name", sub_id)
        del SUBS[sub_id]
    async with LINKS_LOCK:
        for link in LINKS.values():
            if link.get("sub_id") == sub_id:
                link["sub_id"] = None
    asyncio.create_task(save_state())
    log_activity("sub", f"گروه «{name}» حذف شد", "warn")
    return name

# ── Link Management ───────────────────────────────────────────────────────────
@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    lv = float(body.get("limit_value") or 0)
    lu = body.get("limit_unit") or "GB"
    limit_bytes = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
    exp_days = int(body.get("expires_days") or 0)
    expires_at = (datetime.now() + timedelta(days=exp_days)).isoformat() if exp_days > 0 else None
    try:
        port = int(body.get("port") or DEFAULT_PORT)
    except (TypeError, ValueError):
        port = DEFAULT_PORT
    try:
        ip_limit = int(body.get("ip_limit") or 0)
    except (TypeError, ValueError):
        ip_limit = 0

    sv = float(body.get("speed_limit_value") or 0)
    su = body.get("speed_limit_unit") or "MBIT"
    speed_limit_bytes = 0 if sv <= 0 else parse_speed_to_bytes(sv, su)

    uid, link = await make_link(
        label=body.get("label") or "لینک جدید",
        limit_bytes=limit_bytes,
        expires_at=expires_at,
        note=body.get("note") or "",
        sub_id=body.get("sub_id") or None,
        protocol=body.get("protocol") or DEFAULT_PROTOCOL,
        fingerprint=body.get("fingerprint") or DEFAULT_FINGERPRINT,
        alpn=body.get("alpn") or "",
        port=port,
        ip_limit=ip_limit,
        speed_limit_bytes=speed_limit_bytes,
    )

    host = get_host(request)
    return {
        "uuid": uid,
        **link,
        "expired": False,
        "vless_link": vless_link_for_link(link, uid, host),
        "sub_url": f"https://{host}/sub/{uid}",
    }

@app.get("/api/links")
async def list_links(request: Request, _=Depends(require_auth)):
    host = get_host(request)
    async with LINKS_LOCK:
        snap = dict(LINKS)
    result = []
    for uid, d in snap.items():
        proto = d.get("protocol", DEFAULT_PROTOCOL)
        result.append({
            "uuid": uid,
            **d,
            "protocol": proto,
            "expired": is_link_expired(d),
            "vless_link": vless_link_for_link(d, uid, host),
            "sub_url": f"https://{host}/sub/{uid}",
            "connected_ips": len(unique_ips_for_uuid(uid)),
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.patch("/api/links/{uid}")
async def update_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        link = LINKS[uid]
        old_sub = link.get("sub_id")
        label = link.get("label")
        if "active" in body:
            link["active"] = bool(body["active"])
            log_activity("link", f"کانفیگ «{label}» {'فعال' if link['active'] else 'غیرفعال'} شد", "ok" if link["active"] else "warn")
        if "label" in body:
            link["label"] = str(body["label"])[:60]
        if "note" in body:
            link["note"] = str(body["note"])[:200]
        if "reset_usage" in body and body["reset_usage"]:
            link["used_bytes"] = 0
            log_activity("link", f"مصرف کانفیگ «{label}» ریست شد", "info")
        if "limit_value" in body:
            lv = float(body.get("limit_value") or 0)
            lu = body.get("limit_unit") or "GB"
            link["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
        if "expires_days" in body:
            ed = int(body["expires_days"] or 0)
            link["expires_at"] = (datetime.now() + timedelta(days=ed)).isoformat() if ed > 0 else None
        if "fingerprint" in body:
            fp = str(body.get("fingerprint") or DEFAULT_FINGERPRINT).strip().lower()
            link["fingerprint"] = fp if fp in FINGERPRINTS else DEFAULT_FINGERPRINT
        if "alpn" in body:
            link["alpn"] = str(body.get("alpn") or "").strip()[:100]
        if "port" in body:
            try:
                p = int(body.get("port") or DEFAULT_PORT)
            except (TypeError, ValueError):
                p = DEFAULT_PORT
            link["port"] = p if (MIN_PORT <= p <= MAX_PORT) else DEFAULT_PORT
        if "ip_limit" in body:
            try:
                il = int(body.get("ip_limit") or 0)
            except (TypeError, ValueError):
                il = 0
            link["ip_limit"] = max(0, il)
        if "speed_limit_value" in body:
            sv = float(body.get("speed_limit_value") or 0)
            su = body.get("speed_limit_unit") or "MBIT"
            link["speed_limit_bytes"] = 0 if sv <= 0 else parse_speed_to_bytes(sv, su)
            from speed_limit import reset_bucket
            reset_bucket(uid)
        if any(k in body for k in ("label", "note", "limit_value", "expires_days", "fingerprint", "alpn", "port", "ip_limit", "speed_limit_value")):
            log_activity("link", f"کانفیگ «{link['label']}» ویرایش شد", "info")
        new_sub = body.get("sub_id", "UNCHANGED")
        if new_sub != "UNCHANGED":
            link["sub_id"] = new_sub or None

    if new_sub != "UNCHANGED":
        async with SUBS_LOCK:
            if old_sub and old_sub in SUBS:
                ids = SUBS[old_sub].get("link_ids", [])
                if uid in ids:
                    ids.remove(uid)
            if new_sub and new_sub in SUBS:
                ids = SUBS[new_sub].setdefault("link_ids", [])
                if uid not in ids:
                    ids.append(uid)

    asyncio.create_task(save_state())
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    label = await remove_link(uid)
    if label is None:
        raise HTTPException(status_code=404, detail="link not found")
    return {"ok": True, "deleted": uid}

# ══════════════════════════════════════════════════════════════════════════════
# Node manager — RVG / Marzban / 3x-ui
# ══════════════════════════════════════════════════════════════════════════════
NODE_PANEL_TYPES = {"rvg", "marzban", "xui"}
NODE_AUTH_TYPES = {"token", "credentials"}
NODE_SECRET_FIELDS = {"token", "username", "password"}

def public_node(node_id: str, node: dict) -> dict:
    """Return node metadata without ever sending credentials back to the browser."""
    return {
        "id": node_id,
        **{k: v for k, v in node.items() if k not in NODE_SECRET_FIELDS},
        "has_token": bool(node.get("token")),
        "has_credentials": bool(node.get("username") or node.get("password")),
    }

def node_or_404(node_id: str) -> dict:
    node = NODES.get(node_id)
    if not node:
        raise HTTPException(status_code=404, detail="نود پیدا نشد")
    return dict(node)

def node_http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, NodeError):
        return HTTPException(status_code=502, detail=str(exc))
    logger.exception("Unexpected node error")
    return HTTPException(status_code=502, detail="خطای غیرمنتظره در ارتباط با نود")

@app.get("/api/nodes")
async def list_nodes(_=Depends(require_auth_or_node)):
    async with NODES_LOCK:
        nodes = [public_node(node_id, node) for node_id, node in NODES.items()]
    nodes.sort(key=lambda n: n.get("created_at", ""), reverse=True)
    return {"nodes": nodes}

@app.post("/api/nodes")
async def create_node(request: Request, _=Depends(require_auth)):
    body = await request.json()
    panel_type = str(body.get("panel_type", "rvg")).lower()
    auth_type = str(body.get("auth_type", "token")).lower()
    if panel_type not in NODE_PANEL_TYPES or auth_type not in NODE_AUTH_TYPES:
        raise HTTPException(status_code=400, detail="نوع پنل یا احراز هویت نامعتبر است")
    try:
        base_url = normalize_base_url(str(body.get("base_url", "")))
    except NodeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if auth_type == "token" and not str(body.get("token", "")).strip():
        raise HTTPException(status_code=400, detail="API Token الزامی است")
    if auth_type == "credentials" and not str(body.get("password", "")):
        raise HTTPException(status_code=400, detail="رمز عبور الزامی است")
    node_id = secrets.token_urlsafe(12)
    node = {
        "name": str(body.get("name") or base_url)[:80],
        "panel_type": panel_type,
        "base_url": base_url,
        "auth_type": auth_type,
        "token": str(body.get("token", "")).strip(),
        "username": str(body.get("username", "")).strip(),
        "password": str(body.get("password", "")),
        "verify_ssl": bool(body.get("verify_ssl", True)),
        "enabled": bool(body.get("enabled", True)),
        "created_at": datetime.now().isoformat(),
        "last_check": None,
        "last_error": None,
    }
    # Test before saving so a typo does not create a dead node.
    try:
        async with PanelNodeClient(node) as remote:
            overview = await remote.overview()
    except Exception as exc:
        raise node_http_error(exc)
    node["last_check"] = datetime.now().isoformat()
    node["last_overview"] = overview
    async with NODES_LOCK:
        NODES[node_id] = node
    await save_state()
    log_activity("node", f"نود «{node['name']}» اضافه شد", "ok")
    return {"node": public_node(node_id, node)}

@app.patch("/api/nodes/{node_id}")
async def update_node(node_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with NODES_LOCK:
        if node_id not in NODES:
            raise HTTPException(status_code=404, detail="نود پیدا نشد")
        node = NODES[node_id]
        for field in ("name", "panel_type", "auth_type", "token", "username", "password", "enabled", "verify_ssl"):
            if field in body and (field not in NODE_SECRET_FIELDS or body[field] not in (None, "")):
                node[field] = body[field]
        if "base_url" in body:
            try:
                node["base_url"] = normalize_base_url(str(body["base_url"]))
            except NodeError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        snapshot = dict(node)
    await save_state()
    return {"node": public_node(node_id, snapshot)}

@app.delete("/api/nodes/{node_id}")
async def delete_node(node_id: str, _=Depends(require_auth)):
    async with NODES_LOCK:
        node = NODES.pop(node_id, None)
    if not node:
        raise HTTPException(status_code=404, detail="نود پیدا نشد")
    await save_state()
    log_activity("node", f"نود «{node.get('name', node_id)}» حذف شد", "warn")
    return {"ok": True}

@app.post("/api/nodes/{node_id}/test")
async def test_node(node_id: str, _=Depends(require_auth)):
    node = node_or_404(node_id)
    try:
        async with PanelNodeClient(node) as remote:
            overview = await remote.overview()
    except Exception as exc:
        async with NODES_LOCK:
            if node_id in NODES:
                NODES[node_id]["last_check"] = datetime.now().isoformat()
                NODES[node_id]["last_error"] = str(exc)
        asyncio.create_task(save_state())
        raise node_http_error(exc)
    async with NODES_LOCK:
        if node_id in NODES:
            NODES[node_id]["last_check"] = datetime.now().isoformat()
            NODES[node_id]["last_error"] = None
            NODES[node_id]["last_overview"] = overview
    asyncio.create_task(save_state())
    return {"ok": True, "overview": overview}

@app.get("/api/nodes/{node_id}/configs")
async def node_configs(node_id: str, _=Depends(require_auth)):
    node = node_or_404(node_id)
    try:
        async with PanelNodeClient(node) as remote:
            configs = await remote.list_configs()
        return {"configs": configs}
    except Exception as exc:
        raise node_http_error(exc)

@app.post("/api/nodes/{node_id}/configs")
async def node_create_config(node_id: str, request: Request, _=Depends(require_auth)):
    node = node_or_404(node_id)
    try:
        async with PanelNodeClient(node) as remote:
            result = await remote.create_config(await request.json())
        return {"ok": True, "result": result}
    except Exception as exc:
        raise node_http_error(exc)

@app.patch("/api/nodes/{node_id}/configs/{config_id}")
async def node_update_config(node_id: str, config_id: str, request: Request, _=Depends(require_auth)):
    node = node_or_404(node_id)
    try:
        async with PanelNodeClient(node) as remote:
            result = await remote.update_config(config_id, await request.json())
        return {"ok": True, "result": result}
    except Exception as exc:
        raise node_http_error(exc)

@app.delete("/api/nodes/{node_id}/configs/{config_id}")
async def node_delete_config(node_id: str, config_id: str, _=Depends(require_auth)):
    node = node_or_404(node_id)
    try:
        async with PanelNodeClient(node) as remote:
            result = await remote.delete_config(config_id)
        return {"ok": True, "result": result}
    except Exception as exc:
        raise node_http_error(exc)

@app.get("/api/nodes-subscription")
async def nodes_subscription(_=Depends(require_auth)):
    """Aggregate share links exposed by configured nodes into one base64 subscription."""
    import base64
    links = []
    errors = []
    async with NODES_LOCK:
        nodes = [(node_id, dict(node)) for node_id, node in NODES.items() if node.get("enabled", True)]
    for node_id, node in nodes:
        try:
            async with PanelNodeClient(node) as remote:
                configs = await remote.list_configs()
            for config in configs:
                value = config.get("vless_link") or config.get("subscription_url") or config.get("link")
                if value:
                    links.append(value)
        except Exception as exc:
            errors.append(f"{node.get('name', node_id)}: {exc}")
    content = base64.b64encode("\n".join(links).encode()).decode()
    return Response(content=content, media_type="text/plain", headers={"X-RVG-Node-Errors": str(len(errors))})

# ══════════════════════════════════════════════════════════════════════════════
# This RVG is a NODE. The master panel talks to /api/node/v1 with Bearer token.
# ══════════════════════════════════════════════════════════════════════════════

def serialize_node_config(uid: str, link: dict, host: str) -> dict:
    return {
        "id": uid,
        "uuid": uid,
        "label": link.get("label"),
        "active": is_link_allowed(link),
        "enabled": bool(link.get("active", True)),
        "expired": is_link_expired(link),
        "protocol": link.get("protocol", DEFAULT_PROTOCOL),
        "fingerprint": link.get("fingerprint", DEFAULT_FINGERPRINT),
        "alpn": link.get("alpn") or "",
        "port": link.get("port", DEFAULT_PORT),
        "limit_bytes": link.get("limit_bytes", 0),
        "used_bytes": link.get("used_bytes", 0),
        "speed_limit_bytes": link.get("speed_limit_bytes", 0),
        "ip_limit": link.get("ip_limit", 0),
        "expires_at": link.get("expires_at"),
        "note": link.get("note") or "",
        "created_at": link.get("created_at"),
        "is_default": bool(link.get("is_default")),
        "vless_link": vless_link_for_link(link, uid, host),
        "subscription_url": f"https://{host}/sub/{uid}",
        "connected_ips": len(unique_ips_for_uuid(uid)),
    }


def node_overview_payload() -> dict:
    snap = dict(LINKS)
    return {
        "service": BRAND,
        "role": "node",
        "version": VERSION,
        "links_count": len(snap),
        "active_links": sum(1 for item in snap.values() if is_link_allowed(item)),
        "expired_links": sum(1 for item in snap.values() if is_link_expired(item)),
        "active_connections": len(connections),
        "total_bytes": stats["total_bytes"],
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "host": CONFIG.get("host"),
    }


async def node_create_from_body(body: dict, request: Request) -> dict:
    if "limit_bytes" in body:
        limit_bytes = max(0, int(body.get("limit_bytes") or 0))
    else:
        lv = float(body.get("limit_value") or 0)
        limit_bytes = 0 if lv <= 0 else parse_size_to_bytes(lv, body.get("limit_unit") or "GB")
    expires_at = body.get("expires_at")
    if not expires_at:
        exp_days = int(body.get("expires_days") or 0)
        expires_at = (datetime.now() + timedelta(days=exp_days)).isoformat() if exp_days > 0 else None
    if "speed_limit_bytes" in body:
        speed_limit_bytes = max(0, int(body.get("speed_limit_bytes") or 0))
    else:
        sv = float(body.get("speed_limit_value") or 0)
        speed_limit_bytes = 0 if sv <= 0 else parse_speed_to_bytes(sv, body.get("speed_limit_unit") or "MBIT")
    uid, link = await make_link(
        label=body.get("label") or "لینک نود",
        limit_bytes=limit_bytes,
        expires_at=expires_at,
        note=body.get("note") or "",
        protocol=body.get("protocol") or DEFAULT_PROTOCOL,
        fingerprint=body.get("fingerprint") or DEFAULT_FINGERPRINT,
        alpn=body.get("alpn") or "",
        port=int(body.get("port", DEFAULT_PORT) or DEFAULT_PORT),
        ip_limit=max(0, int(body.get("ip_limit", 0) or 0)),
        speed_limit_bytes=speed_limit_bytes,
    )
    return serialize_node_config(uid, link, get_host(request))


@app.get("/api/master")
async def get_master_settings(request: Request, _=Depends(require_auth)):
    await ensure_node_api_token()
    return {"api": public_node_api(request, reveal=False), "master": public_master()}


@app.get("/api/master/token")
async def reveal_node_token(request: Request, _=Depends(require_auth)):
    await ensure_node_api_token()
    return {"api": public_node_api(request, reveal=True)}


@app.post("/api/master/token/rotate")
async def rotate_node_token(request: Request, _=Depends(require_auth)):
    if env_node_api_token():
        raise HTTPException(status_code=400, detail="توکن از متغیر محیطی NODE_API_TOKEN می‌آید و از پنل قابل چرخش نیست")
    async with NODE_API_LOCK:
        NODE_API["token"] = new_node_api_token()
        NODE_API["created_at"] = datetime.now().isoformat()
        NODE_API["source"] = "rotated"
    await save_state()
    log_activity("api", "توکن API نود چرخانده شد", "warn")
    return {"ok": True, "api": public_node_api(request, reveal=True)}


@app.post("/api/master")
async def connect_to_master(request: Request, _=Depends(require_auth)):
    """Save master URL/token and optionally register this node on an RVG master."""
    body = await request.json()
    try:
        url = normalize_base_url(str(body.get("url") or body.get("base_url") or ""))
    except NodeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    panel_type = str(body.get("panel_type") or "rvg").lower()
    if panel_type not in {"rvg", "generic"}:
        raise HTTPException(status_code=400, detail="نوع پنل مستر نامعتبر است")
    auth_type = str(body.get("auth_type") or "credentials").lower()
    if auth_type not in {"token", "credentials"}:
        raise HTTPException(status_code=400, detail="روش ورود مستر نامعتبر است")
    token = current_node_api_token() or await ensure_node_api_token()
    host = get_host(request)
    scheme = "https" if host not in {"localhost", "127.0.0.1"} else "http"
    node_public = f"{scheme}://{host}"
    snapshot = {
        "url": url,
        "name": str(body.get("name") or url)[:80],
        "panel_type": panel_type,
        "auth_type": auth_type,
        "token": str(body.get("token") or MASTER.get("token") or "").strip(),
        "username": str(body.get("username") or MASTER.get("username") or "").strip(),
        "password": str(body.get("password") if body.get("password") not in (None, "") else MASTER.get("password") or ""),
        "verify_ssl": bool(body.get("verify_ssl", True)),
        "heartbeat_path": str(body.get("heartbeat_path") or "").strip(),
        "health_path": str(body.get("health_path") or "").strip(),
        "enabled": True,
        "registered": False,
        "last_error": None,
        "last_ok": None,
        "last_check": datetime.now().isoformat(),
    }
    if auth_type == "token" and panel_type == "rvg" and not snapshot["token"]:
        raise HTTPException(status_code=400, detail="توکن پنل مستر الزامی است")
    if auth_type == "credentials" and panel_type == "rvg" and not snapshot["password"]:
        raise HTTPException(status_code=400, detail="رمز پنل مستر الزامی است")
    try:
        async with MasterClient(snapshot) as remote:
            ping = await remote.ping()
            if bool(body.get("register", True)) and panel_type == "rvg":
                result = await remote.register(node_public, token, snapshot["name"] or f"{BRAND}-{host}")
                snapshot["registered"] = bool(result.get("registered"))
            else:
                result = {"registered": False, "ping": ping}
    except Exception as exc:
        snapshot["last_error"] = str(exc)
        async with MASTER_LOCK:
            MASTER.clear()
            MASTER.update(snapshot)
            MASTER["enabled"] = False
        await save_state()
        raise node_http_error(exc)
    snapshot["last_ok"] = datetime.now().isoformat()
    async with MASTER_LOCK:
        MASTER.clear()
        MASTER.update(snapshot)
    await save_state()
    log_activity("master", f"به پنل مستر «{snapshot['name']}» متصل شد", "ok")
    return {"ok": True, "master": public_master(), "result": result}


@app.post("/api/master/test")
async def test_master(_=Depends(require_auth)):
    async with MASTER_LOCK:
        snapshot = dict(MASTER)
    if not snapshot.get("url"):
        raise HTTPException(status_code=400, detail="هنوز به پنل مستر وصل نشده‌اید")
    try:
        async with MasterClient(snapshot) as remote:
            ping = await remote.ping()
    except Exception as exc:
        async with MASTER_LOCK:
            if MASTER:
                MASTER["last_check"] = datetime.now().isoformat()
                MASTER["last_error"] = str(exc)
        asyncio.create_task(save_state())
        raise node_http_error(exc)
    async with MASTER_LOCK:
        if MASTER:
            MASTER["last_check"] = datetime.now().isoformat()
            MASTER["last_ok"] = datetime.now().isoformat()
            MASTER["last_error"] = None
    asyncio.create_task(save_state())
    return {"ok": True, "ping": ping, "master": public_master()}


@app.delete("/api/master")
async def disconnect_master(_=Depends(require_auth)):
    async with MASTER_LOCK:
        name = MASTER.get("name") or MASTER.get("url") or "مستر"
        MASTER.clear()
    await save_state()
    log_activity("master", f"اتصال به پنل مستر «{name}» قطع شد", "warn")
    return {"ok": True, "master": public_master()}


async def _master_heartbeat_loop():
    while True:
        await asyncio.sleep(60)
        try:
            async with MASTER_LOCK:
                snapshot = dict(MASTER)
            if not snapshot.get("enabled") or not snapshot.get("url"):
                continue
            payload = {**node_overview_payload(), "api_base": f"https://{CONFIG.get('host', 'localhost')}/api/node/v1"}
            async with MasterClient(snapshot) as remote:
                await remote.heartbeat(payload)
            async with MASTER_LOCK:
                if MASTER.get("url") == snapshot.get("url"):
                    MASTER["last_check"] = datetime.now().isoformat()
                    MASTER["last_ok"] = datetime.now().isoformat()
                    MASTER["last_error"] = None
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            async with MASTER_LOCK:
                if MASTER:
                    MASTER["last_check"] = datetime.now().isoformat()
                    MASTER["last_error"] = str(exc)
            logger.warning(f"Master heartbeat failed: {exc}")


@app.post("/api/rvg-node/heartbeat")
async def receive_node_heartbeat(request: Request, _=Depends(require_auth_or_node)):
    """Accept heartbeats from a child RVG node when this instance is used as master."""
    body = await request.json()
    log_activity("node", f"Heartbeat از نود {body.get('host') or body.get('api_base') or 'نامشخص'}", "info")
    return {"ok": True, "received_at": datetime.now().isoformat()}


@app.get("/api/node/v1")
@app.get("/api/node/v1/info")
async def node_api_info(request: Request, _=Depends(require_node_api)):
    info = public_node_api(request, reveal=False)
    info.pop("token", None)
    return {**info, **node_overview_payload()}


@app.get("/api/node/v1/health")
async def node_api_health(_=Depends(require_node_api)):
    return {"status": "ok", "role": "node", "version": VERSION, "connections": len(connections), "uptime": uptime()}


@app.get("/api/node/v1/overview")
async def node_api_overview(_=Depends(require_node_api)):
    async with LINKS_LOCK:
        return node_overview_payload()


@app.get("/api/node/v1/stats")
async def node_api_stats(_=Depends(require_node_api)):
    async with LINKS_LOCK:
        overview = node_overview_payload()
    return {**overview, "hourly": dict(hourly_traffic), "recent_errors": list(error_logs)[-10:]}


@app.get("/api/node/v1/connections")
async def node_api_connections(_=Depends(require_node_api)):
    async with LINKS_LOCK:
        snap = dict(LINKS)
    items = []
    for conn_id, c in connections.items():
        link = snap.get(c.get("uuid"))
        items.append({
            "id": conn_id,
            "uuid": c.get("uuid"),
            "ip": c.get("ip"),
            "label": link.get("label") if link else None,
            "bytes": c.get("bytes", 0),
            "transport": c.get("transport", "vless-ws"),
            "connected_at": c.get("connected_at"),
        })
    return {"connections": items, "count": len(items)}


@app.get("/api/node/v1/configs")
async def node_api_configs(request: Request, _=Depends(require_node_api)):
    host = get_host(request)
    async with LINKS_LOCK:
        snap = dict(LINKS)
    return {"configs": [serialize_node_config(uid, item, host) for uid, item in snap.items()]}


@app.get("/api/node/v1/configs/{uid}")
async def node_api_get_config(uid: str, request: Request, _=Depends(require_node_api)):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
    if not link:
        raise HTTPException(status_code=404, detail="config not found")
    return serialize_node_config(uid, link, get_host(request))


@app.post("/api/node/v1/configs")
async def node_api_create_config(request: Request, _=Depends(require_node_api)):
    body = await request.json()
    return await node_create_from_body(body, request)


@app.patch("/api/node/v1/configs/{uid}")
async def node_api_update_config(uid: str, request: Request, _=Depends(require_node_api)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="config not found")
        link = LINKS[uid]
        if "active" in body:
            link["active"] = bool(body["active"])
        if "label" in body:
            link["label"] = str(body["label"])[:60]
        if "note" in body:
            link["note"] = str(body["note"])[:200]
        if body.get("reset_usage"):
            link["used_bytes"] = 0
        if "limit_bytes" in body:
            link["limit_bytes"] = max(0, int(body.get("limit_bytes") or 0))
        elif "limit_value" in body:
            lv = float(body.get("limit_value") or 0)
            link["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, body.get("limit_unit") or "GB")
        if "expires_at" in body:
            link["expires_at"] = body.get("expires_at")
        elif "expires_days" in body:
            ed = int(body.get("expires_days") or 0)
            link["expires_at"] = (datetime.now() + timedelta(days=ed)).isoformat() if ed > 0 else None
        if "fingerprint" in body:
            fp = str(body.get("fingerprint") or DEFAULT_FINGERPRINT).strip().lower()
            link["fingerprint"] = fp if fp in FINGERPRINTS else DEFAULT_FINGERPRINT
        if "alpn" in body:
            link["alpn"] = str(body.get("alpn") or "").strip()[:100]
        if "port" in body:
            try:
                p = int(body.get("port") or DEFAULT_PORT)
            except (TypeError, ValueError):
                p = DEFAULT_PORT
            link["port"] = p if (MIN_PORT <= p <= MAX_PORT) else DEFAULT_PORT
        if "ip_limit" in body:
            link["ip_limit"] = max(0, int(body.get("ip_limit") or 0))
        if "speed_limit_bytes" in body:
            link["speed_limit_bytes"] = max(0, int(body.get("speed_limit_bytes") or 0))
        elif "speed_limit_value" in body:
            sv = float(body.get("speed_limit_value") or 0)
            link["speed_limit_bytes"] = 0 if sv <= 0 else parse_speed_to_bytes(sv, body.get("speed_limit_unit") or "MBIT")
        if "protocol" in body and body["protocol"] in PROTOCOLS:
            link["protocol"] = body["protocol"]
    asyncio.create_task(save_state())
    async with LINKS_LOCK:
        updated = dict(LINKS.get(uid) or {})
    return {"ok": True, "config": serialize_node_config(uid, updated, get_host(request)) if updated else None}


@app.delete("/api/node/v1/configs/{uid}")
async def node_api_delete_config(uid: str, _=Depends(require_node_api)):
    if await remove_link(uid) is None:
        raise HTTPException(status_code=404, detail="config not found")
    return {"ok": True}


@app.get("/api/node/v1/subscription")
async def node_api_subscription(request: Request, _=Depends(require_node_api)):
    import base64
    host = get_host(request)
    async with LINKS_LOCK:
        lines = [vless_link_for_link(d, uid, host) for uid, d in LINKS.items() if is_link_allowed(d)]
    content = base64.b64encode("\n".join(lines).encode()).decode()
    return Response(content=content, media_type="text/plain",
                    headers={"profile-title": quote(BRAND), "support-url": "https://t.me/Farajian2004f"})


@app.get("/api/node/v1/subs")
async def node_api_subs(request: Request, _=Depends(require_node_api)):
    host = get_host(request)
    async with SUBS_LOCK:
        snap_subs = dict(SUBS)
    async with LINKS_LOCK:
        snap_links = dict(LINKS)
    result = []
    for sid, s in snap_subs.items():
        link_ids = s.get("link_ids", [])
        result.append({
            "sub_id": sid,
            "name": s.get("name"),
            "desc": s.get("desc", ""),
            "has_password": s.get("password_hash") is not None,
            "links_count": len(link_ids),
            "active_count": sum(1 for lid in link_ids if is_link_allowed(snap_links.get(lid))),
            "public_url": f"https://{host}/p/{s['uuid_key']}",
            "sub_url": f"https://{host}/sub-group/{s['uuid_key']}",
        })
    return {"subs": result}

# ══════════════════════════════════════════════════════════════════════════════
# VLESS Relay — جدا شده به relay_vless.py (دست نخورده)
# ══════════════════════════════════════════════════════════════════════════════

from relay_vless import (
    RELAY_BUF,
    parse_vless_header,
    check_and_use,
    relay_ws_to_tcp,
    relay_tcp_to_ws,
    websocket_tunnel,
)

app.add_api_websocket_route("/ws/{uuid}", websocket_tunnel)

# ══════════════════════════════════════════════════════════════════════════════
# XHTTP — Siz10a XHTTP Ultra (ترابرد جدید، جدا از VLESS/WS، هر ۳ مد)
# ══════════════════════════════════════════════════════════════════════════════
from xhttp_siz10 import router as xhttp_router
app.include_router(xhttp_router)

# ══════════════════════════════════════════════════════════════════════════════
# ربات مدیریت تلگرام (اختیاری — فقط اگه TELEGRAM_BOT_TOKEN ست شده باشه فعال می‌شه)
# ══════════════════════════════════════════════════════════════════════════════
from telegram_bot import start_bot as _tg_start_bot, stop_bot as _tg_stop_bot

# ── HTTP Proxy ────────────────────────────────────────────────────────────────
_HOP = {"connection","keep-alive","proxy-authenticate","proxy-authorization",
        "te","trailers","transfer-encoding","upgrade","content-encoding","content-length"}

@app.api_route("/proxy/{target_url:path}", methods=["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"])
async def http_proxy(target_url: str, request: Request):
    if not target_url.startswith("http"):
        target_url = "https://" + target_url
    try:
        body = await request.body()
        headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP and k.lower() != "host"}
        resp = await http_client.request(method=request.method, url=target_url, headers=headers, content=body)
        stats["total_bytes"] += len(resp.content)
        stats["total_requests"] += 1
        hourly_traffic[now_ir().strftime("%H:00")] += len(resp.content)
        return Response(content=resp.content, status_code=resp.status_code,
                        headers={k: v for k, v in resp.headers.items() if k.lower() not in _HOP})
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "url": target_url, "time": datetime.now().isoformat()})
        raise HTTPException(status_code=502, detail=f"Proxy error: {exc}")

# ── Public sub page ───────────────────────────────────────────────────────────
@app.get("/p/{uuid_key}", response_class=HTMLResponse)
async def public_sub_page(uuid_key: str, request: Request):
    from pages import get_public_page_html
    async with SUBS_LOCK:
        sub = next(({"sub_id": sid, **s} for sid, s in SUBS.items() if s.get("uuid_key") == uuid_key), None)
    if not sub:
        return HTMLResponse("<h2 style='font-family:sans-serif;padding:40px'>گروه پیدا نشد</h2>", status_code=404)
    return HTMLResponse(content=get_public_page_html(uuid_key))

@app.get("/api/public/sub/{uuid_key}")
async def public_sub_data(uuid_key: str, request: Request):
    async with SUBS_LOCK:
        sub_entry = next(((sid, s) for sid, s in SUBS.items() if s.get("uuid_key") == uuid_key), None)
    if not sub_entry:
        raise HTTPException(status_code=404, detail="not found")
    sub_id, sub = sub_entry

    has_pw = sub.get("password_hash") is not None
    if has_pw:
        pw = request.query_params.get("pw", "")
        if hash_password(pw) != sub["password_hash"]:
            return JSONResponse({"locked": True, "name": sub["name"]})

    host = get_host(request)
    link_ids = sub.get("link_ids", [])
    async with LINKS_LOCK:
        snap = dict(LINKS)

    links_out = []
    active_conns = 0
    for lid in link_ids:
        link = snap.get(lid)
        if not link:
            continue
        allowed = is_link_allowed(link)
        conn_count = sum(1 for c in connections.values() if c.get("uuid") == lid)
        active_conns += conn_count
        proto = link.get("protocol", DEFAULT_PROTOCOL)
        links_out.append({
            "uuid": lid,
            "label": link["label"],
            "active": allowed,
            "protocol": proto,
            "used_bytes": link.get("used_bytes", 0),
            "used_fmt": fmt_bytes(link.get("used_bytes", 0)),
            "limit_bytes": link.get("limit_bytes", 0),
            "limit_fmt": "∞" if link.get("limit_bytes", 0) == 0 else fmt_bytes(link["limit_bytes"]),
            "expires_at": link.get("expires_at"),
            "vless_link": vless_link_for_link(link, lid, host),
            "sub_url": f"https://{host}/sub/{lid}",
            "connections": conn_count,
            "ip_limit": link.get("ip_limit", 0),
            "speed_limit_bytes": link.get("speed_limit_bytes", 0),
        })

    total_used = sum(l["used_bytes"] for l in links_out)
    return {
        "locked": False,
        "name": sub["name"],
        "desc": sub.get("desc", ""),
        "sub_url": f"https://{host}/sub-group/{uuid_key}",
        "active_connections": active_conns,
        "total_used_fmt": fmt_bytes(total_used),
        "links": links_out,
    }

# ── HTML Pages (login + dashboard) ───────────────────────────────────────────
from pages import LOGIN_HTML, DASHBOARD_HTML

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/login")
    await ensure_default_link()
    return HTMLResponse(content=DASHBOARD_HTML)

@app.get("/test-ws", response_class=HTMLResponse)
async def test_ws_redirect():
    return HTMLResponse(content="<script>location.href='/dashboard'</script>")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=CONFIG["port"], log_level="info", workers=1)
