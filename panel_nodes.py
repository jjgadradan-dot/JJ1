"""Remote panel adapters and the outbound master client.

RVG itself is a node. The master panel (another RVG or a custom panel)
calls this node's `/api/node/v1` API. When the admin enters a master URL
here, `MasterClient` registers this node on that master and sends heartbeats.

`PanelNodeClient` stays so a *different* RVG instance that is used as the
master can still talk to this node (and to Marzban / 3x-ui).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx


class NodeError(RuntimeError):
    """A safe error that can be displayed to the panel administrator."""


def normalize_base_url(value: str) -> str:
    value = (value or "").strip().rstrip("/")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise NodeError("آدرس پنل باید یک URL معتبر با http یا https باشد")
    if parsed.username or parsed.password:
        raise NodeError("نام کاربری و رمز را داخل URL قرار ندهید")
    return value


def extract_bearer_token(authorization: str = "", extra: str = "") -> str:
    """Pull a token from Authorization: Bearer … or a dedicated header."""
    supplied = (authorization or "").strip()
    if supplied.lower().startswith("bearer "):
        supplied = supplied[7:].strip()
    return supplied or (extra or "").strip()


def _message(response: httpx.Response) -> str:
    try:
        body = response.json()
        if isinstance(body, dict):
            return str(body.get("detail") or body.get("msg") or body.get("message") or response.reason_phrase)
    except Exception:
        pass
    return response.reason_phrase or f"HTTP {response.status_code}"


@dataclass
class PanelNodeClient:
    node: dict[str, Any]
    timeout: float = 15.0

    def __post_init__(self) -> None:
        self.kind = self.node.get("panel_type", "rvg")
        self.base_url = normalize_base_url(self.node.get("base_url", ""))
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(self.timeout, connect=min(self.timeout, 8.0)),
            follow_redirects=True,
            verify=bool(self.node.get("verify_ssl", True)),
            headers={"Accept": "application/json", "User-Agent": "RVG-Node-Manager/1.0"},
        )

    async def __aenter__(self) -> "PanelNodeClient":
        await self.authenticate()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.client.aclose()

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            response = await self.client.request(method, path, **kwargs)
        except httpx.TimeoutException as exc:
            raise NodeError("زمان اتصال به نود تمام شد") from exc
        except httpx.HTTPError as exc:
            raise NodeError(f"اتصال به نود برقرار نشد: {exc}") from exc
        if response.status_code >= 400:
            raise NodeError(f"خطای نود ({response.status_code}): {_message(response)}")
        return response

    async def authenticate(self) -> None:
        auth_type = self.node.get("auth_type", "token")
        token = self.node.get("token", "")
        username = self.node.get("username", "")
        password = self.node.get("password", "")

        if self.kind == "rvg":
            if auth_type == "token":
                if not token:
                    raise NodeError("API Token نود RVG وارد نشده است")
                self.client.headers["Authorization"] = f"Bearer {token}"
            else:
                await self._request("POST", "/api/login", json={"password": password})
        elif self.kind == "marzban":
            if auth_type == "token":
                if not token:
                    raise NodeError("توکن Marzban وارد نشده است")
                self.client.headers["Authorization"] = f"Bearer {token}"
            else:
                response = await self._request(
                    "POST", "/api/admin/token",
                    data={"username": username, "password": password, "grant_type": "password"},
                )
                access_token = response.json().get("access_token")
                if not access_token:
                    raise NodeError("Marzban توکن ورود برنگرداند")
                self.client.headers["Authorization"] = f"Bearer {access_token}"
        elif self.kind == "xui":
            if auth_type == "token":
                if not token:
                    raise NodeError("توکن 3x-ui وارد نشده است")
                self.client.headers["Authorization"] = f"Bearer {token}"
            else:
                response = await self._request("POST", "/login", data={"username": username, "password": password})
                data = response.json()
                if isinstance(data, dict) and data.get("success") is False:
                    raise NodeError(str(data.get("msg") or "ورود به 3x-ui ناموفق بود"))
        else:
            raise NodeError("نوع پنل پشتیبانی نمی‌شود")

    async def overview(self) -> dict[str, Any]:
        if self.kind == "rvg":
            path = "/api/node/v1/overview" if self.node.get("auth_type") == "token" else "/stats"
            data = (await self._request("GET", path)).json()
            return {
                "online": True,
                "version": data.get("version", "RVG"),
                "users": data.get("links_count", 0),
                "active": data.get("active_links", 0),
                "connections": data.get("active_connections", 0),
                "traffic_bytes": data.get("total_bytes", int(float(data.get("total_traffic_mb", 0)) * 1024**2)),
                "uptime": data.get("uptime", "—"),
            }
        if self.kind == "marzban":
            data = (await self._request("GET", "/api/system")).json()
            return {
                "online": True,
                "version": data.get("version", "Marzban"),
                "users": data.get("total_user", data.get("users", 0)),
                "active": data.get("users_active", data.get("active_users", 0)),
                "connections": data.get("online_users", 0),
                "traffic_bytes": data.get("total_traffic", data.get("incoming_bandwidth", 0) + data.get("outgoing_bandwidth", 0)),
                "uptime": data.get("uptime", "—"),
            }
        # 3x-ui APIs differ slightly between forks; list is the most stable endpoint.
        response = (await self._request("GET", "/panel/api/inbounds/list")).json()
        inbounds = response.get("obj", []) if isinstance(response, dict) else []
        clients = 0
        active = 0
        traffic = 0
        for inbound in inbounds or []:
            traffic += int(inbound.get("up", 0) or 0) + int(inbound.get("down", 0) or 0)
            try:
                settings = inbound.get("settings") or "{}"
                settings = json.loads(settings) if isinstance(settings, str) else settings
                members = settings.get("clients", [])
                clients += len(members)
                active += sum(1 for member in members if member.get("enable", True))
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
        return {"online": True, "version": "3x-ui", "users": clients, "active": active,
                "connections": 0, "traffic_bytes": traffic, "uptime": "—", "inbounds": len(inbounds or [])}

    async def list_configs(self) -> list[dict[str, Any]]:
        if self.kind == "rvg":
            path = "/api/node/v1/configs" if self.node.get("auth_type") == "token" else "/api/links"
            data = (await self._request("GET", path)).json()
            return data.get("configs", data.get("links", []))
        if self.kind == "marzban":
            data = (await self._request("GET", "/api/users")).json()
            users = data.get("users", data if isinstance(data, list) else [])
            return [{"id": u.get("username"), "label": u.get("username"), "active": u.get("status") == "active",
                     "used_bytes": u.get("used_traffic", 0), "limit_bytes": u.get("data_limit", 0),
                     "subscription_url": u.get("subscription_url") or u.get("subscription_url_path"), "native": u}
                    for u in users]
        data = (await self._request("GET", "/panel/api/inbounds/list")).json()
        items = data.get("obj", []) if isinstance(data, dict) else []
        return [{"id": str(i.get("id")), "label": i.get("remark") or f"Inbound {i.get('id')}",
                 "active": i.get("enable", True), "used_bytes": int(i.get("up", 0) or 0) + int(i.get("down", 0) or 0),
                 "limit_bytes": i.get("total", 0), "native": i} for i in items or []]

    async def create_config(self, payload: dict[str, Any]) -> Any:
        if self.kind == "rvg":
            path = "/api/node/v1/configs" if self.node.get("auth_type") == "token" else "/api/links"
        elif self.kind == "marzban":
            path = "/api/user"
        else:
            path = "/panel/api/inbounds/add"
        return (await self._request("POST", path, json=payload)).json()

    async def update_config(self, config_id: str, payload: dict[str, Any]) -> Any:
        if self.kind == "rvg":
            path = f"/api/node/v1/configs/{config_id}" if self.node.get("auth_type") == "token" else f"/api/links/{config_id}"
            method = "PATCH"
        elif self.kind == "marzban":
            path, method = f"/api/user/{config_id}", "PUT"
        else:
            path, method = f"/panel/api/inbounds/update/{config_id}", "POST"
        return (await self._request(method, path, json=payload)).json()

    async def delete_config(self, config_id: str) -> Any:
        if self.kind == "rvg":
            path = f"/api/node/v1/configs/{config_id}" if self.node.get("auth_type") == "token" else f"/api/links/{config_id}"
        elif self.kind == "marzban":
            path = f"/api/user/{config_id}"
        else:
            path = f"/panel/api/inbounds/del/{config_id}"
        return (await self._request("DELETE" if self.kind != "xui" else "POST", path)).json()


@dataclass
class MasterClient:
    """Outbound client used by this RVG node to talk to its master panel."""

    master: dict[str, Any]
    timeout: float = 15.0

    def __post_init__(self) -> None:
        self.kind = (self.master.get("panel_type") or "rvg").lower()
        self.base_url = normalize_base_url(self.master.get("url") or self.master.get("base_url") or "")
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(self.timeout, connect=min(self.timeout, 8.0)),
            follow_redirects=True,
            verify=bool(self.master.get("verify_ssl", True)),
            headers={"Accept": "application/json", "User-Agent": "RVG-Node/1.0"},
        )

    async def __aenter__(self) -> "MasterClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.client.aclose()

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            response = await self.client.request(method, path, **kwargs)
        except httpx.TimeoutException as exc:
            raise NodeError("زمان اتصال به پنل مستر تمام شد") from exc
        except httpx.HTTPError as exc:
            raise NodeError(f"اتصال به پنل مستر برقرار نشد: {exc}") from exc
        if response.status_code >= 400:
            raise NodeError(f"خطای مستر ({response.status_code}): {_message(response)}")
        return response

    async def ping(self) -> dict[str, Any]:
        """Reachability check that works for RVG and generic masters."""
        if self.kind == "rvg":
            data = (await self._request("GET", "/health")).json()
            return {"online": True, "kind": "rvg", "status": data.get("status", "ok"), "uptime": data.get("uptime")}
        path = self.master.get("health_path") or "/health"
        response = await self._request("GET", path)
        try:
            body = response.json()
        except Exception:
            body = {"raw": response.text[:200]}
        return {"online": True, "kind": self.kind, "status": "ok", "body": body}

    async def login_rvg(self) -> None:
        password = self.master.get("password") or ""
        if not password:
            raise NodeError("رمز پنل مستر وارد نشده است")
        await self._request("POST", "/api/login", json={"password": password})

    async def register(self, node_public_url: str, node_token: str, node_name: str) -> dict[str, Any]:
        """Register this node on an RVG master so the master can pull the API."""
        if self.kind != "rvg":
            ping = await self.ping()
            return {"registered": False, "ping": ping, "note": "پنل عمومی فقط پینگ می‌شود"}
        auth_type = self.master.get("auth_type", "credentials")
        if auth_type == "token" and self.master.get("token"):
            self.client.headers["Authorization"] = f"Bearer {self.master['token']}"
        else:
            await self.login_rvg()
        payload = {
            "name": node_name[:80],
            "base_url": normalize_base_url(node_public_url),
            "panel_type": "rvg",
            "auth_type": "token",
            "token": node_token,
            "verify_ssl": bool(self.master.get("verify_ssl", True)),
            "enabled": True,
        }
        data = (await self._request("POST", "/api/nodes", json=payload)).json()
        return {"registered": True, "node": data.get("node", data)}

    async def heartbeat(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Tell the master this node is alive. Falls back to a health ping."""
        path = self.master.get("heartbeat_path") or "/api/rvg-node/heartbeat"
        try:
            data = (await self._request("POST", path, json=payload)).json()
            return {"ok": True, "via": "heartbeat", "response": data}
        except NodeError:
            ping = await self.ping()
            return {"ok": True, "via": "ping", "response": ping}
