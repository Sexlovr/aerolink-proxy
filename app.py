"""
Aerolink Proxy - Round-robin multi-key proxy for Claude Code upstream provider.

Features:
- Round-robin key rotation
- Automatic retry on 402/auth errors with next key
- Raw passthrough (no request modification except auth header)
- SSE streaming support
- Web dashboard for key management
- Password-protected admin panel
"""

import asyncio
import json
import os
import time
import hashlib
import secrets
import hmac
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional
from html import escape as html_escape

from fastapi import FastAPI, Request, Response, HTTPException, Form
from fastapi.responses import HTMLResponse, StreamingResponse, RedirectResponse
import httpx

# ── Config ──────────────────────────────────────────────────────────────────

UPSTREAM_BASE = os.getenv("UPSTREAM_BASE_URL", "https://capi.aerolink.lat")
_proxy_key = os.getenv("PROXY_KEY", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
CONFIG_PATH = Path(os.getenv("CONFIG_PATH", os.path.expanduser("~/.aerolink-proxy/config.json")))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "5"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "info")

# ── Rate Limiter ────────────────────────────────────────────────────────────

class RateLimiter:
    def __init__(self, max_attempts: int = 5, window: int = 300, max_keys: int = 10000):
        self.max_attempts = max_attempts
        self.window = window
        self.max_keys = max_keys
        self._attempts: dict[str, list[float]] = defaultdict(list)
        self._last_cleanup = time.time()

    def _cleanup(self):
        now = time.time()
        if now - self._last_cleanup < 60:
            return
        self._last_cleanup = now
        empty_keys = [k for k, v in self._attempts.items() if not v or now - v[-1] >= self.window]
        for k in empty_keys:
            del self._attempts[k]
        if len(self._attempts) > self.max_keys:
            oldest = sorted(self._attempts.keys(), key=lambda k: self._attempts[k][-1] if self._attempts[k] else 0)
            for k in oldest[:len(oldest) - self.max_keys]:
                del self._attempts[k]

    def is_limited(self, key: str) -> bool:
        self._cleanup()
        now = time.time()
        self._attempts[key] = [t for t in self._attempts[key] if now - t < self.window]
        return len(self._attempts[key]) >= self.max_attempts

    def record(self, key: str):
        self._attempts[key].append(time.time())

    def remaining(self, key: str) -> int:
        now = time.time()
        self._attempts[key] = [t for t in self._attempts[key] if now - t < self.window]
        return max(0, self.max_attempts - len(self._attempts[key]))

login_limiter = RateLimiter(max_attempts=5, window=300)
proxy_limiter = RateLimiter(max_attempts=30, window=60)

# ── Blocked Paths ───────────────────────────────────────────────────────────

BLOCKED_PREFIXES = (
    "/.env", "/.git", "/wp-", "/phpmy", "/admin/config", "/debug",
    "/.well-known", "/cgi-", "/scripts", "/owa", "/autodiscover",
    "/.ssh", "/.DS_Store", "/server-status", "/server-info",
    "/phpinfo", "/actuator", "/jmx", "/solr",
)

# ── Config Storage ──────────────────────────────────────────────────────────

def _empty_config():
    return {
        "keys": [],
        "stats": {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "retried_requests": 0,
            "total_tokens_used": 0,
        },
        "settings": {
            "max_retries": MAX_RETRIES,
            "timeout": 120,
            "enabled": True,
        },
    }

def load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    cfg = _empty_config()
    save_config(cfg)
    return cfg

def save_config(cfg: dict):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2))
    tmp.replace(CONFIG_PATH)

# ── Key Manager ─────────────────────────────────────────────────────────────

class KeyManager:
    def __init__(self):
        self.config = load_config()
        self._current_index = 0

    def reload(self):
        self.config = load_config()

    def get_all_keys(self) -> list:
        return self.config.get("keys", [])

    def get_next_key(self) -> Optional[dict]:
        keys = [k for k in self.config.get("keys", []) if k.get("enabled", True)]
        if not keys:
            return None
        key = keys[self._current_index % len(keys)]
        self._current_index = (self._current_index + 1) % len(keys)
        return key

    def mark_used(self, key_id: str, tokens: int = 0):
        for k in self.config["keys"]:
            if k["id"] == key_id:
                k["last_used"] = time.time()
                k["total_uses"] = k.get("total_uses", 0) + 1
                k["tokens_used"] = k.get("tokens_used", 0) + tokens
                break
        self.config["stats"]["total_requests"] += 1
        self.config["stats"]["total_tokens_used"] += tokens
        save_config(self.config)

    def mark_error(self, key_id: str, error: str):
        for k in self.config["keys"]:
            if k["id"] == key_id:
                k["last_error"] = error
                k["last_error_time"] = time.time()
                k["error_count"] = k.get("error_count", 0) + 1
                break
        save_config(self.config)

    def mark_success(self, key_id: str):
        for k in self.config["keys"]:
            if k["id"] == key_id:
                k["last_error"] = None
                k["last_error_time"] = None
                break
        self.config["stats"]["successful_requests"] += 1
        save_config(self.config)

    def mark_failed(self):
        self.config["stats"]["failed_requests"] += 1
        save_config(self.config)

    def mark_retried(self):
        self.config["stats"]["retried_requests"] = \
            self.config["stats"].get("retried_requests", 0) + 1
        save_config(self.config)

    def add_key(self, name: str, api_key: str, enabled: bool = True) -> dict:
        key_id = hashlib.sha256(api_key.encode()).hexdigest()[:12]
        key_obj = {
            "id": key_id,
            "name": name,
            "key_preview": api_key[:8] + "..." + api_key[-4:] if len(api_key) > 12 else "***",
            "key_hash": hashlib.sha256(api_key.encode()).hexdigest(),
            "full_key": api_key,
            "enabled": enabled,
            "total_uses": 0,
            "tokens_used": 0,
            "error_count": 0,
            "last_used": None,
            "last_error": None,
            "last_error_time": None,
            "created_at": time.time(),
        }
        self.config["keys"].append(key_obj)
        save_config(self.config)
        return key_obj

    def remove_key(self, key_id: str) -> bool:
        before = len(self.config["keys"])
        self.config["keys"] = [k for k in self.config["keys"] if k["id"] != key_id]
        save_config(self.config)
        return len(self.config["keys"]) < before

    def toggle_key(self, key_id: str) -> bool:
        for k in self.config["keys"]:
            if k["id"] == key_id:
                k["enabled"] = not k.get("enabled", True)
                save_config(self.config)
                return True
        return False

    def get_stats(self) -> dict:
        stats = self.config.get("stats", {})
        stats["active_keys"] = len([k for k in self.config.get("keys", []) if k.get("enabled", True)])
        stats["total_keys"] = len(self.config.get("keys", []))
        return stats

    def update_settings(self, settings: dict):
        self.config["settings"].update(settings)
        save_config(self.config)


key_manager = KeyManager()

# ── Shared HTTP Client ──────────────────────────────────────────────────────

_http_client: Optional[httpx.AsyncClient] = None

async def get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10, read=120, write=10, pool=10),
            follow_redirects=True,
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
        )
    return _http_client

# ── Lifespan ────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(application):
    global _proxy_key
    persisted_key = key_manager.config.get("proxy_key")
    if persisted_key:
        _proxy_key = persisted_key
        print("[STARTUP] Proxy key loaded from config")
    elif _proxy_key:
        key_manager.config["proxy_key"] = _proxy_key
        save_config(key_manager.config)
        print("[STARTUP] Proxy key saved to config")
    else:
        _proxy_key = secrets.token_hex(32)
        key_manager.config["proxy_key"] = _proxy_key
        save_config(key_manager.config)
        print("[STARTUP] Proxy key generated and saved to config")
    await get_http_client()
    yield
    global _http_client
    if _http_client and not _http_client.is_closed:
        await _http_client.aclose()

# ── App ─────────────────────────────────────────────────────────────────────

app = FastAPI(title="Aerolink Proxy", docs_url=None, redoc_url=None, lifespan=lifespan)


# ── Security Middleware ─────────────────────────────────────────────────────

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    path = request.url.path

    # Block common probe paths
    for prefix in BLOCKED_PREFIXES:
        if path.lower().startswith(prefix):
            return Response(status_code=404)

    # Block non-standard methods on proxy
    if path.startswith("/proxy") and request.method not in (
        "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"
    ):
        return Response(status_code=405)

    response = await call_next(request)

    # Strip server headers
    for h in ("server", "x-powered-by"):
        if h in response.headers:
            del response.headers[h]

    # Security headers
    response.headers["x-content-type-options"] = "nosniff"
    response.headers["x-frame-options"] = "DENY"
    response.headers["x-xss-protection"] = "1; mode=block"
    response.headers["referrer-policy"] = "no-referrer"
    response.headers["cache-control"] = "no-store, no-cache, must-revalidate"

    # Log proxy requests only (minimal info)
    if path.startswith("/proxy"):
        print(f"[{request.method}] {path} -> {response.status_code}")

    return response


# ── Auth ────────────────────────────────────────────────────────────────────

def get_proxy_key() -> str:
    return _proxy_key

def verify_proxy_key(request: Request) -> bool:
    # Accept proxy key from either header format
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return hmac.compare_digest(auth[7:], _proxy_key)
    xapi = request.headers.get("x-api-key", "")
    if xapi:
        return hmac.compare_digest(xapi, _proxy_key)
    return False


def verify_admin(request: Request) -> bool:
    cookie = request.cookies.get("admin_session")
    if not cookie:
        return False
    expected = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()
    return hmac.compare_digest(cookie, expected)


# ── Proxy Endpoint ──────────────────────────────────────────────────────────

@app.api_route("/proxy/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def proxy_handler(request: Request, path: str):
    client_ip = request.client.host if request.client else "unknown"

    # Rate limit proxy
    if proxy_limiter.is_limited(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    if not verify_proxy_key(request):
        proxy_limiter.record(client_ip)
        raise HTTPException(status_code=401, detail="Unauthorized")

    cfg = key_manager.config
    if not cfg.get("settings", {}).get("enabled", True):
        raise HTTPException(status_code=503, detail="Proxy is disabled")

    max_retries = cfg.get("settings", {}).get("max_retries", MAX_RETRIES)
    timeout = cfg.get("settings", {}).get("timeout", 120)

    body = await request.body()

    upstream_url = f"{UPSTREAM_BASE}/{path}"
    if request.url.query:
        upstream_url += f"?{request.url.query}"

    headers = {}
    for k, v in request.headers.items():
        if k.lower() not in ("host", "content-length", "transfer-encoding", "x-forwarded-for", "x-api-key", "authorization"):
            headers[k] = v

    errors = []
    client = await get_http_client()

    for attempt in range(max_retries):
        key_obj = key_manager.get_next_key()
        if not key_obj:
            raise HTTPException(status_code=503, detail="No API keys available")

        api_key = key_obj["full_key"]
        key_id = key_obj["id"]

        req_headers = {**headers, "x-api-key": api_key}

        try:
            upstream_resp = await client.request(
                method=request.method,
                url=upstream_url,
                headers=req_headers,
                content=body if body else None,
            )

            if upstream_resp.status_code in (402, 401, 403, 429) or upstream_resp.status_code >= 500:
                error_short = f"HTTP {upstream_resp.status_code}"
                key_manager.mark_error(key_id, error_short)
                errors.append(error_short)

                if attempt < max_retries - 1:
                    key_manager.mark_retried()
                    await asyncio.sleep(0.5)
                    continue
                else:
                    key_manager.mark_failed()
                    raise HTTPException(
                        status_code=upstream_resp.status_code,
                        detail="All keys exhausted"
                    )

            key_manager.mark_used(key_id)

            content_type = upstream_resp.headers.get("content-type", "")
            is_stream = "text/event-stream" in content_type or \
                         "chunked" in upstream_resp.headers.get("transfer-encoding", "")

            resp_headers = {}
            for k, v in upstream_resp.headers.items():
                if k.lower() not in ("transfer-encoding", "content-length", "content-encoding"):
                    resp_headers[k] = v

            if is_stream:
                async def stream_generator(resp=upstream_resp, kid=key_id):
                    try:
                        async for chunk in resp.aiter_bytes():
                            yield chunk
                        key_manager.mark_success(kid)
                    except Exception:
                        key_manager.mark_error(kid, "Stream error")

                return StreamingResponse(
                    stream_generator(),
                    status_code=upstream_resp.status_code,
                    headers=resp_headers,
                    media_type=content_type,
                )
            else:
                key_manager.mark_success(key_id)
                return Response(
                    content=upstream_resp.content,
                    status_code=upstream_resp.status_code,
                    headers=resp_headers,
                    media_type=content_type,
                )

        except httpx.TimeoutException:
            key_manager.mark_error(key_id, "Timeout")
            errors.append("Timeout")
            if attempt < max_retries - 1:
                key_manager.mark_retried()
                continue
            key_manager.mark_failed()
            raise HTTPException(status_code=504, detail="Upstream timeout")

        except httpx.ConnectError:
            key_manager.mark_error(key_id, "Connect error")
            errors.append("Connect error")
            if attempt < max_retries - 1:
                key_manager.mark_retried()
                continue
            key_manager.mark_failed()
            raise HTTPException(status_code=502, detail="Upstream unreachable")

        except HTTPException:
            raise
        except Exception:
            key_manager.mark_error(key_id, "Request error")
            errors.append("Request error")
            if attempt < max_retries - 1:
                key_manager.mark_retried()
                continue
            key_manager.mark_failed()
            raise HTTPException(status_code=500, detail="Request failed")

    raise HTTPException(status_code=500, detail="All retries exhausted")


# ── Admin Dashboard ─────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return RedirectResponse(url="/admin", status_code=302)


@app.get("/admin", response_class=HTMLResponse)
async def admin_login(request: Request):
    if verify_admin(request):
        return RedirectResponse(url="/admin/dashboard", status_code=302)
    return HTMLResponse(ADMIN_LOGIN_HTML)


@app.post("/admin/login")
async def admin_login_post(request: Request, password: str = Form(...)):
    client_ip = request.client.host if request.client else "unknown"

    if login_limiter.is_limited(client_ip):
        remaining_min = int((login_limiter.window - (time.time() - login_limiter._attempts[client_ip][-1])) / 60) + 1
        return HTMLResponse(
            ADMIN_LOGIN_HTML.replace("{{error}}", f"Too many attempts. Try again in {remaining_min}m"),
            status_code=429
        )

    if not ADMIN_PASSWORD or not hmac.compare_digest(password, ADMIN_PASSWORD):
        login_limiter.record(client_ip)
        return HTMLResponse(ADMIN_LOGIN_HTML.replace("{{error}}", "Invalid password"), status_code=401)

    login_limiter._attempts.pop(client_ip, None)
    resp = RedirectResponse(url="/admin/dashboard", status_code=302)
    session = secrets.token_hex(32)
    resp.set_cookie("admin_session", session, httponly=True, secure=True, samesite="strict", max_age=86400)
    return resp


@app.get("/admin/dashboard", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    if not verify_admin(request):
        return RedirectResponse(url="/admin", status_code=302)
    key_manager.reload()
    stats = key_manager.get_stats()
    keys = key_manager.get_all_keys()
    settings = key_manager.config.get("settings", {})
    current_key = get_proxy_key()

    keys_html = ""
    for k in keys:
        status = "enabled" if k.get("enabled", True) else "disabled"
        status_color = "#22c55e" if k.get("enabled", True) else "#ef4444"
        last_used = time.strftime("%Y-%m-%d %H:%M", time.localtime(k["last_used"])) if k.get("last_used") else "Never"
        last_err = html_escape(k.get("last_error", "-") or "-")
        if len(last_err) > 50:
            last_err = last_err[:50] + "..."
        error_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(k["last_error_time"])) if k.get("last_error_time") else "-"

        keys_html += f"""
        <tr>
            <td>{html_escape(k['name'])}</td>
            <td><code>{k['key_preview']}</code></td>
            <td style="color:{status_color};font-weight:600">{status}</td>
            <td>{k.get('total_uses', 0)}</td>
            <td>{k.get('tokens_used', 0):,}</td>
            <td>{k.get('error_count', 0)}</td>
            <td>{last_used}</td>
            <td title="{html_escape(k.get('last_error', '') or '')}">{last_err}</td>
            <td>{error_time}</td>
            <td>
                <button onclick="toggleKey('{k['id']}')" class="btn-sm">{status}</button>
                <button onclick="deleteKey('{k['id']}')" class="btn-sm btn-danger">delete</button>
            </td>
        </tr>"""

    enabled_count = stats.get("active_keys", 0)
    total_count = stats.get("total_keys", 0)
    total_req = stats.get("total_requests", 0)
    success_req = stats.get("successful_requests", 0)
    failed_req = stats.get("failed_requests", 0)
    retried = stats.get("retried_requests", 0)
    total_tokens = stats.get("total_tokens_used", 0)

    return HTMLResponse(ADMIN_DASHBOARD_HTML.replace("{{keys_html}}", keys_html)
                        .replace("{{enabled_count}}", str(enabled_count))
                        .replace("{{total_count}}", str(total_count))
                        .replace("{{total_req}}", str(total_req))
                        .replace("{{success_req}}", str(success_req))
                        .replace("{{failed_req}}", str(failed_req))
                        .replace("{{retried}}", str(retried))
                        .replace("{{total_tokens}}", f"{total_tokens:,}")
                        .replace("{{proxy_key}}", current_key)
                        .replace("{{upstream_url}}", UPSTREAM_BASE)
                        .replace("{{max_retries}}", str(settings.get("max_retries", MAX_RETRIES)))
                        .replace("{{timeout}}", str(settings.get("timeout", 120)))
                        .replace("{{proxy_enabled}}", "checked" if settings.get("enabled", True) else ""))


@app.post("/admin/api/keys")
async def add_key(request: Request):
    if not verify_admin(request):
        raise HTTPException(status_code=401, detail="Unauthorized")
    data = await request.json()
    name = data.get("name", "Unnamed")
    api_key = data.get("key", "").strip()
    enabled = data.get("enabled", True)
    if not api_key:
        raise HTTPException(status_code=400, detail="API key required")
    key_obj = key_manager.add_key(name, api_key, enabled)
    return {"ok": True, "key": {k: v for k, v in key_obj.items() if k != "full_key" and k != "key_hash"}}


@app.delete("/admin/api/keys/{key_id}")
async def delete_key(request: Request, key_id: str):
    if not verify_admin(request):
        raise HTTPException(status_code=401, detail="Unauthorized")
    key_manager.remove_key(key_id)
    return {"ok": True}


@app.post("/admin/api/keys/{key_id}/toggle")
async def toggle_key(request: Request, key_id: str):
    if not verify_admin(request):
        raise HTTPException(status_code=401, detail="Unauthorized")
    key_manager.toggle_key(key_id)
    return {"ok": True}


@app.post("/admin/api/settings")
async def update_settings(request: Request):
    if not verify_admin(request):
        raise HTTPException(status_code=401, detail="Unauthorized")
    data = await request.json()
    key_manager.update_settings(data)
    return {"ok": True}


@app.post("/admin/api/regenerate-proxy-key")
async def regenerate_proxy_key(request: Request):
    if not verify_admin(request):
        raise HTTPException(status_code=401, detail="Unauthorized")
    global _proxy_key
    new_key = secrets.token_hex(32)
    _proxy_key = new_key
    os.environ["PROXY_KEY"] = new_key
    key_manager.config["proxy_key"] = new_key
    save_config(key_manager.config)
    return {"ok": True, "proxy_key": new_key}


@app.get("/admin/api/stats")
async def get_stats(request: Request):
    if not verify_admin(request):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return key_manager.get_stats()


@app.get("/admin/api/config")
async def get_config(request: Request):
    if not verify_admin(request):
        raise HTTPException(status_code=401, detail="Unauthorized")
    cfg = {
        "keys": [
            {k: v for k, v in key_obj.items() if k not in ("full_key", "key_hash")}
            for key_obj in key_manager.config.get("keys", [])
        ],
        "stats": dict(key_manager.config.get("stats", {})),
        "settings": dict(key_manager.config.get("settings", {})),
    }
    return cfg


@app.get("/health")
async def health():
    return {"status": "ok"}


# ── HTML Templates ──────────────────────────────────────────────────────────

ADMIN_LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Aerolink Proxy - Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',-apple-system,sans-serif;background:#0a0a0a;color:#e5e5e5;display:flex;align-items:center;justify-content:center;min-height:100vh}
.login-card{background:#1a1a2e;border:1px solid #333;border-radius:16px;padding:48px;width:100%;max-width:400px;box-shadow:0 25px 50px -12px rgba(0,0,0,.5)}
h1{font-size:24px;margin-bottom:8px;text-align:center}
.subtitle{color:#888;text-align:center;margin-bottom:32px;font-size:14px}
input[type="password"]{width:100%;padding:12px 16px;background:#0a0a0a;border:1px solid #333;border-radius:8px;color:#fff;font-size:16px;margin-bottom:16px}
input:focus{outline:none;border-color:#6366f1}
button{width:100%;padding:12px;background:#6366f1;color:#fff;border:none;border-radius:8px;font-size:16px;cursor:pointer;font-weight:600}
button:hover{background:#5558e6}
.error{color:#ef4444;text-align:center;margin-bottom:16px;font-size:14px}
.logo{font-size:32px;text-align:center;margin-bottom:16px}
</style>
</head>
<body>
<div class="login-card">
<div class="logo">&#x1F680;</div>
<h1>Aerolink Proxy</h1>
<p class="subtitle">Admin Dashboard</p>
<div class="error">{{error}}</div>
<form method="POST" action="/admin/login">
<input type="password" name="password" placeholder="Enter admin password" autofocus required>
<button type="submit">Login</button>
</form>
</div>
</body>
</html>"""

ADMIN_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Aerolink Proxy - Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',-apple-system,sans-serif;background:#0a0a0a;color:#e5e5e5;min-height:100vh}
.nav{background:#111;border-bottom:1px solid #222;padding:16px 24px;display:flex;align-items:center;justify-content:space-between}
.nav h1{font-size:18px;font-weight:600}
.nav .brand{display:flex;align-items:center;gap:12px}
.nav .status{font-size:13px;color:#888}
.nav .status span{color:#22c55e;font-weight:600}
.container{max-width:1200px;margin:0 auto;padding:24px}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:16px;margin-bottom:24px}
.stat-card{background:#1a1a2e;border:1px solid #222;border-radius:12px;padding:20px}
.stat-card .label{font-size:12px;color:#888;text-transform:uppercase;letter-spacing:1px}
.stat-card .value{font-size:28px;font-weight:700;margin-top:4px}
.stat-card .value.green{color:#22c55e}
.stat-card .value.red{color:#ef4444}
.stat-card .value.blue{color:#6366f1}
.section{background:#1a1a2e;border:1px solid #222;border-radius:12px;padding:24px;margin-bottom:24px}
.section h2{font-size:16px;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.section h2::before{content:'';width:3px;height:18px;background:#6366f1;border-radius:2px}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:10px 12px;font-size:12px;color:#888;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #333}
td{padding:10px 12px;font-size:13px;border-bottom:1px solid #1a1a2e}
tr:hover{background:#111}
.btn-sm{padding:4px 10px;border:1px solid #333;border-radius:6px;background:transparent;color:#ccc;cursor:pointer;font-size:11px;margin-right:4px}
.btn-sm:hover{background:#222}
.btn-danger{border-color:#ef4444;color:#ef4444}
.btn-danger:hover{background:#ef444422}
.add-form{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.add-form input,.add-form select{padding:8px 12px;background:#0a0a0a;border:1px solid #333;border-radius:8px;color:#fff;font-size:13px}
.add-form input:focus,.add-form select:focus{outline:none;border-color:#6366f1}
.add-form button{padding:8px 16px;background:#6366f1;color:#fff;border:none;border-radius:8px;cursor:pointer;font-weight:600;font-size:13px}
.add-form button:hover{background:#5558e6}
.proxy-info{background:#111;border:1px solid #222;border-radius:8px;padding:16px;margin-top:12px}
.proxy-info code{background:#0a0a0a;padding:2px 8px;border-radius:4px;font-size:13px}
.proxy-info .row{margin-bottom:8px;font-size:13px}
.proxy-info .label{color:#888;display:inline-block;width:140px}
.toast{position:fixed;bottom:24px;right:24px;background:#22c55e;color:#000;padding:12px 20px;border-radius:8px;font-weight:600;font-size:14px;display:none;z-index:999}
.code-block{background:#0a0a0a;border:1px solid #222;border-radius:8px;padding:16px;font-family:'Fira Code',monospace;font-size:13px;overflow-x:auto;margin-top:8px;word-break:break-all}
.settings-form{display:flex;gap:16px;flex-wrap:wrap;align-items:flex-end}
.settings-form label{display:block;font-size:12px;color:#888;margin-bottom:4px}
.settings-form input{padding:8px 12px;background:#0a0a0a;border:1px solid #333;border-radius:8px;color:#fff;font-size:13px;width:100px}
</style>
</head>
<body>
<div class="nav">
<div class="brand">
<h1>Aerolink Proxy</h1>
<span class="status">Status: <span>Running</span></span>
</div>
</div>
<div class="container">

<div class="stats-grid">
<div class="stat-card"><div class="label">Active Keys</div><div class="value blue">{{enabled_count}} / {{total_count}}</div></div>
<div class="stat-card"><div class="label">Total Requests</div><div class="value">{{total_req}}</div></div>
<div class="stat-card"><div class="label">Successful</div><div class="value green">{{success_req}}</div></div>
<div class="stat-card"><div class="label">Failed</div><div class="value red">{{failed_req}}</div></div>
<div class="stat-card"><div class="label">Retried</div><div class="value blue">{{retried}}</div></div>
<div class="stat-card"><div class="label">Total Tokens</div><div class="value">{{total_tokens}}</div></div>
</div>

<div class="section">
<h2>Proxy Configuration</h2>
<div class="proxy-info">
<div class="row"><span class="label">Upstream URL:</span> <code>{{upstream_url}}</code></div>
<div class="row"><span class="label">Claude Code URL:</span> <code id="proxy-url"></code> <button class="btn-sm" onclick="copyUrl()">Copy</button></div>
<div class="row"><span class="label">Proxy Key:</span> <code id="proxy-key">{{proxy_key}}</code> <button class="btn-sm" onclick="copyKey()">Copy</button> <button class="btn-sm" onclick="regenKey()">Regenerate</button></div>
<div class="row"><span class="label">Max Retries:</span> <code>{{max_retries}}</code></div>
<div class="row"><span class="label">Timeout:</span> <code>{{timeout}}s</code></div>
</div>

<div class="code-block" style="margin-top:12px">
<strong>Add to Claude Code config (~/.claude/settings.json or similar):</strong><br><br>
{<br>
&nbsp;&nbsp;"env": {<br>
&nbsp;&nbsp;&nbsp;&nbsp;"ANTHROPIC_BASE_URL": "<span id="claude-config-url"></span>",<br>
&nbsp;&nbsp;&nbsp;&nbsp;"ANTHROPIC_API_KEY": "<span id="claude-config-key">{{proxy_key}}</span>"<br>
&nbsp;&nbsp;}<br>
}
</div>
</div>

<div class="section">
<h2>Settings</h2>
<div class="settings-form">
<div><label>Max Retries</label><input type="number" id="set-max-retries" value="{{max_retries}}" min="1" max="20"></div>
<div><label>Timeout (s)</label><input type="number" id="set-timeout" value="{{timeout}}" min="10" max="600"></div>
<div><label>Enabled</label><input type="checkbox" id="set-enabled" {{proxy_enabled}} style="margin-top:20px;width:20px;height:20px"></div>
<button onclick="saveSettings()" style="padding:8px 16px;background:#6366f1;color:#fff;border:none;border-radius:8px;cursor:pointer;font-weight:600">Save Settings</button>
</div>
</div>

<div class="section">
<h2>API Keys</h2>
<div class="add-form">
<input type="text" id="key-name" placeholder="Key name (e.g. Key 1)" style="width:200px">
<input type="text" id="key-value" placeholder="Paste API key here" style="flex:1;min-width:300px">
<button onclick="addKey()">Add Key</button>
</div>
<table>
<thead>
<tr><th>Name</th><th>Key</th><th>Status</th><th>Uses</th><th>Tokens</th><th>Errors</th><th>Last Used</th><th>Last Error</th><th>Error Time</th><th>Actions</th></tr>
</thead>
<tbody>
{{keys_html}}
</tbody>
</table>
</div>

</div>

<div class="toast" id="toast"></div>

<script>
const HOST = window.location.origin;

document.getElementById('proxy-url').textContent = HOST + '/proxy';
document.getElementById('claude-config-url').textContent = HOST + '/proxy';
document.getElementById('claude-config-key').textContent = '{{proxy_key}}';

function showToast(msg) {
const t = document.getElementById('toast');
t.textContent = msg;
t.style.display = 'block';
setTimeout(() => t.style.display = 'none', 2500);
}

function copyUrl() {
navigator.clipboard.writeText(HOST + '/proxy');
showToast('URL copied!');
}

function copyKey() {
navigator.clipboard.writeText('{{proxy_key}}');
showToast('Key copied!');
}

async function addKey() {
const name = document.getElementById('key-name').value.trim() || 'Unnamed';
const key = document.getElementById('key-value').value.trim();
if (!key) return alert('Enter an API key');
const res = await fetch('/admin/api/keys', {
method: 'POST',
headers: {'Content-Type': 'application/json'},
body: JSON.stringify({name, key, enabled: true})
});
if (res.ok) { location.reload(); } else { alert('Failed to add key'); }
}

async function deleteKey(id) {
if (!confirm('Delete this key?')) return;
await fetch('/admin/api/keys/' + id, {method: 'DELETE'});
location.reload();
}

async function toggleKey(id) {
await fetch('/admin/api/keys/' + id + '/toggle', {method: 'POST'});
location.reload();
}

async function saveSettings() {
const data = {
max_retries: parseInt(document.getElementById('set-max-retries').value),
timeout: parseInt(document.getElementById('set-timeout').value),
enabled: document.getElementById('set-enabled').checked
};
await fetch('/admin/api/settings', {
method: 'POST',
headers: {'Content-Type': 'application/json'},
body: JSON.stringify(data)
});
showToast('Settings saved!');
}

async function regenKey() {
if (!confirm('Regenerate proxy key? Claude Code configs will need updating.')) return;
const res = await fetch('/admin/api/regenerate-proxy-key', {method: 'POST'});
const data = await res.json();
if (data.ok) { location.reload(); }
}
</script>
</body>
</html>"""


# ── Run ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "7860"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level=LOG_LEVEL)
