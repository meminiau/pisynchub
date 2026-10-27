import os
import json
import time
import secrets
import hashlib
import asyncio
from typing import Optional, List, Dict, Any
import httpx
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(title="PiSyncHub", version="2.0.0")

CONFIG_DIR = os.environ.get("CONFIG_DIR", "/config")
AUTH_FILE = os.path.join(CONFIG_DIR, "auth.json")
NODES_FILE = os.path.join(CONFIG_DIR, "nodes.json")
SESSIONS_FILE = os.path.join(CONFIG_DIR, "sessions.json")
BACKUPS_DIR = os.path.join(CONFIG_DIR, "backups")

os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(BACKUPS_DIR, exist_ok=True)

# Cache Pi-hole v6 SIDs in memory so we never exhaust Pi-hole's 16-seat max_sessions limit
# Format: { "http://192.168.0.2": {"sid": "...", "csrf": "...", "expires": 1700000000} }
PIHOLE_SESSION_CACHE: Dict[str, Dict[str, Any]] = {}
SESSION_LOCK = asyncio.Lock()


# --- Persistent Admin Auth Helpers ---
def load_sessions() -> set:
    if os.path.exists(SESSIONS_FILE):
        try:
            with open(SESSIONS_FILE, "r") as f:
                return set(json.load(f))
        except Exception:
            pass
    return set()


def save_sessions(sessions: set):
    try:
        with open(SESSIONS_FILE, "w") as f:
            json.dump(list(sessions), f)
    except Exception:
        pass


ACTIVE_SESSIONS = load_sessions()


def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000
    )
    return key.hex(), salt


def verify_password(stored_hash: str, salt: str, password: str) -> bool:
    new_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(stored_hash, new_hash)


def is_setup_completed() -> bool:
    return os.path.exists(AUTH_FILE)


def load_auth() -> Optional[Dict[str, Any]]:
    if not is_setup_completed():
        return None
    try:
        with open(AUTH_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return None


def check_auth_token(request: Request) -> bool:
    token = request.cookies.get("pisync_session")
    return bool(token and token in ACTIVE_SESSIONS)


def normalize_url(url: str) -> str:
    u = url.strip().rstrip("/")
    if not u.startswith("http://") and not u.startswith("https://"):
        u = "http://" + u
    for suffix in ["/admin", "/api"]:
        if u.endswith(suffix):
            u = u[: -len(suffix)]
    return u.rstrip("/")


def load_nodes() -> List[Dict[str, Any]]:
    if not os.path.exists(NODES_FILE):
        return []
    try:
        with open(NODES_FILE, "r") as f:
            nodes = json.load(f)
            for n in nodes:
                n["url"] = normalize_url(n.get("url", ""))
            return nodes
    except Exception:
        return []


def save_nodes(nodes: List[Dict[str, Any]]):
    with open(NODES_FILE, "w") as f:
        json.dump(nodes, f, indent=4)


# --- Pydantic Models ---
class AuthModel(BaseModel):
    username: str
    password: str


class NodeModel(BaseModel):
    name: str
    url: str
    api_key: Optional[str] = ""


class SyncRequestModel(BaseModel):
    source_index: int
    target_indices: List[int]
    sync_adlists: bool = True
    sync_domains: bool = True
    run_gravity: bool = True


# --- Core Health & Auth Endpoints ---
@app.get("/api/health")
def health():
    return {"status": "ok", "service": "PiSyncHub", "version": "2.0.0"}


@app.get("/api/auth/status")
def auth_status(request: Request):
    auth_data = load_auth()
    logged_in = check_auth_token(request)
    return {
        "setup_required": not is_setup_completed(),
        "logged_in": logged_in,
        "username": auth_data.get("username") if (auth_data and logged_in) else None,
    }


@app.post("/api/auth/setup")
def auth_setup(creds: AuthModel, response: Response):
    if is_setup_completed():
        raise HTTPException(status_code=400, detail="Setup already completed")
    user = creds.username.strip()
    pwd = creds.password.strip()
    if not user or not pwd:
        raise HTTPException(status_code=400, detail="Username and password required")
    if len(pwd) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    pwd_hash, salt = hash_password(pwd)
    with open(AUTH_FILE, "w") as f:
        json.dump({"username": user, "password_hash": pwd_hash, "salt": salt}, f, indent=4)

    token = secrets.token_hex(32)
    ACTIVE_SESSIONS.add(token)
    save_sessions(ACTIVE_SESSIONS)
    response.set_cookie(key="pisync_session", value=token, httponly=True, samesite="lax")
    return {"status": "success", "username": user}


@app.post("/api/auth/login")
def auth_login(creds: AuthModel, response: Response):
    if not is_setup_completed():
        raise HTTPException(status_code=400, detail="Setup required")
    auth_data = load_auth()
    user = creds.username.strip()
    pwd = creds.password.strip()
    if auth_data and user == auth_data.get("username"):
        if verify_password(auth_data.get("password_hash", ""), auth_data.get("salt", ""), pwd):
            token = secrets.token_hex(32)
            ACTIVE_SESSIONS.add(token)
            save_sessions(ACTIVE_SESSIONS)
            response.set_cookie(key="pisync_session", value=token, httponly=True, samesite="lax")
            return {"status": "success", "username": user}
    raise HTTPException(status_code=401, detail="Invalid username or password")


@app.post("/api/auth/logout")
def auth_logout(request: Request, response: Response):
    token = request.cookies.get("pisync_session")
    if token in ACTIVE_SESSIONS:
        ACTIVE_SESSIONS.remove(token)
        save_sessions(ACTIVE_SESSIONS)
    response.delete_cookie("pisync_session")
    return {"status": "success"}


# --- Node Management Endpoints ---
@app.get("/api/nodes")
def get_nodes(request: Request):
    if not check_auth_token(request):
        raise HTTPException(status_code=401, detail="Authentication required")
    nodes = load_nodes()
    safe_nodes = [{"name": n["name"], "url": n["url"], "has_key": bool(n.get("api_key"))} for n in nodes]
    return {"status": "success", "nodes": safe_nodes}


@app.post("/api/nodes")
def add_node(node: NodeModel, request: Request):
    if not check_auth_token(request):
        raise HTTPException(status_code=401, detail="Authentication required")
    name = node.name.strip()
    url = normalize_url(node.url)
    if not name or not url:
        raise HTTPException(status_code=400, detail="Name and URL are required")
    nodes = load_nodes()
    # Update existing if URL or Name matches, otherwise append
    updated = False
    for existing in nodes:
        if existing["url"] == url or existing["name"].lower() == name.lower():
            existing["name"] = name
            existing["url"] = url
            existing["api_key"] = node.api_key.strip() if node.api_key else existing.get("api_key", "")
            updated = True
            break
    if not updated:
        nodes.append({"name": name, "url": url, "api_key": (node.api_key or "").strip()})
    save_nodes(nodes)
    PIHOLE_SESSION_CACHE.pop(url, None)
    return {"status": "success", "nodes": nodes}


@app.delete("/api/nodes/{index}")
def delete_node(index: int, request: Request):
    if not check_auth_token(request):
        raise HTTPException(status_code=401, detail="Authentication required")
    nodes = load_nodes()
    if 0 <= index < len(nodes):
        removed = nodes.pop(index)
        PIHOLE_SESSION_CACHE.pop(removed.get("url", ""), None)
        save_nodes(nodes)
        return {"status": "success", "removed": removed}
    raise HTTPException(status_code=404, detail="Node index not found")


# --- Pi-hole v6 Session Manager (Prevents HTTP 429 Seat Exhaustion) ---
async def get_pihole_headers(
    client: httpx.AsyncClient, base_url: str, password: str, force_refresh: bool = False
) -> tuple[Dict[str, str], Optional[str]]:
    now = time.time()
    if not force_refresh and base_url in PIHOLE_SESSION_CACHE:
        cached = PIHOLE_SESSION_CACHE[base_url]
        if cached.get("expires", 0) > now and cached.get("sid"):
            sid = cached["sid"]
            headers = {"sid": sid, "X-FTL-SID": sid}
            if cached.get("csrf"):
                headers["X-FTL-CSRF"] = cached["csrf"]
            return headers, None

    if not password:
        return {}, None

    async with SESSION_LOCK:
        # Double-check cache after acquiring lock
        if not force_refresh and base_url in PIHOLE_SESSION_CACHE:
            cached = PIHOLE_SESSION_CACHE[base_url]
            if cached.get("expires", 0) > now and cached.get("sid"):
                sid = cached["sid"]
                return {"sid": sid, "X-FTL-SID": sid}, None

        try:
            r = await client.post(
                f"{base_url}/api/auth",
                json={"password": password},
                timeout=5.0,
            )
            if r.status_code == 200:
                data = r.json()
                session = data.get("session", {})
                sid = session.get("sid")
                csrf = session.get("csrf", "")
                validity = int(session.get("validity", 1800))
                if sid:
                    PIHOLE_SESSION_CACHE[base_url] = {
                        "sid": sid,
                        "csrf": csrf,
                        "expires": now + max(validity - 60, 60),
                    }
                    headers = {"sid": sid, "X-FTL-SID": sid}
                    if csrf:
                        headers["X-FTL-CSRF"] = csrf
                    return headers, None
                return {}, "Invalid password (no SID returned)"
            elif r.status_code == 429:
                return {}, "HTTP 429: Pi-hole API seats exceeded (wait or restart FTL)"
            elif r.status_code == 401:
                return {}, "HTTP 401: Invalid Pi-hole password"
            else:
                return {}, f"Auth HTTP {r.status_code}"
        except Exception as e:
            return {}, f"Connection error: {str(e)}"


async def pihole_get(
    client: httpx.AsyncClient, base_url: str, password: str, endpoint: str
) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    headers, err = await get_pihole_headers(client, base_url, password, force_refresh=False)
    try:
        r = await client.get(f"{base_url}{endpoint}", headers=headers)
        if r.status_code == 401 and password:
            headers, err = await get_pihole_headers(client, base_url, password, force_refresh=True)
            if err:
                return None, err
            r = await client.get(f"{base_url}{endpoint}", headers=headers)
        if r.status_code == 200:
            return r.json(), None
        return None, err or f"HTTP {r.status_code} on {endpoint}"
    except Exception as e:
        return None, str(e)


# --- Comprehensive Pi-hole v6 Node Telemetry Collector ---
async def fetch_node_telemetry(node: Dict[str, Any]) -> Dict[str, Any]:
    base_url = normalize_url(node.get("url", ""))
    password = node.get("api_key", "")
    name = node.get("name", "Pi-hole")

    async with httpx.AsyncClient(timeout=6.0, verify=False, follow_redirects=True) as client:
        summary_data, err = await pihole_get(client, base_url, password, "/api/stats/summary")
        if not summary_data:
            return {
                "name": name,
                "url": base_url,
                "online": False,
                "status": "offline",
                "error": err or "Unreachable",
                "queries": 0,
                "blocked": 0,
                "percent_blocked": 0.0,
                "unique_domains": 0,
                "forwarded": 0,
                "cached": 0,
                "clients_ever_seen": 0,
                "unique_clients": 0,
                "gravity_size": 0,
                "query_types": {},
                "upstreams": [],
                "history": [],
                "client_history": {"timestamps": [], "clients": {}},
                "top_permitted": [],
                "top_blocked": [],
                "top_clients": [],
                "top_clients_blocked": [],
                "version": {},
            }

        # Fetch all rich dashboard datasets concurrently using the cached session
        results = await asyncio.gather(
            pihole_get(client, base_url, password, "/api/history"),
            pihole_get(client, base_url, password, "/api/history/clients"),
            pihole_get(client, base_url, password, "/api/stats/upstreams"),
            pihole_get(client, base_url, password, "/api/stats/top_domains?blocked=false&count=10"),
            pihole_get(client, base_url, password, "/api/stats/top_domains?blocked=true&count=10"),
            pihole_get(client, base_url, password, "/api/stats/top_clients?blocked=false&count=10"),
            pihole_get(client, base_url, password, "/api/stats/top_clients?blocked=true&count=10"),
            pihole_get(client, base_url, password, "/api/dns/blocking"),
            pihole_get(client, base_url, password, "/api/info/version"),
            return_exceptions=True,
        )

        def extract(idx: int) -> Dict[str, Any]:
            res = results[idx]
            if isinstance(res, tuple) and isinstance(res[0], dict):
                return res[0]
            return {}

        hist_raw = extract(0)
        chist_raw = extract(1)
        up_raw = extract(2)
        top_perm_raw = extract(3)
        top_blk_raw = extract(4)
        top_cli_raw = extract(5)
        top_cli_blk_raw = extract(6)
        blocking_raw = extract(7)
        ver_raw = extract(8)

        # 1. Summary & Query Types
        q_data = summary_data.get("queries", {}) if isinstance(summary_data.get("queries"), dict) else summary_data
        c_data = summary_data.get("clients", {}) if isinstance(summary_data.get("clients"), dict) else {}
        g_data = summary_data.get("gravity", {}) if isinstance(summary_data.get("gravity"), dict) else {}

        total_q = int(q_data.get("total", summary_data.get("total_queries", 0)) or 0)
        blocked_q = int(q_data.get("blocked", summary_data.get("blocked_queries", 0)) or 0)
        pct_blocked = float(q_data.get("percent_blocked", summary_data.get("percent_blocked", 0.0)) or 0.0)
        unique_dom = int(q_data.get("unique_domains", 0) or 0)
        forwarded_q = int(q_data.get("forwarded", 0) or 0)
        cached_q = int(q_data.get("cached", 0) or 0)
        query_types = q_data.get("types", {}) if isinstance(q_data.get("types"), dict) else {}

        gravity_size = int(g_data.get("domains_being_blocked", summary_data.get("domains_being_blocked", 0)) or 0)
        active_clients = int(c_data.get("active", 0) or 0)
        total_clients = int(c_data.get("total", 0) or 0)

        # 2. History Timeline (10-min buckets)
        history_list = []
        for h in hist_raw.get("history", []):
            if isinstance(h, dict):
                history_list.append({
                    "timestamp": h.get("timestamp", 0),
                    "total": int(h.get("total", 0) or 0),
                    "cached": int(h.get("cached", 0) or 0),
                    "blocked": int(h.get("blocked", 0) or 0),
                    "forwarded": int(h.get("forwarded", 0) or 0),
                })

        # 3. Client Activity Timeline
        client_history_parsed = {"timestamps": [], "clients": {}}
        if isinstance(chist_raw.get("history"), list) and chist_raw.get("history"):
            client_names = chist_raw.get("clients", {})
            for entry in chist_raw["history"]:
                ts = entry.get("timestamp", 0)
                client_history_parsed["timestamps"].append(ts)
                data_map = entry.get("data", {})
                for cip, count in data_map.items():
                    cname = cip
                    if isinstance(client_names.get(cip), dict):
                        cname = client_names[cip].get("name") or cip
                    elif isinstance(client_names.get(cip), str) and client_names[cip]:
                        cname = client_names[cip]
                    client_history_parsed["clients"].setdefault(cname, []).append(int(count or 0))

        # 4. Upstreams (Include blocklist + cache + upstream servers like Pi-hole v6 chart)
        upstreams_list = []
        if blocked_q > 0:
            upstreams_list.append({"name": "blocklist", "count": blocked_q})
        if cached_q > 0:
            upstreams_list.append({"name": "cache", "count": cached_q})
        for u in up_raw.get("upstreams", []):
            if isinstance(u, dict):
                u_count = int(u.get("count", 0) or 0)
                if u_count > 0:
                    u_name = u.get("name") or u.get("ip") or "upstream"
                    u_port = u.get("port")
                    label = f"{u_name}#{u_port}" if u_port and str(u_port) not in str(u_name) else str(u_name)
                    if label.lower() not in ["blocklist", "cache"]:
                        upstreams_list.append({"name": label, "count": u_count})

        # 5. Top Domains & Clients Helper
        def parse_domains(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
            items = raw.get("domains", raw.get("top_domains", []))
            out = []
            if isinstance(items, list):
                for d in items:
                    if isinstance(d, dict):
                        out.append({"domain": d.get("domain", ""), "count": int(d.get("count", 0) or 0)})
            elif isinstance(items, dict):
                for k, v in items.items():
                    out.append({"domain": k, "count": int(v or 0)})
            return out[:10]

        def parse_clients(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
            items = raw.get("clients", raw.get("top_clients", []))
            out = []
            if isinstance(items, list):
                for c in items:
                    if isinstance(c, dict):
                        label = c.get("name") or c.get("ip") or "unknown"
                        ip = c.get("ip", "")
                        out.append({"client": label, "ip": ip, "count": int(c.get("count", 0) or 0)})
            elif isinstance(items, dict):
                for k, v in items.items():
                    out.append({"client": k, "ip": k, "count": int(v or 0)})
            return out[:10]

        b_status = blocking_raw.get("blocking", summary_data.get("status", "enabled"))
        is_enabled = str(b_status).lower() in ["enabled", "true", "1"]

        # 6. Version Info
        ver_info = {}
        if isinstance(ver_raw.get("version"), dict):
            v = ver_raw["version"]
            ver_info = {
                "core": v.get("core", {}).get("local", {}).get("version", ""),
                "ftl": v.get("ftl", {}).get("local", {}).get("version", ""),
                "web": v.get("web", {}).get("local", {}).get("version", ""),
                "docker": v.get("docker", {}).get("local", ""),
            }

        return {
            "name": name,
            "url": base_url,
            "online": True,
            "status": "enabled" if is_enabled else "disabled",
            "error": None,
            "queries": total_q,
            "blocked": blocked_q,
            "percent_blocked": round(pct_blocked, 1),
            "unique_domains": unique_dom,
            "forwarded": forwarded_q,
            "cached": cached_q,
            "unique_clients": active_clients,
            "clients_ever_seen": total_clients,
            "gravity_size": gravity_size,
            "query_types": query_types,
            "upstreams": upstreams_list,
            "history": history_list,
            "client_history": client_history_parsed,
            "top_permitted": parse_domains(top_perm_raw),
                       "top_blocked": parse_domains(top_blk_raw),
            "top_clients": parse_clients(top_cli_raw),
            "top_clients_blocked": parse_clients(top_cli_blk_raw),
            "version": ver_info,
        }


@app.get("/api/dashboard/stats")
async def get_dashboard_stats(request: Request):
    if not check_auth_token(request):
        raise HTTPException(status_code=401, detail="Authentication required")
    nodes = load_nodes()
    results = await asyncio.gather(*[fetch_node_telemetry(n) for n in nodes])
    return {"status": "success", "nodes": results}


# --- Full Selective Sync Engine (Adlists + Domains + Gravity Rebuild) ---
@app.post("/api/sync")
async def trigger_sync(req: SyncRequestModel, request: Request):
    if not check_auth_token(request):
        raise HTTPException(status_code=401, detail="Authentication required")
    nodes = load_nodes()
    if req.source_index < 0 or req.source_index >= len(nodes):
        raise HTTPException(status_code=400, detail="Invalid source node")

    source = nodes[req.source_index]
    source_url = normalize_url(source["url"])
    source_pwd = source.get("api_key", "")
    sync_log = []

    async with httpx.AsyncClient(timeout=20.0, verify=False, follow_redirects=True) as client:
        s_headers, s_err = await get_pihole_headers(client, source_url, source_pwd)
        if s_err:
            raise HTTPException(status_code=400, detail=f"Source {source['name']} auth failed: {s_err}")

        # 1. Pull Adlists from Source
        lists_data = []
        if req.sync_adlists:
            r_lists, err_l = await pihole_get(client, source_url, source_pwd, "/api/lists")
            if r_lists and "lists" in r_lists:
                lists_data = r_lists["lists"]
                sync_log.append(f"Fetched {len(lists_data)} adlists from {source['name']}.")
            else:
                sync_log.append(f"Warning: Could not read adlists from {source['name']} ({err_l}).")

        # 2. Pull Domains (Allow/Deny Exact & Regex) from Source
        domains_data = []
        if req.sync_domains:
            r_doms, err_d = await pihole_get(client, source_url, source_pwd, "/api/domains")
            if r_doms and "domains" in r_doms:
                domains_data = r_doms["domains"]
                sync_log.append(f"Fetched {len(domains_data)} domain rules from {source['name']}.")
            else:
                sync_log.append(f"Warning: Could not read domains from {source['name']} ({err_d}).")

        # 3. Push to each selected Target Node
        for idx in req.target_indices:
            if idx == req.source_index or idx < 0 or idx >= len(nodes):
                continue
            target = nodes[idx]
            target_url = normalize_url(target["url"])
            target_pwd = target.get("api_key", "")

            t_headers, t_err = await get_pihole_headers(client, target_url, target_pwd)
            if t_err:
                sync_log.append(f"❌ {target['name']}: Auth failed ({t_err})")
                continue

            # Sync Adlists
            if req.sync_adlists and lists_data:
                added_lists = 0
                for item in lists_data:
                    addr = item.get("address")
                    ltype = item.get("type", "block")
                    if not addr:
                        continue
                    try:
                        resp = await client.post(
                            f"{target_url}/api/lists",
                            params={"type": ltype},
                            headers=t_headers,
                            json={
                                "address": addr,
                                "comment": item.get("comment") or "Synced by PiSyncHub",
                                "groups": item.get("groups", [0]),
                                "enabled": bool(item.get("enabled", True)),
                            },
                        )
                        if resp.status_code in [200, 201]:
                            added_lists += 1
                    except Exception:
                        pass
                sync_log.append(f"✔ {target['name']}: Processed {len(lists_data)} adlists ({added_lists} newly added).")

            # Sync Custom Domains
            if req.sync_domains and domains_data:
                added_doms = 0
                for dom in domains_data:
                    d_name = dom.get("domain")
                    d_type = dom.get("type", "allow")
                    d_kind = dom.get("kind", "exact")
                    if not d_name:
                        continue
                    try:
                        resp = await client.post(
                            f"{target_url}/api/domains/{d_type}/{d_kind}",
                            headers=t_headers,
                            json={
                                "domain": d_name,
                                "comment": dom.get("comment") or "Synced by PiSyncHub",
                                "groups": dom.get("groups", [0]),
                                "enabled": bool(dom.get("enabled", True)),
                            },
                        )
                        if resp.status_code in [200, 201]:
                            added_doms += 1
                    except Exception:
                        pass
                sync_log.append(f"✔ {target['name']}: Processed {len(domains_data)} domain rules ({added_doms} newly added).")

            # Trigger Gravity Update on Target
            if req.run_gravity:
                try:
                    g_resp = await client.post(f"{target_url}/api/action/gravity", headers=t_headers)
                    if g_resp.status_code in [200, 202]:
                        sync_log.append(f"🔄 {target['name']}: Gravity update triggered successfully.")
                except Exception as e:
                    sync_log.append(f"⚠️ {target['name']}: Gravity trigger error ({str(e)})")

    return {"status": "success", "log": sync_log}


# --- Static Asset Routes ---
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/icon.png")
def get_icon_png():
    if os.path.exists("icon.png"):
        return FileResponse("icon.png", media_type="image/png")
    return Response(status_code=404)


@app.get("/icon.svg")
def get_icon_svg():
    if os.path.exists("icon.svg"):
        return FileResponse("icon.svg", media_type="image/svg+xml")
    if os.path.exists("icon.png"):
        return FileResponse("icon.png", media_type="image/png")
    return Response(status_code=404)


@app.get("/{full_path:path}")
def serve_frontend(full_path: str):
    static_file = os.path.join("static", full_path)
    if full_path and os.path.exists(static_file) and os.path.isfile(static_file):
        return FileResponse(static_file)
    return FileResponse("static/index.html
