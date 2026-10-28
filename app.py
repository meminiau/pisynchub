import os
import io
import json
import secrets
import hashlib
import asyncio
from datetime import datetime
from typing import Optional, List, Dict, Any
import httpx
from fastapi import FastAPI, Request, Response, HTTPException, UploadFile, File, Form, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

app = FastAPI(title="PiSyncHub", version="1.0.0")

CONFIG_DIR = os.environ.get("CONFIG_DIR", "/config")
AUTH_FILE = os.path.join(CONFIG_DIR, "auth.json")
NODES_FILE = os.path.join(CONFIG_DIR, "nodes.json")
BACKUPS_DIR = os.path.join(CONFIG_DIR, "backups")

os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(BACKUPS_DIR, exist_ok=True)

ACTIVE_SESSIONS = set()

# --- Auth Helpers ---
def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
    return key.hex(), salt

def verify_password(stored_hash: str, salt: str, password: str) -> bool:
    new_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(stored_hash, new_hash)

def is_setup_completed() -> bool:
    return os.path.exists(AUTH_FILE)

def load_auth():
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

def load_nodes() -> List[Dict[str, Any]]:
    if not os.path.exists(NODES_FILE):
        return []
    try:
        with open(NODES_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []

def save_nodes(nodes: List[Dict[str, Any]]):
    with open(NODES_FILE, "w") as f:
        json.dump(nodes, f, indent=4)

# --- Models ---
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

# --- Auth Endpoints ---
@app.get("/api/health")
def health():
    return {"status": "ok", "service": "PiSyncHub"}

@app.get("/api/auth/status")
def auth_status(request: Request):
    auth_data = load_auth()
    return {
        "setup_required": not is_setup_completed(),
        "logged_in": check_auth_token(request),
        "username": auth_data.get("username") if auth_data and check_auth_token(request) else None
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
        if verify_password(auth_data.get("password_hash"), auth_data.get("salt"), pwd):
            token = secrets.token_hex(32)
            ACTIVE_SESSIONS.add(token)
            response.set_cookie(key="pisync_session", value=token, httponly=True, samesite="lax")
            return {"status": "success", "username": user}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/api/auth/logout")
def auth_logout(request: Request, response: Response):
    token = request.cookies.get("pisync_session")
    if token in ACTIVE_SESSIONS:
        ACTIVE_SESSIONS.remove(token)
    response.delete_cookie("pisync_session")
    return {"status": "success"}

# --- Node Endpoints ---
@app.get("/api/nodes")
def get_nodes(request: Request):
    if not check_auth_token(request):
        raise HTTPException(status_code=401, detail="Auth required")
    return {"status": "success", "nodes": load_nodes()}

@app.post("/api/nodes")
def add_node(node: NodeModel, request: Request):
    if not check_auth_token(request):
        raise HTTPException(status_code=401, detail="Auth required")
    name = node.name.strip()
    url = node.url.strip().rstrip("/")
    if not name or not url:
        raise HTTPException(status_code=400, detail="Name and URL are required")
    nodes = load_nodes()
    nodes.append({"name": name, "url": url, "api_key": node.api_key.strip()})
    save_nodes(nodes)
    return {"status": "success", "nodes": nodes}

@app.delete("/api/nodes/{index}")
def delete_node(index: int, request: Request):
    if not check_auth_token(request):
        raise HTTPException(status_code=401, detail="Auth required")
    nodes = load_nodes()
    if 0 <= index < len(nodes):
        removed = nodes.pop(index)
        save_nodes(nodes)
        return {"status": "success", "removed": removed, "nodes": nodes}
    raise HTTPException(status_code=404, detail="Node index not found")

# --- Pi-hole v6 Session Engine ---
async def get_pihole_session(client: httpx.AsyncClient, base_url: str, password: str) -> Optional[str]:
    if not password:
        return None
    try:
        r = await client.post(f"{base_url}/api/auth", json={"password": password}, timeout=4.0)
        if r.status_code == 200:
            return r.json().get("session", {}).get("sid")
    except Exception:
        pass
    return None

async def fetch_node_stats(node: Dict[str, Any]) -> Dict[str, Any]:
    base_url = node.get("url", "").rstrip("/")
    password = node.get("api_key", "")

    async with httpx.AsyncClient(timeout=6.0) as client:
        headers = {}
        if password:
            sid = await get_pihole_session(client, base_url, password)
            if sid:
                headers["sid"] = sid
                headers["X-FTL-SID"] = sid

        try:
            resp = await client.get(f"{base_url}/api/stats/summary", headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                q_data = data.get("queries", {}) if isinstance(data.get("queries"), dict) else data
                total_q = q_data.get("total", data.get("total_queries", 0))
                blocked_q = q_data.get("blocked", data.get("blocked_queries", 0))
                pct = q_data.get("percent_blocked", data.get("percent_blocked", 0.0))

                g_data = data.get("gravity", {}) if isinstance(data.get("gravity"), dict) else {}
                gravity_size = g_data.get("domains_being_blocked", data.get("domains_being_blocked", 0))

                # Optional analytics endpoints
                qtypes = {}
                upstreams = {}
                top_items = {}
                try:
                    qt_r = await client.get(f"{base_url}/api/stats/querytypes", headers=headers)
                    if qt_r.status_code == 200:
                        qtypes = qt_r.json().get("querytypes", {})
                except Exception:
                    pass

                try:
                    up_r = await client.get(f"{base_url}/api/stats/upstreams", headers=headers)
                    if up_r.status_code == 200:
                        upstreams = up_r.json().get("upstreams", {})
                except Exception:
                    pass

                try:
                    top_r = await client.get(f"{base_url}/api/stats/top_items", headers=headers)
                    if top_r.status_code == 200:
                        top_items = top_r.json()
                except Exception:
                    pass

                return {
                    "name": node.get("name", "Pi-hole"),
                    "url": base_url,
                    "online": True,
                    "queries": total_q,
                    "blocked": blocked_q,
                    "percent_blocked": round(float(pct), 1) if pct else 0.0,
                    "gravity_size": gravity_size,
                    "querytypes": qtypes,
                    "upstreams": upstreams,
                    "top_items": top_items,
                    "status": "online"
                }
        except Exception:
            pass

    return {
        "name": node.get("name", "Pi-hole"),
        "url": base_url,
        "online": False,
        "queries": 0,
        "blocked": 0,
        "percent_blocked": 0.0,
        "gravity_size": 0,
        "querytypes": {},
        "upstreams": {},
        "top_items": {},
        "status": "offline"
    }

@app.get("/api/dashboard/stats")
async def get_dashboard_stats(request: Request):
    if not check_auth_token(request):
        raise HTTPException(status_code=401, detail="Auth required")
    nodes = load_nodes()
    tasks = [fetch_node_stats(n) for n in nodes]
    results = await asyncio.gather(*tasks)
    return {"status": "success", "nodes": results}

# --- Teleporter Backup & Restore Engine ---
@app.get("/api/backups")
def list_backups(request: Request):
    if not check_auth_token(request):
        raise HTTPException(status_code=401, detail="Auth required")
    files = []
    for f in sorted(os.listdir(BACKUPS_DIR), reverse=True):
        if f.endswith(".zip"):
            path = os.path.join(BACKUPS_DIR, f)
            files.append({
                "filename": f,
                "size_kb": round(os.path.getsize(path) / 1024, 1),
                "created": datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S")
            })
    return {"status": "success", "backups": files}

@app.post("/api/backup/node/{index}")
async def backup_node(index: int, request: Request):
    if not check_auth_token(request):
        raise HTTPException(status_code=401, detail="Auth required")
    nodes = load_nodes()
    if index < 0 or index >= len(nodes):
        raise HTTPException(status_code=404, detail="Node not found")
    node = nodes[index]

    async with httpx.AsyncClient(timeout=30.0) as client:
        headers = {}
        if node.get("api_key"):
            sid = await get_pihole_session(client, node["url"], node["api_key"])
            if sid:
                headers["sid"] = sid
                headers["X-FTL-SID"] = sid

        try:
            r = await client.get(f"{node['url']}/api/teleporter", headers=headers)
            if r.status_code == 200:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                clean_name = "".join(c for c in node["name"] if c.isalnum() or c in ("-", "_"))
                fname = f"teleporter_{clean_name}_{ts}.zip"
                dest = os.path.join(BACKUPS_DIR, fname)
                with open(dest, "wb") as f:
                    f.write(r.content)
                return {"status": "success", "filename": fname, "size": len(r.content)}
            raise HTTPException(status_code=r.status_code, detail=f"Pi-hole returned HTTP {r.status_code}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to fetch teleporter archive: {str(e)}")

@app.get("/api/backup/download/{filename}")
def download_backup(filename: str, request: Request):
    if not check_auth_token(request):
        raise HTTPException(status_code=401, detail="Auth required")
    safe_name = os.path.basename(filename)
    path = os.path.join(BACKUPS_DIR, safe_name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(path, media_type="application/zip", filename=safe_name)

@app.post("/api/restore/node/{index}")
async def restore_node(index: int, request: Request, file: UploadFile = File(...)):
    if not check_auth_token(request):
        raise HTTPException(status_code=401, detail="Auth required")
    nodes = load_nodes()
    if index < 0 or index >= len(nodes):
        raise HTTPException(status_code=404, detail="Node not found")
    node = nodes[index]

    content = await file.read()
    async with httpx.AsyncClient(timeout=30.0) as client:
        headers = {}
        if node.get("api_key"):
            sid = await get_pihole_session(client, node["url"], node["api_key"])
            if sid:
                headers["sid"] = sid
                headers["X-FTL-SID"] = sid

        try:
            files_payload = {"file": (file.filename or "teleporter.zip", io.BytesIO(content), "application/zip")}
            r = await client.post(f"{node['url']}/api/teleporter", headers=headers, files=files_payload)
            if r.status_code in (200, 204):
                return {"status": "success", "detail": f"Restored Teleporter archive to {node['name']}"}
            return JSONResponse(status_code=r.status_code, content={"detail": r.text})
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to push restore: {str(e)}")

# --- Sync Engine ---
@app.post("/api/sync")
async def trigger_sync(req: SyncRequestModel, request: Request):
    if not check_auth_token(request):
        raise HTTPException(status_code=401, detail="Auth required")
    nodes = load_nodes()
    if req.source_index < 0 or req.source_index >= len(nodes):
        raise HTTPException(status_code=400, detail="Invalid source node")

    source = nodes[req.source_index]
    sync_results = []

    async with httpx.AsyncClient(timeout=15.0) as client:
        s_headers = {}
        if source.get("api_key"):
            s_sid = await get_pihole_session(client, source["url"], source["api_key"])
            if s_sid:
                s_headers["sid"] = s_sid
                s_headers["X-FTL-SID"] = s_sid

        lists_data = []
        if req.sync_adlists:
            try:
                r = await client.get(f"{source['url']}/api/lists", headers=s_headers)
                if r.status_code == 200:
                    lists_data = r.json().get("lists", [])
                else:
                    sync_results.append(f"Lists fetch failed on {source['name']} ({r.status_code})")
            except Exception as e:
                sync_results.append(f"Lists fetch error: {str(e)}")

        domains_data = []
        if req.sync_domains:
            try:
                r = await client.get(f"{source['url']}/api/domains", headers=s_headers)
                if r.status_code == 200:
                    domains_data = r.json().get("domains", [])
                else:
                    sync_results.append(f"Domains fetch failed on {source['name']} ({r.status_code})")
            except Exception as e:
                sync_results.append(f"Domains fetch error: {str(e)}")

        for t_idx in req.target_indices:
            if t_idx == req.source_index or t_idx >= len(nodes):
                continue
            target = nodes[t_idx]
            t_headers = {}
            if target.get("api_key"):
                t_sid = await get_pihole_session(client, target["url"], target["api_key"])
                if t_sid:
                    t_headers["sid"] = t_sid
                    t_headers["X-FTL-SID"] = t_sid

            if req.sync_adlists and lists_data:
                try:
                    for item in lists_data:
                        await client.post(
                            f"{target['url']}/api/lists",
                            headers=t_headers,
                            json={
                                "address": item.get("address"),
                                "comment": item.get("comment", "PiSyncHub Sync"),
                                "enabled": item.get("enabled", True)
                            }
                        )
                    sync_results.append(f"Synced {len(lists_data)} adlists to {target['name']}")
                except Exception as ex:
                    sync_results.append(f"Adlists error on {target['name']}: {str(ex)}")

            if req.sync_domains and domains_data:
                try:
                    for d in domains_data:
                        await client.post(
                            f"{target['url']}/api/domains",
                            headers=t_headers,
                            json={
                                "domain": d.get("domain"),
                                "type": d.get("type", "allow"),
                                "kind": d.get("kind", "exact"),
                                "comment": d.get("comment", "PiSyncHub Sync"),
                                "enabled": d.get("enabled", True)
                            }
                        )
                    sync_results.append(f"Synced {len(domains_data)} domains to {target['name']}")
                except Exception as ex:
                    sync_results.append(f"Domains error on {target['name']}: {str(ex)}")

    return {"status": "success", "log": sync_results}

# --- Static File Routing ---
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/icon.png")
def get_icon_png():
    if os.path.exists("icon.png"):
        return FileResponse("icon.png", media_type="image/png")
    return Response(status_code=404)

@app.get("/{full_path:path}")
def serve_frontend(full_path: str):
    static_file = os.path.join("static", full_path)
    if full_path and os.path.exists(static_file) and os.path.isfile(static_file):
        return FileResponse(static_file)
    return FileResponse("static/index.html")
            
