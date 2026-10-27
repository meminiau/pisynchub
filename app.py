import os
import json
import secrets
import hashlib
import asyncio
from typing import Optional, List, Dict, Any
import httpx
from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(title="PiSyncHub")

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

# --- Core Health & Auth Endpoints ---
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
    auth_data = {"username": user, "password_hash": pwd_hash, "salt": salt}
    with open(AUTH_FILE, "w") as f:
        json.dump(auth_data, f, indent=4)

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
    raise HTTPException(status_code=401, detail="Invalid username or password")

@app.post("/api/auth/logout")
def auth_logout(request: Request, response: Response):
    token = request.cookies.get("pisync_session")
    if token in ACTIVE_SESSIONS:
        ACTIVE_SESSIONS.remove(token)
    response.delete_cookie("pisync_session")
    return {"status": "success"}

# --- Node Management Endpoints ---
@app.get("/api/nodes")
def get_nodes(request: Request):
    if not check_auth_token(request):
        raise HTTPException(status_code=401, detail="Authentication required")
    return {"status": "success", "nodes": load_nodes()}

@app.post("/api/nodes")
def add_node(node: NodeModel, request: Request):
    if not check_auth_token(request):
        raise HTTPException(status_code=401, detail="Authentication required")
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
        raise HTTPException(status_code=401, detail="Authentication required")
    nodes = load_nodes()
    if 0 <= index < len(nodes):
        removed = nodes.pop(index)
        save_nodes(nodes)
        return {"status": "success", "removed": removed, "nodes": nodes}
    raise HTTPException(status_code=404, detail="Node index not found")

# --- Pi-hole v6 Auth Session Helper ---
async def get_pihole_session(client: httpx.AsyncClient, base_url: str, password: str) -> Optional[str]:
    """Logs into Pi-hole v6 and acquires an active sid token."""
    if not password:
        return None
    try:
        r = await client.post(f"{base_url}/api/auth", json={"password": password}, timeout=4.0)
        if r.status_code == 200:
            data = r.json()
            return data.get("session", {}).get("sid")
    except Exception:
        pass
    return None

# --- Pi-hole v6 Live Status & Teleporter Sync Engine ---
async def fetch_node_stats(node: Dict[str, Any]) -> Dict[str, Any]:
    base_url = node["url"]
    password = node.get("api_key", "")
    
    async with httpx.AsyncClient(timeout=4.0) as client:
        headers = {}
        if password:
            sid = await get_pihole_session(client, base_url, password)
            if sid:
                headers["sid"] = sid

        try:
            resp = await client.get(f"{base_url}/api/stats/summary", headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "name": node["name"],
                    "url": base_url,
                    "online": True,
                    "queries": data.get("queries", {}).get("total", 0),
                    "blocked": data.get("queries", {}).get("blocked", 0),
                    "percent_blocked": round(data.get("queries", {}).get("percent_blocked", 0.0), 1),
                    "gravity_size": data.get("gravity", {}).get("domains_being_blocked", 0),
                    "status": data.get("status", "enabled")
                }
        except Exception:
            pass

    return {
        "name": node["name"],
        "url": base_url,
        "online": False,
        "queries": 0,
        "blocked": 0,
        "percent_blocked": 0.0,
        "gravity_size": 0,
        "status": "offline"
    }

@app.get("/api/dashboard/stats")
async def get_dashboard_stats(request: Request):
    if not check_auth_token(request):
        raise HTTPException(status_code=401, detail="Authentication required")
    nodes = load_nodes()
    tasks = [fetch_node_stats(n) for n in nodes]
    results = await asyncio.gather(*tasks)
    return {"status": "success", "nodes": results}

@app.post("/api/sync")
async def trigger_sync(req: SyncRequestModel, request: Request):
    if not check_auth_token(request):
        raise HTTPException(status_code=401, detail="Authentication required")
    nodes = load_nodes()
    if req.source_index < 0 or req.source_index >= len(nodes):
        raise HTTPException(status_code=400, detail="Invalid source node")
    
    source = nodes[req.source_index]
    sync_results = []
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        # 1. Authenticate with Source
        source_headers = {}
        if source.get("api_key"):
            s_sid = await get_pihole_session(client, source["url"], source["api_key"])
            if s_sid:
                source_headers["sid"] = s_sid

        # 2. Extract source lists
        lists_data = []
        if req.sync_adlists:
            try:
                r = await client.get(f"{source['url']}/api/lists", headers=source_headers)
                if r.status_code == 200:
                    lists_data = r.json().get("lists", [])
                else:
                    sync_results.append(f"Failed to fetch lists from {source['name']} (HTTP {r.status_code})")
            except Exception as e:
                sync_results.append(f"Failed to fetch adlists from {source['name']}: {str(e)}")

        # 3. Push to Target Nodes
        for target_idx in req.target_indices:
            if target_idx == req.source_index or target_idx >= len(nodes):
                continue
            target = nodes[target_idx]
            
            # Authenticate with Target
            target_headers = {}
            if target.get("api_key"):
                t_sid = await get_pihole_session(client, target["url"], target["api_key"])
                if t_sid:
                    target_headers["sid"] = t_sid

            if req.sync_adlists and lists_data:
                try:
                    for adlist in lists_data:
                        await client.post(
                            f"{target['url']}/api/lists",
                            headers=target_headers,
                            json={
                                "address": adlist.get("address"),
                                "comment": adlist.get("comment", "Synced via PiSyncHub"),
                                "enabled": adlist.get("enabled", True)
                            }
                        )
                    sync_results.append(f"Successfully synced {len(lists_data)} adlists to {target['name']}")
                except Exception as ex:
                    sync_results.append(f"Error pushing to {target['name']}: {str(ex)}")

    return {"status": "success", "log": sync_results}

# --- Static File Serving ---
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/icon.svg")
def get_icon_svg():
    if os.path.exists("icon.svg"):
        return FileResponse("icon.svg", media_type="image/svg+xml")
    return Response(status_code=404)

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
    
