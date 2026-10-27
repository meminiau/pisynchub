import os
import json
import secrets
import hashlib
from typing import Optional
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

# In-memory active session tokens
ACTIVE_SESSIONS = set()

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

def load_nodes():
    if not os.path.exists(NODES_FILE):
        return []
    try:
        with open(NODES_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []

def save_nodes(nodes):
    with open(NODES_FILE, "w") as f:
        json.dump(nodes, f, indent=4)

def check_auth_token(request: Request) -> bool:
    token = request.cookies.get("pisync_session")
    return bool(token and token in ACTIVE_SESSIONS)

# --- Pydantic Request Models ---
class AuthModel(BaseModel):
    username: str
    password: str

class NodeModel(BaseModel):
    name: str
    url: str
    api_key: Optional[str] = ""

# --- System & Health Endpoints ---
@app.get("/api/health")
def health():
    return {"status": "ok", "service": "PiSyncHub"}

# --- Auth Endpoints ---
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
    auth_data = {
        "username": user,
        "password_hash": pwd_hash,
        "salt": salt
    }
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

# --- Node Management ---
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
        raise HTTPException(status_code=400, detail="Node name and URL are required")

    nodes = load_nodes()
    nodes.append({"name": name, "url": url, "api_key": node.api_key.strip()})
    save_nodes(nodes)
    return {"status": "success", "nodes": nodes}

# --- Static File Serving ---
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/icon.svg")
def get_icon():
    icon_path = "icon.svg"
    if os.path.exists(icon_path):
        return FileResponse(icon_path, media_type="image/svg+xml")
    return Response(status_code=404)

@app.get("/{full_path:path}")
def serve_spa(full_path: str):
    static_file = os.path.join("static", full_path)
    if full_path and os.path.exists(static_file) and os.path.isfile(static_file):
        return FileResponse(static_file)
    return FileResponse("static/index.html")
    
