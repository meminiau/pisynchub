import os
import json
import httpx
from datetime import datetime
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="PiSyncHub")
CONFIG_FILE = "/config/nodes.json"
BACKUP_DIR = "/config/backups"

os.makedirs(BACKUP_DIR, exist_ok=True)

if not os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, "w") as f:
        json.dump([], f)

def load_nodes():
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def save_nodes(nodes):
    with open(CONFIG_FILE, "w") as f:
        json.dump(nodes, f, indent=4)

class Node(BaseModel):
    id: str
    name: str
    url: str
    password: str

async def get_sid(client, url, password):
    res = await client.post(f"{url}/api/auth", json={"password": password})
    if res.status_code == 200:
        return res.json().get("session", {}).get("sid")
    return None

@app.get("/api/health")
def health():
    return {"status": "ok"}

@app.get("/api/nodes")
def get_nodes():
    return [{"id": n["id"], "name": n["name"], "url": n["url"]} for n in load_nodes()]

@app.post("/api/nodes")
def add_node(node: Node):
    nodes = load_nodes()
    nodes.append(node.dict())
    save_nodes(nodes)
    return {"status": "success"}

@app.delete("/api/nodes/{node_id}")
def delete_node(node_id: str):
    save_nodes([n for n in load_nodes() if n["id"] != node_id])
    return {"status": "success"}

@app.get("/api/dashboard")
async def dashboard():
    nodes = load_nodes()
    results = []
    async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
        for node in nodes:
            try:
                sid = await get_sid(client, node["url"], node["password"])
                if not sid:
                    results.append({"id": node["id"], "name": node["name"], "status": "offline"})
                    continue
                
                stats = await client.get(f"{node['url']}/api/stats/summary", headers={"sid": sid})
                if stats.status_code == 200:
                    data = stats.json()
                    results.append({
                        "id": node["id"],
                        "name": node["name"],
                        "status": "online",
                        "queries": data.get("queries", {}).get("total", 0),
                        "blocked": data.get("queries", {}).get("blocked", 0),
                        "percent": data.get("queries", {}).get("percent_blocked", 0.0)
                    })
                else:
                    results.append({"id": node["id"], "name": node["name"], "status": "error"})
            except:
                results.append({"id": node["id"], "name": node["name"], "status": "unreachable"})
    return results

@app.post("/api/blocking")
async def toggle_blocking(action: str, time: int = 0):
    async with httpx.AsyncClient(verify=False) as client:
        for node in load_nodes():
            try:
                sid = await get_sid(client, node["url"], node["password"])
                if sid:
                    payload = {"blocking": action}
                    if action == "disable" and time > 0:
                        payload["timer"] = time
                    await client.post(f"{node['url']}/api/dns/blocking", json=payload, headers={"sid": sid})
            except:
                pass
    return {"status": "success"}

@app.get("/api/backup/{node_id}")
async def backup_node(node_id: str):
    node = next((n for n in load_nodes() if n["id"] == node_id), None)
    if not node:
        raise HTTPException(status_code=404)
        
    async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
        sid = await get_sid(client, node["url"], node["password"])
        res = await client.get(f"{node['url']}/api/teleporter", headers={"sid": sid})
        if res.status_code == 200:
            filename = f"{node['name']}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.tar.gz"
            with open(os.path.join(BACKUP_DIR, filename), "wb") as f:
                f.write(res.content)
            return {"status": "success", "file": filename}
    return {"status": "error"}

app.mount("/", StaticFiles(directory="static", html=True), name="static")
