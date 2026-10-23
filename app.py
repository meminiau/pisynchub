import os
import re
import json
import glob
import httpx
from datetime import datetime
from typing import List
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

app = FastAPI(title="PiSyncHub")

CONFIG_DIR = os.environ.get("CONFIG_DIR", "/config")
CONFIG_FILE = os.path.join(CONFIG_DIR, "nodes.json")
BACKUP_DIR = os.path.join(CONFIG_DIR, "backups")
MAX_BACKUPS_PER_NODE = 10

os.makedirs(BACKUP_DIR, exist_ok=True)

if not os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, "w") as f:
        json.dump([], f)


def load_nodes():
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []


def save_nodes(nodes):
    with open(CONFIG_FILE, "w") as f:
        json.dump(nodes, f, indent=4)


def safe_name(val: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "_", val)


def prune_backups(node_prefix: str):
    pattern = os.path.join(BACKUP_DIR, f"{node_prefix}_backup_*.tar.gz")
    files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    for old_file in files[MAX_BACKUPS_PER_NODE:]:
        try:
            os.remove(old_file)
        except OSError:
            pass


class NodeCreate(BaseModel):
    id: str
    name: str
    url: str
    password: str


class BlockingRequest(BaseModel):
    blocking: bool
    timer: int = 0
    node_ids: List[str] = []


class TeleportOptions(BaseModel):
    adlists: bool = True
    domains: bool = True
    groups: bool = True
    local_dns: bool = True
    upstream_dns: bool = True
    system_dhcp: bool = False
    run_gravity: bool = True


class TeleportRequest(BaseModel):
    source_id: str
    target_ids: List[str]
    options: TeleportOptions


async def pihole_login(client: httpx.AsyncClient, url: str, password: str):
    res = await client.post(f"{url}/api/auth", json={"password": password})
    if res.status_code == 200:
        data = res.json()
        return data.get("session", {}).get("sid")
    return None


async def pihole_logout(client: httpx.AsyncClient, url: str, sid: str):
    if not sid:
        return
    try:
        await client.delete(f"{url}/api/auth", headers={"X-FTL-SID": sid, "sid": sid})
    except Exception:
        pass


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/nodes")
def get_nodes():
    return [{"id": n["id"], "name": n["name"], "url": n["url"]} for n in load_nodes()]


@app.post("/api/nodes")
def add_or_update_node(node: NodeCreate):
    nodes = load_nodes()
    clean_id = safe_name(node.id.lower())
    clean_url = node.url.strip().rstrip("/")
    nodes = [n for n in nodes if n["id"] != clean_id]
    nodes.append({
        "id": clean_id,
        "name": node.name.strip(),
        "url": clean_url,
        "password": node.password
    })
    save_nodes(nodes)
    return {"status": "success", "id": clean_id}


@app.delete("/api/nodes/{node_id}")
def delete_node(node_id: str):
    save_nodes([n for n in load_nodes() if n["id"] != node_id])
    return {"status": "success"}


@app.get("/api/dashboard")
async def get_dashboard():
    nodes = load_nodes()
    node_results = []
    totals = {
        "queries": 0,
        "blocked": 0,
        "percent_blocked": 0.0,
        "domains_being_blocked": 0,
        "online_nodes": 0,
        "total_nodes": len(nodes)
    }

    async with httpx.AsyncClient(verify=False, timeout=6.0) as client:
        for node in nodes:
            sid = None
            try:
                sid = await pihole_login(client, node["url"], node["password"])
                if not sid:
                    node_results.append({
                        "id": node["id"],
                        "name": node["name"],
                        "url": node["url"],
                        "status": "auth_failed",
                        "blocking": "unknown",
                        "queries": 0,
                        "blocked": 0,
                        "percent": 0.0,
                        "domains_blocked": 0,
                        "clients": 0
                    })
                    continue

                headers = {"X-FTL-SID": sid, "sid": sid}
                stats_res = await client.get(f"{node['url']}/api/stats/summary", headers=headers)
                block_res = await client.get(f"{node['url']}/api/dns/blocking", headers=headers)

                if stats_res.status_code == 200:
                    sdata = stats_res.json()
                    q = sdata.get("queries", {})
                    g = sdata.get("gravity", {})
                    c = sdata.get("clients", {})

                    b_state = "enabled"
                    b_timer = None
                    if block_res.status_code == 200:
                        bdata = block_res.json()
                        raw_b = bdata.get("blocking", "enabled")
                        b_state = "enabled" if raw_b in (True, "enabled") else "disabled"
                        b_timer = bdata.get("timer")

                    q_total = int(q.get("total", 0))
                    q_blocked = int(q.get("blocked", 0))
                    q_pct = float(q.get("percent_blocked", 0.0))
                    dom_blocked = int(g.get("domains_being_blocked", 0))
                    active_clients = int(c.get("active", 0))

                    totals["queries"] += q_total
                    totals["blocked"] += q_blocked
                    totals["domains_being_blocked"] = max(totals["domains_being_blocked"], dom_blocked)
                    totals["online_nodes"] += 1

                    node_results.append({
                        "id": node["id"],
                        "name": node["name"],
                        "url": node["url"],
                        "status": "online",
                        "blocking": b_state,
                        "timer": b_timer,
                        "queries": q_total,
                        "blocked": q_blocked,
                        "percent": q_pct,
                        "domains_blocked": dom_blocked,
                        "clients": active_clients
                    })
                else:
                    node_results.append({
                        "id": node["id"],
                        "name": node["name"],
                        "url": node["url"],
                        "status": "error",
                        "blocking": "unknown",
                        "queries": 0,
                        "blocked": 0,
                        "percent": 0.0,
                        "domains_blocked": 0,
                        "clients": 0
                    })
            except Exception:
                node_results.append({
                    "id": node["id"],
                    "name": node["name"],
                    "url": node["url"],
                    "status": "unreachable",
                    "blocking": "unknown",
                    "queries": 0,
                    "blocked": 0,
                    "percent": 0.0,
                    "domains_blocked": 0,
                    "clients": 0
                })
            finally:
                await pihole_logout(client, node["url"], sid)

    if totals["queries"] > 0:
        totals["percent_blocked"] = round((totals["blocked"] / totals["queries"]) * 100, 2)

    return {"totals": totals, "nodes": node_results}


@app.post("/api/blocking")
async def set_blocking(req: BlockingRequest):
    nodes = load_nodes()
    targets = [n for n in nodes if not req.node_ids or n["id"] in req.node_ids]
    results = []

    async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
        for node in targets:
            sid = None
            try:
                sid = await pihole_login(client, node["url"], node["password"])
                if not sid:
                    results.append({"id": node["id"], "status": "auth_failed"})
                    continue
                headers = {"X-FTL-SID": sid, "sid": sid}
                payload = {"blocking": req.blocking}
                if not req.blocking and req.timer > 0:
                    payload["timer"] = req.timer
                res = await client.post(f"{node['url']}/api/dns/blocking", json=payload, headers=headers)
                results.append({"id": node["id"], "status": "ok" if res.status_code == 200 else "error"})
            except Exception as e:
                results.append({"id": node["id"], "status": str(e)})
            finally:
                await pihole_logout(client, node["url"], sid)

    return {"status": "completed", "results": results}


async def perform_single_backup(client: httpx.AsyncClient, node: dict):
    sid = None
    try:
        sid = await pihole_login(client, node["url"], node["password"])
        if not sid:
            return {"node": node["name"], "status": "error", "detail": "Authentication failed"}
        headers = {"X-FTL-SID": sid, "sid": sid}
        res = await client.get(f"{node['url']}/api/teleporter", headers=headers)
        if res.status_code == 200:
            prefix = safe_name(node["id"])
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{prefix}_backup_{timestamp}.tar.gz"
            filepath = os.path.join(BACKUP_DIR, filename)
            with open(filepath, "wb") as f:
                f.write(res.content)
            prune_backups(prefix)
            return {"node": node["name"], "status": "success", "file": filename}
        return {"node": node["name"], "status": "error", "detail": f"HTTP {res.status_code}"}
    except Exception as e:
        return {"node": node["name"], "status": "error", "detail": str(e)}
    finally:
        await pihole_logout(client, node["url"], sid)


@app.post("/api/backups/create/{node_id}")
async def create_backup(node_id: str):
    nodes = load_nodes()
    async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
        if node_id == "all":
            results = []
            for node in nodes:
                results.append(await perform_single_backup(client, node))
            return {"status": "completed", "results": results}
        else:
            node = next((n for n in nodes if n["id"] == node_id), None)
            if not node:
                raise HTTPException(status_code=404, detail="Node not found")
            res = await perform_single_backup(client, node)
            return {"status": "completed", "results": [res]}


@app.get("/api/backups")
def list_backups():
    files = sorted(glob.glob(os.path.join(BACKUP_DIR, "*.tar.gz")), key=os.path.getmtime, reverse=True)
    out = []
    for f in files:
        stat = os.stat(f)
        out.append({
            "filename": os.path.basename(f),
            "size_kb": round(stat.st_size / 1024, 1),
            "created": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        })
    return out


@app.get("/api/backups/download/{filename}")
def download_backup(filename: str):
    clean_name = os.path.basename(filename)
    filepath = os.path.join(BACKUP_DIR, clean_name)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Backup file not found")
    return FileResponse(filepath, media_type="application/gzip", filename=clean_name)


@app.delete("/api/backups/{filename}")
def delete_backup(filename: str):
    clean_name = os.path.basename(filename)
    filepath = os.path.join(BACKUP_DIR, clean_name)
    if os.path.exists(filepath):
        os.remove(filepath)
    return {"status": "deleted"}


@app.post("/api/teleport")
async def teleport_sync(req: TeleportRequest):
    nodes = load_nodes()
    source = next((n for n in nodes if n["id"] == req.source_id), None)
    if not source:
        raise HTTPException(status_code=404, detail="Source Pi-hole not found")

    targets = [n for n in nodes if n["id"] in req.target_ids and n["id"] != req.source_id]
    if not targets:
        raise HTTPException(status_code=400, detail="Please select at least one valid Target Pi-hole")

    async with httpx.AsyncClient(verify=False, timeout=60.0) as client:
        # 1. Export Teleporter archive from Source Pi-hole
        src_sid = await pihole_login(client, source["url"], source["password"])
        if not src_sid:
            raise HTTPException(status_code=401, detail=f"Failed to authenticate with source: {source['name']}")

        try:
            src_headers = {"X-FTL-SID": src_sid, "sid": src_sid}
            export_res = await client.get(f"{source['url']}/api/teleporter", headers=src_headers)
            if export_res.status_code != 200:
                raise HTTPException(status_code=500, detail=f"Failed to export from {source['name']} (HTTP {export_res.status_code})")
            archive_bytes = export_res.content
        finally:
            await pihole_logout(client, source["url"], src_sid)

        # Save a safety snapshot of the source archive automatically
        prefix = safe_name(source["id"])
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        snap_name = f"{prefix}_backup_{timestamp}.tar.gz"
        with open(os.path.join(BACKUP_DIR, snap_name), "wb") as f:
            f.write(archive_bytes)
        prune_backups(prefix)

        # Build Pi-hole v6 Teleporter granular import configuration
        import_options = {
            "config": bool(req.options.local_dns or req.options.upstream_dns or req.options.system_dhcp),
            "dhcp_leases": bool(req.options.system_dhcp),
            "gravity": {
                "group": bool(req.options.groups),
                "adlist": bool(req.options.adlists),
                "adlist_by_group": bool(req.options.adlists and req.options.groups),
                "domainlist": bool(req.options.domains),
                "domainlist_by_group": bool(req.options.domains and req.options.groups),
                "client": bool(req.options.groups),
                "client_by_group": bool(req.options.groups)
            }
        }

        # 2. Upload & Import into each Target Pi-hole
        sync_results = []
        for target in targets:
            tgt_sid = None
            try:
                tgt_sid = await pihole_login(client, target["url"], target["password"])
                if not tgt_sid:
                    sync_results.append({
                        "target": target["name"],
                        "status": "error",
                        "detail": "Authentication failed (check password)"
                    })
                    continue

                tgt_headers = {"X-FTL-SID": tgt_sid, "sid": tgt_sid}
                files = {"file": ("teleporter.tar.gz", archive_bytes, "application/gzip")}
                data = {"import": json.dumps(import_options)}

                imp_res = await client.post(
                    f"{target['url']}/api/teleporter",
                    headers=tgt_headers,
                    files=files,
                    data=data
                )

                if imp_res.status_code in (200, 201, 204):
                    grav_msg = ""
                    if req.options.run_gravity:
                        grav_res = await client.post(f"{target['url']}/api/action/gravity", headers=tgt_headers)
                        grav_msg = " + Gravity updated" if grav_res.status_code == 200 else " (Gravity update skipped)"
                    sync_results.append({
                        "target": target["name"],
                        "status": "success",
                        "detail": f"Teleport imported successfully{grav_msg}"
                    })
                else:
                    sync_results.append({
                        "target": target["name"],
                        "status": "error",
                        "detail": f"HTTP {imp_res.status_code} (Ensure webserver.api.app_sudo is Enabled on {target['name']})"
                    })
            except Exception as e:
                sync_results.append({
                    "target": target["name"],
                    "status": "error",
                    "detail": str(e)
                })
            finally:
                await pihole_logout(client, target["url"], tgt_sid)

        return {
            "status": "completed",
            "snapshot_saved": snap_name,
            "results": sync_results
        }


app.mount("/", StaticFiles(directory="static", html=True), name="static")
    
