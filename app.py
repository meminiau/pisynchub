import os
import json
import secrets
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, static_folder="static")

CONFIG_DIR = os.environ.get("CONFIG_DIR", "/config")
AUTH_FILE = os.path.join(CONFIG_DIR, "auth.json")
NODES_FILE = os.path.join(CONFIG_DIR, "nodes.json")
SECRET_FILE = os.path.join(CONFIG_DIR, "secret.key")

os.makedirs(CONFIG_DIR, exist_ok=True)

# Persistent session secret
if not os.path.exists(SECRET_FILE):
    with open(SECRET_FILE, "w") as f:
        f.write(secrets.token_hex(32))
with open(SECRET_FILE, "r") as f:
    app.secret_key = f.read().strip()

def is_setup_completed():
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

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_setup_completed():
            return jsonify({"status": "error", "message": "Setup required", "setup_required": True}), 401
        if not session.get("logged_in"):
            return jsonify({"status": "error", "message": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function

# --- Frontend Static Serving ---
@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/<path:path>")
def static_proxy(path):
    return send_from_directory("static", path)

# --- Authentication Endpoints ---
@app.route("/api/auth/status", methods=["GET"])
def auth_status():
    return jsonify({
        "setup_required": not is_setup_completed(),
        "logged_in": bool(session.get("logged_in")),
        "username": session.get("username")
    })

@app.route("/api/auth/setup", methods=["POST"])
def auth_setup():
    if is_setup_completed():
        return jsonify({"status": "error", "message": "Setup already completed"}), 400

    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password required"}), 400
    if len(password) < 6:
        return jsonify({"status": "error", "message": "Password must be at least 6 characters"}), 400

    auth_data = {
        "username": username,
        "password_hash": generate_password_hash(password)
    }
    with open(AUTH_FILE, "w") as f:
        json.dump(auth_data, f, indent=4)

    session["logged_in"] = True
    session["username"] = username
    return jsonify({"status": "success", "username": username})

@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    if not is_setup_completed():
        return jsonify({"status": "error", "message": "Setup required", "setup_required": True}), 400

    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    auth_data = load_auth()

    if auth_data and username == auth_data.get("username") and check_password_hash(auth_data.get("password_hash"), password):
        session["logged_in"] = True
        session["username"] = username
        return jsonify({"status": "success", "username": username})

    return jsonify({"status": "error", "message": "Invalid username or password"}), 401

@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    session.clear()
    return jsonify({"status": "success"})

# --- Protected Node Management ---
@app.route("/api/nodes", methods=["GET"])
@login_required
def get_nodes():
    return jsonify({"status": "success", "nodes": load_nodes()})

@app.route("/api/nodes", methods=["POST"])
@login_required
def add_node():
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    url = data.get("url", "").strip()
    api_key = data.get("api_key", "").strip()

    if not name or not url:
        return jsonify({"status": "error", "message": "Node name and URL are required"}), 400

    nodes = load_nodes()
    nodes.append({"name": name, "url": url, "api_key": api_key})
    save_nodes(nodes)
    return jsonify({"status": "success", "nodes": nodes})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8085)
    
