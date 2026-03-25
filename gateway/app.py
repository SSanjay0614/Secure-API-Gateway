# gateway/app.py
import json
import base64
import os
import time
from datetime import datetime, timedelta
from pathlib import Path

import requests
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

# AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# -------------------- RATE LIMITER --------------------
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="AES-256 Secure Gateway")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# -------------------- CONFIG --------------------
AI_SERVICE  = "http://127.0.0.1:5001"
DB_SERVICE  = "http://127.0.0.1:5002"
SECRET_KEY  = "supersecretkey"
ALGORITHM   = "HS256"
USERS_FILE  = "users.json"
LOGS_DIR    = "logs"

# 🔐 AES-256 (32-byte key, 16-byte IV)
KEY = b"12345678901234567890123456789012"
IV  = b"1234567890123456"

# -------------------- AUDIT LOGGING --------------------
Path(LOGS_DIR).mkdir(exist_ok=True)

def audit_log(method: str, path: str, ip: str, username: str, status_code: int, elapsed_ms: float):
    today     = datetime.now().strftime("%Y-%m-%d")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_path  = os.path.join(LOGS_DIR, f"audit_{today}.log")
    line      = (
        f"[{timestamp}] | {method} {path} "
        f"| IP: {ip} | USER: {username} | STATUS: {status_code} | {elapsed_ms:.1f}ms\n"
    )
    with open(log_path, "a") as f:
        f.write(line)

def extract_username_from_request(request: Request) -> str:
    """Best-effort JWT username extract — returns '-' if token missing/invalid."""
    try:
        auth  = request.headers.get("Authorization", "")
        token = auth.replace("Bearer ", "")
        if not token:
            return "guest"
        payload  = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub", "-")
        return username
    except Exception:
        return "invalid_token"

# -------------------- AUDIT MIDDLEWARE --------------------
# Sits at the very bottom of the stack — sees EVERY request and its final
# response status code, including 401s that never reach route handlers.

LOGGED_PREFIXES = ("/api/", "/login", "/register")

class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Only log API and auth routes — skip /ui, /dashboard, /docs etc.
        if not any(request.url.path.startswith(p) for p in LOGGED_PREFIXES):
            return await call_next(request)

        start    = time.time()
        ip       = get_remote_address(request)
        username = extract_username_from_request(request)

        response    = await call_next(request)
        elapsed_ms  = (time.time() - start) * 1000

        audit_log(
            method      = request.method,
            path        = request.url.path,
            ip          = ip,
            username    = username,
            status_code = response.status_code,
            elapsed_ms  = elapsed_ms,
        )
        return response

app.add_middleware(AuditMiddleware)

# -------------------- JWT ENFORCEMENT --------------------
bearer_scheme = HTTPBearer()

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> str:
    token = credentials.credentials
    try:
        payload  = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token: no subject")
        return username
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Unauthorised: {str(e)}")

# -------------------- USER STORE --------------------
def load_users() -> dict:
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users: dict):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

# -------------------- AES HELPERS --------------------
def encrypt_field(value: str) -> str:
    padder    = padding.PKCS7(128).padder()
    padded    = padder.update(value.encode()) + padder.finalize()
    cipher    = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    ct        = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(ct).decode()

def decrypt_field(value: str) -> str:
    try:
        ct        = base64.b64decode(value)
        cipher    = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
        decryptor = cipher.decryptor()
        padded    = decryptor.update(ct) + decryptor.finalize()
        unpadder  = padding.PKCS7(128).unpadder()
        return (unpadder.update(padded) + unpadder.finalize()).decode()
    except Exception:
        return value

def is_encrypted(value: str) -> bool:
    try:
        decoded = base64.b64decode(value)
        return len(decoded) % 16 == 0 and len(decoded) >= 16
    except Exception:
        return False

# -------------------- FORWARD (AI) --------------------
async def forward_raw(base_url: str, path: str, request: Request):
    url  = f"{base_url}/{path}"
    body = await request.body()
    try:
        request_json = json.loads(body.decode()) if body else None
        res = requests.request(
            method  = request.method,
            url     = url,
            headers = {k: v for k, v in request.headers.items()
                       if k.lower() not in ['host', 'content-length', 'content-type']},
            json    = request_json
        )
        return JSONResponse(status_code=res.status_code, content=res.json())
    except Exception as e:
        return JSONResponse(status_code=500, content={"detail": f"Forwarding Error: {str(e)}"})

# ==================== PUBLIC ROUTES ====================

@app.post("/register")
@limiter.limit("5/minute")
async def register(request: Request):
    data     = await request.json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password are required")
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    users = load_users()
    if username in users:
        raise HTTPException(status_code=409, detail="Username already exists")

    users[username] = encrypt_field(password)
    save_users(users)
    return {"message": f"User '{username}' registered successfully"}


@app.post("/login")
@limiter.limit("10/minute")
async def login(request: Request):
    data     = await request.json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    users = load_users()
    if username not in users:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if decrypt_field(users[username]) != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = jwt.encode(
        {"sub": username, "exp": datetime.utcnow() + timedelta(minutes=30)},
        SECRET_KEY, algorithm=ALGORITHM
    )
    return {"access_token": token}


# ==================== PROTECTED ROUTES ====================

@app.post("/api/db/users")
@limiter.limit("15/minute")
async def add_user(request: Request, username: str = Depends(verify_token)):
    body = await request.body()
    try:
        data = json.loads(body.decode())
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    name = data.get("name", "").strip()
    role = data.get("role", "").strip()
    if not name or not role:
        raise HTTPException(status_code=400, detail="name and role are required")

    encrypted_payload = {
        "name": encrypt_field(name),
        "role": encrypt_field(role)
    }
    res = requests.post(f"{DB_SERVICE}/api/db/users", json=encrypted_payload)
    return JSONResponse(status_code=res.status_code, content=res.json())


@app.get("/api/db/users")
@limiter.limit("30/minute")
async def get_users(request: Request, username: str = Depends(verify_token)):
    res  = requests.get(f"{DB_SERVICE}/api/db/users")
    data = res.json()

    decrypted_users = []
    for user in data.get("users", []):
        raw_name = user.get("name", "")
        raw_role = user.get("role", "")
        decrypted_users.append({
            "id":   user.get("id"),
            "name": decrypt_field(raw_name) if is_encrypted(raw_name) else raw_name,
            "role": decrypt_field(raw_role) if is_encrypted(raw_role) else raw_role,
        })

    return JSONResponse(status_code=200, content={
        "count": len(decrypted_users),
        "users": decrypted_users
    })


@app.delete("/api/db/users/{id}")
@limiter.limit("10/minute")
async def del_user(id: int, request: Request, username: str = Depends(verify_token)):
    res = requests.delete(f"{DB_SERVICE}/api/db/users/{id}")
    return JSONResponse(status_code=res.status_code, content=res.json())


@app.post("/api/ai/detect-language")
@limiter.limit("20/minute")
async def ai_detect(request: Request, username: str = Depends(verify_token)):
    return await forward_raw(AI_SERVICE, "api/ai/detect-language", request)


# ==================== UI ====================

@app.get("/ui", response_class=HTMLResponse)
def login_ui():
    return """
    <html><head><style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center;
               height: 100vh; background: #f0f2f5; margin: 0; }
        .card { background: white; padding: 30px; border-radius: 12px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 340px; text-align: center; }
        h2 { margin-bottom: 6px; }
        .tabs { display: flex; margin-bottom: 20px; border-bottom: 2px solid #eee; }
        .tab { flex: 1; padding: 10px; cursor: pointer; font-weight: bold;
               color: #888; border-bottom: 3px solid transparent; margin-bottom: -2px; }
        .tab.active { color: #1a73e8; border-bottom-color: #1a73e8; }
        .panel { display: none; }
        .panel.active { display: block; }
        input { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ddd;
                border-radius: 6px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #1a73e8; color: white;
                 border: none; border-radius: 6px; cursor: pointer; font-weight: bold; margin-top: 4px; }
        .msg  { margin-top: 10px; font-size: 13px; min-height: 18px; }
        .err  { color: #ea4335; }
        .ok   { color: #34a853; }
        .guest-bar  { margin-top: 18px; padding-top: 14px; border-top: 1px solid #eee; }
        .btn-guest  { background: #fff; color: #5f6368; border: 1px solid #dadce0;
                      font-weight: normal; font-size: 13px; padding: 9px; }
        .btn-guest:hover { background: #f8f9fa; }
        .guest-note { font-size: 11px; color: #aaa; margin-top: 6px; }
    </style></head><body>
    <div class="card">
        <h2>🔐 AES-256 Gateway</h2>
        <div class="tabs">
            <div class="tab active" onclick="switchTab('login')">Login</div>
            <div class="tab"        onclick="switchTab('register')">Register</div>
        </div>

        <div id="panel-login" class="panel active">
            <input id="lu" placeholder="Username">
            <input id="lp" type="password" placeholder="Password">
            <button onclick="doLogin()">Login</button>
            <div id="login-msg" class="msg"></div>
            <div class="guest-bar">
                <button class="btn-guest" onclick="guestAccess()">
                    👁 Continue as Guest (Demo)
                </button>
                <div class="guest-note">
                    View the dashboard — all API calls will return 401 Unauthorised
                </div>
            </div>
        </div>

        <div id="panel-register" class="panel">
            <input id="ru" placeholder="Username">
            <input id="rp" type="password" placeholder="Password (min 6 chars)">
            <input id="rp2" type="password" placeholder="Confirm Password">
            <button onclick="doRegister()">Create Account</button>
            <div id="reg-msg" class="msg"></div>
        </div>
    </div>

    <script>
    function switchTab(tab) {
        document.querySelectorAll('.tab').forEach((t, i) => {
            t.classList.toggle('active', (i===0&&tab==='login')||(i===1&&tab==='register'));
        });
        document.getElementById('panel-login').classList.toggle('active', tab==='login');
        document.getElementById('panel-register').classList.toggle('active', tab==='register');
        document.getElementById('login-msg').textContent = '';
        document.getElementById('reg-msg').textContent   = '';
    }

    async function doLogin() {
        const msg = document.getElementById('login-msg');
        msg.textContent = '';
        const r = await fetch('/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: lu.value, password: lp.value})
        });
        const d = await r.json();
        if (d.access_token) {
            localStorage.setItem("token", d.access_token);
            localStorage.setItem("username", lu.value);
            window.location.href = "/dashboard";
        } else {
            msg.className = 'msg err';
            msg.textContent = d.detail || 'Login failed';
        }
    }

    async function doRegister() {
        const msg = document.getElementById('reg-msg');
        msg.textContent = '';
        if (rp.value !== rp2.value) {
            msg.className = 'msg err';
            msg.textContent = 'Passwords do not match';
            return;
        }
        const r = await fetch('/register', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: ru.value, password: rp.value})
        });
        const d = await r.json();
        if (r.ok) {
            msg.className = 'msg ok';
            msg.textContent = '✅ Registered! You can now login.';
            ru.value = ''; rp.value = ''; rp2.value = '';
        } else {
            msg.className = 'msg err';
            msg.textContent = d.detail || 'Registration failed';
        }
    }

    function guestAccess() {
        localStorage.removeItem("token");
        localStorage.setItem("guest", "true");
        window.location.href = "/dashboard";
    }
    </script></body></html>
    """


@app.get("/dashboard", response_class=HTMLResponse)
def dash_ui():
    return """
    <html><head>
    <style>
        body { font-family: sans-serif; margin: 40px; background: #f0f2f5; }
        .card { max-width: 900px; margin: auto; background: white; padding: 30px;
                border-radius: 15px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 25px; margin-top: 20px; }
        .section { border: 1px solid #e0e0e0; padding: 20px; border-radius: 10px; }
        input, textarea { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ddd;
                          border-radius: 6px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #1a73e8; color: white; border: none;
                 border-radius: 6px; cursor: pointer; font-weight: bold; margin-top:5px; }
        pre { background: #202124; color: #8ab4f8; padding: 15px; border-radius: 8px;
              overflow-x: auto; min-height: 100px; font-size: 13px; }
        .del-group { display: flex; gap: 5px; margin-top: 15px;
                     border-top: 1px solid #eee; padding-top: 15px; }
        #guest-banner { display:none; background: #fff3cd; border: 1px solid #ffc107;
                        color: #856404; padding: 10px 16px; border-radius: 8px;
                        margin-bottom: 16px; font-size: 13px; }
        #guest-banner a { color: #1a73e8; cursor: pointer; font-weight: bold; }
    </style></head><body>
    <div class="card">

        <div id="guest-banner">
            ⚠️ You are in <strong>Guest / Demo Mode</strong> — no token is set.
            Every API call below will return <strong>401 Unauthorised</strong>
            and will be logged as <strong>USER: guest</strong>.
            <a onclick="window.location.href='/ui'"> Login to get full access →</a>
        </div>

        <div style="display:flex; justify-content:space-between; align-items:center;
                    border-bottom: 2px solid #eee; padding-bottom:10px;">
            <h2 style="margin:0;">Secure Gateway Dashboard</h2>
            <button onclick="logout()"
                    style="width:auto; padding:5px 15px; background:#5f6368;">Logout</button>
        </div>

        <div class="grid">
            <div class="section">
                <h3>User DB Service (5002)</h3>
                <input id="dn" placeholder="Name">
                <input id="dr" placeholder="Role">
                <button onclick="api('POST','/api/db/users',{name:dn.value, role:dr.value})">Add User</button>
                <button onclick="api('GET','/api/db/users')" style="background:#34a853;">Get All Users</button>
                <div class="del-group">
                    <input id="di" placeholder="ID to delete" style="margin:0;">
                    <button onclick="api('DELETE','/api/db/users/'+di.value)"
                            style="background:#ea4335; width:100px; margin:0;">Delete</button>
                </div>
            </div>

            <div class="section">
                <h3>AI Language Service (5001)</h3>
                <textarea id="at" placeholder="Text to detect..." style="height:100px;"></textarea>
                <button onclick="api('POST','/api/ai/detect-language',{text:at.value})">Analyze Text</button>
            </div>
        </div>

        <h3>System Output (Decrypted)</h3>
        <pre id="out">Ready...</pre>
    </div>

    <script>
    window.addEventListener('load', () => {
        const token = localStorage.getItem("token");
        const guest = localStorage.getItem("guest");
        if (!token) {
            if (!guest) {
                window.location.href = '/ui';
                return;
            }
            document.getElementById('guest-banner').style.display = 'block';
        }
    });

    function logout() {
        localStorage.clear();
        window.location.href = '/ui';
    }

    async function api(m, p, b=null) {
        const token = localStorage.getItem("token");
        try {
            const res = await fetch(p, {
                method: m,
                headers: {
                    ...(token ? {'Authorization': 'Bearer ' + token} : {}),
                    'Content-Type': 'application/json'
                },
                body: (b && m !== 'GET' && m !== 'DELETE') ? JSON.stringify(b) : null
            });
            const data = await res.json();
            document.getElementById('out').innerText = JSON.stringify(data, null, 2);
        } catch(e) {
            document.getElementById('out').innerText = "Error: " + e.message;
        }
    }
    </script></body></html>
    """
