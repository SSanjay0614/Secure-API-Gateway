# gateway/app.py
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from jose import jwt
from datetime import datetime, timedelta
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import requests
import json
import base64

# AES Libraries
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# -------------------- RATE LIMITER --------------------
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="AES-256 Secure Gateway")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# -------------------- CONFIG --------------------
AI_SERVICE = "http://127.0.0.1:5001"
DB_SERVICE = "http://127.0.0.1:5002"

SECRET_KEY = "supersecretkey"
ALGORITHM  = "HS256"

# 🔐 AES-256 Keys (32-byte key, 16-byte IV)
KEY = b"12345678901234567890123456789012"
IV  = b"1234567890123456"

# -------------------- AES HELPERS --------------------
def encrypt_field(value: str) -> str:
    """Encrypt a single string field with AES-256 CBC, return base64."""
    padder    = padding.PKCS7(128).padder()
    padded    = padder.update(value.encode()) + padder.finalize()
    cipher    = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    ct        = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(ct).decode()

def decrypt_field(value: str) -> str:
    """Decrypt a single AES-256 CBC base64-encoded field."""
    try:
        ct        = base64.b64decode(value)
        cipher    = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
        decryptor = cipher.decryptor()
        padded    = decryptor.update(ct) + decryptor.finalize()
        unpadder  = padding.PKCS7(128).unpadder()
        return (unpadder.update(padded) + unpadder.finalize()).decode()
    except Exception:
        return value  # return as-is if it can't be decrypted

def is_encrypted(value: str) -> bool:
    """Check if a string looks like an AES-encrypted base64 blob."""
    try:
        decoded = base64.b64decode(value)
        return len(decoded) % 16 == 0 and len(decoded) >= 16
    except Exception:
        return False

# -------------------- FORWARD (AI — no field encryption needed) --------------------
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

# -------------------- AUTH --------------------
@app.post("/login")
@limiter.limit("10/minute")
async def login(request: Request):
    data  = await request.json()
    token = jwt.encode(
        {"sub": data.get("username"), "exp": datetime.utcnow() + timedelta(minutes=30)},
        SECRET_KEY, algorithm=ALGORITHM
    )
    return {"access_token": token}

# -------------------- DB: ADD USER --------------------
@app.post("/api/db/users")
@limiter.limit("15/minute")
async def add_user(request: Request):
    """
    Receive plaintext {name, role} from the UI.
    Encrypt both fields at the gateway with AES-256.
    Send the encrypted payload to DB service → stored encrypted in db.json.
    """
    body = await request.body()
    try:
        data = json.loads(body.decode())
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    name = data.get("name", "").strip()
    role = data.get("role", "").strip()
    if not name or not role:
        raise HTTPException(status_code=400, detail="name and role are required")

    # Encrypt at gateway before forwarding to DB
    encrypted_payload = {
        "name": encrypt_field(name),
        "role": encrypt_field(role)
    }

    res = requests.post(f"{DB_SERVICE}/api/db/users", json=encrypted_payload)
    return JSONResponse(status_code=res.status_code, content=res.json())

# -------------------- DB: GET ALL USERS --------------------
@app.get("/api/db/users")
@limiter.limit("30/minute")
async def get_users(request: Request):
    """
    Fetch all users from DB service (they are stored encrypted).
    Decrypt name and role at the gateway level.
    Return plaintext list back to the UI.
    """
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

# -------------------- DB: DELETE USER --------------------
@app.delete("/api/db/users/{id}")
@limiter.limit("10/minute")
async def del_user(id: int, request: Request):
    res = requests.delete(f"{DB_SERVICE}/api/db/users/{id}")
    return JSONResponse(status_code=res.status_code, content=res.json())

# -------------------- AI --------------------
@app.post("/api/ai/detect-language")
@limiter.limit("20/minute")
async def ai_detect(request: Request):
    return await forward_raw(AI_SERVICE, "api/ai/detect-language", request)

# -------------------- UI (original, unchanged) --------------------

@app.get("/ui", response_class=HTMLResponse)
def login_ui():
    return """
    <html><head><style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f2f5; margin:0; }
        .card { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 320px; text-align: center; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #1a73e8; color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; }
    </style></head><body>
    <div class="card">
        <h2>AES-256 Gateway</h2>
        <input id="u" placeholder="Username">
        <input id="p" type="password" placeholder="Password">
        <button onclick="auth()">Login</button>
    </div>
    <script>
    async function auth() {
        const r = await fetch('/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: u.value, password: p.value})
        });
        const d = await r.json();
        if (d.access_token) {
            localStorage.setItem("token", d.access_token);
            window.location.href = "/dashboard";
        }
    }
    </script></body></html>
    """

@app.get("/dashboard", response_class=HTMLResponse)
def dash_ui():
    return """
    <html><head>
    <style>
        body { font-family: sans-serif; margin: 40px; background: #f0f2f5; }
        .card { max-width: 900px; margin: auto; background: white; padding: 30px; border-radius: 15px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 25px; margin-top: 20px; }
        .section { border: 1px solid #e0e0e0; padding: 20px; border-radius: 10px; }
        input, textarea { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #1a73e8; color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; margin-top:5px; }
        pre { background: #202124; color: #8ab4f8; padding: 15px; border-radius: 8px; overflow-x: auto; min-height: 100px; font-size: 13px; }
        .del-group { display: flex; gap: 5px; margin-top: 15px; border-top: 1px solid #eee; padding-top: 15px; }
    </style></head><body>
    <div class="card">
        <div style="display:flex; justify-content:space-between; align-items:center; border-bottom: 2px solid #eee; padding-bottom:10px;">
            <h2 style="margin:0;">Secure Gateway Dashboard</h2>
            <button onclick="localStorage.clear(); window.location.href='/ui';" style="width:auto; padding:5px 15px; background:#5f6368;">Logout</button>
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
                    <button onclick="api('DELETE','/api/db/users/'+di.value)" style="background:#ea4335; width:100px; margin:0;">Delete</button>
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
    async function api(m, p, b=null) {
        try {
            const res = await fetch(p, {
                method: m,
                headers: {
                    'Authorization': 'Bearer ' + localStorage.getItem("token"),
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