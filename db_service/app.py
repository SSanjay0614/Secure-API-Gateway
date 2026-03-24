# db_service/app.py
# NOTE: This service stores exactly what it receives.
# The gateway encrypts name/role before sending here, so db.json holds encrypted blobs.
# The gateway also decrypts on read — this service never sees or handles plaintext names/roles.

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from tinydb import TinyDB, Query

app        = FastAPI(title="User Database Service")
db         = TinyDB("db.json")
users_table = db.table("users")

# Accept any string for name/role — could be plaintext or encrypted blob
class UserInput(BaseModel):
    name: str
    role: str

# -------------------- UI --------------------
@app.get("/ui", response_class=HTMLResponse)
def get_ui():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>User DB Manager</title>
        <style>
            body { font-family: sans-serif; margin: 40px; background: #f4f4f9; }
            .container { max-width: 800px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 12px; border-bottom: 1px solid #ddd; text-align: left; }
            .form-group { margin-bottom: 15px; }
            input { padding: 8px; margin-right: 10px; border: 1px solid #ccc; border-radius: 4px; }
            button { padding: 8px 15px; cursor: pointer; border-radius: 4px; border: none; background: #007bff; color: white; }
            button.delete { background: #dc3545; }
            button:hover { opacity: 0.8; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>User Database Manager (Raw / Encrypted View)</h2>
            <p style="color:#888; font-size:13px;">
                ⚠️ Name and Role are stored encrypted. Use the Gateway dashboard to see decrypted values.
            </p>

            <div class="form-group">
                <input type="text" id="name" placeholder="Name">
                <input type="text" id="role" placeholder="Role">
                <button onclick="addUser()">Add User</button>
            </div>

            <table>
                <thead>
                    <tr><th>ID</th><th>Name (encrypted)</th><th>Role (encrypted)</th><th>Actions</th></tr>
                </thead>
                <tbody id="userTableBody"></tbody>
            </table>
        </div>

        <script>
            async function fetchUsers() {
                const data = await (await fetch('/api/db/users')).json();
                const tb = document.getElementById('userTableBody');
                tb.innerHTML = '';
                data.users.forEach(u => {
                    tb.innerHTML += `<tr>
                        <td>${u.id}</td>
                        <td style="font-size:11px; color:#888; word-break:break-all;">${u.name}</td>
                        <td style="font-size:11px; color:#888; word-break:break-all;">${u.role}</td>
                        <td><button class="delete" onclick="deleteUser(${u.id})">Delete</button></td>
                    </tr>`;
                });
            }
            async function addUser() {
                const name = document.getElementById('name').value;
                const role = document.getElementById('role').value;
                if (!name || !role) return alert("Fill both fields");
                await fetch('/api/db/users', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({name, role})
                });
                document.getElementById('name').value = '';
                document.getElementById('role').value = '';
                fetchUsers();
            }
            async function deleteUser(id) {
                await fetch('/api/db/users/' + id, {method: 'DELETE'});
                fetchUsers();
            }
            fetchUsers();
        </script>
    </body>
    </html>
    """

# -------------------- ROUTES --------------------
@app.get("/")
def home():
    return {"message": "User Database Service Running. Go to /ui for the interface."}

@app.get("/api/db/users")
def get_users():
    return {"count": len(users_table), "users": users_table.all()}

@app.get("/api/db/users/{user_id}")
def get_user(user_id: int):
    User   = Query()
    result = users_table.search(User.id == user_id)
    if result:
        return result[0]
    raise HTTPException(status_code=404, detail="User not found")

@app.post("/api/db/users")
def add_user(user: UserInput):
    new_user = {
        "id":   len(users_table) + 1,
        "name": user.name,   # stored as-is (encrypted blob sent by gateway)
        "role": user.role    # stored as-is (encrypted blob sent by gateway)
    }
    users_table.insert(new_user)
    return {"message": "User added successfully", "user": new_user}

@app.delete("/api/db/users/{user_id}")
def delete_user(user_id: int):
    User = Query()
    if users_table.remove(User.id == user_id):
        return {"message": f"User {user_id} deleted"}
    raise HTTPException(status_code=404, detail="User not found")

@app.get("/api/db/health")
def health():
    return {"status": "DB service running", "total_records": len(users_table)}