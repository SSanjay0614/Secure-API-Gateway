# 🔐 Secure API Gateway

A security-focused microservices project built with **FastAPI** that demonstrates real-world encryption, JWT authentication, and rate limiting across three independent services connected through a secure API gateway.

---

## 📌 What This Project Does

User data is **never stored in plaintext**. When a user is added through the gateway dashboard, the `name` and `role` fields are encrypted at the **gateway level** using AES-256 CBC before being forwarded to the database service. When users are fetched, the gateway decrypts the fields and returns clean plaintext to the UI — the database service itself never sees or handles unencrypted data.

```
Browser (plaintext)
    │
    ▼
┌─────────────────────────────┐
│     Gateway  :8000          │  ← JWT Auth · AES-256 · Rate Limiting
│  encrypt on write           │
│  decrypt on read            │
└────────┬────────────────────┘
         │                    │
         ▼                    ▼
┌─────────────────┐   ┌──────────────────────┐
│  DB Service     │   │  AI Service          │
│  :5002          │   │  :5001               │
│  TinyDB         │   │  XLM-RoBERTa model   │
│  (stores blobs) │   │  (language detect)   │
└─────────────────┘   └──────────────────────┘
```

---

## 🗂️ Project Structure

```
Crypto-Project/
│
├── gateway/
│   ├── app.py            ← Main gateway (JWT + AES-256 + Rate Limiting + UI)
│   └── users.json        ← Registered users
│
├── db_service/
│   ├── app.py            ← User CRUD API (stores encrypted blobs)
│   └── db.json           ← TinyDB file (encrypted at rest)
│
├── ai_service/
│   └── app.py            ← Language detection API (XLM-RoBERTa)
│
├── attacks/
│   ├── attack_suite.py   ← Custom attack/penetration test script
│   └── locustfile.py     ← Load testing with Locust
│
└── README.md
```

---

## 🔒 Security Features

| Feature | Implementation |
|---|---|
| **AES-256 CBC Encryption** | User fields encrypted at gateway before DB storage |
| **JWT Authentication** | HS256 tokens, 30-minute expiry on all API routes |
| **Rate Limiting** | Per-IP limits via `slowapi` on every endpoint |
| **Encrypted at Rest** | `db.json` stores only base64 ciphertext — never plaintext |
| **Gateway-only Decryption** | DB service has zero knowledge of plaintext values |

### Rate Limits

| Endpoint | Limit |
|---|---|
| `POST /login` | 10 / minute |
| `POST /api/db/users` | 15 / minute |
| `GET /api/db/users` | 30 / minute |
| `DELETE /api/db/users/{id}` | 10 / minute |
| `POST /api/ai/detect-language` | 20 / minute |

---

## ⚙️ Setup & Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/crypto-project.git
cd crypto-project
```

### 2. Install dependencies

```bash
pip install fastapi uvicorn python-jose cryptography tinydb requests slowapi transformers torch
```

### 3. Clear any old data (important — avoids plaintext/ciphertext mix)

```bash
rm -f db_service/db.json
```

---

## 🚀 Running the Project

Open **three separate terminals** and run each service:

```bash
# Terminal 1 — Gateway (main entry point)
uvicorn gateway.app:app --port 8000 --reload

# Terminal 2 — Database Service
uvicorn db_service.app:app --port 5002 --reload

# Terminal 3 — AI Language Service
uvicorn ai_service.app:app --port 5001 --reload
```

Then open your browser at:

| URL | Description |
|---|---|
| `http://localhost:8000/ui` | Gateway login page |
| `http://localhost:8000/dashboard` | Main secure dashboard |
| `http://localhost:5002/ui` | DB raw view (shows encrypted blobs) |
| `http://localhost:5001/ui` | AI language detector UI |

---

## 🖥️ How to Use

1. **Login** at `http://localhost:8000/ui` with any username/password (JWT is issued on any credentials)
2. **Add a user** — enter name and role, click *Add User*. The gateway encrypts both fields before storing.
3. **Get All Users** — gateway fetches encrypted records from DB, decrypts them, and returns plaintext to the dashboard.
4. **See the encryption** — open `http://localhost:5002/ui` directly to see the raw encrypted blobs sitting in the table.
5. **Detect language** — paste any text in the AI panel and click *Analyze Text*.

---

## 🔑 AES-256 Encryption Details

- **Algorithm:** AES-256 in CBC mode
- **Key size:** 32 bytes
- **IV size:** 16 bytes
- **Padding:** PKCS7
- **Encoding:** Base64 (for safe storage in JSON)
- **Library:** Python `cryptography` (hazmat primitives)

> ⚠️ The key and IV are hardcoded for demonstration purposes. In a production system these must be stored in environment variables or a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault).

---

## 🧪 Attack & Load Testing

### Custom Attack Suite

```bash
python attacks/attack_suite.py
```

Tests include SQL injection attempts, JWT tampering, brute-force login simulation, and oversized payload attacks.

### Load Testing with Locust

```bash
locust -f attacks/locustfile.py --host=http://localhost:8000
```

Then open `http://localhost:8089` to configure and run load tests.

---

## 📦 Dependencies

| Package | Purpose |
|---|---|
| `fastapi` | Web framework for all three services |
| `uvicorn` | ASGI server |
| `python-jose` | JWT encoding / decoding |
| `cryptography` | AES-256 CBC encryption |
| `tinydb` | Lightweight JSON database |
| `slowapi` | Rate limiting for FastAPI |
| `transformers` | XLM-RoBERTa language detection model |
| `torch` | PyTorch backend for the AI model |
| `requests` | Inter-service HTTP communication |

---

## 📄 License

MIT License — free to use, modify, and distribute.
