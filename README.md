# 📡 SMS Burst API

Pure REST API version of SMS Burst — **no web UI, no sessions, stateless instances**.  
Multi-instance ready, PostgreSQL-backed, API-key secured, Render 500MB optimized.

---

## 🏗️ Architecture

```
Client (your script / app)
        │
        │  HTTPS + X-API-Key header
        ▼
┌────────────────┐    ┌────────────────┐
│ sms-burst-api-1│    │ sms-burst-api-2│   ← Both on Render free tier
│  (Gunicorn)    │    │  (Gunicorn)    │   ← Both share same DB
└───────┬────────┘    └───────┬────────┘
        └──────────┬──────────┘
                   ▼
        ┌──────────────────────┐
        │   PostgreSQL (free)  │   ← Jobs, API keys, blacklist, rate log
        └──────────────────────┘
```

**Why this works across instances:**
- All job state lives in the DB, not in memory
- Rate limiting is DB-backed (not per-process counters)
- Stopping a job writes `status=stopped` to DB; running instance checks this and exits
- No Flask sessions needed — pure stateless API key auth

---

## 🚀 Deploy to Render

### 1. Push to GitHub/GitLab
```bash
git add .
git commit -m "sms-burst api"
git push
```

### 2. Connect to Render
- Go to [render.com](https://render.com) → **New → Blueprint**
- Connect your repo → Render reads `render.yaml` automatically
- It creates: 2 web services + 1 PostgreSQL database

### 3. Set your secret key
- Render Dashboard → `sms-burst-api-1` → **Environment**
- Set `MASTER_API_KEY` = something long and random, e.g.:
  ```
  python -c "import secrets; print(secrets.token_urlsafe(40))"
  ```
- Repeat for `sms-burst-api-2` (same key)

### 4. Done!
Both instances auto-start. Test with:
```bash
curl https://sms-burst-api-1.onrender.com/health
```

---

## 🔐 Security Model

| Layer | How |
|-------|-----|
| **Auth** | `X-API-Key` header — SHA-256 hashed before storage, never stored raw |
| **Rate limiting** | Per-key, per-minute, DB-backed (works across instances) |
| **Admin isolation** | Admin keys vs user keys — admins can manage keys/blacklist |
| **No plaintext secrets** | Keys shown ONCE on creation, never retrievable again |
| **HTTPS** | Render enforces HTTPS automatically — never use HTTP |

---

## 📋 API Reference

### Authentication
Every request (except `/health`) requires:
```
X-API-Key: your-api-key-here
```

---

### `GET /health`
No auth required. Returns `{"status": "ok"}`. Use for uptime monitoring.

---

### `POST /api/job/start`
Start an SMS burst job.

**Request:**
```json
{
  "targets": ["9876543210", "9123456789"],
  "mode": "Normal",
  "delay": 0.4,
  "max_requests": 100
}
```

**Params:**
| Field | Type | Description |
|-------|------|-------------|
| `targets` | list or comma-string | Phone numbers (10-digit) |
| `mode` | `Normal` / `Ghost` / `Nuclear` | Burst mode |
| `delay` | float (0.1–60) | Seconds between requests |
| `max_requests` | int (1–1000) | Hard cap on total sends |

**Response (202):**
```json
{
  "job_id": "a1b2c3d4e5f6g7h8",
  "status": "running",
  "targets": 2,
  "mode": "Normal",
  "delay": 0.4,
  "max_requests": 100
}
```

---

### `GET /api/job/<job_id>`
Poll job status.

**Response:**
```json
{
  "job_id": "a1b2c3d4...",
  "status": "running",
  "sent_count": 42,
  "max_requests": 100,
  "logs": ["✅ API_NAME OK [3210]", "⚠️ API2 403"],
  "started_at": "2025-12-23T10:00:00"
}
```

---

### `POST /api/job/<job_id>/stop`
Stop a running job (works even if it's on the other instance).

---

### `GET /api/jobs`
List last 20 jobs for your API key.

---

## 🔑 Admin API Reference

Use your `MASTER_API_KEY` for these routes.

### `POST /admin/keys/create`
Create a new API key.
```json
{ "label": "client-1", "role": "user", "rate_limit": 30 }
```
Returns the raw key **once**. Save it securely.

### `GET /admin/keys`
List all keys (hashed — raw keys not shown).

### `POST /admin/keys/<id>/revoke`
Disable a key instantly (reflected across both instances).

### `GET /admin/blacklist`
### `POST /admin/blacklist`  → `{ "phone": "9876543210" }`
### `DELETE /admin/blacklist/<phone>`

### `GET /admin/jobs`
View all jobs across all API keys.

---

## 💡 Usage Example (Python client)

```python
import requests
import time

BASE   = "https://sms-burst-api-1.onrender.com"
KEY    = "your-api-key"
HEADERS = {"X-API-Key": KEY}

# Start a job
r = requests.post(f"{BASE}/api/job/start", headers=HEADERS, json={
    "targets": ["9876543210"],
    "mode": "Normal",
    "delay": 0.5,
    "max_requests": 50
})
job_id = r.json()["job_id"]
print(f"Started: {job_id}")

# Poll until done
while True:
    s = requests.get(f"{BASE}/api/job/{job_id}", headers=HEADERS).json()
    print(f"Sent: {s['sent_count']} | Status: {s['status']}")
    if s["status"] != "running":
        break
    time.sleep(3)
```

---

## ⚙️ Render RAM Optimization (500MB)

The `gunicorn` start command is tuned for free tier:
```
--workers 2       # 2 processes × ~80MB = ~160MB
--threads 4       # 4 threads per worker (handles concurrency cheaply)
--worker-class gthread
--max-requests 500  # restart workers every 500 requests (prevent memory leaks)
```

Total RAM usage: ~250–350MB per instance — well within 500MB.

---

## 📁 Files

```
sms-burst-api/
├── app.py           # Main API app (this file)
├── requirements.txt # Flask, gunicorn, psycopg2, requests
├── render.yaml      # Render deployment blueprint (2 instances + DB)
├── apidata.json     # Your SMS API definitions (copy from original)
└── README.md
```

> **Note:** Copy your `apidata.json` from the original project into this folder.
