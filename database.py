import sqlite3
import hashlib
import datetime

DB_PATH = "bounty_ai.db"
FREE_MONTHLY_LIMIT = 3

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            tier TEXT DEFAULT 'free',
            scans_used INTEGER DEFAULT 0,
            quota_month TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def _hash_pw(password: str) -> str:
    return hashlib.sha256(password.strip().encode("utf-8")).hexdigest()

def _current_month() -> str:
    return datetime.datetime.now().strftime("%Y-%m")

def register_user(email: str, password: str) -> tuple[bool, str]:
    email = email.strip().lower()
    if "@" not in email or len(password.strip()) < 6:
        return False, "Enter a valid email and a password of at least 6 characters."
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO users (email, password_hash, tier, scans_used, quota_month, created_at) VALUES (?, ?, 'free', 0, ?, ?)",
            (email, _hash_pw(password), _current_month(), datetime.datetime.now().isoformat()),
        )
        conn.commit()
        return True, "Account created! You are on the Free tier (3 scans/month)."
    except sqlite3.IntegrityError:
        return False, "An account with that email already exists."
    finally:
        conn.close()

def authenticate_user(email: str, password: str) -> dict | None:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, email, password_hash, tier, scans_used, quota_month FROM users WHERE email = ?", (email.strip().lower(),))
    row = c.fetchone()
    if not row or row[2] != _hash_pw(password):
        conn.close()
        return None
    uid, uemail, _, tier, scans_used, qmonth = row
    curr_m = _current_month()
    if qmonth != curr_m:
        scans_used = 0
        c.execute("UPDATE users SET scans_used = 0, quota_month = ? WHERE id = ?", (curr_m, uid))
        conn.commit()
    conn.close()
    return {"id": uid, "email": uemail, "tier": tier, "scans_used": scans_used}

def check_and_increment_quota(user_id: int) -> tuple[bool, str]:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT tier, scans_used, quota_month FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return False, "User record not found."
    tier, scans_used, qmonth = row
    curr_m = _current_month()
    if qmonth != curr_m:
        scans_used = 0
    if tier == "free" and scans_used >= FREE_MONTHLY_LIMIT:
        conn.close()
        return False, f"Free tier limit reached ({FREE_MONTHLY_LIMIT}/{FREE_MONTHLY_LIMIT} scans this month). Upgrade to Pro for unlimited scans."
    c.execute("UPDATE users SET scans_used = ?, quota_month = ? WHERE id = ?", (scans_used + 1, curr_m, user_id))
    conn.commit()
    conn.close()
    return True, "OK"

def get_user_status(user_id: int) -> dict:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT email, tier, scans_used FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return {"email": "", "tier": "free", "scans_used": 0}
    return {"email": row[0], "tier": row[1], "scans_used": row[2]}

def upgrade_user_to_pro(user_id: int):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET tier = 'pro' WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

def upgrade_user_to_pro(user_id: int):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET tier = 'pro' WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
