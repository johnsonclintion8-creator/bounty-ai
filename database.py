import os, sqlite3, hashlib, datetime

DB_PATH = "bounty_ai.db"
FREE_MONTHLY_LIMIT = 3
SUPABASE_DB_URL = os.environ.get("SUPABASE_DB_URL", "").strip()

def _get_conn():
    if SUPABASE_DB_URL:
        import psycopg2
        return psycopg2.connect(SUPABASE_DB_URL), True
    return sqlite3.connect(DB_PATH), False

def init_db():
    conn, is_pg = _get_conn()
    c = conn.cursor()
    id_col = "SERIAL PRIMARY KEY" if is_pg else "INTEGER PRIMARY KEY AUTOINCREMENT"
    c.execute(f"CREATE TABLE IF NOT EXISTS users (id {id_col}, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, tier TEXT DEFAULT 'free', scans_used INTEGER DEFAULT 0, quota_month TEXT NOT NULL, created_at TEXT NOT NULL)")
    c.execute(f"CREATE TABLE IF NOT EXISTS reports (id {id_col}, user_id INTEGER NOT NULL, target TEXT NOT NULL, grade TEXT DEFAULT 'N/A', markdown_body TEXT NOT NULL, created_at TEXT NOT NULL)")
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
    conn, is_pg = _get_conn()
    c = conn.cursor()
    ph = "%s" if is_pg else "?"
    try:
        c.execute(f"INSERT INTO users (email, password_hash, tier, scans_used, quota_month, created_at) VALUES ({ph}, {ph}, 'free', 0, {ph}, {ph})", (email, _hash_pw(password), _current_month(), datetime.datetime.now().isoformat()))
        conn.commit()
        return True, "Account created! You are on the Free tier (3 scans/month)."
    except Exception:
        return False, "An account with that email already exists."
    finally:
        conn.close()

def authenticate_user(email: str, password: str) -> dict | None:
    init_db()
    conn, is_pg = _get_conn()
    c = conn.cursor()
    ph = "%s" if is_pg else "?"
    c.execute(f"SELECT id, email, password_hash, tier, scans_used, quota_month FROM users WHERE email = {ph}", (email.strip().lower(),))
    row = c.fetchone()
    if not row or row[2] != _hash_pw(password):
        conn.close()
        return None
    uid, uemail, _, tier, scans_used, qmonth = row
    curr_m = _current_month()
    if qmonth != curr_m:
        scans_used = 0
        c.execute(f"UPDATE users SET scans_used = 0, quota_month = {ph} WHERE id = {ph}", (curr_m, uid))
        conn.commit()
    conn.close()
    return {"id": uid, "email": uemail, "tier": tier, "scans_used": scans_used}

def reset_user_password(email: str, new_password: str) -> tuple[bool, str]:
    if len(new_password.strip()) < 6:
        return False, "New password must be at least 6 characters."
    init_db()
    conn, is_pg = _get_conn()
    c = conn.cursor()
    ph = "%s" if is_pg else "?"
    c.execute(f"SELECT id FROM users WHERE email = {ph}", (email.strip().lower(),))
    row = c.fetchone()
    if not row:
        conn.close()
        return False, "No account found with that email."
    c.execute(f"UPDATE users SET password_hash = {ph} WHERE id = {ph}", (_hash_pw(new_password), row[0]))
    conn.commit()
    conn.close()
    return True, "Password updated! You can now sign in with your new password."

def can_user_scan(user_id: int) -> tuple[bool, str]:
    init_db()
    conn, is_pg = _get_conn()
    c = conn.cursor()
    ph = "%s" if is_pg else "?"
    c.execute(f"SELECT tier, scans_used, quota_month FROM users WHERE id = {ph}", (user_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False, "User record not found."
    tier, scans_used, qmonth = row
    if qmonth != _current_month():
        scans_used = 0
    if tier == "free" and scans_used >= FREE_MONTHLY_LIMIT:
        return False, f"Free tier limit reached ({FREE_MONTHLY_LIMIT}/{FREE_MONTHLY_LIMIT} scans this month). Upgrade to Pro in the sidebar for unlimited scans."
    return True, "OK"

def increment_user_quota(user_id: int):
    init_db()
    conn, is_pg = _get_conn()
    c = conn.cursor()
    ph = "%s" if is_pg else "?"
    c.execute(f"SELECT scans_used, quota_month FROM users WHERE id = {ph}", (user_id,))
    row = c.fetchone()
    if row:
        curr_m = _current_month()
        used = 0 if row[1] != curr_m else row[0]
        c.execute(f"UPDATE users SET scans_used = {ph}, quota_month = {ph} WHERE id = {ph}", (used + 1, curr_m, user_id))
        conn.commit()
    conn.close()

def upgrade_user_to_pro(user_id: int):
    init_db()
    conn, is_pg = _get_conn()
    c = conn.cursor()
    ph = "%s" if is_pg else "?"
    c.execute(f"UPDATE users SET tier = 'pro' WHERE id = {ph}", (user_id,))
    conn.commit()
    conn.close()

def get_user_status(user_id: int) -> dict:
    init_db()
    conn, is_pg = _get_conn()
    c = conn.cursor()
    ph = "%s" if is_pg else "?"
    c.execute(f"SELECT email, tier, scans_used FROM users WHERE id = {ph}", (user_id,))
    row = c.fetchone()
    conn.close()
    return {"email": row[0], "tier": row[1], "scans_used": row[2]} if row else {"email": "", "tier": "free", "scans_used": 0}

def save_cloud_report(user_id: int, target: str, grade: str, markdown_body: str):
    init_db()
    conn, is_pg = _get_conn()
    c = conn.cursor()
    ph = "%s" if is_pg else "?"
    c.execute(f"INSERT INTO reports (user_id, target, grade, markdown_body, created_at) VALUES ({ph}, {ph}, {ph}, {ph}, {ph})", (user_id, target, grade, markdown_body, datetime.datetime.now().strftime("%Y-%m-%d %H:%M")))
    conn.commit()
    conn.close()

def get_user_reports(user_id: int) -> list[dict]:
    init_db()
    conn, is_pg = _get_conn()
    c = conn.cursor()
    ph = "%s" if is_pg else "?"
    c.execute(f"SELECT id, target, grade, markdown_body, created_at FROM reports WHERE user_id = {ph} ORDER BY id DESC LIMIT 30", (user_id,))
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "target": r[1], "grade": r[2], "markdown_body": r[3], "created_at": r[4]} for r in rows]
