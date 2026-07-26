"""
SQLite database layer.
"""
import aiosqlite
import os
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(__file__), "data.db")

# Token expiration settings
TOKEN_LIFETIME_DAYS = 90  # 3 months


async def get_db():
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    return db


async def init_db():
    db = await get_db()
    await db.executescript("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT,
            client_id TEXT NOT NULL,
            refresh_token TEXT NOT NULL,
            status TEXT DEFAULT 'active',       -- active / error / disabled
            last_check TEXT,
            last_error TEXT,
            mail_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            token_created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            uid TEXT NOT NULL,
            folder TEXT DEFAULT 'INBOX',
            sender TEXT,
            subject TEXT,
            body TEXT,
            body_html TEXT,
            received_at TEXT,
            is_read INTEGER DEFAULT 0,
            fetched_at TEXT DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (account_id) REFERENCES accounts(id),
            UNIQUE(account_id, uid, folder)
        );
        CREATE INDEX IF NOT EXISTS idx_emails_account ON emails(account_id);
        CREATE INDEX IF NOT EXISTS idx_emails_folder ON emails(folder);
        
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
    """)
    
    # Add token_created_at column if missing (migration for existing DB)
    try:
        await db.execute("SELECT token_created_at FROM accounts LIMIT 1")
    except aiosqlite.OperationalError:
        await db.execute("ALTER TABLE accounts ADD COLUMN token_created_at TEXT DEFAULT (datetime('now','localtime'))")
        await db.commit()
    
    # Create default admin if no users exist
    count = await db.execute_fetchall("SELECT COUNT(*) FROM users")
    if count[0][0] == 0:
        import hashlib
        default_pw = "admin123"
        pw_hash = hashlib.sha256(default_pw.encode()).hexdigest()
        await db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", ("admin", pw_hash))
        await db.commit()
    
    await db.close()


async def import_accounts(lines: list[str]) -> dict:
    """Import accounts from lines. Format: email----password----client_id----refresh_token"""
    db = await get_db()
    added = 0
    skipped = 0
    errors = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split('----')
        if len(parts) < 4:
            errors.append(f"格式错误: {line[:60]}")
            continue
        email, password, client_id, refresh_token = [p.strip() for p in parts[:4]]
        try:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            await db.execute(
                "INSERT OR IGNORE INTO accounts (email, password, client_id, refresh_token, token_created_at) VALUES (?,?,?,?,?)",
                (email, password, client_id, refresh_token, now)
            )
            if db.total_changes:
                added += 1
            else:
                skipped += 1
        except Exception as e:
            errors.append(f"{email}: {e}")
    await db.commit()
    await db.close()
    return {"added": added, "skipped": skipped, "errors": errors}


async def get_accounts(page=1, per_page=50):
    db = await get_db()
    offset = (page - 1) * per_page
    rows = await db.execute_fetchall(
        "SELECT * FROM accounts ORDER BY id DESC LIMIT ? OFFSET ?", (per_page, offset)
    )
    count_row = await db.execute_fetchall("SELECT COUNT(*) as c FROM accounts")
    total = count_row[0][0]
    await db.close()
    return rows, total


async def get_account(account_id: int):
    db = await get_db()
    row = await db.execute_fetchall("SELECT * FROM accounts WHERE id=?", (account_id,))
    await db.close()
    return row[0] if row else None


async def get_all_active_accounts():
    db = await get_db()
    rows = await db.execute_fetchall(
        "SELECT * FROM accounts WHERE status='active' ORDER BY id"
    )
    await db.close()
    return rows


async def update_account_status(account_id: int, status: str, error: str = None, mail_count: int = None):
    db = await get_db()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if mail_count is not None:
        await db.execute(
            "UPDATE accounts SET status=?, last_error=?, last_check=?, mail_count=? WHERE id=?",
            (status, error, now, mail_count, account_id)
        )
    else:
        await db.execute(
            "UPDATE accounts SET status=?, last_error=?, last_check=? WHERE id=?",
            (status, error, now, account_id)
        )
    await db.commit()
    await db.close()


async def save_emails(account_id: int, folder: str, emails: list[dict]):
    db = await get_db()
    saved = 0
    for em in emails:
        try:
            await db.execute(
                """INSERT OR IGNORE INTO emails (account_id, uid, folder, sender, subject, body, body_html, received_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (account_id, em['uid'], folder, em.get('from',''), em.get('subject',''),
                 em.get('body',''), em.get('body_html',''), em.get('date',''))
            )
            saved += 1
        except Exception:
            pass
    await db.commit()
    await db.close()
    return saved


async def get_emails(account_id: int, folder: str = None, page=1, per_page=50):
    db = await get_db()
    offset = (page - 1) * per_page
    if folder:
        rows = await db.execute_fetchall(
            "SELECT * FROM emails WHERE account_id=? AND folder=? ORDER BY id DESC LIMIT ? OFFSET ?",
            (account_id, folder, per_page, offset)
        )
        count_row = await db.execute_fetchall(
            "SELECT COUNT(*) FROM emails WHERE account_id=? AND folder=?", (account_id, folder)
        )
    else:
        rows = await db.execute_fetchall(
            "SELECT * FROM emails WHERE account_id=? ORDER BY id DESC LIMIT ? OFFSET ?",
            (account_id, per_page, offset)
        )
        count_row = await db.execute_fetchall(
            "SELECT COUNT(*) FROM emails WHERE account_id=?", (account_id,)
        )
    total = count_row[0][0]
    await db.close()
    return rows, total


async def get_email(email_id: int):
    db = await get_db()
    row = await db.execute_fetchall("SELECT * FROM emails WHERE id=?", (email_id,))
    await db.close()
    return row[0] if row else None


async def get_stats():
    db = await get_db()
    accounts = await db.execute_fetchall("SELECT COUNT(*) FROM accounts")
    active = await db.execute_fetchall("SELECT COUNT(*) FROM accounts WHERE status='active'")
    errors = await db.execute_fetchall("SELECT COUNT(*) FROM accounts WHERE status='error'")
    emails = await db.execute_fetchall("SELECT COUNT(*) FROM emails")
    
    # Token expiration stats
    cutoff = (datetime.now() - timedelta(days=TOKEN_LIFETIME_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    warning_cutoff = (datetime.now() - timedelta(days=TOKEN_LIFETIME_DAYS - 14)).strftime("%Y-%m-%d %H:%M:%S")
    
    expired = await db.execute_fetchall(
        "SELECT COUNT(*) FROM accounts WHERE token_created_at IS NOT NULL AND token_created_at <= ?", (cutoff,)
    )
    expiring_soon = await db.execute_fetchall(
        "SELECT COUNT(*) FROM accounts WHERE token_created_at IS NOT NULL AND token_created_at > ? AND token_created_at <= ?",
        (cutoff, warning_cutoff)
    )
    
    await db.close()
    return {
        "total_accounts": accounts[0][0],
        "active_accounts": active[0][0],
        "error_accounts": errors[0][0],
        "total_emails": emails[0][0],
        "expired_tokens": expired[0][0],
        "expiring_soon_tokens": expiring_soon[0][0],
    }


async def get_expiring_accounts(warning_days: int = 14):
    """Get accounts with tokens expiring within warning_days."""
    db = await get_db()
    cutoff = (datetime.now() - timedelta(days=TOKEN_LIFETIME_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    warning_cutoff = (datetime.now() - timedelta(days=TOKEN_LIFETIME_DAYS - warning_days)).strftime("%Y-%m-%d %H:%M:%S")
    
    rows = await db.execute_fetchall(
        """SELECT id, email, status, token_created_at,
                  CAST(julianday(token_created_at, '+' || ? || ' days') - julianday('now','localtime') AS INTEGER) as days_left
           FROM accounts 
           WHERE token_created_at IS NOT NULL AND token_created_at <= ?
           ORDER BY token_created_at ASC""",
        (TOKEN_LIFETIME_DAYS, warning_cutoff)
    )
    await db.close()
    return rows


async def refresh_token_date(account_id: int):
    """Mark a token as refreshed (reset the timer)."""
    db = await get_db()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    await db.execute("UPDATE accounts SET token_created_at=? WHERE id=?", (now, account_id))
    await db.commit()
    await db.close()


async def delete_account(account_id: int):
    db = await get_db()
    await db.execute("DELETE FROM emails WHERE account_id=?", (account_id,))
    await db.execute("DELETE FROM accounts WHERE id=?", (account_id,))
    await db.commit()
    await db.close()


async def disable_account(account_id: int):
    db = await get_db()
    await db.execute("UPDATE accounts SET status='disabled' WHERE id=?", (account_id,))
    await db.commit()
    await db.close()


async def enable_account(account_id: int):
    db = await get_db()
    await db.execute("UPDATE accounts SET status='active' WHERE id=?", (account_id,))
    await db.commit()
    await db.close()


async def verify_user(username: str, password: str) -> bool:
    """Verify login credentials."""
    import hashlib
    db = await get_db()
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    row = await db.execute_fetchall(
        "SELECT id FROM users WHERE username=? AND password_hash=?", (username, pw_hash)
    )
    await db.close()
    return len(row) > 0


async def change_password(username: str, new_password: str):
    """Change user password."""
    import hashlib
    db = await get_db()
    pw_hash = hashlib.sha256(new_password.encode()).hexdigest()
    await db.execute("UPDATE users SET password_hash=? WHERE username=?", (pw_hash, username))
    await db.commit()
    await db.close()


async def update_refresh_token(account_id: int, new_refresh_token: str):
    """Update refresh_token and reset the token timer."""
    db = await get_db()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    await db.execute(
        "UPDATE accounts SET refresh_token=?, token_created_at=? WHERE id=?",
        (new_refresh_token, now, account_id)
    )
    await db.commit()
    await db.close()


async def get_account_token_info(account_id: int):
    """Get token expiration info for a single account."""
    db = await get_db()
    row = await db.execute_fetchall(
        """SELECT *,
                  CAST(julianday(token_created_at, '+' || ? || ' days') - julianday('now','localtime') AS INTEGER) as days_left
           FROM accounts WHERE id=?""",
        (TOKEN_LIFETIME_DAYS, account_id)
    )
    await db.close()
    return row[0] if row else None
