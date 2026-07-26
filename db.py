"""
数据库层 - SQLite + aiosqlite
支持多供应商邮箱（Microsoft/Google 等）
"""
import aiosqlite
import os
import hashlib
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(__file__), "data.db")

# ─── 认证 ───
# 内存存储，重启后重置为默认密码
_admin_user = {
    "username": "admin",
    "password_hash": hashlib.sha256("admin123".encode()).hexdigest()
}


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db_conn:
        await db_conn.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT,
                client_id TEXT NOT NULL,
                refresh_token TEXT NOT NULL,
                provider TEXT DEFAULT 'microsoft',
                client_secret TEXT DEFAULT '',
                status TEXT DEFAULT 'pending',
                enabled INTEGER DEFAULT 1,
                mail_count INTEGER DEFAULT 0,
                last_check TEXT,
                token_created_at TEXT,
                error TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            )
        """)
        await db_conn.execute("""
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER,
                folder TEXT,
                uid TEXT,
                from_addr TEXT,
                subject TEXT,
                body TEXT,
                body_html TEXT,
                date TEXT,
                fetched_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (account_id) REFERENCES accounts(id)
            )
        """)
        await db_conn.commit()
        # 迁移：添加新列
        for col, dtype, default in [
            ("provider", "TEXT", "'microsoft'"),
            ("client_secret", "TEXT", "''"),
            ("enabled", "INTEGER", "1"),
            ("mail_count", "INTEGER", "0"),
        ]:
            try:
                await db_conn.execute(f"ALTER TABLE accounts ADD COLUMN {col} {dtype} DEFAULT {default}")
                await db_conn.commit()
            except:
                pass


def verify_user(username: str, password: str) -> bool:
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    return username == _admin_user["username"] and pw_hash == _admin_user["password_hash"]


def change_password(old_password: str, new_password: str) -> bool:
    old_hash = hashlib.sha256(old_password.encode()).hexdigest()
    if old_hash != _admin_user["password_hash"]:
        return False
    _admin_user["password_hash"] = hashlib.sha256(new_password.encode()).hexdigest()
    return True


async def import_accounts(lines: list[str]) -> dict:
    """导入账号。格式：邮箱----密码----client_id----refresh_token"""
    result = {"success": 0, "failed": 0, "errors": []}
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split('----')
        if len(parts) < 4:
            result["failed"] += 1
            result["errors"].append(f"格式错误: {line[:30]}...")
            continue
        email_addr, password, client_id, refresh_token = parts[0].strip(), parts[1].strip(), parts[2].strip(), parts[3].strip()
        # 自动识别供应商
        from mail_fetcher import detect_provider
        provider = detect_provider(email_addr)
        try:
            await add_account(email_addr, password, client_id, refresh_token, provider)
            result["success"] += 1
        except Exception as e:
            result["failed"] += 1
            result["errors"].append(f"{email_addr}: {str(e)[:50]}")
    return result


async def add_account(email: str, password: str, client_id: str, refresh_token: str,
                      provider: str = "microsoft", client_secret: str = ""):
    async with aiosqlite.connect(DB_PATH) as db_conn:
        now = datetime.now().isoformat()
        await db_conn.execute("""
            INSERT OR REPLACE INTO accounts (email, password, client_id, refresh_token, provider, client_secret, token_created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (email, password, client_id, refresh_token, provider, client_secret, now))
        await db_conn.commit()


async def get_accounts(page: int = 1, per_page: int = 50):
    async with aiosqlite.connect(DB_PATH) as db_conn:
        db_conn.row_factory = aiosqlite.Row
        offset = (page - 1) * per_page
        cursor = await db_conn.execute(
            "SELECT * FROM accounts ORDER BY id LIMIT ? OFFSET ?", (per_page, offset)
        )
        rows = await cursor.fetchall()
        cursor2 = await db_conn.execute("SELECT COUNT(*) FROM accounts")
        total = (await cursor2.fetchone())[0]
        return [dict(row) for row in rows], total


async def get_all_active_accounts():
    async with aiosqlite.connect(DB_PATH) as db_conn:
        db_conn.row_factory = aiosqlite.Row
        cursor = await db_conn.execute(
            "SELECT * FROM accounts WHERE enabled = 1 ORDER BY id"
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def get_account(account_id: int):
    async with aiosqlite.connect(DB_PATH) as db_conn:
        db_conn.row_factory = aiosqlite.Row
        cursor = await db_conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None


async def update_account_status(account_id: int, status: str, error: str = None, mail_count: int = None):
    async with aiosqlite.connect(DB_PATH) as db_conn:
        now = datetime.now().isoformat()
        if mail_count is not None:
            await db_conn.execute("""
                UPDATE accounts SET status = ?, last_check = ?, error = ?, mail_count = ? WHERE id = ?
            """, (status, now, error, mail_count, account_id))
        else:
            await db_conn.execute("""
                UPDATE accounts SET status = ?, last_check = ?, error = ? WHERE id = ?
            """, (status, now, error, account_id))
        await db_conn.commit()


async def update_refresh_token(account_id: int, new_refresh_token: str):
    async with aiosqlite.connect(DB_PATH) as db_conn:
        now = datetime.now().isoformat()
        await db_conn.execute("""
            UPDATE accounts SET refresh_token = ?, token_created_at = ? WHERE id = ?
        """, (new_refresh_token, now, account_id))
        await db_conn.commit()


async def refresh_token_date(account_id: int):
    async with aiosqlite.connect(DB_PATH) as db_conn:
        now = datetime.now().isoformat()
        await db_conn.execute("UPDATE accounts SET token_created_at = ? WHERE id = ?", (now, account_id))
        await db_conn.commit()


async def save_emails(account_id: int, folder: str, emails: list[dict]) -> int:
    async with aiosqlite.connect(DB_PATH) as db_conn:
        count = 0
        for em in emails:
            try:
                await db_conn.execute("""
                    INSERT INTO emails (account_id, folder, uid, from_addr, subject, body, body_html, date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (account_id, folder, em.get('uid', ''), em.get('from', ''),
                      em.get('subject', ''), em.get('body', ''), em.get('body_html', ''), em.get('date', '')))
                count += 1
            except:
                pass
        await db_conn.commit()
        return count


async def get_emails(account_id: int, folder: str = None, limit: int = 50, page: int = 1, per_page: int = 50):
    async with aiosqlite.connect(DB_PATH) as db_conn:
        db_conn.row_factory = aiosqlite.Row
        offset = (page - 1) * per_page
        if folder:
            cursor = await db_conn.execute(
                "SELECT * FROM emails WHERE account_id = ? AND folder = ? ORDER BY id DESC LIMIT ? OFFSET ?",
                (account_id, folder, per_page, offset)
            )
            cursor2 = await db_conn.execute(
                "SELECT COUNT(*) FROM emails WHERE account_id = ? AND folder = ?",
                (account_id, folder)
            )
        else:
            cursor = await db_conn.execute(
                "SELECT * FROM emails WHERE account_id = ? ORDER BY id DESC LIMIT ? OFFSET ?",
                (account_id, per_page, offset)
            )
            cursor2 = await db_conn.execute(
                "SELECT COUNT(*) FROM emails WHERE account_id = ?", (account_id,)
            )
        rows = await cursor.fetchall()
        total = (await cursor2.fetchone())[0]
        return [dict(row) for row in rows], total


async def get_email(email_id: int):
    async with aiosqlite.connect(DB_PATH) as db_conn:
        db_conn.row_factory = aiosqlite.Row
        cursor = await db_conn.execute("SELECT * FROM emails WHERE id = ?", (email_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_expiring_accounts(warning_days: int = 14):
    async with aiosqlite.connect(DB_PATH) as db_conn:
        db_conn.row_factory = aiosqlite.Row
        threshold = (datetime.now() - timedelta(days=90 - warning_days)).isoformat()
        cursor = await db_conn.execute("""
            SELECT * FROM accounts WHERE token_created_at IS NOT NULL AND token_created_at < ?
        """, (threshold,))
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def get_stats():
    async with aiosqlite.connect(DB_PATH) as db_conn:
        cursor = await db_conn.execute("SELECT COUNT(*) FROM accounts")
        total = (await cursor.fetchone())[0]
        cursor = await db_conn.execute("SELECT COUNT(*) FROM accounts WHERE status = 'active'")
        ok = (await cursor.fetchone())[0]
        cursor = await db_conn.execute("SELECT COUNT(*) FROM accounts WHERE status = 'error'")
        err = (await cursor.fetchone())[0]
        cursor = await db_conn.execute("SELECT COUNT(*) FROM emails")
        total_emails = (await cursor.fetchone())[0]
        return {"total": total, "ok": ok, "error": err, "pending": total - ok - err, "total_emails": total_emails}


async def disable_account(account_id: int):
    async with aiosqlite.connect(DB_PATH) as db_conn:
        await db_conn.execute("UPDATE accounts SET enabled = 0 WHERE id = ?", (account_id,))
        await db_conn.commit()


async def enable_account(account_id: int):
    async with aiosqlite.connect(DB_PATH) as db_conn:
        await db_conn.execute("UPDATE accounts SET enabled = 1 WHERE id = ?", (account_id,))
        await db_conn.commit()


async def delete_account(account_id: int):
    async with aiosqlite.connect(DB_PATH) as db_conn:
        await db_conn.execute("DELETE FROM emails WHERE account_id = ?", (account_id,))
        await db_conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        await db_conn.commit()
