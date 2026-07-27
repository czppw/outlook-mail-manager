"""
数据库层 - SQLite + aiosqlite
支持多供应商邮箱（Microsoft/Google 等）

数据安全说明：
- 重新导入同一邮箱使用 UPSERT（保留 id / 状态 / 历史邮件关联）
- emails 表有 (account_id, folder, uid) 唯一索引，重复取件不会重复入库
- 管理员密码持久化在 settings 表（重启不丢失），首次启动可用
  OMM_ADMIN_PASSWORD 环境变量指定初始密码
- 数据库路径可用 OMM_DB_PATH 环境变量覆盖（便于测试与部署）
"""
import aiosqlite
import os
import hmac
import hashlib
from datetime import datetime, timedelta

DB_PATH = os.environ.get(
    "OMM_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.db")
)

ADMIN_USERNAME = "admin"
TOKEN_LIFETIME_DAYS = 90
TOKEN_WARNING_DAYS = 14


async def _get_setting(key: str):
    async with aiosqlite.connect(DB_PATH) as db_conn:
        cursor = await db_conn.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = await cursor.fetchone()
        return row[0] if row else None


async def _set_setting(key: str, value: str):
    async with aiosqlite.connect(DB_PATH) as db_conn:
        await db_conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value)
        )
        await db_conn.commit()


async def get_setting(key: str):
    """公开的配置读取（全局代理、默认取件方式等）。"""
    return await _get_setting(key)


async def set_setting(key: str, value: str):
    await _set_setting(key, value)


def _hash_password(password: str) -> str:
    # 个人单用户工具，沿用 sha256；如需更强可换 bcrypt/argon2
    return hashlib.sha256(password.encode()).hexdigest()


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
                fetch_mode TEXT DEFAULT 'imap',
                proxy TEXT DEFAULT '',
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
        await db_conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        await db_conn.commit()

        # 迁移：兼容旧部署版本的列名差异（某些旧版用 last_error / sender / received_at）
        async def _columns(table: str) -> set:
            cur = await db_conn.execute(f"PRAGMA table_info({table})")
            return {r[1] for r in await cur.fetchall()}

        acc_cols = await _columns("accounts")
        if "last_error" in acc_cols and "error" not in acc_cols:
            await db_conn.execute("ALTER TABLE accounts RENAME COLUMN last_error TO error")
        em_cols = await _columns("emails")
        if "sender" in em_cols and "from_addr" not in em_cols:
            await db_conn.execute("ALTER TABLE emails RENAME COLUMN sender TO from_addr")
        if "received_at" in em_cols and "date" not in em_cols:
            await db_conn.execute("ALTER TABLE emails RENAME COLUMN received_at TO date")
        await db_conn.commit()

        # 迁移：为旧库添加新列（列已存在时 ALTER 会报错，忽略即可）
        for col, dtype, default in [
            ("provider", "TEXT", "'microsoft'"),
            ("client_secret", "TEXT", "''"),
            ("fetch_mode", "TEXT", "'imap'"),
            ("proxy", "TEXT", "''"),
            ("enabled", "INTEGER", "1"),
            ("mail_count", "INTEGER", "0"),
            ("status", "TEXT", "'pending'"),
            ("last_check", "TEXT", "NULL"),
            ("token_created_at", "TEXT", "NULL"),
            ("error", "TEXT", "NULL"),
        ]:
            try:
                await db_conn.execute(
                    f"ALTER TABLE accounts ADD COLUMN {col} {dtype} DEFAULT {default}"
                )
                await db_conn.commit()
            except Exception:
                pass

        # 迁移：清理孤儿邮件（账号已被 REPLACE/删除导致关联丢失的历史数据）
        await db_conn.execute(
            "DELETE FROM emails WHERE account_id NOT IN (SELECT id FROM accounts)"
        )
        # 迁移：统一历史文件夹标签（旧版 Gmail 垃圾邮件存为 [Gmail]/Spam）
        await db_conn.execute("UPDATE emails SET folder = 'JUNK' WHERE folder = '[Gmail]/Spam'")
        # 迁移：去除重复邮件后再建唯一索引（保留最早一条）
        await db_conn.execute("""
            DELETE FROM emails WHERE id NOT IN (
                SELECT MIN(id) FROM emails GROUP BY account_id, folder, uid
            )
        """)
        await db_conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_emails_dedup
            ON emails(account_id, folder, uid)
        """)
        await db_conn.commit()

    # 首次启动：播种管理员密码（环境变量优先，否则默认 admin123）
    if await _get_setting("admin_password_hash") is None:
        initial = os.environ.get("OMM_ADMIN_PASSWORD", "admin123")
        await _set_setting("admin_password_hash", _hash_password(initial))


# ─── 认证 ───

async def verify_user(username: str, password: str) -> bool:
    if username != ADMIN_USERNAME:
        return False
    stored = await _get_setting("admin_password_hash")
    if stored is None:
        return False
    return hmac.compare_digest(_hash_password(password), stored)


async def change_password(old_password: str, new_password: str) -> bool:
    stored = await _get_setting("admin_password_hash")
    if stored is None or not hmac.compare_digest(_hash_password(old_password), stored):
        return False
    await _set_setting("admin_password_hash", _hash_password(new_password))
    return True


# ─── 账号 ───

async def import_accounts(lines: list[str], ms_fetch_mode: str = "graph") -> dict:
    """导入账号。格式：邮箱----密码----client_id----refresh_token

    Gmail 账号的「密码」字段实为 client_secret，导入时同步写入 client_secret 列。
    同一邮箱重复导入走 UPDATE，保留 id / 状态 / 历史邮件。
    ms_fetch_mode：新导入 MS 账号的默认取件方式（graph/imap），由调用方从全局设置解析。
    """
    result = {"added": 0, "updated": 0, "failed": 0, "errors": []}
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split('----')
        if len(parts) < 4:
            result["failed"] += 1
            result["errors"].append(f"格式错误: {line[:30]}...")
            continue
        email_addr = parts[0].strip()
        password = parts[1].strip()
        client_id = parts[2].strip()
        refresh_token = parts[3].strip()
        from mail_fetcher import detect_provider
        provider = detect_provider(email_addr)
        # Gmail：密码字段实际存的是 client_secret；Google 仅支持 IMAP
        client_secret = password if provider == "google" else ""
        fetch_mode = ms_fetch_mode if provider == "microsoft" else "imap"
        try:
            outcome = await add_account(
                email_addr, password, client_id, refresh_token,
                provider=provider, client_secret=client_secret,
                fetch_mode=fetch_mode,
            )
            result["added" if outcome == "added" else "updated"] += 1
        except Exception as e:
            result["failed"] += 1
            result["errors"].append(f"{email_addr}: {str(e)[:50]}")
    return result


async def add_account(email: str, password: str, client_id: str, refresh_token: str,
                      provider: str = "microsoft", client_secret: str = "",
                      fetch_mode: str = "imap") -> str:
    """新增或更新账号。重复邮箱只更新凭据字段，保留 id/状态/邮件关联。
    返回 'added' 或 'updated'。"""
    async with aiosqlite.connect(DB_PATH) as db_conn:
        now = datetime.now().isoformat()
        cursor = await db_conn.execute("SELECT id FROM accounts WHERE email = ?", (email,))
        row = await cursor.fetchone()
        if row:
            await db_conn.execute("""
                UPDATE accounts
                SET password = ?, client_id = ?, refresh_token = ?,
                    provider = ?, client_secret = ?, token_created_at = ?
                WHERE email = ?
            """, (password, client_id, refresh_token, provider, client_secret, now, email))
            await db_conn.commit()
            return "updated"
        await db_conn.execute("""
            INSERT INTO accounts
                (email, password, client_id, refresh_token, provider, client_secret, fetch_mode, token_created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (email, password, client_id, refresh_token, provider, client_secret, fetch_mode, now))
        await db_conn.commit()
        return "added"


async def get_accounts(page: int = 1, per_page: int = 50,
                       provider: str = None, status: str = None,
                       fetch_mode: str = None, keyword: str = None):
    """分页查询账号，支持供应商/状态/取件方式/邮箱关键词筛选。
    status='disabled' 特指已禁用（enabled=0），其余匹配 status 列。"""
    where, params = [], []
    if provider:
        where.append("provider = ?")
        params.append(provider)
    if fetch_mode:
        where.append("fetch_mode = ?")
        params.append(fetch_mode)
    if status == "disabled":
        where.append("enabled = 0")
    elif status:
        where.append("status = ?")
        params.append(status)
    if keyword:
        where.append("email LIKE ?")
        params.append(f"%{keyword}%")
    w = (" WHERE " + " AND ".join(where)) if where else ""

    async with aiosqlite.connect(DB_PATH) as db_conn:
        db_conn.row_factory = aiosqlite.Row
        offset = (page - 1) * per_page
        cursor = await db_conn.execute(
            f"SELECT * FROM accounts{w} ORDER BY id LIMIT ? OFFSET ?",
            (*params, per_page, offset)
        )
        rows = await cursor.fetchall()
        cursor2 = await db_conn.execute(f"SELECT COUNT(*) FROM accounts{w}", params)
        total = (await cursor2.fetchone())[0]
        return [dict(row) for row in rows], total


async def get_accounts_by_ids(account_ids: list[int]) -> list[dict]:
    if not account_ids:
        return []
    placeholders = ",".join("?" * len(account_ids))
    async with aiosqlite.connect(DB_PATH) as db_conn:
        db_conn.row_factory = aiosqlite.Row
        cursor = await db_conn.execute(
            f"SELECT * FROM accounts WHERE id IN ({placeholders}) ORDER BY id",
            account_ids
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


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


async def update_account_prefs(account_id: int, fetch_mode: str):
    async with aiosqlite.connect(DB_PATH) as db_conn:
        await db_conn.execute(
            "UPDATE accounts SET fetch_mode = ? WHERE id = ?",
            (fetch_mode, account_id)
        )
        await db_conn.commit()


async def set_all_ms_fetch_mode(fetch_mode: str) -> int:
    """批量切换全部 Microsoft 账号的取件方式。返回受影响账号数。"""
    async with aiosqlite.connect(DB_PATH) as db_conn:
        cursor = await db_conn.execute(
            "UPDATE accounts SET fetch_mode = ? WHERE provider = 'microsoft'",
            (fetch_mode,)
        )
        await db_conn.commit()
        return cursor.rowcount


async def refresh_token_date(account_id: int):
    async with aiosqlite.connect(DB_PATH) as db_conn:
        now = datetime.now().isoformat()
        await db_conn.execute("UPDATE accounts SET token_created_at = ? WHERE id = ?", (now, account_id))
        await db_conn.commit()


# ─── 邮件 ───

async def save_emails(account_id: int, folder: str, emails: list[dict]) -> int:
    """入库邮件，(account_id, folder, uid) 唯一，重复自动忽略。返回真实新增数。"""
    async with aiosqlite.connect(DB_PATH) as db_conn:
        count = 0
        for em in emails:
            cursor = await db_conn.execute("""
                INSERT OR IGNORE INTO emails
                    (account_id, folder, uid, from_addr, subject, body, body_html, date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (account_id, folder, em.get('uid', ''), em.get('from', ''),
                  em.get('subject', ''), em.get('body', ''), em.get('body_html', ''),
                  em.get('date', '')))
            count += cursor.rowcount
        await db_conn.commit()
        return count


async def get_email_count(account_id: int) -> int:
    async with aiosqlite.connect(DB_PATH) as db_conn:
        cursor = await db_conn.execute(
            "SELECT COUNT(*) FROM emails WHERE account_id = ?", (account_id,)
        )
        return (await cursor.fetchone())[0]


async def get_emails(account_id: int, folder: str = None, page: int = 1, per_page: int = 50):
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


async def get_expiring_accounts(warning_days: int = TOKEN_WARNING_DAYS):
    async with aiosqlite.connect(DB_PATH) as db_conn:
        db_conn.row_factory = aiosqlite.Row
        threshold = (datetime.now() - timedelta(days=TOKEN_LIFETIME_DAYS - warning_days)).isoformat()
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
        return {"total": total, "ok": ok, "error": err, "pending": total - ok - err,
                "total_emails": total_emails}


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
