"""SQLite persistence, migrations, credentials, and server-side sessions."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from collections.abc import Mapping
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import aiosqlite

import security

DB_PATH = os.environ.get(
    "OMM_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.db"),
)

ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123"
TOKEN_LIFETIME_DAYS = 90
TOKEN_WARNING_DAYS = 14
SCHEMA_VERSION = 6
BUSY_TIMEOUT_MS = 5_000
SESSION_DEFAULT_TTL = 7 * 24 * 60 * 60

_ACCOUNT_SECRET_FIELDS = ("password", "client_secret", "refresh_token", "proxy")
_SETTING_SECRET_KEYS = frozenset({"global_proxy"})
_CREDENTIAL_KEY_CHECK_SETTING = "credential_key_check"
_CREDENTIAL_KEY_CHECK_VALUE = "outlook-mail-manager-key-check-v1"
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_email(value: str) -> str:
    normalized = value.strip().lower()
    try:
        normalized.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("email must contain ASCII characters only") from exc
    if (
        len(normalized) > 320
        or normalized.count("@") != 1
        or any(char.isspace() for char in normalized)
    ):
        raise ValueError("invalid email address")
    local, domain = normalized.split("@", 1)
    if not local or not domain or domain.startswith(".") or domain.endswith("."):
        raise ValueError("invalid email address")
    return normalized


@asynccontextmanager
async def _connection():
    """Open a connection with the same durability and integrity settings."""
    conn = await aiosqlite.connect(DB_PATH, timeout=BUSY_TIMEOUT_MS / 1000)
    conn.row_factory = aiosqlite.Row
    try:
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
        await conn.execute("PRAGMA journal_mode = WAL")
        yield conn
    finally:
        await conn.close()


async def _table_exists(conn: aiosqlite.Connection, table: str) -> bool:
    cursor = await conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
    )
    return await cursor.fetchone() is not None


async def _columns(conn: aiosqlite.Connection, table: str) -> set[str]:
    if not await _table_exists(conn, table):
        return set()
    cursor = await conn.execute(f'PRAGMA table_info("{table}")')
    return {row["name"] for row in await cursor.fetchall()}


async def _add_missing_columns(
    conn: aiosqlite.Connection, table: str, definitions: Mapping[str, str]
) -> None:
    columns = await _columns(conn, table)
    for name, definition in definitions.items():
        if name not in columns:
            await conn.execute(
                f'ALTER TABLE "{table}" ADD COLUMN "{name}" {definition}'
            )


def _create_accounts_sql(table: str = "accounts") -> str:
    return f"""
        CREATE TABLE "{table}" (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL DEFAULT '',
            client_id TEXT NOT NULL DEFAULT '',
            refresh_token TEXT NOT NULL DEFAULT '',
            provider TEXT NOT NULL DEFAULT 'microsoft',
            client_secret TEXT NOT NULL DEFAULT '',
            fetch_mode TEXT NOT NULL DEFAULT 'imap',
            proxy TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
            mail_count INTEGER NOT NULL DEFAULT 0,
            last_check TEXT,
            token_created_at TEXT,
            error TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """


def _create_emails_sql(table: str = "emails") -> str:
    return f"""
        CREATE TABLE "{table}" (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            folder TEXT NOT NULL DEFAULT 'INBOX',
            uid TEXT NOT NULL,
            from_addr TEXT,
            subject TEXT,
            body TEXT,
            body_html TEXT,
            date TEXT,
            is_read INTEGER NOT NULL DEFAULT 0,
            fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
            UNIQUE (account_id, folder, uid)
        )
    """


async def _migration_1_normalize_legacy(conn: aiosqlite.Connection) -> None:
    if not await _table_exists(conn, "accounts"):
        await conn.execute(_create_accounts_sql())
    else:
        await _add_missing_columns(
            conn,
            "accounts",
            {
                "password": "TEXT DEFAULT ''",
                "client_id": "TEXT DEFAULT ''",
                "refresh_token": "TEXT DEFAULT ''",
                "provider": "TEXT DEFAULT 'microsoft'",
                "client_secret": "TEXT DEFAULT ''",
                "fetch_mode": "TEXT DEFAULT 'imap'",
                "proxy": "TEXT DEFAULT ''",
                "status": "TEXT DEFAULT 'pending'",
                "enabled": "INTEGER DEFAULT 1",
                "mail_count": "INTEGER DEFAULT 0",
                "last_check": "TEXT",
                "token_created_at": "TEXT",
                "error": "TEXT",
                "created_at": "TEXT",
            },
        )
        account_columns = await _columns(conn, "accounts")
        if "last_error" in account_columns:
            await conn.execute(
                "UPDATE accounts SET error = COALESCE(error, last_error) WHERE last_error IS NOT NULL"
            )

    await conn.execute(
        "UPDATE accounts SET enabled = 0, status = 'active' "
        "WHERE lower(COALESCE(status, '')) = 'disabled'"
    )

    if not await _table_exists(conn, "emails"):
        await conn.execute(_create_emails_sql())
    else:
        await _add_missing_columns(
            conn,
            "emails",
            {
                "account_id": "INTEGER",
                "folder": "TEXT DEFAULT 'INBOX'",
                "uid": "TEXT",
                "from_addr": "TEXT",
                "subject": "TEXT",
                "body": "TEXT",
                "body_html": "TEXT",
                "date": "TEXT",
                "is_read": "INTEGER DEFAULT 0",
                "fetched_at": "TEXT",
            },
        )
        email_columns = await _columns(conn, "emails")
        if "sender" in email_columns:
            await conn.execute(
                "UPDATE emails SET from_addr = COALESCE(from_addr, sender) WHERE sender IS NOT NULL"
            )
        if "received_at" in email_columns:
            await conn.execute(
                "UPDATE emails SET date = COALESCE(date, received_at) WHERE received_at IS NOT NULL"
            )
    await conn.execute(
        "UPDATE emails SET folder = 'JUNK' WHERE folder = '[Gmail]/Spam'"
    )

    await conn.execute(
        "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)"
    )

    cursor = await conn.execute(
        "SELECT value FROM settings WHERE key = 'admin_password_hash'"
    )
    setting_row = await cursor.fetchone()
    if await _table_exists(conn, "users"):
        user_columns = await _columns(conn, "users")
        if {"username", "password_hash"}.issubset(user_columns):
            cursor = await conn.execute(
                "SELECT password_hash FROM users WHERE username = ? ORDER BY id LIMIT 1",
                (ADMIN_USERNAME,),
            )
            row = await cursor.fetchone()
            user_hash = row["password_hash"] if row else None
            seeded_default = hashlib.sha256(b"admin123").hexdigest()
            should_restore_user = user_hash and (
                setting_row is None
                or (
                    setting_row["value"] == seeded_default
                    and user_hash != seeded_default
                )
            )
            if should_restore_user:
                await conn.execute(
                    "INSERT INTO settings(key, value) VALUES('admin_password_hash', ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (user_hash,),
                )

    cursor = await conn.execute(
        "SELECT value FROM settings WHERE key = 'admin_password_hash'"
    )
    if await cursor.fetchone() is None:
        initial = os.environ.get("OMM_ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD)
        if not initial:
            raise ValueError("OMM_ADMIN_PASSWORD must not be empty")
        await conn.execute(
            "INSERT INTO settings(key, value) VALUES('admin_password_hash', ?)",
            (_hash_password(initial),),
        )


async def _migration_2_rebuild_strict_tables(conn: aiosqlite.Connection) -> None:
    await conn.execute("ALTER TABLE accounts RENAME TO accounts_legacy_v2")
    await conn.execute(_create_accounts_sql())
    await conn.execute(
        """
        INSERT INTO accounts (
            id, email, password, client_id, refresh_token, provider, client_secret,
            fetch_mode, proxy, status, enabled, mail_count, last_check,
            token_created_at, error, created_at
        )
        SELECT
            id, email, COALESCE(password, ''), COALESCE(client_id, ''),
            COALESCE(refresh_token, ''), COALESCE(provider, 'microsoft'),
            COALESCE(client_secret, ''), COALESCE(fetch_mode, 'imap'),
            COALESCE(proxy, ''),
            CASE WHEN lower(COALESCE(status, '')) = 'disabled'
                 THEN 'active' ELSE COALESCE(status, 'pending') END,
            CASE WHEN lower(COALESCE(status, '')) = 'disabled' THEN 0
                 WHEN enabled = 0 THEN 0 ELSE 1 END,
            COALESCE(mail_count, 0), last_check, token_created_at, error,
            COALESCE(created_at, datetime('now'))
        FROM accounts_legacy_v2
        ORDER BY id
        """
    )

    cursor = await conn.execute("SELECT COUNT(*) FROM accounts_legacy_v2")
    old_account_count = (await cursor.fetchone())[0]
    cursor = await conn.execute("SELECT COUNT(*) FROM accounts")
    if (await cursor.fetchone())[0] != old_account_count:
        raise RuntimeError("Account migration count mismatch")

    await conn.execute("ALTER TABLE emails RENAME TO emails_legacy_v2")
    await conn.execute(_create_emails_sql())
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS migration_orphan_emails (
            original_id INTEGER PRIMARY KEY,
            account_id INTEGER,
            folder TEXT,
            uid TEXT,
            from_addr TEXT,
            subject TEXT,
            body TEXT,
            body_html TEXT,
            date TEXT,
            is_read INTEGER,
            fetched_at TEXT,
            reason TEXT NOT NULL,
            migrated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    await conn.execute(
        """
        INSERT INTO migration_orphan_emails (
            original_id, account_id, folder, uid, from_addr, subject, body,
            body_html, date, is_read, fetched_at, reason
        )
        SELECT e.id, e.account_id, e.folder, e.uid, e.from_addr, e.subject,
               e.body, e.body_html, e.date, e.is_read, e.fetched_at,
               CASE
                   WHEN e.account_id IS NULL OR a.id IS NULL THEN 'orphan_account'
                   ELSE 'duplicate_identity'
               END
        FROM emails_legacy_v2 e
        LEFT JOIN accounts a ON a.id = e.account_id
        WHERE e.account_id IS NULL OR a.id IS NULL OR EXISTS (
            SELECT 1 FROM emails_legacy_v2 prior
            WHERE prior.id < e.id
              AND prior.account_id = e.account_id
              AND COALESCE(prior.folder, 'INBOX') = COALESCE(e.folder, 'INBOX')
              AND COALESCE(prior.uid, '') = COALESCE(e.uid, '')
        )
        """
    )
    await conn.execute(
        """
        INSERT INTO emails (
            id, account_id, folder, uid, from_addr, subject, body, body_html,
            date, is_read, fetched_at
        )
        SELECT e.id, e.account_id, COALESCE(e.folder, 'INBOX'),
               COALESCE(e.uid, ''), e.from_addr, e.subject, e.body, e.body_html,
               e.date, COALESCE(e.is_read, 0), COALESCE(e.fetched_at, datetime('now'))
        FROM emails_legacy_v2 e
        JOIN accounts a ON a.id = e.account_id
        WHERE NOT EXISTS (
            SELECT 1 FROM emails_legacy_v2 prior
            WHERE prior.id < e.id
              AND prior.account_id = e.account_id
              AND COALESCE(prior.folder, 'INBOX') = COALESCE(e.folder, 'INBOX')
              AND COALESCE(prior.uid, '') = COALESCE(e.uid, '')
        )
        ORDER BY e.id
        """
    )

    cursor = await conn.execute("SELECT COUNT(*) FROM emails_legacy_v2")
    old_email_count = (await cursor.fetchone())[0]
    cursor = await conn.execute("SELECT COUNT(*) FROM emails")
    live_email_count = (await cursor.fetchone())[0]
    cursor = await conn.execute("SELECT COUNT(*) FROM migration_orphan_emails")
    quarantined_count = (await cursor.fetchone())[0]
    if live_email_count + quarantined_count != old_email_count:
        raise RuntimeError("Email migration count mismatch")

    await conn.execute("DROP TABLE emails_legacy_v2")
    await conn.execute("DROP TABLE accounts_legacy_v2")


async def _migration_3_sessions_and_indexes(conn: aiosqlite.Connection) -> None:
    await conn.execute(
        """
        CREATE TABLE sessions (
            token_hash TEXT PRIMARY KEY NOT NULL,
            username TEXT NOT NULL,
            csrf_token TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        )
        """
    )
    statements = (
        "CREATE INDEX idx_accounts_enabled_id ON accounts(enabled, id)",
        "CREATE INDEX idx_accounts_status_enabled_id ON accounts(status, enabled, id)",
        "CREATE INDEX idx_accounts_provider_fetch_mode ON accounts(provider, fetch_mode)",
        "CREATE INDEX idx_emails_account_id_desc ON emails(account_id, id DESC)",
        "CREATE INDEX idx_emails_account_folder_id_desc ON emails(account_id, folder, id DESC)",
        "CREATE INDEX idx_sessions_expires_at ON sessions(expires_at)",
        "CREATE INDEX idx_sessions_username ON sessions(username)",
    )
    for statement in statements:
        await conn.execute(statement)


async def _migration_4_encrypt_credentials(conn: aiosqlite.Connection) -> None:
    cursor = await conn.execute(
        "SELECT id, password, client_secret, refresh_token, proxy FROM accounts"
    )
    for row in await cursor.fetchall():
        values = [
            security.encrypt_value(row[field], DB_PATH)
            for field in _ACCOUNT_SECRET_FIELDS
        ]
        await conn.execute(
            """
            UPDATE accounts
            SET password = ?, client_secret = ?, refresh_token = ?, proxy = ?
            WHERE id = ?
            """,
            (*values, row["id"]),
        )

    cursor = await conn.execute("SELECT value FROM settings WHERE key = 'global_proxy'")
    row = await cursor.fetchone()
    if row is not None:
        await conn.execute(
            "UPDATE settings SET value = ? WHERE key = 'global_proxy'",
            (security.encrypt_value(row["value"], DB_PATH),),
        )


async def _migration_5_normalize_account_emails(conn: aiosqlite.Connection) -> None:
    cursor = await conn.execute(
        "SELECT lower(trim(email)) AS normalized, COUNT(*) AS count "
        "FROM accounts GROUP BY lower(trim(email)) HAVING COUNT(*) > 1"
    )
    for duplicate_group in await cursor.fetchall():
        normalized = duplicate_group["normalized"]
        cursor = await conn.execute(
            "SELECT id FROM accounts WHERE lower(trim(email)) = ? ORDER BY id DESC",
            (normalized,),
        )
        account_ids = [row["id"] for row in await cursor.fetchall()]
        keeper = account_ids[0]
        for duplicate in account_ids[1:]:
            await conn.execute(
                """
                INSERT OR IGNORE INTO emails (
                    account_id, folder, uid, from_addr, subject, body,
                    body_html, date, is_read, fetched_at
                )
                SELECT ?, folder, uid, from_addr, subject, body,
                       body_html, date, is_read, fetched_at
                FROM emails WHERE account_id = ?
                """,
                (keeper, duplicate),
            )
            await conn.execute("DELETE FROM accounts WHERE id = ?", (duplicate,))

    await conn.execute("UPDATE accounts SET email = lower(trim(email))")
    await conn.execute(
        "CREATE UNIQUE INDEX idx_accounts_email_nocase "
        "ON accounts(email COLLATE NOCASE)"
    )


async def _migration_6_account_leases(conn: aiosqlite.Connection) -> None:
    await conn.execute(
        """
        CREATE TABLE account_leases (
            account_id INTEGER PRIMARY KEY NOT NULL,
            owner_token TEXT UNIQUE NOT NULL,
            expires_at INTEGER NOT NULL,
            FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
        )
        """
    )
    await conn.execute(
        "CREATE INDEX idx_account_leases_expires_at ON account_leases(expires_at)"
    )


_MIGRATIONS = {
    1: _migration_1_normalize_legacy,
    2: _migration_2_rebuild_strict_tables,
    3: _migration_3_sessions_and_indexes,
    4: _migration_4_encrypt_credentials,
    5: _migration_5_normalize_account_emails,
    6: _migration_6_account_leases,
}


async def _database_has_encrypted_credentials(conn: aiosqlite.Connection) -> bool:
    if await _table_exists(conn, "accounts"):
        columns = await _columns(conn, "accounts")
        fields = [field for field in _ACCOUNT_SECRET_FIELDS if field in columns]
        if fields:
            condition = " OR ".join(f'"{field}" LIKE ?' for field in fields)
            cursor = await conn.execute(
                f"SELECT 1 FROM accounts WHERE {condition} LIMIT 1",
                [security.ENCRYPTED_PREFIX + "%"] * len(fields),
            )
            if await cursor.fetchone() is not None:
                return True
    if await _table_exists(conn, "settings"):
        cursor = await conn.execute(
            "SELECT 1 FROM settings WHERE value LIKE ? LIMIT 1",
            (security.ENCRYPTED_PREFIX + "%",),
        )
        if await cursor.fetchone() is not None:
            return True
    return False


async def _validate_encrypted_credentials(conn: aiosqlite.Connection) -> None:
    cursor = await conn.execute(
        "SELECT password, client_secret, refresh_token, proxy FROM accounts"
    )
    for row in await cursor.fetchall():
        for field in _ACCOUNT_SECRET_FIELDS:
            if security.is_encrypted(row[field]):
                security.decrypt_value(row[field], DB_PATH)

    cursor = await conn.execute(
        "SELECT key, value FROM settings WHERE value LIKE ?",
        (security.ENCRYPTED_PREFIX + "%",),
    )
    key_check = None
    for row in await cursor.fetchall():
        plaintext = security.decrypt_value(row["value"], DB_PATH)
        if row["key"] == _CREDENTIAL_KEY_CHECK_SETTING:
            key_check = plaintext
    if key_check is not None and not hmac.compare_digest(
        key_check, _CREDENTIAL_KEY_CHECK_VALUE
    ):
        raise security.CredentialDecryptionError(
            "Credential key check value is invalid"
        )
    if key_check is None:
        await conn.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?)",
            (
                _CREDENTIAL_KEY_CHECK_SETTING,
                security.encrypt_value(_CREDENTIAL_KEY_CHECK_VALUE, DB_PATH),
            ),
        )
        await conn.commit()


async def init_db() -> None:
    async with _connection() as conn:
        encrypted_data = await _database_has_encrypted_credentials(conn)
        if encrypted_data and not security.key_source_exists(DB_PATH):
            raise security.CredentialKeyUnavailableError(
                "Encrypted credentials exist but the configured key source is missing"
            )
        security.load_key(DB_PATH)

        while True:
            cursor = await conn.execute("PRAGMA user_version")
            version = (await cursor.fetchone())[0]
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"Database schema version {version} is newer than supported {SCHEMA_VERSION}"
                )
            if version == SCHEMA_VERSION:
                break

            await conn.execute("BEGIN IMMEDIATE")
            try:
                cursor = await conn.execute("PRAGMA user_version")
                current = (await cursor.fetchone())[0]
                if current >= SCHEMA_VERSION:
                    await conn.rollback()
                    break
                target = current + 1
                await _MIGRATIONS[target](conn)
                await conn.execute(f"PRAGMA user_version = {target}")
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

        cursor = await conn.execute("PRAGMA foreign_key_check")
        violations = await cursor.fetchall()
        if violations:
            raise RuntimeError(f"Foreign key check failed: {violations!r}")
        await _validate_encrypted_credentials(conn)


def _hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    return (
        f"scrypt$v=1$n={_SCRYPT_N}$r={_SCRYPT_R}$p={_SCRYPT_P}$"
        f"{salt.hex()}${digest.hex()}"
    )


def valid_new_password(password: str) -> bool:
    """Require at least eight characters with an ASCII letter and a digit."""

    return (
        len(password) >= 8
        and any("a" <= char.lower() <= "z" for char in password)
        and any("0" <= char <= "9" for char in password)
    )


def _verify_password(password: str, stored: str) -> tuple[bool, bool]:
    if len(stored) == 64 and all(char in "0123456789abcdefABCDEF" for char in stored):
        legacy = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(legacy, stored.lower()), True

    try:
        algorithm, version, n_part, r_part, p_part, salt_hex, digest_hex = stored.split(
            "$"
        )
        if algorithm != "scrypt" or version != "v=1":
            return False, False
        n = int(n_part.removeprefix("n="))
        r = int(r_part.removeprefix("r="))
        p = int(p_part.removeprefix("p="))
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        if n <= 1 or r <= 0 or p <= 0 or not salt or not expected:
            return False, False
        actual = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(expected)
        )
    except (ValueError, TypeError, MemoryError, OverflowError):
        return False, False
    needs_upgrade = (n, r, p, len(expected)) != (
        _SCRYPT_N,
        _SCRYPT_R,
        _SCRYPT_P,
        _SCRYPT_DKLEN,
    )
    return hmac.compare_digest(actual, expected), needs_upgrade


async def _get_setting(key: str):
    async with _connection() as conn:
        cursor = await conn.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = await cursor.fetchone()
        value = row["value"] if row else None
        if key in _SETTING_SECRET_KEYS:
            return security.decrypt_value(value, DB_PATH)
        return value


async def _set_setting(key: str, value: str):
    await set_settings({key: value})


async def get_setting(key: str):
    return await _get_setting(key)


async def set_setting(key: str, value: str):
    await _set_setting(key, value)


async def set_settings(values: Mapping[str, str]) -> None:
    """Atomically persist a group of settings."""
    if not values:
        return
    async with _connection() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        try:
            for key, value in values.items():
                stored = (
                    security.encrypt_value(value, DB_PATH)
                    if key in _SETTING_SECRET_KEYS
                    else value
                )
                await conn.execute(
                    "INSERT INTO settings(key, value) VALUES(?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, stored),
                )
            await conn.commit()
        except Exception:
            await conn.rollback()
            raise


async def verify_user(username: str, password: str) -> bool:
    if username != ADMIN_USERNAME:
        return False
    async with _connection() as conn:
        cursor = await conn.execute(
            "SELECT value FROM settings WHERE key = 'admin_password_hash'"
        )
        row = await cursor.fetchone()
        if not row:
            return False
        stored = row["value"]
        valid, needs_upgrade = _verify_password(password, stored)
        if valid and needs_upgrade:
            replacement = _hash_password(password)
            await conn.execute(
                "UPDATE settings SET value = ? "
                "WHERE key = 'admin_password_hash' AND value = ?",
                (replacement, stored),
            )
            await conn.commit()
        return valid


async def change_password(old_password: str, new_password: str) -> bool:
    if not valid_new_password(new_password):
        raise ValueError(
            "new password must contain at least 8 characters, including a letter and a digit"
        )
    async with _connection() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        try:
            cursor = await conn.execute(
                "SELECT value FROM settings WHERE key = 'admin_password_hash'"
            )
            row = await cursor.fetchone()
            if not row or not _verify_password(old_password, row["value"])[0]:
                await conn.rollback()
                return False
            await conn.execute(
                "UPDATE settings SET value = ? WHERE key = 'admin_password_hash'",
                (_hash_password(new_password),),
            )
            await conn.execute(
                "DELETE FROM sessions WHERE username = ?", (ADMIN_USERNAME,)
            )
            await conn.commit()
            return True
        except Exception:
            await conn.rollback()
            raise


def _session_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _new_session_data(username: str, ttl_seconds: int) -> dict:
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    created_at = int(time.time())
    return {
        "token": secrets.token_urlsafe(32),
        "username": username,
        "csrf_token": secrets.token_urlsafe(32),
        "expires_at": created_at + int(ttl_seconds),
        "created_at": created_at,
    }


async def _insert_session(conn: aiosqlite.Connection, session: dict) -> None:
    await conn.execute(
        "INSERT INTO sessions(token_hash, username, csrf_token, expires_at, created_at) "
        "VALUES(?, ?, ?, ?, ?)",
        (
            _session_token_hash(session["token"]),
            session["username"],
            session["csrf_token"],
            session["expires_at"],
            session["created_at"],
        ),
    )


async def create_session(
    username: str = ADMIN_USERNAME,
    ttl_seconds: int = SESSION_DEFAULT_TTL,
) -> dict:
    session = _new_session_data(username, ttl_seconds)
    async with _connection() as conn:
        await _insert_session(conn, session)
        await conn.commit()
    return session


async def authenticate_and_create_session(
    username: str,
    password: str,
    ttl_seconds: int = SESSION_DEFAULT_TTL,
) -> dict | None:
    """Authenticate and insert a session in one transaction with password changes."""
    if username != ADMIN_USERNAME:
        return None
    session = _new_session_data(username, ttl_seconds)
    async with _connection() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        try:
            cursor = await conn.execute(
                "SELECT value FROM settings WHERE key = 'admin_password_hash'"
            )
            row = await cursor.fetchone()
            if not row:
                await conn.rollback()
                return None
            valid, needs_upgrade = _verify_password(password, row["value"])
            if not valid:
                await conn.rollback()
                return None
            if needs_upgrade:
                await conn.execute(
                    "UPDATE settings SET value = ? "
                    "WHERE key = 'admin_password_hash' AND value = ?",
                    (_hash_password(password), row["value"]),
                )
            await _insert_session(conn, session)
            await conn.commit()
            return session
        except Exception:
            await conn.rollback()
            raise


async def get_session(token: str) -> dict | None:
    token_hash = _session_token_hash(token)
    now = int(time.time())
    async with _connection() as conn:
        cursor = await conn.execute(
            "SELECT username, csrf_token, expires_at, created_at "
            "FROM sessions WHERE token_hash = ?",
            (token_hash,),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        if row["expires_at"] <= now:
            await conn.execute(
                "DELETE FROM sessions WHERE token_hash = ?", (token_hash,)
            )
            await conn.commit()
            return None
        return dict(row)


async def revoke_session(token: str) -> bool:
    async with _connection() as conn:
        cursor = await conn.execute(
            "DELETE FROM sessions WHERE token_hash = ?", (_session_token_hash(token),)
        )
        await conn.commit()
        return cursor.rowcount > 0


async def revoke_all_sessions(username: str | None = None) -> int:
    async with _connection() as conn:
        if username is None:
            cursor = await conn.execute("DELETE FROM sessions")
        else:
            cursor = await conn.execute(
                "DELETE FROM sessions WHERE username = ?", (username,)
            )
        await conn.commit()
        return cursor.rowcount


def _decrypt_account(row: aiosqlite.Row | Mapping | None) -> dict | None:
    if row is None:
        return None
    account = dict(row)
    for field in _ACCOUNT_SECRET_FIELDS:
        account[field] = security.decrypt_value(account.get(field), DB_PATH)
    return account


async def import_accounts(lines: list[str], ms_fetch_mode: str = "graph") -> dict:
    result = {"added": 0, "updated": 0, "failed": 0, "errors": []}
    for line_number, line in enumerate(lines, start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("----", 3)
        if len(parts) < 4:
            result["failed"] += 1
            result["errors"].append(f"第 {line_number} 行格式错误")
            continue
        email_addr, supplied_password, client_id, refresh_token = (
            part.strip() for part in parts[:4]
        )
        try:
            email_addr = _normalize_email(email_addr)
        except ValueError:
            result["failed"] += 1
            result["errors"].append(f"第 {line_number} 行邮箱地址无效")
            continue
        if (
            not client_id
            or len(client_id) > 256
            or not refresh_token
            or len(refresh_token) > 8192
            or len(supplied_password) > 2048
        ):
            result["failed"] += 1
            result["errors"].append(f"第 {line_number} 行字段无效")
            continue
        from mail_fetcher import detect_provider

        provider = detect_provider(email_addr)
        client_secret = supplied_password if provider == "google" else ""
        password = "" if provider == "microsoft" else supplied_password
        fetch_mode = ms_fetch_mode if provider == "microsoft" else "imap"
        try:
            outcome = await add_account(
                email_addr,
                password,
                client_id,
                refresh_token,
                provider=provider,
                client_secret=client_secret,
                fetch_mode=fetch_mode,
            )
            result["added" if outcome == "added" else "updated"] += 1
        except Exception as exc:  # noqa: BLE001 - continue importing valid lines
            result["failed"] += 1
            result["errors"].append(
                f"第 {line_number} 行导入失败 ({type(exc).__name__})"
            )
    return result


async def add_account(
    email: str,
    password: str,
    client_id: str,
    refresh_token: str,
    provider: str = "microsoft",
    client_secret: str = "",
    fetch_mode: str = "imap",
) -> str:
    email = _normalize_email(email)
    stored_password = "" if provider == "microsoft" else password
    now = _now_iso()
    async with _connection() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        try:
            cursor = await conn.execute(
                "SELECT id, refresh_token, token_created_at FROM accounts WHERE email = ?",
                (email,),
            )
            existing = await cursor.fetchone()
            if existing is not None:
                cursor = await conn.execute(
                    "SELECT 1 FROM account_leases "
                    "WHERE account_id = ? AND expires_at > ?",
                    (existing["id"], int(time.time())),
                )
                if await cursor.fetchone() is not None:
                    raise RuntimeError("account operation is already running")
            token_changed = existing is None or not hmac.compare_digest(
                security.decrypt_value(existing["refresh_token"], DB_PATH) or "",
                refresh_token,
            )
            token_created_at = now if token_changed else existing["token_created_at"]
            await conn.execute(
                """
                INSERT INTO accounts (
                    email, password, client_id, refresh_token, provider,
                    client_secret, fetch_mode, token_created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(email) DO UPDATE SET
                    password = excluded.password,
                    client_id = excluded.client_id,
                    refresh_token = excluded.refresh_token,
                    provider = excluded.provider,
                    client_secret = excluded.client_secret,
                    token_created_at = excluded.token_created_at
                """,
                (
                    email,
                    security.encrypt_value(stored_password, DB_PATH),
                    client_id,
                    security.encrypt_value(refresh_token, DB_PATH),
                    provider,
                    security.encrypt_value(client_secret, DB_PATH),
                    fetch_mode,
                    token_created_at,
                ),
            )
            await conn.commit()
            return "updated" if existing else "added"
        except Exception:
            await conn.rollback()
            raise


async def get_accounts(
    page: int = 1,
    per_page: int = 50,
    provider: str | None = None,
    status: str | None = None,
    fetch_mode: str | None = None,
    keyword: str | None = None,
):
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
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    async with _connection() as conn:
        offset = (page - 1) * per_page
        cursor = await conn.execute(
            f"SELECT * FROM accounts{clause} ORDER BY id LIMIT ? OFFSET ?",
            (*params, per_page, offset),
        )
        rows = await cursor.fetchall()
        cursor = await conn.execute(f"SELECT COUNT(*) FROM accounts{clause}", params)
        total = (await cursor.fetchone())[0]
        return [_decrypt_account(row) for row in rows], total


async def get_accounts_by_ids(account_ids: list[int]) -> list[dict]:
    if not account_ids:
        return []
    placeholders = ",".join("?" for _ in account_ids)
    async with _connection() as conn:
        cursor = await conn.execute(
            f"SELECT * FROM accounts WHERE id IN ({placeholders}) ORDER BY id",
            account_ids,
        )
        return [_decrypt_account(row) for row in await cursor.fetchall()]


async def get_all_active_accounts():
    async with _connection() as conn:
        cursor = await conn.execute(
            "SELECT * FROM accounts WHERE enabled = 1 ORDER BY id"
        )
        return [_decrypt_account(row) for row in await cursor.fetchall()]


async def get_account(account_id: int):
    async with _connection() as conn:
        cursor = await conn.execute(
            "SELECT * FROM accounts WHERE id = ?", (account_id,)
        )
        return _decrypt_account(await cursor.fetchone())


async def update_account_status(
    account_id: int,
    status: str,
    error: str | None = None,
    mail_count: int | None = None,
):
    async with _connection() as conn:
        now = _now_iso()
        if mail_count is None:
            await conn.execute(
                "UPDATE accounts SET status = ?, last_check = ?, error = ? WHERE id = ?",
                (status, now, error, account_id),
            )
        else:
            await conn.execute(
                "UPDATE accounts SET status = ?, last_check = ?, error = ?, mail_count = ? "
                "WHERE id = ?",
                (status, now, error, mail_count, account_id),
            )
        await conn.commit()


async def update_refresh_token(account_id: int, new_refresh_token: str):
    async with _connection() as conn:
        cursor = await conn.execute(
            "UPDATE accounts SET refresh_token = ?, token_created_at = ? WHERE id = ?",
            (
                security.encrypt_value(new_refresh_token, DB_PATH),
                _now_iso(),
                account_id,
            ),
        )
        await conn.commit()
        return cursor.rowcount > 0


async def update_refresh_token_cas(
    account_id: int, old_refresh_token: str, new_refresh_token: str
) -> bool:
    """Replace a token only when the caller still owns the current value."""
    async with _connection() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        try:
            cursor = await conn.execute(
                "SELECT refresh_token FROM accounts WHERE id = ?", (account_id,)
            )
            row = await cursor.fetchone()
            if not row:
                await conn.rollback()
                return False
            stored_ciphertext = row["refresh_token"]
            current = security.decrypt_value(stored_ciphertext, DB_PATH) or ""
            if not hmac.compare_digest(current, old_refresh_token):
                await conn.rollback()
                return False
            if hmac.compare_digest(current, new_refresh_token):
                await conn.rollback()
                return True
            cursor = await conn.execute(
                "UPDATE accounts SET refresh_token = ?, token_created_at = ? "
                "WHERE id = ? AND refresh_token = ?",
                (
                    security.encrypt_value(new_refresh_token, DB_PATH),
                    _now_iso(),
                    account_id,
                    stored_ciphertext,
                ),
            )
            await conn.commit()
            return cursor.rowcount == 1
        except Exception:
            await conn.rollback()
            raise


compare_and_swap_refresh_token = update_refresh_token_cas


async def acquire_account_lease(
    account_id: int, ttl_seconds: int = 15 * 60
) -> str | None:
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    owner_token = secrets.token_urlsafe(24)
    now = int(time.time())
    async with _connection() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        try:
            await conn.execute(
                "DELETE FROM account_leases WHERE account_id = ? AND expires_at <= ?",
                (account_id, now),
            )
            cursor = await conn.execute(
                "INSERT OR IGNORE INTO account_leases(account_id, owner_token, expires_at) "
                "VALUES(?, ?, ?)",
                (account_id, owner_token, now + ttl_seconds),
            )
            await conn.commit()
            return owner_token if cursor.rowcount == 1 else None
        except Exception:
            await conn.rollback()
            raise


async def release_account_lease(account_id: int, owner_token: str) -> bool:
    async with _connection() as conn:
        cursor = await conn.execute(
            "DELETE FROM account_leases WHERE account_id = ? AND owner_token = ?",
            (account_id, owner_token),
        )
        await conn.commit()
        return cursor.rowcount == 1


async def update_account_prefs(account_id: int, fetch_mode: str):
    async with _connection() as conn:
        await conn.execute(
            "UPDATE accounts SET fetch_mode = ? WHERE id = ?", (fetch_mode, account_id)
        )
        await conn.commit()


async def update_account_proxy(account_id: int, proxy: str) -> bool:
    async with _connection() as conn:
        cursor = await conn.execute(
            "UPDATE accounts SET proxy = ? WHERE id = ?",
            (security.encrypt_value(proxy, DB_PATH), account_id),
        )
        await conn.commit()
        return cursor.rowcount == 1


async def set_all_ms_fetch_mode(fetch_mode: str) -> int:
    async with _connection() as conn:
        cursor = await conn.execute(
            "UPDATE accounts SET fetch_mode = ? WHERE provider = 'microsoft'",
            (fetch_mode,),
        )
        await conn.commit()
        return cursor.rowcount


async def refresh_token_date(account_id: int):
    async with _connection() as conn:
        await conn.execute(
            "UPDATE accounts SET token_created_at = ? WHERE id = ?",
            (_now_iso(), account_id),
        )
        await conn.commit()


async def save_emails(account_id: int, folder: str, emails: list[dict]) -> int:
    async with _connection() as conn:
        count = 0
        for email in emails:
            uid = email.get("uid")
            if uid is None or str(uid) == "":
                raise ValueError("Email UID must not be empty")
            cursor = await conn.execute(
                """
                INSERT INTO emails (
                    account_id, folder, uid, from_addr, subject, body, body_html, date
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(account_id, folder, uid) DO NOTHING
                """,
                (
                    account_id,
                    folder,
                    str(uid),
                    email.get("from", ""),
                    email.get("subject", ""),
                    email.get("body", ""),
                    email.get("body_html", ""),
                    email.get("date", ""),
                ),
            )
            count += cursor.rowcount
        await conn.commit()
        return count


async def get_email_count(account_id: int) -> int:
    async with _connection() as conn:
        cursor = await conn.execute(
            "SELECT COUNT(*) FROM emails WHERE account_id = ?", (account_id,)
        )
        return (await cursor.fetchone())[0]


async def get_emails(
    account_id: int,
    folder: str | None = None,
    page: int = 1,
    per_page: int = 50,
):
    async with _connection() as conn:
        offset = (page - 1) * per_page
        if folder:
            cursor = await conn.execute(
                "SELECT * FROM emails WHERE account_id = ? AND folder = ? "
                "ORDER BY id DESC LIMIT ? OFFSET ?",
                (account_id, folder, per_page, offset),
            )
            count_cursor = await conn.execute(
                "SELECT COUNT(*) FROM emails WHERE account_id = ? AND folder = ?",
                (account_id, folder),
            )
        else:
            cursor = await conn.execute(
                "SELECT * FROM emails WHERE account_id = ? "
                "ORDER BY id DESC LIMIT ? OFFSET ?",
                (account_id, per_page, offset),
            )
            count_cursor = await conn.execute(
                "SELECT COUNT(*) FROM emails WHERE account_id = ?", (account_id,)
            )
        rows = await cursor.fetchall()
        total = (await count_cursor.fetchone())[0]
        return [dict(row) for row in rows], total


async def get_email(email_id: int):
    async with _connection() as conn:
        cursor = await conn.execute("SELECT * FROM emails WHERE id = ?", (email_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_expiring_accounts(warning_days: int = TOKEN_WARNING_DAYS):
    threshold = (
        datetime.fromisoformat(_now_iso())
        - timedelta(days=TOKEN_LIFETIME_DAYS - warning_days)
    ).isoformat()
    async with _connection() as conn:
        cursor = await conn.execute(
            "SELECT * FROM accounts WHERE token_created_at IS NOT NULL "
            "AND julianday(token_created_at) < julianday(?)",
            (threshold,),
        )
        return [_decrypt_account(row) for row in await cursor.fetchall()]


async def get_stats():
    async with _connection() as conn:
        cursor = await conn.execute("SELECT COUNT(*) FROM accounts")
        total = (await cursor.fetchone())[0]
        cursor = await conn.execute(
            "SELECT COUNT(*) FROM accounts WHERE status = 'active' AND enabled = 1"
        )
        ok = (await cursor.fetchone())[0]
        cursor = await conn.execute(
            "SELECT COUNT(*) FROM accounts WHERE status = 'error' AND enabled = 1"
        )
        error = (await cursor.fetchone())[0]
        cursor = await conn.execute("SELECT COUNT(*) FROM accounts WHERE enabled = 0")
        disabled = (await cursor.fetchone())[0]
        cursor = await conn.execute("SELECT COUNT(*) FROM emails")
        total_emails = (await cursor.fetchone())[0]
        return {
            "total": total,
            "ok": ok,
            "error": error,
            "disabled": disabled,
            "pending": total - ok - error - disabled,
            "total_emails": total_emails,
        }


async def disable_account(account_id: int):
    async with _connection() as conn:
        await conn.execute(
            "UPDATE accounts SET enabled = 0 WHERE id = ?", (account_id,)
        )
        await conn.commit()


async def enable_account(account_id: int):
    async with _connection() as conn:
        await conn.execute(
            "UPDATE accounts SET enabled = 1 WHERE id = ?", (account_id,)
        )
        await conn.commit()


async def delete_account(account_id: int):
    async with _connection() as conn:
        await conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        await conn.commit()
