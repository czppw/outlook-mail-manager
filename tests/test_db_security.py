from __future__ import annotations

import asyncio
import hashlib
import os
import sqlite3
import stat
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from cryptography.fernet import Fernet

import db
import security


class DatabaseSecurityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.db_path = Path(self.tempdir.name) / "data.db"
        self.key_path = Path(self.tempdir.name) / "secret.key"
        self.env = mock.patch.dict(
            os.environ,
            {
                "OMM_DB_PATH": str(self.db_path),
                "OMM_SECRET_KEY_FILE": str(self.key_path),
                "OMM_ADMIN_PASSWORD": "initial-password",
            },
            clear=False,
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.original_db_path = db.DB_PATH
        db.DB_PATH = str(self.db_path)
        self.addCleanup(setattr, db, "DB_PATH", self.original_db_path)

    @contextmanager
    def raw(self):
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def create_historical_database(self) -> None:
        legacy_hash = hashlib.sha256(b"legacy-password").hexdigest()
        with self.raw() as conn:
            conn.executescript(
                """
                CREATE TABLE accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT,
                    client_id TEXT NOT NULL,
                    refresh_token TEXT NOT NULL,
                    status TEXT DEFAULT 'active',
                    last_check TEXT,
                    last_error TEXT,
                    mail_count INTEGER DEFAULT 0,
                    created_at TEXT,
                    token_created_at TEXT
                );
                CREATE TABLE emails (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id INTEGER,
                    uid TEXT,
                    folder TEXT,
                    sender TEXT,
                    subject TEXT,
                    body TEXT,
                    body_html TEXT,
                    received_at TEXT,
                    is_read INTEGER DEFAULT 0,
                    fetched_at TEXT
                );
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT
                );
                CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
                """
            )
            conn.execute(
                """
                INSERT INTO accounts (
                    id, email, password, client_id, refresh_token, status,
                    last_error, mail_count, created_at, token_created_at
                ) VALUES (7, 'old@outlook.com', 'old-password', 'client-id',
                          'refresh-old', 'disabled', 'old error', 2,
                          '2024-01-01 00:00:00', '2024-01-02 00:00:00')
                """
            )
            conn.execute(
                """
                INSERT INTO emails (
                    id, account_id, uid, folder, sender, subject, body,
                    body_html, received_at, is_read, fetched_at
                ) VALUES (11, 7, 'uid-1', 'INBOX', 'sender@example.com',
                          'subject', 'body', '<p>body</p>',
                          '2024-01-03 00:00:00', 1, '2024-01-04 00:00:00')
                """
            )
            # An orphan is retained in the migration quarantine instead of dropped.
            conn.execute(
                "INSERT INTO emails(id, account_id, uid, folder, subject) "
                "VALUES(12, 999, 'orphan', 'INBOX', 'orphan subject')"
            )
            conn.execute(
                "INSERT INTO users(username, password_hash) VALUES('admin', ?)",
                (legacy_hash,),
            )
            conn.execute(
                "INSERT INTO settings(key, value) VALUES('global_proxy', 'socks5://u:p@127.0.0.1:1080')"
            )

    def create_current_unversioned_database(self) -> None:
        admin_hash = hashlib.sha256(b"current-password").hexdigest()
        with self.raw() as conn:
            conn.executescript(
                """
                CREATE TABLE accounts (
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
                );
                CREATE TABLE emails (
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
                );
                CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
                CREATE UNIQUE INDEX idx_emails_dedup
                    ON emails(account_id, folder, uid);
                """
            )
            conn.execute(
                """
                INSERT INTO accounts (
                    id, email, password, client_id, refresh_token, provider,
                    client_secret, fetch_mode, proxy, status, enabled,
                    mail_count, token_created_at, error, created_at
                ) VALUES (
                    21, 'current@gmail.com', 'google-password', 'google-client',
                    'google-refresh', 'google', 'google-secret', 'imap',
                    'socks5://account-proxy:1080', 'active', 1, 1,
                    '2025-01-01T00:00:00', NULL, '2025-01-01 00:00:00'
                )
                """
            )
            conn.execute(
                """
                INSERT INTO emails (
                    id, account_id, folder, uid, from_addr, subject, body,
                    body_html, date, fetched_at
                ) VALUES (
                    31, 21, 'INBOX', 'current-uid', 'from@example.com',
                    'current subject', 'current body', '<p>current</p>',
                    '2025-01-02 00:00:00', '2025-01-03 00:00:00'
                )
                """
            )
            conn.executemany(
                "INSERT INTO settings(key, value) VALUES(?, ?)",
                (
                    ("admin_password_hash", admin_hash),
                    ("global_proxy", "http://global-proxy:8080"),
                    ("auto_check_hours", "6"),
                ),
            )

    async def test_historical_migration_preserves_and_encrypts_data(self):
        self.create_historical_database()

        await db.init_db()
        await db.init_db()  # Migrations are idempotent after user_version advances.

        account = await db.get_account(7)
        self.assertEqual(account["email"], "old@outlook.com")
        self.assertEqual(account["password"], "old-password")
        self.assertEqual(account["refresh_token"], "refresh-old")
        self.assertEqual(account["enabled"], 0)
        self.assertEqual(account["status"], "active")
        self.assertEqual(account["error"], "old error")
        self.assertEqual(
            await db.get_setting("global_proxy"),
            "socks5://u:p@127.0.0.1:1080",
        )

        email = await db.get_email(11)
        self.assertEqual(email["from_addr"], "sender@example.com")
        self.assertEqual(email["date"], "2024-01-03 00:00:00")
        self.assertEqual(email["is_read"], 1)

        with self.raw() as conn:
            self.assertEqual(
                conn.execute("PRAGMA user_version").fetchone()[0], db.SCHEMA_VERSION
            )
            stored = conn.execute(
                "SELECT password, refresh_token FROM accounts WHERE id = 7"
            ).fetchone()
            self.assertTrue(stored["password"].startswith(security.ENCRYPTED_PREFIX))
            self.assertTrue(
                stored["refresh_token"].startswith(security.ENCRYPTED_PREFIX)
            )
            self.assertNotIn("old-password", stored["password"])
            proxy = conn.execute(
                "SELECT value FROM settings WHERE key = 'global_proxy'"
            ).fetchone()[0]
            self.assertTrue(proxy.startswith(security.ENCRYPTED_PREFIX))
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM emails").fetchone()[0], 1
            )
            orphan = conn.execute(
                "SELECT subject, reason FROM migration_orphan_emails WHERE original_id = 12"
            ).fetchone()
            self.assertEqual(tuple(orphan), ("orphan subject", "orphan_account"))
            fk = conn.execute("PRAGMA foreign_key_list(emails)").fetchone()
            self.assertEqual(fk["on_delete"], "CASCADE")
            email_columns = {
                row["name"]: row for row in conn.execute("PRAGMA table_info(emails)")
            }
            self.assertEqual(email_columns["account_id"]["notnull"], 1)
            self.assertEqual(email_columns["folder"]["notnull"], 1)
            self.assertEqual(email_columns["uid"]["notnull"], 1)

        self.assertTrue(self.key_path.exists())
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(self.key_path.stat().st_mode), 0o600)

    async def test_legacy_password_is_upgraded_after_successful_login(self):
        self.create_historical_database()
        await db.init_db()

        with self.raw() as conn:
            before = conn.execute(
                "SELECT value FROM settings WHERE key = 'admin_password_hash'"
            ).fetchone()[0]
        self.assertEqual(before, hashlib.sha256(b"legacy-password").hexdigest())

        self.assertFalse(await db.verify_user("admin", "wrong-password"))
        self.assertTrue(await db.verify_user("admin", "legacy-password"))
        with self.raw() as conn:
            after = conn.execute(
                "SELECT value FROM settings WHERE key = 'admin_password_hash'"
            ).fetchone()[0]
        self.assertTrue(after.startswith("scrypt$v=1$"))
        self.assertNotEqual(after, before)
        self.assertTrue(await db.verify_user("admin", "legacy-password"))

    async def test_users_hash_replaces_only_accidentally_seeded_default(self):
        self.create_historical_database()
        with self.raw() as conn:
            conn.execute(
                "INSERT INTO settings(key, value) VALUES('admin_password_hash', ?)",
                (hashlib.sha256(b"admin123").hexdigest(),),
            )

        await db.init_db()
        self.assertTrue(await db.verify_user("admin", "legacy-password"))
        self.assertFalse(await db.verify_user("admin", "admin123"))

    async def test_current_unversioned_schema_is_preserved_and_encrypted(self):
        self.create_current_unversioned_database()
        await db.init_db()

        account = await db.get_account(21)
        self.assertEqual(account["password"], "google-password")
        self.assertEqual(account["client_secret"], "google-secret")
        self.assertEqual(account["refresh_token"], "google-refresh")
        self.assertEqual(account["proxy"], "socks5://account-proxy:1080")
        self.assertEqual((await db.get_accounts_by_ids([21]))[0], account)
        self.assertEqual((await db.get_all_active_accounts())[0], account)
        self.assertEqual(
            await db.get_setting("global_proxy"), "http://global-proxy:8080"
        )
        self.assertEqual(await db.get_setting("auto_check_hours"), "6")
        self.assertEqual((await db.get_email(31))["subject"], "current subject")

        with self.raw() as conn:
            raw = conn.execute(
                "SELECT password, client_secret, refresh_token, proxy FROM accounts WHERE id = 21"
            ).fetchone()
            for field in ("password", "client_secret", "refresh_token", "proxy"):
                self.assertTrue(raw[field].startswith(security.ENCRYPTED_PREFIX))
                self.assertNotEqual(raw[field], account[field])
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0], 1
            )
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM emails").fetchone()[0], 1
            )

    async def test_each_schema_version_rolls_back_atomically(self):
        self.create_historical_database()
        original = db._MIGRATIONS[2]

        async def interrupted_migration(conn):
            await conn.execute("ALTER TABLE accounts RENAME TO accounts_partial")
            raise RuntimeError("simulated interruption")

        db._MIGRATIONS[2] = interrupted_migration
        try:
            with self.assertRaisesRegex(RuntimeError, "simulated interruption"):
                await db.init_db()
        finally:
            db._MIGRATIONS[2] = original

        with self.raw() as conn:
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 1)
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            self.assertIn("accounts", tables)
            self.assertNotIn("accounts_partial", tables)
            self.assertEqual(
                conn.execute("SELECT email FROM accounts WHERE id = 7").fetchone()[0],
                "old@outlook.com",
            )

        await db.init_db()
        self.assertEqual((await db.get_account(7))["refresh_token"], "refresh-old")

    async def test_default_key_file_is_created_beside_database(self):
        default_key = self.db_path.parent / security.DEFAULT_KEY_FILE
        with mock.patch.dict(
            os.environ,
            {
                "OMM_DB_PATH": str(self.db_path),
                "OMM_ADMIN_PASSWORD": "initial-password",
            },
            clear=True,
        ):
            await db.init_db()
        self.assertTrue(default_key.exists())
        self.assertEqual(len(default_key.read_bytes().strip()), 44)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(default_key.stat().st_mode), 0o600)

    async def test_missing_or_wrong_key_fails_closed_without_regeneration(self):
        await db.init_db()
        await db.add_account("key-check@example.com", "", "client", "refresh-token")

        security.clear_key_cache()
        self.key_path.unlink()
        with self.assertRaises(security.CredentialKeyUnavailableError):
            await db.init_db()
        self.assertFalse(self.key_path.exists())

        self.key_path.write_bytes(Fernet.generate_key() + b"\n")
        security.clear_key_cache()
        with self.assertRaises(security.CredentialDecryptionError):
            await db.init_db()

    async def test_default_initial_password_and_environment_key_validation(self):
        fresh_db = Path(self.tempdir.name) / "fresh.db"
        fresh_key = Path(self.tempdir.name) / "fresh.key"
        security.clear_key_cache()
        with mock.patch.dict(
            os.environ,
            {
                "OMM_DB_PATH": str(fresh_db),
                "OMM_SECRET_KEY_FILE": str(fresh_key),
            },
            clear=True,
        ):
            original = db.DB_PATH
            db.DB_PATH = str(fresh_db)
            try:
                await db.init_db()
                self.assertTrue(await db.verify_user("admin", db.DEFAULT_ADMIN_PASSWORD))
                conn = sqlite3.connect(fresh_db)
                try:
                    stored = conn.execute(
                        "SELECT value FROM settings WHERE key = 'admin_password_hash'"
                    ).fetchone()[0]
                finally:
                    conn.close()
                self.assertTrue(stored.startswith("scrypt$v=1$"))
            finally:
                db.DB_PATH = original

        security.clear_key_cache()
        with (
            mock.patch.dict(os.environ, {"OMM_SECRET_KEY": "weak-passphrase"}),
            self.assertRaisesRegex(ValueError, "Fernet key"),
        ):
            security.load_key(str(fresh_db))
        security.clear_key_cache()

    async def test_email_normalization_and_import_errors_do_not_expose_credentials(
        self,
    ):
        await db.init_db()
        first = await db.import_accounts(
            ["User@Outlook.COM----unused----client----refresh-one"]
        )
        second = await db.import_accounts(
            ["user@outlook.com----unused----client----refresh-two"]
        )
        self.assertEqual(first["added"], 1)
        self.assertEqual(second["updated"], 1)
        accounts, total = await db.get_accounts()
        self.assertEqual(total, 1)
        self.assertEqual(accounts[0]["email"], "user@outlook.com")
        self.assertEqual(accounts[0]["refresh_token"], "refresh-two")

        malformed = await db.import_accounts(
            [
                "client-secret-without-delimiters",
                "bad address----private-secret----client-id----refresh-secret",
            ]
        )
        rendered_errors = " ".join(malformed["errors"])
        self.assertEqual(malformed["failed"], 2)
        self.assertNotIn("client-secret", rendered_errors)
        self.assertNotIn("private-secret", rendered_errors)
        self.assertNotIn("refresh-secret", rendered_errors)

    async def test_case_variant_legacy_accounts_are_merged_during_migration(self):
        self.create_historical_database()
        with self.raw() as conn:
            conn.execute(
                """
                INSERT INTO accounts (
                    id, email, password, client_id, refresh_token, status,
                    created_at, token_created_at
                ) VALUES (8, 'OLD@OUTLOOK.COM', 'newer-password', 'new-client',
                          'new-refresh', 'active', '2025-01-01', '2025-01-01')
                """
            )
            conn.execute(
                """
                INSERT INTO emails (
                    id, account_id, uid, folder, sender, subject, fetched_at
                ) VALUES (13, 8, 'uid-2', 'INBOX', 'new@example.com',
                          'new message', '2025-01-01')
                """
            )

        await db.init_db()
        accounts, total = await db.get_accounts()
        self.assertEqual(total, 1)
        self.assertEqual(accounts[0]["id"], 8)
        self.assertEqual(accounts[0]["email"], "old@outlook.com")
        self.assertEqual(await db.get_email_count(8), 2)

    async def test_authentication_and_password_change_are_serialized(self):
        await db.init_db()
        login, changed = await asyncio.gather(
            db.authenticate_and_create_session("admin", "initial-password", 60),
            db.change_password("initial-password", "new-password1"),
        )
        self.assertTrue(changed)
        if login is not None:
            self.assertIsNone(await db.get_session(login["token"]))
        self.assertIsNone(
            await db.authenticate_and_create_session("admin", "initial-password", 60)
        )
        self.assertIsNotNone(
            await db.authenticate_and_create_session("admin", "new-password1", 60)
        )

        for invalid in ("short1", "onlyletters", "12345678"):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                ValueError, "letter and a digit"
            ):
                await db.change_password("new-password1", invalid)

        self.assertTrue(await db.change_password("new-password1", "letters1"))

    def test_scrypt_uses_random_salts(self):
        first = db._hash_password("same-password")
        second = db._hash_password("same-password")
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("scrypt$v=1$"))
        self.assertEqual(db._verify_password("same-password", first), (True, False))
        self.assertEqual(db._verify_password("wrong-password", first), (False, False))

    async def test_account_upsert_encrypts_and_microsoft_password_is_discarded(self):
        await db.init_db()
        outcomes = await asyncio.gather(
            db.add_account(
                "same@outlook.com",
                "unused-one",
                "client-a",
                "token-a",
                fetch_mode="graph",
            ),
            db.add_account(
                "same@outlook.com",
                "unused-two",
                "client-b",
                "token-b",
                fetch_mode="graph",
            ),
        )
        self.assertCountEqual(outcomes, ["added", "updated"])

        accounts, total = await db.get_accounts()
        self.assertEqual(total, 1)
        self.assertEqual(accounts[0]["password"], "")
        self.assertIn(accounts[0]["refresh_token"], {"token-a", "token-b"})
        with self.raw() as conn:
            raw = conn.execute(
                "SELECT password, refresh_token FROM accounts WHERE email = 'same@outlook.com'"
            ).fetchone()
            self.assertEqual(raw["password"], "")
            self.assertTrue(raw["refresh_token"].startswith(security.ENCRYPTED_PREFIX))
            self.assertNotIn(accounts[0]["refresh_token"], raw["refresh_token"])

    async def test_sessions_store_only_token_hash_and_support_revocation(self):
        await db.init_db()
        session_one = await db.create_session(ttl_seconds=60)
        session_two = await db.create_session(ttl_seconds=60)
        session = await db.get_session(session_one["token"])
        self.assertEqual(session["username"], "admin")
        self.assertEqual(session["csrf_token"], session_one["csrf_token"])

        with self.raw() as conn:
            rows = conn.execute("SELECT token_hash FROM sessions").fetchall()
            hashes = {row["token_hash"] for row in rows}
            self.assertNotIn(session_one["token"], hashes)
            self.assertIn(
                hashlib.sha256(session_one["token"].encode()).hexdigest(), hashes
            )

        self.assertTrue(await db.revoke_session(session_one["token"]))
        self.assertIsNone(await db.get_session(session_one["token"]))
        self.assertEqual(await db.revoke_all_sessions("admin"), 1)
        self.assertIsNone(await db.get_session(session_two["token"]))

    async def test_expired_session_and_password_change_revoke_sessions(self):
        await db.init_db()
        session = await db.create_session(ttl_seconds=60)
        with self.raw() as conn:
            conn.execute(
                "UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
                (
                    int(time.time()) - 1,
                    hashlib.sha256(session["token"].encode()).hexdigest(),
                ),
            )
        self.assertIsNone(await db.get_session(session["token"]))

        active = await db.create_session(ttl_seconds=60)
        self.assertTrue(await db.change_password("initial-password", "new-password1"))
        self.assertIsNone(await db.get_session(active["token"]))
        self.assertFalse(await db.verify_user("admin", "initial-password"))
        self.assertTrue(await db.verify_user("admin", "new-password1"))

    async def test_refresh_token_cas_rejects_stale_writer(self):
        await db.init_db()
        await db.add_account("cas@example.com", "", "client", "token-1")
        account = (await db.get_accounts())[0][0]

        self.assertFalse(
            await db.update_refresh_token_cas(account["id"], "stale", "token-2")
        )
        self.assertTrue(
            await db.update_refresh_token_cas(account["id"], "token-1", "token-2")
        )
        self.assertFalse(
            await db.update_refresh_token_cas(account["id"], "token-1", "token-3")
        )
        self.assertEqual(
            (await db.get_account(account["id"]))["refresh_token"], "token-2"
        )

    async def test_account_lease_is_cross_connection_and_token_age_only_changes_on_rotation(
        self,
    ):
        await db.init_db()
        await db.add_account("lease@example.com", "", "client", "token-1")
        account = (await db.get_accounts())[0][0]

        first_lease = await db.acquire_account_lease(account["id"], ttl_seconds=60)
        self.assertIsNotNone(first_lease)
        self.assertIsNone(await db.acquire_account_lease(account["id"], ttl_seconds=60))
        self.assertFalse(await db.release_account_lease(account["id"], "wrong-owner"))
        self.assertTrue(await db.release_account_lease(account["id"], first_lease))
        second_lease = await db.acquire_account_lease(account["id"], ttl_seconds=60)
        self.assertIsNotNone(second_lease)
        self.assertTrue(await db.release_account_lease(account["id"], second_lease))

        created_at = (await db.get_account(account["id"]))["token_created_at"]
        await asyncio.sleep(0.01)
        self.assertTrue(
            await db.update_refresh_token_cas(account["id"], "token-1", "token-1")
        )
        self.assertEqual(
            (await db.get_account(account["id"]))["token_created_at"], created_at
        )
        await asyncio.sleep(0.01)
        self.assertTrue(
            await db.update_refresh_token_cas(account["id"], "token-1", "token-2")
        )
        self.assertNotEqual(
            (await db.get_account(account["id"]))["token_created_at"], created_at
        )

    async def test_batch_settings_are_transparent_and_connection_pragmas_apply(self):
        await db.init_db()
        await db.set_settings(
            {
                "global_proxy": "http://user:pass@proxy.test:8080",
                "auto_check_hours": "12",
                "default_ms_fetch_mode": "graph",
            }
        )
        self.assertEqual(
            await db.get_setting("global_proxy"), "http://user:pass@proxy.test:8080"
        )
        self.assertEqual(await db.get_setting("auto_check_hours"), "12")

        async with db._connection() as conn:
            self.assertEqual(
                (await (await conn.execute("PRAGMA foreign_keys")).fetchone())[0], 1
            )
            self.assertEqual(
                (await (await conn.execute("PRAGMA busy_timeout")).fetchone())[0], 5000
            )
            journal_mode = (
                await (await conn.execute("PRAGMA journal_mode")).fetchone()
            )[0]
            self.assertEqual(journal_mode.lower(), "wal")

        with self.raw() as conn:
            raw_proxy = conn.execute(
                "SELECT value FROM settings WHERE key = 'global_proxy'"
            ).fetchone()[0]
            self.assertTrue(raw_proxy.startswith(security.ENCRYPTED_PREFIX))
            indexes = {
                row["name"]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'index'"
                )
            }
            self.assertIn("idx_emails_account_id_desc", indexes)
            self.assertIn("idx_sessions_expires_at", indexes)
            conn.executescript(
                """
                CREATE TRIGGER reject_batch_setting
                BEFORE INSERT ON settings
                WHEN NEW.key = 'batch_reject'
                BEGIN
                    SELECT RAISE(ABORT, 'simulated batch failure');
                END;
                """
            )

        with self.assertRaises(sqlite3.IntegrityError):
            await db.set_settings(
                {"batch_first": "must-roll-back", "batch_reject": "rejected"}
            )
        self.assertIsNone(await db.get_setting("batch_first"))

    async def test_foreign_key_cascade_and_empty_uid_rejection(self):
        await db.init_db()
        await db.add_account("mail@example.com", "", "client", "token")
        account = (await db.get_accounts())[0][0]
        self.assertEqual(
            await db.save_emails(
                account["id"],
                "INBOX",
                [{"uid": "uid-1", "subject": "preserved"}],
            ),
            1,
        )
        with self.assertRaises(ValueError):
            await db.save_emails(account["id"], "INBOX", [{"uid": ""}])
        await db.delete_account(account["id"])
        self.assertEqual(await db.get_email_count(account["id"]), 0)


if __name__ == "__main__":
    unittest.main()
