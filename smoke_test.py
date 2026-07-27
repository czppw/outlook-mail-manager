#!/usr/bin/env python3
"""Offline smoke tests for the database, Graph mapping, and HTTP workflow."""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests

REPO = Path(__file__).resolve().parent
INITIAL_PASSWORD = "SmokeAdminPass!123"
NEW_PASSWORD = "SmokeAdminPass!456"
CSRF_PATTERN = re.compile(r'<meta name="csrf-token" content="([^"]+)">')


def check(name: str, condition: bool, detail: str = "") -> None:
    tag = "PASS" if condition else "FAIL"
    print(f"  [{tag}] {name}" + (f" - {detail}" if detail and not condition else ""))
    assert condition, f"{name}: {detail}" if detail else name


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _csrf(response: requests.Response) -> str:
    match = CSRF_PATTERN.search(response.text)
    assert match, "CSRF token missing from authenticated page"
    return match.group(1)


def test_graph_mapping():
    print("\n== Part 1: Graph field mapping ==")
    import mail_fetcher

    class FakeResp:
        def __init__(self, payload, status=200):
            self._payload = payload
            self.status_code = status
            self.text = json.dumps(payload)

        def json(self):
            return self._payload

    calls = {}

    def fake_post(url, data=None, timeout=None, proxies=None):
        calls["token_data"] = data
        return FakeResp({"access_token": "AT", "refresh_token": "NEW_RT"})

    def fake_get(url, headers=None, params=None, timeout=None, proxies=None):
        calls["auth"] = headers.get("Authorization")
        return FakeResp(
            {
                "value": [
                    {
                        "id": "msg1",
                        "subject": "Hello",
                        "from": {
                            "emailAddress": {"name": "Alice", "address": "a@x.com"}
                        },
                        "receivedDateTime": "2026-07-27T01:00:00Z",
                        "body": {"contentType": "html", "content": "<b>hi</b>"},
                    }
                ],
            }
        )

    original_post = mail_fetcher.requests.post
    original_get = mail_fetcher.requests.get
    mail_fetcher.requests.post = fake_post
    mail_fetcher.requests.get = fake_get
    try:
        results, new_token = mail_fetcher._fetch_via_graph(
            "u@outlook.com",
            "cid",
            "RT",
            "",
            "",
            10,
        )
    finally:
        mail_fetcher.requests.post = original_post
        mail_fetcher.requests.get = original_get

    check("rotated refresh token returned", new_token == "NEW_RT")
    check(
        "refresh request contains Mail.Read",
        "Mail.Read" in calls["token_data"]["scope"],
    )
    check("Graph bearer token set", calls["auth"] == "Bearer AT")
    check("Graph fetches INBOX and JUNK", set(results) == {"INBOX", "JUNK"})
    message = results["INBOX"][0]
    check(
        "Graph fields mapped",
        message["uid"] == "msg1"
        and message["subject"] == "Hello"
        and "Alice" in message["from"]
        and message["body_html"] == "<b>hi</b>",
    )


def test_fmt_dt():
    print("\n== Part 2: Date formatting ==")
    from app import fmt_dt

    check("ISO timestamp", fmt_dt("2026-07-27T10:17:05.629267") == "2026-07-27 10:17")
    check("empty timestamp", fmt_dt(None) == "-" and fmt_dt("") == "-")
    check(
        "RFC2822 timestamp",
        fmt_dt("Mon, 27 Jul 2026 10:17:05 +0800") == "2026-07-27 10:17",
    )
    rendered = fmt_dt("2026-07-27T01:00:00Z")
    check(
        "UTC timestamp",
        len(rendered) == 16 and rendered[4] == "-" and rendered[10] == " ",
    )
    check("unknown timestamp", fmt_dt("some random string") == "some random string")


def test_classify_error():
    print("\n== Part 3: Error classification ==")
    from app import classify_error

    check(
        "invalid token",
        classify_error('Token refresh failed: {"error":"invalid_grant"}') == "令牌失效",
    )
    check(
        "invalid scope", classify_error("invalid_scope AADSTS70011") == "权限范围不符"
    )
    check("timeout", classify_error("network timed out") == "连接超时")
    check("network", classify_error("Connection refused") == "网络错误")
    check(
        "IMAP authentication",
        classify_error("XOAUTH2 auth failed: NO") == "IMAP认证失败",
    )
    check("empty error", classify_error(None) == "" and classify_error("") == "")


def test_db_layer(tmpdir):
    print("\n== Part 4: Database ==")
    root = Path(str(tmpdir))
    os.environ["OMM_DB_PATH"] = str(root / "database.db")
    os.environ["OMM_SECRET_KEY_FILE"] = str(root / "database.key")
    os.environ["OMM_ADMIN_PASSWORD"] = INITIAL_PASSWORD
    import db

    importlib.reload(db)

    async def run():
        await db.init_db()
        result = await db.import_accounts(
            [
                "a@outlook.com----unused----cid1----rt1",
                "g@gmail.com----secret2----cid2----rt2",
            ]
        )
        check(
            "first import", result["added"] == 2 and result["failed"] == 0, str(result)
        )

        accounts, _ = await db.get_accounts()
        gmail = next(account for account in accounts if account["provider"] == "google")
        microsoft = next(
            account for account in accounts if account["provider"] == "microsoft"
        )
        check("Gmail client secret mapping", gmail["client_secret"] == "secret2")
        check("Microsoft password discarded", microsoft["password"] == "")
        check("Microsoft defaults to Graph", microsoft["fetch_mode"] == "graph")

        account_id = microsoft["id"]
        await db.update_account_status(account_id, "active", mail_count=7)
        saved = await db.save_emails(
            account_id,
            "INBOX",
            [
                {
                    "uid": "1",
                    "from": "x",
                    "subject": "s",
                    "body": "",
                    "body_html": "",
                    "date": "",
                }
            ],
        )
        check("first email saved", saved == 1)

        result = await db.import_accounts(
            ["a@outlook.com----ignored----cid1----rt1new"]
        )
        check(
            "duplicate import updates",
            result["updated"] == 1 and result["added"] == 0,
            str(result),
        )
        account = await db.get_account(account_id)
        check(
            "duplicate import preserves state",
            account["id"] == account_id
            and account["status"] == "active"
            and account["mail_count"] == 7,
        )
        check("duplicate import replaces token", account["refresh_token"] == "rt1new")
        check(
            "duplicate import preserves mail", await db.get_email_count(account_id) == 1
        )

        duplicate = await db.save_emails(
            account_id,
            "INBOX",
            [
                {
                    "uid": "1",
                    "from": "x",
                    "subject": "s",
                    "body": "",
                    "body_html": "",
                    "date": "",
                }
            ],
        )
        check("email UID is idempotent", duplicate == 0)

        check(
            "password change", await db.change_password(INITIAL_PASSWORD, NEW_PASSWORD)
        )
        check("new password accepted", await db.verify_user("admin", NEW_PASSWORD))
        check(
            "old password rejected", not await db.verify_user("admin", INITIAL_PASSWORD)
        )

    asyncio.run(run())

    with sqlite3.connect(root / "database.db") as connection:
        row = connection.execute(
            "SELECT password, client_secret, refresh_token FROM accounts WHERE email = ?",
            ("g@gmail.com",),
        ).fetchone()
    check(
        "credentials encrypted at rest",
        all(value.startswith("enc:v1:") for value in row),
    )


def test_legacy_schema(tmpdir):
    print("\n== Part 5: Legacy migration ==")
    root = Path(str(tmpdir))
    path = root / "legacy.db"
    key_path = root / "legacy.key"
    with sqlite3.connect(path) as connection:
        connection.executescript("""
            CREATE TABLE accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL,
                password TEXT, client_id TEXT, refresh_token TEXT, status TEXT DEFAULT 'pending',
                last_check TEXT, last_error TEXT, mail_count INTEGER DEFAULT 0,
                created_at TEXT, token_created_at TEXT);
            CREATE TABLE emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT, account_id INTEGER NOT NULL,
                uid TEXT NOT NULL, folder TEXT DEFAULT 'INBOX', sender TEXT, subject TEXT,
                body TEXT, body_html TEXT, received_at TEXT, is_read INTEGER DEFAULT 0,
                fetched_at TEXT);
            INSERT INTO accounts (email, password, client_id, refresh_token)
            VALUES ('old@outlook.com', 'p', 'c', 'r');
        """)

    os.environ["OMM_DB_PATH"] = str(path)
    os.environ["OMM_SECRET_KEY_FILE"] = str(key_path)
    os.environ["OMM_ADMIN_PASSWORD"] = INITIAL_PASSWORD
    import db

    importlib.reload(db)
    asyncio.run(db.init_db())

    with sqlite3.connect(path) as connection:
        account_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(accounts)")
        }
        email_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(emails)")
        }
        account_count = connection.execute("SELECT COUNT(*) FROM accounts").fetchone()[
            0
        ]
        stored_token = connection.execute(
            "SELECT refresh_token FROM accounts"
        ).fetchone()[0]
    check(
        "last_error migrated",
        "error" in account_columns and "last_error" not in account_columns,
    )
    check(
        "sender migrated",
        "from_addr" in email_columns and "sender" not in email_columns,
    )
    check(
        "received_at migrated",
        "date" in email_columns and "received_at" not in email_columns,
    )
    check("legacy account retained", account_count == 1)
    check("legacy token encrypted", stored_token.startswith("enc:v1:"))


def _start_server(env: dict[str, str], base_url: str) -> subprocess.Popen:
    proc = subprocess.Popen(
        [sys.executable, "app.py"],
        cwd=REPO,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(100):
        if proc.poll() is not None:
            raise RuntimeError(f"server exited with status {proc.returncode}")
        try:
            response = requests.get(base_url + "/healthz", timeout=1)
            if (
                response.status_code == 200
                and response.json().get("version") == "1.0.0"
            ):
                return proc
        except (requests.RequestException, ValueError):
            pass
        time.sleep(0.1)
    proc.terminate()
    proc.wait(timeout=10)
    raise RuntimeError("server did not become healthy")


def _login(
    session: requests.Session, base_url: str, password: str
) -> requests.Response:
    return session.post(
        base_url + "/login",
        data={"username": "admin", "password": password},
        allow_redirects=False,
        timeout=10,
    )


def test_http(tmpdir):
    print("\n== Part 6: HTTP end-to-end ==")
    root = Path(str(tmpdir))
    database = root / "http.db"
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    env = dict(os.environ)
    env.update(
        {
            "OMM_ADMIN_PASSWORD": INITIAL_PASSWORD,
            "OMM_AUTO_CHECK_HOURS": "0",
            "OMM_DB_PATH": str(database),
            "OMM_HOST": "127.0.0.1",
            "OMM_MS_FETCH_MODE": "imap",
            "OMM_PORT": str(port),
            "OMM_SECRET_KEY_FILE": str(root / "http.key"),
            "OMM_SECURE_COOKIE": "0",
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
        }
    )

    proc = _start_server(env, base_url)
    try:
        session = requests.Session()
        response = session.get(base_url + "/", allow_redirects=False, timeout=10)
        check(
            "anonymous page redirects",
            response.status_code == 302 and response.headers["location"] == "/login",
        )
        response = session.get(
            base_url + "/api/stats", allow_redirects=False, timeout=10
        )
        check(
            "anonymous API rejected",
            response.status_code == 401 and response.json()["error"] == "Unauthorized",
        )
        response = requests.post(
            base_url + "/check-all", allow_redirects=False, timeout=10
        )
        check(
            "anonymous action rejected as JSON",
            response.status_code == 401 and response.json()["error"] == "Unauthorized",
        )

        response = _login(session, base_url, "wrong-password")
        check("bad password rejected", response.status_code == 401)
        response = _login(session, base_url, INITIAL_PASSWORD)
        check("login succeeds", response.status_code == 303)
        cookie = response.headers.get("set-cookie", "")
        check(
            "session cookie is HttpOnly and SameSite strict",
            "HttpOnly" in cookie and "SameSite=strict" in cookie,
        )
        check("HTTP test cookie is not Secure", "Secure" not in cookie)

        page = session.get(base_url + "/", timeout=10)
        csrf = _csrf(page)
        check(
            "authenticated home available",
            page.status_code == 200 and "version-widget" in page.text,
        )
        response = session.post(base_url + "/import", data={"text": "x"}, timeout=10)
        check(
            "missing CSRF rejected",
            response.status_code == 422 or response.status_code == 403,
        )

        import_text = (
            "t1@outlook.com----unused----cid----rt\nt2@gmail.com----sec----cid----rt2"
        )
        response = session.post(
            base_url + "/import",
            data={"text": import_text, "csrf_token": csrf},
            timeout=10,
        )
        check(
            "HTTP import adds accounts",
            response.status_code == 200 and "<strong>2</strong>" in response.text,
        )
        response = session.post(
            base_url + "/import",
            data={"text": import_text, "csrf_token": csrf},
            timeout=10,
        )
        check(
            "HTTP import is idempotent",
            response.status_code == 200 and "<strong>2</strong>" in response.text,
        )

        response = session.post(
            base_url + "/account/1/prefs",
            data={"fetch_mode": "graph", "csrf_token": csrf},
            timeout=10,
        )
        check(
            "account fetch mode changed",
            response.status_code == 200 and response.json()["fetch_mode"] == "graph",
        )

        response = session.post(
            base_url + "/settings",
            data={
                "global_proxy": "http://127.0.0.1:9",
                "default_ms_fetch_mode": "imap",
                "auto_check_hours": "12",
                "csrf_token": csrf,
            },
            timeout=10,
        )
        check(
            "settings saved",
            response.status_code == 200 and "http://127.0.0.1:9" in response.text,
        )

        response = session.post(
            base_url + "/export",
            data={"account_id": "all", "current_password": "wrong", "csrf_token": csrf},
            timeout=10,
        )
        check("export requires current password", response.status_code == 403)
        response = session.post(
            base_url + "/export",
            data={
                "account_id": "all",
                "current_password": INITIAL_PASSWORD,
                "csrf_token": csrf,
            },
            timeout=10,
        )
        check(
            "export succeeds",
            response.status_code == 200
            and "t1@outlook.com--------cid----rt" in response.text,
        )
        check(
            "Gmail secret exported",
            "t2@gmail.com----sec----cid----rt2" in response.text,
        )
        check(
            "export is non-cacheable",
            "no-store" in response.headers.get("cache-control", ""),
        )

        response = session.post(
            base_url + "/accounts/bulk-fetch-mode",
            data={"fetch_mode": "imap", "csrf_token": csrf},
            timeout=10,
        )
        check(
            "bulk fetch mode changed",
            response.status_code == 200 and "Microsoft" in response.text,
        )

        response = session.post(
            base_url + "/check-all",
            headers={"X-CSRF-Token": csrf},
            timeout=30,
        )
        payload = response.json()
        check(
            "health check response shape",
            response.status_code == 200
            and set(payload) == {"success", "failed", "total_emails"},
        )
        check(
            "offline fake accounts fail quickly",
            payload["failed"] == 2 and payload["success"] == 0,
            str(payload),
        )

        response = session.post(
            base_url + "/password",
            data={
                "old_password": INITIAL_PASSWORD,
                "new_password": NEW_PASSWORD,
                "csrf_token": csrf,
            },
            allow_redirects=False,
            timeout=10,
        )
        check(
            "password changed",
            response.status_code == 303
            and response.headers["location"] == "/login?changed=1",
        )
        response = session.get(
            base_url + "/api/stats", allow_redirects=False, timeout=10
        )
        check("password change revokes session", response.status_code == 401)
        check(
            "old password rejected",
            _login(requests.Session(), base_url, INITIAL_PASSWORD).status_code == 401,
        )

        session = requests.Session()
        check(
            "new password accepted",
            _login(session, base_url, NEW_PASSWORD).status_code == 303,
        )
        page = session.get(base_url + "/", timeout=10)
        csrf = _csrf(page)
        response = session.post(
            base_url + "/logout",
            data={"csrf_token": csrf},
            allow_redirects=False,
            timeout=10,
        )
        check("logout is CSRF-protected POST", response.status_code == 303)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    proc = _start_server(env, base_url)
    try:
        check(
            "password persists after restart",
            _login(requests.Session(), base_url, NEW_PASSWORD).status_code == 303,
        )
        limited = requests.Session()
        for _ in range(5):
            _login(limited, base_url, "wrong-password")
        response = _login(limited, base_url, NEW_PASSWORD)
        check("login rate limit activates", response.status_code == 429)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            "SELECT email, password, client_secret, refresh_token, fetch_mode FROM accounts ORDER BY id",
        ).fetchall()
    check("HTTP imported two accounts", len(rows) == 2)
    check("bulk mode persisted", rows[0][4] == "imap")
    encrypted_values = [rows[0][3], rows[1][1], rows[1][2], rows[1][3]]
    check(
        "HTTP credentials encrypted",
        all(value.startswith("enc:v1:") for value in encrypted_values),
    )


def main() -> None:
    with tempfile.TemporaryDirectory(
        prefix="omm_smoke_", ignore_cleanup_errors=True
    ) as tmpdir:
        print(f"Test directory: {tmpdir}")
        test_graph_mapping()
        test_fmt_dt()
        test_classify_error()
        test_db_layer(tmpdir)
        test_legacy_schema(tmpdir)
        test_http(tmpdir)
    print("\nAll smoke tests passed")


if __name__ == "__main__":
    main()
