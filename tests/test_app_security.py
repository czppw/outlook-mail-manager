from __future__ import annotations

import asyncio
import importlib
import re
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from email_sanitizer import sanitize_email_html

CSRF_PATTERN = re.compile(r'<meta name="csrf-token" content="([^"]+)">')
INITIAL_PASSWORD = "WebSecurityPass!123"
NEW_PASSWORD = "WebSecurityPass!456"


@pytest.fixture
def web_app(tmp_path, monkeypatch):
    monkeypatch.setenv("OMM_ADMIN_PASSWORD", INITIAL_PASSWORD)
    monkeypatch.setenv("OMM_AUTO_CHECK_HOURS", "0")
    monkeypatch.setenv("OMM_DB_PATH", str(tmp_path / "web.db"))
    monkeypatch.setenv("OMM_MAX_REQUEST_BYTES", "1024")
    monkeypatch.setenv("OMM_SECRET_KEY_FILE", str(tmp_path / "web.key"))
    monkeypatch.setenv("OMM_SECURE_COOKIE", "1")

    import app
    import db

    importlib.reload(db)
    return importlib.reload(app)


def _login(client: TestClient, password: str = INITIAL_PASSWORD):
    return client.post(
        "/login",
        data={"username": "admin", "password": password},
        follow_redirects=False,
    )


def _csrf(client: TestClient) -> str:
    response = client.get("/")
    match = CSRF_PATTERN.search(response.text)
    assert match
    return match.group(1)


def _request_with_origin(host: str, origin: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/login",
            "headers": [
                (b"host", host.encode("ascii")),
                (b"origin", origin.encode("ascii")),
            ],
        }
    )


def test_origin_validation_supports_explicit_public_origin(web_app, monkeypatch):
    direct = _request_with_origin(
        "101.34.216.204:8899", "http://101.34.216.204:8899"
    )
    proxied = _request_with_origin("127.0.0.1:8899", "http://101.34.216.204")
    malicious = _request_with_origin("127.0.0.1:8899", "http://attacker.test")

    assert web_app._origin_allowed(direct) is True
    assert web_app._origin_allowed(proxied) is False

    monkeypatch.setenv("OMM_ALLOWED_ORIGINS", "http://101.34.216.204")
    assert web_app._origin_allowed(proxied) is True
    assert web_app._origin_allowed(malicious) is False


@pytest.mark.parametrize(
    "origin",
    [
        "file:///tmp/page.html",
        "http://101.34.216.204/path",
        "http://user@101.34.216.204",
        "http://101.34.216.204:invalid",
    ],
)
def test_origin_validation_rejects_malformed_values(web_app, origin):
    assert web_app._origin_allowed(_request_with_origin("127.0.0.1:8899", origin)) is False


def test_request_limit_security_headers_and_secure_cookie(web_app):
    with TestClient(web_app.app, base_url="https://testserver") as client:
        oversized = client.post(
            "/login",
            content=b"x" * 1025,
            headers={"content-type": "application/octet-stream"},
        )
        assert oversized.status_code == 413
        assert oversized.json() == {"error": "Request body too large"}

        response = _login(client)
        assert response.status_code == 303
        cookie = response.headers["set-cookie"]
        assert "HttpOnly" in cookie
        assert "SameSite=strict" in cookie
        assert "Secure" in cookie

        page = client.get("/")
        assert page.headers["x-content-type-options"] == "nosniff"
        assert page.headers["x-frame-options"] == "DENY"
        assert page.headers["referrer-policy"] == "no-referrer"
        assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
        assert page.headers["strict-transport-security"].startswith("max-age=")


def test_csrf_password_revocation_and_export_reauthentication(web_app):
    with TestClient(web_app.app, base_url="https://testserver") as client:
        assert _login(client).status_code == 303
        csrf = _csrf(client)

        rejected = client.post(
            "/settings",
            data={
                "global_proxy": "",
                "default_ms_fetch_mode": "graph",
                "auto_check_hours": "0",
                "csrf_token": "wrong",
            },
        )
        assert rejected.status_code == 403

        imported = client.post(
            "/import",
            data={
                "text": "user@gmail.com----client-secret----client-id----refresh-token",
                "csrf_token": csrf,
            },
        )
        assert imported.status_code == 200

        denied_export = client.post(
            "/export",
            data={
                "account_id": "all",
                "current_password": "wrong-password",
                "csrf_token": csrf,
            },
        )
        assert denied_export.status_code == 403

        exported = client.post(
            "/export",
            data={
                "account_id": "all",
                "current_password": INITIAL_PASSWORD,
                "csrf_token": csrf,
            },
        )
        assert exported.status_code == 200
        assert (
            "user@gmail.com----client-secret----client-id----refresh-token"
            in exported.text
        )
        assert "no-store" in exported.headers["cache-control"]

        changed = client.post(
            "/password",
            data={
                "old_password": INITIAL_PASSWORD,
                "new_password": NEW_PASSWORD,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert changed.status_code == 303
        assert changed.headers["location"] == "/login?changed=1"
        assert client.get("/api/stats").status_code == 401
        assert _login(client, INITIAL_PASSWORD).status_code == 401
        assert _login(client, NEW_PASSWORD).status_code == 303


def test_update_endpoints_use_global_proxy_and_require_csrf(web_app, monkeypatch):
    calls = []

    def fake_check(proxy):
        calls.append(("check", proxy))
        return {
            "current_version": "1.0.0",
            "latest_version": "1.1.0",
            "update_available": True,
            "release_url": "https://github.com/czppw/outlook-mail-manager/releases/tag/v1.1.0",
        }

    def fake_apply(version, proxy):
        calls.append(("apply", version, proxy))
        return {
            "from_version": "1.0.0",
            "to_version": version,
            "restart_required": True,
        }

    async def no_restart():
        return None

    monkeypatch.setattr(web_app.update_manager, "check_for_update", fake_check)
    monkeypatch.setattr(web_app.update_manager, "apply_update", fake_apply)
    monkeypatch.setattr(web_app, "_restart_after_response", no_restart)

    with TestClient(web_app.app, base_url="https://testserver") as client:
        assert _login(client).status_code == 303
        csrf = _csrf(client)
        saved = client.post(
            "/settings",
            data={
                "global_proxy": "socks5://127.0.0.1:1080",
                "default_ms_fetch_mode": "graph",
                "auto_check_hours": "0",
                "csrf_token": csrf,
            },
        )
        assert saved.status_code == 200

        status = client.get("/api/update/status")
        assert status.status_code == 200
        assert status.json()["update_available"] is True
        assert calls[-1] == ("check", "socks5://127.0.0.1:1080")

        missing_csrf = client.post("/api/update/apply", json={"version": "1.1.0"})
        assert missing_csrf.status_code == 403

        invalid_json_shape = client.post(
            "/api/update/apply",
            json=["1.1.0"],
            headers={"X-CSRF-Token": csrf},
        )
        assert invalid_json_shape.status_code == 400

        applied = client.post(
            "/api/update/apply",
            json={"version": "1.1.0"},
            headers={"X-CSRF-Token": csrf},
        )
        assert applied.status_code == 200
        assert applied.json()["to_version"] == "1.1.0"
        assert calls[-1] == ("apply", "1.1.0", "socks5://127.0.0.1:1080")


def test_email_html_sanitizer_blocks_active_and_remote_content():
    cleaned = sanitize_email_html(
        "<script>alert(1)</script>"
        '<img src="https://tracker.invalid/pixel">'
        '<a href="javascript:alert(2)">bad</a>'
        '<a href="https://example.com/path">safe</a>'
    )
    assert "<script" not in cleaned
    assert "<img" not in cleaned
    assert "tracker.invalid" not in cleaned
    assert "javascript:" not in cleaned
    assert 'href="https://example.com/path"' in cleaned
    assert "Content-Security-Policy" in cleaned


def test_health_check_identifies_version(web_app):
    with TestClient(web_app.app, base_url="https://testserver") as client:
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"ok": True, "version": "1.0.0"}


def test_lifespan_holds_instance_lock_and_recovers_updates(web_app, monkeypatch):
    events = []

    @contextmanager
    def fake_instance_lock():
        events.append("lock-enter")
        try:
            yield
        finally:
            events.append("lock-exit")

    def fake_recovery():
        events.append("recover")
        return True

    monkeypatch.setattr(
        web_app.update_manager, "application_instance_lock", fake_instance_lock
    )
    monkeypatch.setattr(
        web_app.update_manager, "recover_interrupted_update", fake_recovery
    )

    with TestClient(web_app.app, base_url="https://testserver") as client:
        assert client.get("/healthz").status_code == 200
        assert events == ["lock-enter", "recover"]
    assert events == ["lock-enter", "recover", "lock-exit"]


@pytest.mark.asyncio
async def test_cancelled_fetch_finishes_token_cas_and_releases_lease(
    web_app, monkeypatch
):
    calls = []
    refresh_started = asyncio.Event()
    allow_refresh = asyncio.Event()
    account = {
        "id": 1,
        "email": "user@outlook.com",
        "client_id": "client",
        "refresh_token": "refresh-old",
        "client_secret": "",
        "provider": "microsoft",
        "fetch_mode": "graph",
        "proxy": "http://proxy.test:8080",
        "enabled": 1,
    }

    async def acquire(account_id):
        calls.append("lease-acquired")
        return "lease-owner"

    async def release(account_id, owner):
        calls.append("lease-released")
        return True

    async def get_account(account_id):
        return dict(account)

    async def refresh(*args, **kwargs):
        refresh_started.set()
        await allow_refresh.wait()
        calls.append("provider-rotated")
        return "access", "refresh-new"

    async def cas(*args):
        calls.append("cas-persisted")
        return True

    async def fetch(*args, **kwargs):
        calls.append("mail-fetched")
        return {"INBOX": [], "JUNK": []}

    async def email_count(account_id):
        return 0

    async def save(account_id, folder, emails):
        return 0

    async def status(*args, **kwargs):
        calls.append("status-active")

    monkeypatch.setattr(web_app.db, "acquire_account_lease", acquire)
    monkeypatch.setattr(web_app.db, "release_account_lease", release)
    monkeypatch.setattr(web_app.db, "get_account", get_account)
    monkeypatch.setattr(web_app.db, "update_refresh_token_cas", cas)
    monkeypatch.setattr(web_app.db, "save_emails", save)
    monkeypatch.setattr(web_app.db, "get_email_count", email_count)
    monkeypatch.setattr(web_app.db, "update_account_status", status)
    monkeypatch.setattr(web_app.mail_fetcher, "refresh_access_token", refresh)
    monkeypatch.setattr(web_app.mail_fetcher, "check_account_with_access_token", fetch)

    task = asyncio.create_task(web_app._fetch_and_save(account, 1))
    await refresh_started.wait()
    task.cancel()
    allow_refresh.set()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert calls.index("provider-rotated") < calls.index("cas-persisted")
    assert calls.index("cas-persisted") < calls.index("mail-fetched")
    assert calls.index("status-active") < calls.index("lease-released")


@pytest.mark.asyncio
async def test_partial_fetch_saves_valid_mail_before_error_status(web_app, monkeypatch):
    calls = []
    account = {
        "id": 2,
        "email": "user@outlook.com",
        "client_id": "client",
        "refresh_token": "refresh",
        "client_secret": "",
        "provider": "microsoft",
        "fetch_mode": "imap",
        "proxy": "",
        "enabled": 1,
    }

    async def return_account(account_id):
        return dict(account)

    async def acquire(account_id):
        return "owner"

    async def release(account_id, owner):
        calls.append("released")
        return True

    async def refresh(current):
        return "access", False, ""

    async def partial_fetch(*args, **kwargs):
        raise web_app.mail_fetcher.MailboxFetchError(
            {"INBOX": [{"uid": "1"}], "JUNK": []},
            ["INBOX: one malformed message skipped"],
        )

    async def save(account_id, folder, emails):
        calls.append(("saved", folder, len(emails)))
        return len(emails)

    async def count(account_id):
        return 1

    async def status(account_id, value, error=None, mail_count=None):
        calls.append(("status", value, error, mail_count))

    monkeypatch.setattr(web_app.db, "get_account", return_account)
    monkeypatch.setattr(web_app.db, "acquire_account_lease", acquire)
    monkeypatch.setattr(web_app.db, "release_account_lease", release)
    monkeypatch.setattr(web_app.db, "save_emails", save)
    monkeypatch.setattr(web_app.db, "get_email_count", count)
    monkeypatch.setattr(web_app.db, "update_account_status", status)
    monkeypatch.setattr(web_app, "_refresh_account", refresh)
    monkeypatch.setattr(
        web_app.mail_fetcher, "check_account_with_access_token", partial_fetch
    )

    with pytest.raises(web_app.AccountPartialFetchError) as caught:
        await web_app._fetch_and_save(account, 10)

    assert caught.value.saved == 1
    assert ("saved", "INBOX", 1) in calls
    error_status = next(call for call in calls if call[0] == "status")
    assert error_status[1] == "error"
    assert error_status[3] == 1
    assert calls[-1] == "released"
