"""FastAPI application for securely managing OAuth2 mail accounts."""

from __future__ import annotations

import asyncio
import hmac
import logging
import math
import os
import time
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta
from typing import Annotated
from urllib.parse import urlencode, urlsplit

import aiosqlite
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import db
import mail_fetcher
import update_manager
from email_sanitizer import sanitize_email_html
from web_security import RequestBodyLimitMiddleware, SecurityHeadersMiddleware

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SESSION_COOKIE = "omm_session"
SESSION_MAX_AGE = 7 * 24 * 60 * 60
FETCH_CONCURRENCY = 5
MAX_IMPORT_LINES = 10_000
MAX_REQUEST_BYTES = int(os.environ.get("OMM_MAX_REQUEST_BYTES", str(2 * 1024 * 1024)))
SECURE_COOKIE = os.environ.get("OMM_SECURE_COOKIE", "1").strip().lower() not in {
    "0",
    "false",
    "no",
}
CHECK_ORIGIN = os.environ.get("OMM_CHECK_ORIGIN", "1").strip().lower() not in {
    "0",
    "false",
    "no",
}
AUTO_CHECK_DEFAULT_HOURS = float(os.environ.get("OMM_AUTO_CHECK_HOURS", "0"))

LOGIN_MAX_FAILS = 5
LOGIN_LOCK_SECONDS = 300
_login_fails: dict[str, list[float]] = {}
_account_locks: dict[int, asyncio.Lock] = {}
_batch_lock = asyncio.Lock()


class AccountBusyError(RuntimeError):
    pass


class AccountPartialFetchError(RuntimeError):
    def __init__(self, message: str, saved: int):
        self.saved = saved
        super().__init__(message)


def classify_error(error: str | None) -> str:
    if not error:
        return ""
    value = error.lower()
    if "invalid_grant" in value:
        return "令牌失效"
    if "invalid_scope" in value:
        return "权限范围不符"
    if "mailbox" in value and ("notfound" in value or "not found" in value):
        return "邮箱不存在"
    if "unauthorized" in value or "401" in value:
        return "认证失败"
    if "forbidden" in value or "403" in value:
        return "无访问权限"
    if "xoauth2" in value:
        return "IMAP认证失败"
    if "timeout" in value or "timed out" in value:
        return "连接超时"
    if any(
        word in value for word in ("network", "connection", "unreachable", "resolve")
    ):
        return "网络错误"
    return "取件失败"


async def _auto_check_hours() -> float:
    value = await db.get_setting("auto_check_hours")
    if value is not None:
        try:
            parsed = float(value)
            if math.isfinite(parsed):
                return max(0.0, parsed)
        except ValueError:
            pass
    return max(0.0, AUTO_CHECK_DEFAULT_HOURS)


async def _auto_check_loop() -> None:
    await asyncio.sleep(600)
    while True:
        try:
            hours = await _auto_check_hours()
            if hours <= 0:
                await asyncio.sleep(3600)
                continue
            logger.info("Automatic account health check started")
            result = await _fetch_all_accounts(limit=1)
            logger.info("Automatic account health check finished: %s", result)
            await asyncio.sleep(hours * 3600)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - keep background scheduler alive
            logger.warning(
                "Automatic account health check failed: %s", type(exc).__name__
            )
            await asyncio.sleep(3600)


@asynccontextmanager
async def lifespan(_: FastAPI):
    with update_manager.application_instance_lock():
        recovered = await asyncio.to_thread(update_manager.recover_interrupted_update)
        if recovered:
            logger.warning("Recovered an interrupted application update")
        await db.init_db()
        checker = asyncio.create_task(
            _auto_check_loop(), name="automatic-mail-health-check"
        )
        try:
            yield
        finally:
            checker.cancel()
            with suppress(asyncio.CancelledError):
                await checker


app = FastAPI(title="OAuth2 Mail Manager", lifespan=lifespan)
app.mount(
    "/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static"
)
app.add_middleware(RequestBodyLimitMiddleware, max_bytes=MAX_REQUEST_BYTES)
app.add_middleware(SecurityHeadersMiddleware, enable_hsts=SECURE_COOKIE)
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


def fmt_dt(value) -> str:
    if not value:
        return "-"
    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone()
        return parsed.strftime("%Y-%m-%d %H:%M")
    except ValueError:
        pass
    try:
        from email.utils import parsedate_to_datetime

        parsed = parsedate_to_datetime(text)
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone()
        return parsed.strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError, OverflowError):
        return text[:30]


templates.env.filters["fmt_dt"] = fmt_dt


def _render(
    request: Request, name: str, context: dict | None = None, status: int = 200
):
    values = dict(context or {})
    session = getattr(request.state, "session", None) or {}
    values.setdefault("csrf_token", session.get("csrf_token", ""))
    values.setdefault("current_version", update_manager.get_current_version())
    return templates.TemplateResponse(request, name, values, status_code=status)


def _session_token(request: Request) -> str | None:
    return request.cookies.get(SESSION_COOKIE)


def _is_api_path(path: str) -> bool:
    return path.startswith(("/api/", "/fetch/")) or path in {
        "/fetch-all",
        "/check-all",
    }


def _canonical_origin(value: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(value.strip())
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        return None
    default_port = 443 if parsed.scheme == "https" else 80
    return parsed.scheme, parsed.hostname.lower().rstrip("."), port or default_port


def _configured_origins() -> set[tuple[str, str, int]]:
    configured = os.environ.get("OMM_ALLOWED_ORIGINS", "")
    return {
        canonical
        for raw in configured.split(",")
        if raw.strip() and (canonical := _canonical_origin(raw)) is not None
    }


def _origin_allowed(request: Request) -> bool:
    origin = request.headers.get("origin")
    if not origin:
        return True
    canonical = _canonical_origin(origin)
    if canonical is None:
        return False

    host = request.headers.get("host", "").strip()
    same_origin = _canonical_origin(f"{canonical[0]}://{host}")
    return canonical == same_origin or canonical in _configured_origins()


@app.middleware("http")
async def authenticate_request(request: Request, call_next):
    path = request.url.path
    public = path == "/login" or path == "/healthz" or path.startswith("/static/")
    token = _session_token(request)
    session = await db.get_session(token) if token else None
    request.state.session = session

    if not public and session is None:
        if _is_api_path(path):
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        return RedirectResponse("/login", status_code=302)

    if (
        CHECK_ORIGIN
        and request.method in {"POST", "PUT", "PATCH", "DELETE"}
        and not _origin_allowed(request)
    ):
        return JSONResponse({"error": "Invalid request origin"}, status_code=403)
    return await call_next(request)


def _require_csrf(request: Request, form_token: str | None = None) -> None:
    session = getattr(request.state, "session", None)
    supplied = form_token or request.headers.get("X-CSRF-Token", "")
    expected = session.get("csrf_token", "") if session else ""
    if not supplied or not expected or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _login_locked(ip: str) -> int:
    record = _login_fails.get(ip)
    if not record:
        return 0
    if record[1] and record[1] <= time.time():
        _login_fails.pop(ip, None)
        return 0
    if record[1]:
        return max(1, int(record[1] - time.time()))
    return 0


def _record_login_fail(ip: str) -> None:
    record = _login_fails.setdefault(ip, [0.0, 0.0])
    record[0] += 1
    if record[0] >= LOGIN_MAX_FAILS:
        record[0] = 0
        record[1] = time.time() + LOGIN_LOCK_SECONDS
        logger.warning("Login temporarily locked for client %s", ip)


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        secure=SECURE_COOKIE,
        samesite="strict",
        path="/",
    )


@app.get("/healthz")
async def healthz():
    return {"ok": True, "version": update_manager.get_current_version()}


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, changed: int = 0):
    if request.state.session:
        return RedirectResponse("/", status_code=302)
    return _render(request, "login.html", {"changed": bool(changed)})


@app.post("/login")
async def do_login(
    request: Request, username: str = Form(...), password: str = Form(...)
):
    ip = _client_ip(request)
    locked = _login_locked(ip)
    if locked:
        return _render(
            request,
            "login.html",
            {"error": f"尝试次数过多，请 {locked // 60 + 1} 分钟后再试"},
            429,
        )
    session = await db.authenticate_and_create_session(
        username, password, SESSION_MAX_AGE
    )
    if session is None:
        _record_login_fail(ip)
        return _render(request, "login.html", {"error": "用户名或密码错误"}, 401)
    _login_fails.pop(ip, None)
    response = RedirectResponse("/", status_code=303)
    _set_session_cookie(response, session["token"])
    return response


@app.post("/logout")
async def logout(request: Request, csrf_token: str = Form(...)):
    _require_csrf(request, csrf_token)
    token = _session_token(request)
    if token:
        await db.revoke_session(token)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@app.get("/password", response_class=HTMLResponse)
async def password_page(request: Request):
    return _render(request, "password.html")


@app.post("/password")
async def change_password(
    request: Request,
    old_password: str = Form(...),
    new_password: str = Form(...),
    csrf_token: str = Form(...),
):
    _require_csrf(request, csrf_token)
    if not db.valid_new_password(new_password):
        return _render(
            request,
            "password.html",
            {"error": "密码至少8位，且必须包含英文字母和数字"},
            400,
        )
    if not await db.change_password(old_password, new_password):
        return _render(request, "password.html", {"error": "旧密码错误"}, 400)
    response = RedirectResponse("/login?changed=1", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


async def _global_proxy() -> str:
    configured = await db.get_setting("global_proxy")
    if configured is not None:
        return configured.strip()
    return os.environ.get("OMM_PROXY", "").strip()


def _validate_proxy(proxy: str) -> str:
    value = proxy.strip()
    if not value:
        return ""
    parsed = urlsplit(value)
    if (
        parsed.scheme.lower() not in {"http", "socks4", "socks5", "socks5h"}
        or not parsed.hostname
    ):
        raise ValueError("代理地址无效")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("代理端口无效") from exc
    return value


async def _default_ms_fetch_mode() -> str:
    mode = await db.get_setting("default_ms_fetch_mode")
    if mode in {"graph", "imap"}:
        return mode
    return (
        "imap"
        if os.environ.get("OMM_MS_FETCH_MODE", "graph").lower() == "imap"
        else "graph"
    )


def _with_token_days(accounts: list[dict]) -> list[dict]:
    now = datetime.now().astimezone()
    for account in accounts:
        account["days_left"] = None
        value = account.get("token_created_at")
        if value:
            try:
                created = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if created.tzinfo is None:
                    created = created.astimezone()
                account["days_left"] = (
                    created + timedelta(days=db.TOKEN_LIFETIME_DAYS) - now
                ).days
            except ValueError:
                pass
        account["error_kind"] = classify_error(account.get("error"))
    return accounts


@app.get("/", response_class=HTMLResponse)
async def index(
    request: Request,
    page: int = 1,
    provider: str = "",
    status: str = "",
    fetch_mode: str = "",
    q: str = "",
):
    page = max(1, page)
    accounts, total = await db.get_accounts(
        page=page,
        per_page=50,
        provider=provider or None,
        status=status or None,
        fetch_mode=fetch_mode or None,
        keyword=q.strip()[:200] or None,
    )
    _with_token_days(accounts)
    stats = await db.get_stats()
    expiring = await db.get_expiring_accounts()
    total_pages = max(1, (total + 49) // 50)
    query = urlencode(
        {
            key: value
            for key, value in {
                "provider": provider,
                "status": status,
                "fetch_mode": fetch_mode,
                "q": q,
            }.items()
            if value
        }
    )
    return _render(
        request,
        "index.html",
        {
            "accounts": accounts,
            "stats": stats,
            "expiring": expiring,
            "warning_days": db.TOKEN_WARNING_DAYS,
            "provider": provider,
            "status": status,
            "fetch_mode": fetch_mode,
            "q": q,
            "qs": query,
            "page": page,
            "total_pages": total_pages,
            "total": total,
        },
    )


@app.get("/import", response_class=HTMLResponse)
async def import_page(request: Request):
    return _render(request, "import.html")


@app.post("/import")
async def do_import(
    request: Request,
    text: str = Form(""),
    file: Annotated[UploadFile | None, File()] = None,
    csrf_token: str = Form(...),
):
    _require_csrf(request, csrf_token)
    lines = text.splitlines() if text.strip() else []
    if file and file.filename:
        content = await file.read(MAX_REQUEST_BYTES + 1)
        if len(content) > MAX_REQUEST_BYTES:
            return _render(request, "import.html", {"error": "文件过大"}, 413)
        lines.extend(content.decode("utf-8", errors="replace").splitlines())
    if not lines:
        return _render(request, "import.html", {"error": "请提供账号数据"}, 400)
    if len(lines) > MAX_IMPORT_LINES:
        return _render(request, "import.html", {"error": "导入行数过多"}, 413)
    result = await db.import_accounts(
        lines, ms_fetch_mode=await _default_ms_fetch_mode()
    )
    return _render(request, "import.html", {"result": result})


@app.get("/tokens", response_class=HTMLResponse)
async def token_status_page(request: Request):
    accounts = await db.get_all_active_accounts()
    _with_token_days(accounts)
    expiring = [
        item
        for item in accounts
        if item["days_left"] is not None and item["days_left"] <= db.TOKEN_WARNING_DAYS
    ]
    expiring.sort(key=lambda item: item["days_left"])
    return _render(
        request,
        "tokens.html",
        {
            "expiring": expiring,
            "stats": await db.get_stats(),
            "token_lifetime_days": db.TOKEN_LIFETIME_DAYS,
            "warning_days": db.TOKEN_WARNING_DAYS,
        },
    )


@app.get("/account/{account_id}", response_class=HTMLResponse)
async def account_detail(
    request: Request, account_id: int, folder: str = "", page: int = 1
):
    account = await db.get_account(account_id)
    if not account:
        return RedirectResponse("/", status_code=302)
    page = max(1, page)
    emails, total = await db.get_emails(
        account_id, folder=folder or None, page=page, per_page=50
    )
    return _render(
        request,
        "inbox.html",
        {
            "account": account,
            "emails": emails,
            "folder": folder,
            "page": page,
            "total_pages": max(1, (total + 49) // 50),
            "total": total,
        },
    )


@app.get("/email/{email_id}", response_class=HTMLResponse)
async def email_detail(request: Request, email_id: int):
    message = await db.get_email(email_id)
    if not message:
        return RedirectResponse("/", status_code=302)
    message["body_html"] = sanitize_email_html(message.get("body_html") or "")
    return _render(request, "email_detail.html", {"email": message})


def _account_lock(account_id: int) -> asyncio.Lock:
    return _account_locks.setdefault(account_id, asyncio.Lock())


@asynccontextmanager
async def _account_operation(account_id: int):
    async with _account_lock(account_id):
        lease = await db.acquire_account_lease(account_id)
        if lease is None:
            raise AccountBusyError("Account operation is already running")
        try:
            yield
        finally:
            await asyncio.shield(db.release_account_lease(account_id, lease))


async def _run_critical(coroutine):
    """Finish credential and status commits if the requesting task is cancelled."""
    task = asyncio.create_task(coroutine)
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        try:
            await asyncio.shield(task)
        finally:
            raise


async def _refresh_account(account: dict) -> tuple[str, bool, str]:
    proxy = account.get("proxy", "") or await _global_proxy()
    access_token, new_refresh_token = await mail_fetcher.refresh_access_token(
        account["client_id"],
        account["refresh_token"],
        provider_key=account.get("provider", "microsoft"),
        client_secret=account.get("client_secret", ""),
        fetch_mode=account.get("fetch_mode", "imap"),
        proxy=proxy,
    )
    persisted = False
    for attempt in range(3):
        try:
            persisted = await db.update_refresh_token_cas(
                account["id"], account["refresh_token"], new_refresh_token
            )
            break
        except aiosqlite.OperationalError:
            if attempt == 2:
                raise
            await asyncio.sleep(0.1 * (attempt + 1))
    if not persisted:
        raise RuntimeError(
            "Account credentials changed during refresh; retry the operation"
        )
    return access_token, new_refresh_token != account["refresh_token"], proxy


async def _fetch_and_save_operation(account_id: int, limit: int) -> tuple[int, bool]:
    async with _account_operation(account_id):
        current = await db.get_account(account_id)
        if not current or not current.get("enabled"):
            raise RuntimeError("Account is no longer active")
        try:
            access_token, token_rotated, proxy = await _refresh_account(current)
            partial_error = None
            try:
                result = await mail_fetcher.check_account_with_access_token(
                    current["email"],
                    access_token,
                    provider_key=current.get("provider", "microsoft"),
                    limit=limit,
                    fetch_mode=current.get("fetch_mode", "imap"),
                    proxy=proxy,
                )
            except mail_fetcher.MailboxFetchError as exc:
                result = exc.partial_results
                partial_error = str(exc)[:500]

            saved = 0
            for folder, emails in result.items():
                saved += await db.save_emails(current["id"], folder, emails)
            total = await db.get_email_count(current["id"])
            if partial_error:
                await db.update_account_status(
                    current["id"], "error", error=partial_error, mail_count=total
                )
                raise AccountPartialFetchError(partial_error, saved)
            await db.update_account_status(current["id"], "active", mail_count=total)
            return saved, token_rotated
        except AccountPartialFetchError:
            raise
        except Exception as exc:
            await db.update_account_status(current["id"], "error", error=str(exc)[:500])
            raise


async def _fetch_and_save(account: dict, limit: int) -> tuple[int, bool]:
    return await _run_critical(_fetch_and_save_operation(account["id"], limit))


@app.post("/fetch/{account_id}")
async def fetch_single(request: Request, account_id: int):
    _require_csrf(request)
    account = await db.get_account(account_id)
    if not account:
        return JSONResponse({"error": "Account not found"}, status_code=404)
    try:
        saved, rotated = await _fetch_and_save(account, 50)
        return {"ok": True, "fetched": saved, "token_refreshed": rotated}
    except AccountPartialFetchError as exc:
        return JSONResponse(
            {"ok": False, "partial": True, "fetched": exc.saved, "error": str(exc)},
            status_code=207,
        )
    except Exception as exc:  # noqa: BLE001 - translate provider failures to account state
        message = str(exc)[:500]
        return JSONResponse({"ok": False, "error": message}, status_code=502)


async def _fetch_all_accounts(limit: int) -> dict:
    async with _batch_lock:
        accounts = await db.get_all_active_accounts()
        semaphore = asyncio.Semaphore(FETCH_CONCURRENCY)
        result = {"success": 0, "failed": 0, "total_emails": 0}

        async def fetch_one(account: dict):
            async with semaphore:
                try:
                    saved, _ = await _fetch_and_save(account, limit)
                    result["success"] += 1
                    result["total_emails"] += saved
                except AccountPartialFetchError as exc:
                    result["failed"] += 1
                    result["total_emails"] += exc.saved
                except Exception:  # noqa: BLE001
                    result["failed"] += 1

        await asyncio.gather(*(fetch_one(account) for account in accounts))
        return result


@app.post("/fetch-all")
async def fetch_all(request: Request):
    _require_csrf(request)
    return await _fetch_all_accounts(30)


@app.post("/check-all")
async def check_all(request: Request):
    _require_csrf(request)
    return await _fetch_all_accounts(1)


@app.post("/account/{account_id}/toggle")
async def toggle_account(
    request: Request,
    account_id: int,
    action: str = Form(...),
    csrf_token: str = Form(...),
):
    _require_csrf(request, csrf_token)

    async def toggle_operation():
        async with _account_operation(account_id):
            if action == "disable":
                await db.disable_account(account_id)
            elif action == "enable":
                await db.enable_account(account_id)
            elif action == "delete":
                await db.delete_account(account_id)
            else:
                raise HTTPException(status_code=400, detail="Invalid action")

    try:
        await _run_critical(toggle_operation())
    except AccountBusyError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if action == "delete":
        _account_locks.pop(account_id, None)
    return RedirectResponse("/", status_code=303)


@app.post("/account/{account_id}/refresh-token")
async def refresh_token_endpoint(
    request: Request, account_id: int, csrf_token: str = Form(...)
):
    _require_csrf(request, csrf_token)
    account = await db.get_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    async def refresh_operation():
        async with _account_operation(account_id):
            current = await db.get_account(account_id)
            try:
                await _refresh_account(current)
                await db.update_account_status(account_id, "active")
            except Exception as exc:
                await db.update_account_status(
                    account_id, "error", error=str(exc)[:500]
                )
                raise

    try:
        await _run_critical(refresh_operation())
    except Exception as exc:  # noqa: BLE001 - status is committed inside the lease
        logger.info("Manual token refresh failed: %s", type(exc).__name__)
    return RedirectResponse("/tokens", status_code=303)


@app.get("/account/{account_id}/edit-token", response_class=HTMLResponse)
async def edit_token_page(request: Request, account_id: int):
    account = await db.get_account(account_id)
    if not account:
        return RedirectResponse("/", status_code=302)
    return _render(request, "edit_token.html", {"account": account})


@app.post("/account/{account_id}/edit-token")
async def update_token(
    request: Request,
    account_id: int,
    new_refresh_token: str = Form(""),
    account_proxy: str = Form(""),
    csrf_token: str = Form(...),
):
    _require_csrf(request, csrf_token)
    account = await db.get_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    try:
        proxy = _validate_proxy(account_proxy)
    except ValueError as exc:
        return _render(
            request, "edit_token.html", {"account": account, "error": str(exc)}, 400
        )

    async def update_operation():
        async with _account_operation(account_id):
            await db.update_account_proxy(account_id, proxy)
            if new_refresh_token.strip():
                await db.update_refresh_token(account_id, new_refresh_token.strip())

    try:
        await _run_critical(update_operation())
    except AccountBusyError:
        return _render(
            request,
            "edit_token.html",
            {"account": account, "error": "账号正在取件，请稍后重试"},
            409,
        )
    return RedirectResponse("/", status_code=303)


@app.post("/account/{account_id}/prefs")
async def update_prefs(
    request: Request,
    account_id: int,
    fetch_mode: str = Form("imap"),
    csrf_token: str = Form(...),
):
    _require_csrf(request, csrf_token)
    account = await db.get_account(account_id)
    if not account:
        return JSONResponse({"error": "Account not found"}, status_code=404)
    if fetch_mode not in {"imap", "graph"} or account.get("provider") != "microsoft":
        fetch_mode = "imap"
    async def prefs_operation():
        async with _account_operation(account_id):
            await db.update_account_prefs(account_id, fetch_mode)

    try:
        await _run_critical(prefs_operation())
    except AccountBusyError:
        return JSONResponse({"error": "Account operation is already running"}, status_code=409)
    return {"ok": True, "fetch_mode": fetch_mode}


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    configured_proxy = await db.get_setting("global_proxy")
    return _render(
        request,
        "settings.html",
        {
            "global_proxy": configured_proxy
            if configured_proxy is not None
            else os.environ.get("OMM_PROXY", ""),
            "proxy_from_env": configured_proxy is None
            and bool(os.environ.get("OMM_PROXY")),
            "default_ms_fetch_mode": await _default_ms_fetch_mode(),
            "auto_check_hours": await _auto_check_hours(),
        },
    )


@app.post("/settings")
async def save_settings(
    request: Request,
    global_proxy: str = Form(""),
    default_ms_fetch_mode: str = Form("graph"),
    auto_check_hours: str = Form("0"),
    csrf_token: str = Form(...),
):
    _require_csrf(request, csrf_token)
    try:
        proxy = _validate_proxy(global_proxy)
        hours = float(auto_check_hours)
        if not math.isfinite(hours) or not 0 <= hours <= 24 * 30:
            raise ValueError("自动检测间隔超出范围")
    except ValueError as exc:
        return _render(
            request,
            "settings.html",
            {
                "global_proxy": global_proxy,
                "proxy_from_env": False,
                "default_ms_fetch_mode": default_ms_fetch_mode,
                "auto_check_hours": auto_check_hours,
                "error": str(exc),
            },
            400,
        )
    if default_ms_fetch_mode not in {"graph", "imap"}:
        default_ms_fetch_mode = "graph"
    await db.set_settings(
        {
            "global_proxy": proxy,
            "default_ms_fetch_mode": default_ms_fetch_mode,
            "auto_check_hours": str(hours),
        }
    )
    return _render(
        request,
        "settings.html",
        {
            "global_proxy": proxy,
            "proxy_from_env": False,
            "default_ms_fetch_mode": default_ms_fetch_mode,
            "auto_check_hours": hours,
            "success": "设置已保存",
        },
    )


@app.post("/accounts/bulk-fetch-mode")
async def bulk_fetch_mode(
    request: Request,
    fetch_mode: str = Form(...),
    csrf_token: str = Form(...),
):
    _require_csrf(request, csrf_token)
    if fetch_mode not in {"graph", "imap"}:
        raise HTTPException(status_code=400, detail="Invalid fetch mode")
    count = await db.set_all_ms_fetch_mode(fetch_mode)
    return _render(
        request,
        "settings.html",
        {
            "global_proxy": await _global_proxy(),
            "proxy_from_env": False,
            "default_ms_fetch_mode": await _default_ms_fetch_mode(),
            "auto_check_hours": await _auto_check_hours(),
            "success": f"已更新 {count} 个 Microsoft 账号",
        },
    )


def _export_response(accounts: list[dict]) -> Response:
    lines = []
    for account in accounts:
        second = account.get("client_secret") or ""
        lines.append(
            "----".join(
                [
                    account["email"],
                    second,
                    account["client_id"],
                    account["refresh_token"],
                ]
            )
        )
    response = Response("\n".join(lines) + "\n", media_type="text/plain; charset=utf-8")
    response.headers["Content-Disposition"] = (
        'attachment; filename="accounts_export.txt"'
    )
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return response


@app.post("/export")
async def export_accounts(
    request: Request,
    account_id: Annotated[list[str] | None, Form()] = None,
    current_password: str = Form(...),
    csrf_token: str = Form(...),
):
    _require_csrf(request, csrf_token)
    if not await db.verify_user(db.ADMIN_USERNAME, current_password):
        raise HTTPException(status_code=403, detail="Current password is incorrect")
    if account_id == ["all"]:
        accounts, _ = await db.get_accounts(page=1, per_page=1_000_000)
    else:
        try:
            ids = [int(value) for value in account_id or []]
        except ValueError as exc:
            raise HTTPException(
                status_code=400, detail="Invalid account selection"
            ) from exc
        accounts = await db.get_accounts_by_ids(ids)
    if not accounts:
        raise HTTPException(status_code=400, detail="No accounts selected")
    return _export_response(accounts)


@app.get("/api/stats")
async def api_stats():
    return await db.get_stats()


@app.get("/api/account/{account_id}/emails")
async def api_account_emails(
    account_id: int, folder: str = "", page: int = 1, per_page: int = 50
):
    per_page = max(1, min(per_page, 100))
    page = max(1, page)
    emails, total = await db.get_emails(
        account_id, folder=folder or None, page=page, per_page=per_page
    )
    return {
        "emails": [
            {
                "id": message["id"],
                "from": message["from_addr"],
                "subject": message["subject"],
                "date": message["date"],
                "folder": message["folder"],
            }
            for message in emails
        ],
        "page": page,
        "total_pages": max(1, (total + per_page - 1) // per_page),
        "total": total,
    }


@app.get("/api/update/status")
async def update_status():
    try:
        return await asyncio.to_thread(
            update_manager.check_for_update, await _global_proxy()
        )
    except update_manager.UpdateError as exc:
        return JSONResponse({"error": str(exc)}, status_code=502)


async def _restart_after_response() -> None:
    await asyncio.sleep(1.0)
    update_manager.restart_current_process()


@app.post("/api/update/apply")
async def apply_update(request: Request):
    _require_csrf(request)
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            raise TypeError("Update request must be a JSON object")
        version = str(payload.get("version", ""))
        result = await asyncio.to_thread(
            update_manager.apply_update,
            version,
            await _global_proxy(),
        )
    except (ValueError, TypeError, update_manager.UpdateError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    asyncio.create_task(_restart_after_response())
    return result


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=os.environ.get("OMM_HOST", "127.0.0.1"),
        port=int(os.environ.get("OMM_PORT", "8899")),
        proxy_headers=True,
        forwarded_allow_ips=os.environ.get("OMM_FORWARDED_ALLOW_IPS", "127.0.0.1"),
    )
