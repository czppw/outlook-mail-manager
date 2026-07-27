"""
OAuth2 邮箱批量管理器 - FastAPI 应用
支持 Outlook/Hotmail/Gmail 等 OAuth2 邮箱。
功能：导入账号、自动识别供应商、IMAP/Graph 取件、代理支持、
     Web 界面查看邮件（动态加载）、登录认证（限速）、令牌过期管理
"""
import asyncio
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from fastapi import FastAPI, Request, Form, UploadFile, File, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import db
import mail_fetcher

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Batch fetch concurrency limit
FETCH_CONCURRENCY = 5

# Session config
SESSION_SECRET = os.environ.get("SESSION_SECRET", secrets.token_hex(32))
SESSION_COOKIE = "omm_session"
SESSION_MAX_AGE = 86400 * 7  # 7 days

# Simple in-memory session store
_sessions: dict[str, dict] = {}

# Login rate limiting: ip -> [fail_count, locked_until_ts]
LOGIN_MAX_FAILS = 5
LOGIN_LOCK_SECONDS = 300
_login_fails: dict[str, list] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_db()
    logger.info("Database initialized")
    yield

app = FastAPI(title="OAuth2 Mail Manager", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


def fmt_dt(value) -> str:
    """显示层时间格式化：ISO(带T/微秒/Z) 或 RFC2822 → 'YYYY-MM-DD HH:MM'。
    带时区的转换为服务器本地时间；解析不了的原样截断返回。"""
    if not value:
        return "-"
    s = str(value).strip()
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is not None:
            dt = dt.astimezone()
        return dt.strftime("%Y-%m-%d %H:%M")
    except ValueError:
        pass
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(s)
        if dt.tzinfo is not None:
            dt = dt.astimezone()
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return s[:30]


templates.env.filters["fmt_dt"] = fmt_dt


# ─────────── Auth Helpers ───────────

def _get_session_token(request: Request) -> str | None:
    return request.cookies.get(SESSION_COOKIE)


def _is_authenticated(request: Request) -> bool:
    token = _get_session_token(request)
    if not token:
        return False
    session = _sessions.get(token)
    if not session:
        return False
    if session.get("expires", datetime.min) < datetime.now():
        del _sessions[token]
        return False
    return True


def _create_session(response: Response, username: str):
    token = secrets.token_hex(32)
    _sessions[token] = {
        "user": username,
        "expires": datetime.now() + timedelta(seconds=SESSION_MAX_AGE)
    }
    response.set_cookie(
        SESSION_COOKIE, token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="lax"
    )


class AuthRequired(Exception):
    pass


def _require_auth(request: Request):
    if not _is_authenticated(request):
        raise AuthRequired()


def _require_auth_api(request: Request):
    """API 端点未认证时返回 401 JSON，而不是重定向。"""
    if not _is_authenticated(request):
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Unauthorized")


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _login_locked(ip: str) -> int:
    """返回剩余锁定秒数，未锁定返回 0。"""
    rec = _login_fails.get(ip)
    if rec and rec[1] > time.time():
        return int(rec[1] - time.time())
    return 0


def _record_login_fail(ip: str):
    rec = _login_fails.setdefault(ip, [0, 0.0])
    rec[0] += 1
    if rec[0] >= LOGIN_MAX_FAILS:
        rec[1] = time.time() + LOGIN_LOCK_SECONDS
        rec[0] = 0
        logger.warning(f"Login locked for {ip} ({LOGIN_LOCK_SECONDS}s) after {LOGIN_MAX_FAILS} fails")


def _clear_login_fail(ip: str):
    _login_fails.pop(ip, None)


# ─────────── Login / Logout ───────────

@app.exception_handler(AuthRequired)
async def auth_required_handler(request: Request, exc: AuthRequired):
    return RedirectResponse("/login", status_code=302)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if _is_authenticated(request):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request, "login.html", {})


@app.post("/login")
async def do_login(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = _client_ip(request)
    locked = _login_locked(ip)
    if locked:
        return templates.TemplateResponse(request, "login.html", {
            "error": f"尝试次数过多，请 {locked // 60 + 1} 分钟后再试"
        })
    if await db.verify_user(username, password):
        _clear_login_fail(ip)
        resp = RedirectResponse("/", status_code=302)
        _create_session(resp, username)
        return resp
    _record_login_fail(ip)
    return templates.TemplateResponse(request, "login.html", {
        "error": "用户名或密码错误"
    })


@app.get("/logout")
async def logout(request: Request):
    token = _get_session_token(request)
    if token and token in _sessions:
        del _sessions[token]
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@app.get("/password", response_class=HTMLResponse)
async def password_page(request: Request):
    _require_auth(request)
    return templates.TemplateResponse(request, "password.html", {})


@app.post("/password")
async def change_password(request: Request, old_password: str = Form(...), new_password: str = Form(...)):
    _require_auth(request)
    if len(new_password) < 6:
        return templates.TemplateResponse(request, "password.html", {"error": "密码至少6位"})

    ok = await db.change_password(old_password, new_password)
    if not ok:
        return templates.TemplateResponse(request, "password.html", {"error": "旧密码错误"})
    return templates.TemplateResponse(request, "password.html", {"success": "密码已修改，重启后仍然有效"})


# ─────────── Global config ───────────

async def _global_proxy() -> str:
    """全局代理：设置页（settings 表）优先，其次 OMM_PROXY 环境变量。"""
    p = await db.get_setting("global_proxy")
    if p:
        return p
    return os.environ.get("OMM_PROXY", "").strip()


async def _default_ms_fetch_mode() -> str:
    """新导入 MS 账号的默认取件方式：设置页优先，其次环境变量，默认 graph。"""
    mode = await db.get_setting("default_ms_fetch_mode")
    if mode in ("graph", "imap"):
        return mode
    env_mode = os.environ.get("OMM_MS_FETCH_MODE", "graph").strip().lower()
    return "imap" if env_mode == "imap" else "graph"


# ─────────── Pages ───────────

def _with_token_days(accounts: list[dict]) -> list[dict]:
    """为账号列表计算令牌剩余天数（None 表示未知）。"""
    now = datetime.now()
    for acc in accounts:
        acc["days_left"] = None
        if acc.get("token_created_at"):
            try:
                created = datetime.fromisoformat(acc["token_created_at"])
                acc["days_left"] = (created + timedelta(days=db.TOKEN_LIFETIME_DAYS) - now).days
            except ValueError:
                pass
    return accounts


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, page: int = 1):
    _require_auth(request)
    accounts, total = await db.get_accounts(page=page, per_page=50)
    _with_token_days(accounts)
    stats = await db.get_stats()
    expiring = await db.get_expiring_accounts()
    total_pages = max(1, (total + 49) // 50)
    return templates.TemplateResponse(request, "index.html", {
        "accounts": accounts, "stats": stats,
        "expiring": expiring,
        "warning_days": db.TOKEN_WARNING_DAYS,
        "page": page, "total_pages": total_pages, "total": total
    })


@app.get("/import", response_class=HTMLResponse)
async def import_page(request: Request):
    _require_auth(request)
    return templates.TemplateResponse(request, "import.html", {})


@app.post("/import")
async def do_import(request: Request, text: str = Form(""), file: UploadFile = File(None)):
    _require_auth(request)
    lines = []
    if text.strip():
        lines = text.strip().split('\n')
    if file and file.filename:
        content = await file.read()
        lines.extend(content.decode('utf-8', errors='replace').split('\n'))

    if not lines:
        return templates.TemplateResponse(request, "import.html", {
            "error": "请提供账号数据"
        })

    result = await db.import_accounts(lines, ms_fetch_mode=await _default_ms_fetch_mode())
    return templates.TemplateResponse(request, "import.html", {
        "result": result
    })


@app.get("/tokens", response_class=HTMLResponse)
async def token_status_page(request: Request):
    """Token expiration overview page."""
    _require_auth(request)
    all_accounts = await db.get_all_active_accounts()
    _with_token_days(all_accounts)
    stats = await db.get_stats()

    expiring = [a for a in all_accounts
                if a["days_left"] is not None and a["days_left"] <= db.TOKEN_WARNING_DAYS]
    expiring.sort(key=lambda x: x["days_left"])

    return templates.TemplateResponse(request, "tokens.html", {
        "expiring": expiring,
        "stats": stats,
        "token_lifetime_days": db.TOKEN_LIFETIME_DAYS,
        "warning_days": db.TOKEN_WARNING_DAYS,
    })


@app.get("/account/{account_id}", response_class=HTMLResponse)
async def account_detail(request: Request, account_id: int, folder: str = "", page: int = 1):
    _require_auth(request)
    account = await db.get_account(account_id)
    if not account:
        return RedirectResponse("/", status_code=302)

    emails, total = await db.get_emails(account_id, folder=folder or None, page=page, per_page=50)
    total_pages = max(1, (total + 49) // 50)
    return templates.TemplateResponse(request, "inbox.html", {
        "account": account, "emails": emails,
        "folder": folder, "page": page, "total_pages": total_pages, "total": total
    })


@app.get("/email/{email_id}", response_class=HTMLResponse)
async def email_detail(request: Request, email_id: int):
    _require_auth(request)
    em = await db.get_email(email_id)
    if not em:
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request, "email_detail.html", {
        "email": em
    })


# ─────────── Actions ───────────

async def _fetch_and_save(account: dict, limit: int) -> tuple[int, bool]:
    """取件并入库。返回 (新增邮件数, token是否轮换)。抛异常由调用方处理。"""
    result, new_refresh_token = await mail_fetcher.check_account(
        account['email'], account['password'],
        account['client_id'], account['refresh_token'],
        provider_key=account.get('provider', 'microsoft'),
        client_secret=account.get('client_secret', ''),
        limit=limit,
        fetch_mode=account.get('fetch_mode', 'imap'),
        proxy=await _global_proxy(),
    )
    total_saved = 0
    for folder, emails in result.items():
        total_saved += await db.save_emails(account['id'], folder, emails)
    # 自动保存轮换后的 refresh_token（微软/谷歌每次刷新都会轮换）
    token_refreshed = bool(new_refresh_token) and new_refresh_token != account['refresh_token']
    if token_refreshed:
        await db.update_refresh_token(account['id'], new_refresh_token)
        logger.info(f"Refreshed token for {account['email']}")
    # mail_count 记录库内该账号邮件总数（而不是当次新增数）
    mail_total = await db.get_email_count(account['id'])
    await db.update_account_status(account['id'], 'active', mail_count=mail_total)
    return total_saved, token_refreshed


@app.post("/fetch/{account_id}")
async def fetch_single(request: Request, account_id: int):
    """Fetch emails for a single account."""
    _require_auth(request)
    account = await db.get_account(account_id)
    if not account:
        return JSONResponse({"error": "Account not found"}, status_code=404)

    try:
        total_saved, token_refreshed = await _fetch_and_save(account, limit=50)
        return JSONResponse({"ok": True, "fetched": total_saved,
                             "token_refreshed": token_refreshed})
    except Exception as e:
        await db.update_account_status(account_id, 'error', error=str(e)[:500])
        return JSONResponse({"ok": False, "error": str(e)[:500]})


@app.post("/fetch-all")
async def fetch_all(request: Request):
    """Fetch emails for all active accounts."""
    _require_auth(request)
    accounts = await db.get_all_active_accounts()
    if not accounts:
        return JSONResponse({"error": "No active accounts"}, status_code=400)

    sem = asyncio.Semaphore(FETCH_CONCURRENCY)
    results = {"success": 0, "failed": 0, "total_emails": 0}

    async def fetch_one(acc):
        async with sem:
            try:
                total_saved, _ = await _fetch_and_save(acc, limit=30)
                results["success"] += 1
                results["total_emails"] += total_saved
            except Exception as e:
                await db.update_account_status(acc['id'], 'error', error=str(e)[:500])
                results["failed"] += 1

    await asyncio.gather(*[fetch_one(a) for a in accounts])
    return JSONResponse(results)


@app.post("/account/{account_id}/toggle")
async def toggle_account(request: Request, account_id: int, action: str = Form(...)):
    _require_auth(request)
    if action == "disable":
        await db.disable_account(account_id)
    elif action == "enable":
        await db.enable_account(account_id)
    elif action == "delete":
        await db.delete_account(account_id)
    return RedirectResponse("/", status_code=302)


@app.post("/account/{account_id}/refresh-token")
async def refresh_token_endpoint(request: Request, account_id: int):
    """Mark token as refreshed (reset 3-month timer)."""
    _require_auth(request)
    await db.refresh_token_date(account_id)
    return RedirectResponse("/", status_code=302)


@app.get("/account/{account_id}/edit-token", response_class=HTMLResponse)
async def edit_token_page(request: Request, account_id: int):
    """更新 refresh_token 页。"""
    _require_auth(request)
    account = await db.get_account(account_id)
    if not account:
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request, "edit_token.html", {
        "account": account,
    })


@app.post("/account/{account_id}/edit-token")
async def update_token(request: Request, account_id: int, new_refresh_token: str = Form(...)):
    """Update refresh_token for an account."""
    _require_auth(request)
    if not new_refresh_token.strip():
        account = await db.get_account(account_id)
        return templates.TemplateResponse(request, "edit_token.html", {
            "account": account, "error": "令牌不能为空",
        })
    await db.update_refresh_token(account_id, new_refresh_token.strip())
    return RedirectResponse("/", status_code=302)


@app.post("/account/{account_id}/prefs")
async def update_prefs(request: Request, account_id: int, fetch_mode: str = Form("imap")):
    """列表下拉切换取件方式（imap/graph），JSON 返回。"""
    _require_auth(request)
    if fetch_mode not in ("imap", "graph"):
        fetch_mode = "imap"
    account = await db.get_account(account_id)
    if not account:
        return JSONResponse({"error": "Account not found"}, status_code=404)
    if account.get("provider") != "microsoft":
        fetch_mode = "imap"  # 非 MS 账号仅支持 IMAP
    await db.update_account_prefs(account_id, fetch_mode)
    return JSONResponse({"ok": True, "fetch_mode": fetch_mode})


# ─────────── 全局设置 ───────────

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    _require_auth(request)
    return templates.TemplateResponse(request, "settings.html", {
        "global_proxy": await _global_proxy(),
        "proxy_from_env": not bool(await db.get_setting("global_proxy")) and bool(os.environ.get("OMM_PROXY")),
        "default_ms_fetch_mode": await _default_ms_fetch_mode(),
    })


@app.post("/settings")
async def save_settings(request: Request, global_proxy: str = Form(""),
                        default_ms_fetch_mode: str = Form("graph")):
    _require_auth(request)
    if default_ms_fetch_mode not in ("graph", "imap"):
        default_ms_fetch_mode = "graph"
    await db.set_setting("global_proxy", global_proxy.strip())
    await db.set_setting("default_ms_fetch_mode", default_ms_fetch_mode)
    return templates.TemplateResponse(request, "settings.html", {
        "global_proxy": global_proxy.strip(),
        "proxy_from_env": False,
        "default_ms_fetch_mode": default_ms_fetch_mode,
        "success": "设置已保存，立即生效",
    })


@app.post("/accounts/bulk-fetch-mode")
async def bulk_fetch_mode(request: Request, fetch_mode: str = Form(...)):
    """一键切换全部现有 Microsoft 账号的取件方式。"""
    _require_auth(request)
    if fetch_mode not in ("graph", "imap"):
        return RedirectResponse("/settings", status_code=302)
    n = await db.set_all_ms_fetch_mode(fetch_mode)
    logger.info(f"Bulk switched {n} MS accounts to {fetch_mode}")
    return templates.TemplateResponse(request, "settings.html", {
        "global_proxy": await _global_proxy(),
        "proxy_from_env": False,
        "default_ms_fetch_mode": await _default_ms_fetch_mode(),
        "success": f"已将 {n} 个 Microsoft 账号全部切换为 {fetch_mode.upper()} 模式",
    })


@app.get("/export")
async def export_accounts(request: Request):
    """导出全部账号为导入格式文本（email----密码----client_id----refresh_token）。
    Gmail 账号第二个字段导出 client_secret，与导入格式一致，可直接用于再导入。"""
    _require_auth(request)
    accounts, _ = await db.get_accounts(page=1, per_page=1_000_000)
    lines = []
    for a in accounts:
        second = a.get("client_secret") or a.get("password") or ""
        lines.append("----".join([
            a["email"], second, a["client_id"], a["refresh_token"]
        ]))
    content = "\n".join(lines) + "\n"
    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="accounts_export.txt"'},
    )


# ─────────── JSON API ───────────

@app.get("/api/stats")
async def api_stats(request: Request):
    _require_auth_api(request)
    return await db.get_stats()


@app.get("/api/account/{account_id}/emails")
async def api_account_emails(request: Request, account_id: int,
                             folder: str = "", page: int = 1, per_page: int = 50):
    """邮件分页 JSON（收件箱「加载更多」动态加载用）。"""
    _require_auth_api(request)
    per_page = max(1, min(per_page, 100))
    emails, total = await db.get_emails(account_id, folder=folder or None,
                                        page=page, per_page=per_page)
    total_pages = max(1, (total + per_page - 1) // per_page)
    return {
        "emails": [
            {
                "id": em["id"],
                "from": em["from_addr"],
                "subject": em["subject"],
                "date": em["date"],
                "folder": em["folder"],
            }
            for em in emails
        ],
        "page": page,
        "total_pages": total_pages,
        "total": total,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("OMM_PORT", "8899")))
