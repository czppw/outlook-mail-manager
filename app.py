"""
OAuth2 邮箱批量管理器 - FastAPI 应用
支持 Outlook/Hotmail/Gmail 等 OAuth2 IMAP 邮箱。
功能：导入账号、自动识别供应商、OAuth2 IMAP 取件、Web 界面查看邮件、登录认证、令牌过期管理
"""
import asyncio
import logging
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from fastapi import FastAPI, Request, Form, UploadFile, File, Depends, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import db
import mail_fetcher

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Batch fetch concurrency limit
FETCH_CONCURRENCY = 5

# Session config
SESSION_SECRET = os.environ.get("SESSION_SECRET", secrets.token_hex(32))
SESSION_COOKIE = "omm_session"
SESSION_MAX_AGE = 86400 * 7  # 7 days

# Simple in-memory session store
_sessions: dict[str, dict] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_db()
    logger.info("Database initialized")
    yield

app = FastAPI(title="OAuth2 Mail Manager", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


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
    if db.verify_user(username, password):
        resp = RedirectResponse("/", status_code=302)
        _create_session(resp, username)
        return resp
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
    token = _get_session_token(request)
    username = _sessions.get(token, {}).get("user", "admin")
    
    if not db.verify_user(username, old_password):
        return templates.TemplateResponse(request, "password.html", {"error": "旧密码错误"})
    
    if len(new_password) < 6:
        return templates.TemplateResponse(request, "password.html", {"error": "密码至少6位"})
    
    db.change_password(username, new_password)
    return templates.TemplateResponse(request, "password.html", {"success": "密码已修改"})


# ─────────── Pages ───────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, page: int = 1):
    _require_auth(request)
    accounts, total = await db.get_accounts(page=page, per_page=50)
    stats = await db.get_stats()
    expiring = await db.get_expiring_accounts(warning_days=14)
    total_pages = max(1, (total + 49) // 50)
    return templates.TemplateResponse(request, "index.html", {
        "accounts": accounts, "stats": stats,
        "expiring": expiring,
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

    result = await db.import_accounts(lines)
    return templates.TemplateResponse(request, "import.html", {
                "result": result
            })


@app.get("/tokens", response_class=HTMLResponse)
async def token_status_page(request: Request):
    """Token expiration overview page."""
    _require_auth(request)
    from datetime import datetime, timedelta
    now = datetime.now()
    all_accounts = await db.get_all_active_accounts()
    stats = await db.get_stats()

    TOKEN_LIFETIME_DAYS = 90
    expiring = []
    for acc in all_accounts:
        if acc.get('token_created_at'):
            created = datetime.fromisoformat(acc['token_created_at'])
            expires_at = created + timedelta(days=TOKEN_LIFETIME_DAYS)
            days_left = (expires_at - now).days
            acc['days_left'] = days_left
            if days_left <= 30:
                expiring.append(acc)
    expiring.sort(key=lambda x: x['days_left'])

    return templates.TemplateResponse(request, "tokens.html", {
        "expiring": expiring,
        "stats": stats,
        "token_lifetime_days": TOKEN_LIFETIME_DAYS,
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

@app.post("/fetch/{account_id}")
async def fetch_single(request: Request, account_id: int):
    """Fetch emails for a single account."""
    _require_auth(request)
    account = await db.get_account(account_id)
    if not account:
        return JSONResponse({"error": "Account not found"}, status_code=404)

    try:
        result, new_refresh_token = await mail_fetcher.check_account(
            account['email'], account['password'],
            account['client_id'], account['refresh_token'],
            provider_key=account.get('provider', 'microsoft'),
            client_secret=account.get('client_secret', ''),
            limit=50
        )
        total_saved = 0
        for folder, emails in result.items():
            saved = await db.save_emails(account_id, folder, emails)
            total_saved += saved
        # Auto-save new refresh_token (Microsoft rotates it)
        if new_refresh_token and new_refresh_token != account['refresh_token']:
            await db.update_refresh_token(account_id, new_refresh_token)
            logger.info(f"Refreshed token for {account['email']}")
        await db.update_account_status(account_id, 'active', mail_count=total_saved)
        return JSONResponse({"ok": True, "fetched": total_saved, "folders": list(result.keys()),
                             "token_refreshed": new_refresh_token != account['refresh_token']})
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
                result, new_refresh_token = await mail_fetcher.check_account(
                    acc['email'], acc['password'],
                    acc['client_id'], acc['refresh_token'],
                    provider_key=acc.get('provider', 'microsoft'),
                    client_secret=acc.get('client_secret', ''),
                    limit=30
                )
                total = 0
                for folder, emails in result.items():
                    saved = await db.save_emails(acc['id'], folder, emails)
                    total += saved
                # Auto-save new refresh_token
                if new_refresh_token and new_refresh_token != acc['refresh_token']:
                    await db.update_refresh_token(acc['id'], new_refresh_token)
                await db.update_account_status(acc['id'], 'active', mail_count=total)
                results["success"] += 1
                results["total_emails"] += total
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
    """Page to manually update refresh_token."""
    _require_auth(request)
    account = await db.get_account(account_id)
    if not account:
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request, "edit_token.html", {"account": account})


@app.post("/account/{account_id}/edit-token")
async def update_token(request: Request, account_id: int, new_refresh_token: str = Form(...)):
    """Update refresh_token for an account."""
    _require_auth(request)
    if not new_refresh_token.strip():
        account = await db.get_account(account_id)
        return templates.TemplateResponse(request, "edit_token.html", {
            "account": account, "error": "令牌不能为空"
        })
    await db.update_refresh_token(account_id, new_refresh_token.strip())
    return RedirectResponse("/", status_code=302)


@app.get("/api/stats")
async def api_stats():
    return await db.get_stats()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8899)
