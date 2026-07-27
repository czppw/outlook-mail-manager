"""
OAuth2 Mail Fetcher - 通用批量邮箱取件工具
支持 Outlook/Hotmail/Gmail 等 OAuth2 邮箱。

取件方式：
- IMAP（SASL XOAUTH2），Microsoft / Google 均支持
- Microsoft Graph API（仅 Microsoft，应对 IMAP 风控；要求 refresh_token 带 Mail.Read scope）

代理支持：
- 全局：环境变量 OMM_PROXY（如 socks5://user:pass@host:port 或 http://host:port）
- 单账号：accounts.proxy 列（优先于全局）
- token 刷新 / Graph 请求走 requests proxies；IMAP 走 PySocks 包装 socket
"""
import imaplib
import socket
import email
import asyncio
import logging
import os
from email.header import decode_header
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

IMAP_TIMEOUT = 30
HTTP_TIMEOUT = 20

# ─────────── 供应商配置 ───────────
PROVIDERS = {
    "microsoft": {
        "name": "Microsoft",
        "domains": ["outlook.com", "hotmail.com", "live.com", "msn.com", "office365.com", "outlook.cn"],
        "imap_host": "outlook.office365.com",
        "imap_port": 993,
        "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "scope": "https://outlook.office365.com/IMAP.AccessAsUser.All offline_access",
        "graph_scope": "https://graph.microsoft.com/Mail.Read offline_access",
        "needs_client_secret": False,
    },
    "google": {
        "name": "Google",
        "domains": ["gmail.com", "googlemail.com"],
        "imap_host": "imap.gmail.com",
        "imap_port": 993,
        "token_url": "https://oauth2.googleapis.com/token",
        "scope": "https://mail.google.com/",
        "needs_client_secret": True,
    },
}

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


def detect_provider(email_addr: str) -> str:
    """根据邮箱域名自动识别供应商。"""
    domain = email_addr.split("@")[-1].lower() if "@" in email_addr else ""
    for provider_key, provider in PROVIDERS.items():
        if domain in provider["domains"]:
            return provider_key
    # 默认用微软（很多企业邮箱也走 outlook.office365.com）
    return "microsoft"


def default_fetch_mode(provider_key: str) -> str:
    """新导入账号的默认取件方式。MS 近期 IMAP 风控，默认 Graph；
    可用环境变量 OMM_MS_FETCH_MODE=imap 改回。Google 仅支持 IMAP。"""
    if provider_key == "microsoft":
        mode = os.environ.get("OMM_MS_FETCH_MODE", "graph").strip().lower()
        return "graph" if mode == "graph" else "imap"
    return "imap"


def get_provider_config(provider_key: str) -> dict:
    return PROVIDERS.get(provider_key, PROVIDERS["microsoft"])


def _effective_proxy(proxy: str = "") -> str:
    """单账号代理优先，其次全局 OMM_PROXY。"""
    return (proxy or "").strip() or os.environ.get("OMM_PROXY", "").strip()


def _requests_proxies(proxy: str):
    return {"http": proxy, "https": proxy} if proxy else None


# ─────────── OAuth2 token ───────────

def get_access_token(client_id: str, refresh_token: str, provider_key: str = "microsoft",
                     client_secret: str = "", proxy: str = "",
                     scope_override: str = "") -> tuple[str, str]:
    """用 refresh_token 换取 access_token。返回 (access_token, new_refresh_token)。
    微软和 Google 都会在每次刷新时轮换 refresh_token。"""
    provider = get_provider_config(provider_key)

    data = {
        "client_id": client_id,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": scope_override or provider["scope"],
    }
    if client_secret:
        data["client_secret"] = client_secret

    try:
        # requests 会自动做 form-urlencoded 编码
        resp = requests.post(provider["token_url"], data=data, timeout=HTTP_TIMEOUT,
                             proxies=_requests_proxies(_effective_proxy(proxy)))
    except requests.RequestException as e:
        raise Exception(f"Token refresh network error: {e}")

    if resp.status_code != 200:
        raise Exception(f"Token refresh failed ({resp.status_code}): {resp.text[:200]}")

    result = resp.json()
    access_token = result.get("access_token")
    if not access_token:
        raise Exception("No access_token in response")
    return access_token, result.get("refresh_token", refresh_token)


# ─────────── 代理 IMAP ───────────

def _parse_proxy(proxy_url: str) -> dict:
    import socks  # PySocks，仅在使用代理时才需要
    u = urlparse(proxy_url)
    scheme = (u.scheme or "socks5").lower()
    type_map = {
        "socks5": socks.SOCKS5, "socks5h": socks.SOCKS5,
        "socks4": socks.SOCKS4, "http": socks.HTTP,
    }
    if scheme not in type_map:
        raise ValueError(f"Unsupported proxy scheme: {scheme} (支持 socks5/socks5h/socks4/http)")
    return {
        "type": type_map[scheme],
        "host": u.hostname,
        "port": u.port or 1080,
        "username": u.username,
        "password": u.password,
    }


class _ProxyIMAP4SSL(imaplib.IMAP4_SSL):
    """通过 SOCKS/HTTP(CONNECT) 代理建立 IMAP SSL 连接。"""

    def __init__(self, host: str, port: int, proxy_url: str, timeout: int = IMAP_TIMEOUT):
        self._proxy_url = proxy_url
        super().__init__(host, port, timeout=timeout)

    def _create_socket(self, timeout):
        import socks
        p = _parse_proxy(self._proxy_url)
        sock = socks.create_connection(
            (self.host, self.port),
            timeout=timeout or self.timeout or IMAP_TIMEOUT,
            proxy_type=p["type"], addr=p["host"], port=p["port"],
            username=p.get("username"), password=p.get("password"),
        )
        return self.ssl_context.wrap_socket(sock, server_hostname=self.host)


def _open_imap(host: str, port: int, proxy: str = "") -> imaplib.IMAP4_SSL:
    effective = _effective_proxy(proxy)
    if effective:
        return _ProxyIMAP4SSL(host, port, effective, timeout=IMAP_TIMEOUT)
    return imaplib.IMAP4_SSL(host, port, timeout=IMAP_TIMEOUT)


# ─────────── IMAP 取件 ───────────

def build_xoauth2_auth(user: str, access_token: str) -> bytes:
    import base64
    auth_str = f"user={user}\x01auth=Bearer {access_token}\x01\x01"
    return base64.b64encode(auth_str.encode()).decode().encode()


def decode_mime_header(raw: str) -> str:
    if not raw:
        return ""
    parts = decode_header(raw)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or 'utf-8', errors='replace'))
        else:
            decoded.append(str(part))
    return ''.join(decoded)


def _detect_junk_folder(imap: imaplib.IMAP4_SSL, fallback: str) -> str:
    r"""通过 IMAP SPECIAL-USE 属性（\Junk / \Spam）定位垃圾邮件文件夹，
    兼容非英文界面 Gmail 等本地化文件夹名。"""
    try:
        status, folder_list = imap.list()
        if status == 'OK':
            for item in folder_list:
                line = item.decode(errors='replace') if isinstance(item, bytes) else str(item)
                if '\\Junk' in line or '\\Spam' in line:
                    parts = line.split('"')
                    return parts[-2] if len(parts) >= 3 else line.split()[-1]
    except Exception as e:
        logger.warning(f"Detect junk folder failed: {e}")
    return fallback


def fetch_folder_emails(imap: imaplib.IMAP4_SSL, folder: str, limit: int = 50) -> list[dict]:
    """从指定文件夹获取邮件。"""
    emails = []
    try:
        status, _ = imap.select(folder, readonly=True)
        if status != 'OK':
            logger.warning(f"Cannot select folder {folder}")
            return emails

        status, data = imap.search(None, 'ALL')
        if status != 'OK' or not data[0]:
            return emails

        msg_ids = data[0].split()
        msg_ids = msg_ids[-limit:] if len(msg_ids) > limit else msg_ids

        for msg_id in msg_ids:
            try:
                status, msg_data = imap.fetch(msg_id, '(RFC822)')
                if status != 'OK':
                    continue
                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)

                body = ""
                body_html = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        if content_type == 'text/plain' and not body:
                            payload = part.get_payload(decode=True)
                            if payload:
                                charset = part.get_content_charset() or 'utf-8'
                                body = payload.decode(charset, errors='replace')
                        elif content_type == 'text/html' and not body_html:
                            payload = part.get_payload(decode=True)
                            if payload:
                                charset = part.get_content_charset() or 'utf-8'
                                body_html = payload.decode(charset, errors='replace')
                else:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        charset = msg.get_content_charset() or 'utf-8'
                        content = payload.decode(charset, errors='replace')
                        if msg.get_content_type() == 'text/html':
                            body_html = content
                        else:
                            body = content

                emails.append({
                    # 注意：这是 IMAP 邮件序号，同一文件夹内短期内稳定，
                    # 配合 (account_id, folder, uid) 唯一索引去重足够用
                    'uid': msg_id.decode(),
                    'from': decode_mime_header(msg.get('From', '')),
                    'subject': decode_mime_header(msg.get('Subject', '')),
                    'body': body[:50000],
                    'body_html': body_html[:100000],
                    'date': msg.get('Date', ''),
                })
            except Exception as e:
                logger.warning(f"Fetch single email error: {e}")

    except Exception as e:
        logger.warning(f"Fetch folder {folder} error: {e}")

    return emails


def _fetch_via_imap(email_addr: str, client_id: str, refresh_token: str,
                    provider_key: str, client_secret: str, proxy: str,
                    limit: int) -> tuple[dict, str]:
    provider = get_provider_config(provider_key)
    access_token, new_refresh_token = get_access_token(
        client_id, refresh_token, provider_key, client_secret, proxy=proxy
    )
    imap = _open_imap(provider["imap_host"], provider["imap_port"], proxy=proxy)
    auth_string = build_xoauth2_auth(email_addr, access_token)

    try:
        imap.authenticate("XOAUTH2", lambda x: auth_string)
        logger.info(f"Authenticated as {email_addr} via {provider['name']} IMAP")
    except imaplib.IMAP4.error as e:
        raise Exception(f"XOAUTH2 auth failed: {e}")

    # 垃圾邮件文件夹：优先 SPECIAL-USE 探测，兼容本地化名称
    junk_fallback = '[Gmail]/Spam' if provider_key == "google" else 'JUNK'
    junk_folder = _detect_junk_folder(imap, junk_fallback)

    results = {}
    # 统一对外标签为 INBOX / JUNK，与 Web 界面筛选 tab 对应
    for label, folder in [("INBOX", "INBOX"), ("JUNK", junk_folder)]:
        try:
            results[label] = fetch_folder_emails(imap, folder, limit=limit)
        except Exception as e:
            logger.warning(f"Error fetching {folder}: {e}")
            results[label] = []

    try:
        imap.logout()
    except Exception:
        pass

    return results, new_refresh_token


# ─────────── Microsoft Graph 取件 ───────────

def _fetch_via_graph(email_addr: str, client_id: str, refresh_token: str,
                     client_secret: str, proxy: str, limit: int) -> tuple[dict, str]:
    """通过 Microsoft Graph API 取件。要求 refresh_token 具有 Mail.Read scope
    （若 token 只有 IMAP scope，刷新时会报 invalid_scope / unauthorized_client）。"""
    provider = get_provider_config("microsoft")
    access_token, new_refresh_token = get_access_token(
        client_id, refresh_token, "microsoft", client_secret,
        proxy=proxy, scope_override=provider["graph_scope"],
    )

    headers = {"Authorization": f"Bearer {access_token}"}
    proxies = _requests_proxies(_effective_proxy(proxy))
    results = {}

    # well-known 文件夹名：inbox / junkemail（语言无关，无需本地化名）
    for label, well_known in [("INBOX", "inbox"), ("JUNK", "junkemail")]:
        try:
            resp = requests.get(
                f"{GRAPH_BASE}/me/mailFolders/{well_known}/messages",
                headers=headers,
                params={
                    "$top": limit,
                    "$orderby": "receivedDateTime desc",
                    "$select": "id,subject,from,receivedDateTime,body",
                },
                timeout=HTTP_TIMEOUT,
                proxies=proxies,
            )
            if resp.status_code != 200:
                raise Exception(f"Graph fetch {label} failed ({resp.status_code}): {resp.text[:200]}")

            emails = []
            for m in resp.json().get("value", []):
                frm = (m.get("from") or {}).get("emailAddress") or {}
                from_str = f"{frm.get('name', '')} <{frm.get('address', '')}>".strip()
                body_obj = m.get("body") or {}
                is_html = (body_obj.get("contentType") or "").lower() == "html"
                emails.append({
                    "uid": m.get("id", ""),
                    "from": from_str,
                    "subject": m.get("subject") or "",
                    "body": "" if is_html else (body_obj.get("content") or "")[:50000],
                    "body_html": (body_obj.get("content") or "")[:100000] if is_html else "",
                    "date": m.get("receivedDateTime", ""),
                })
            results[label] = emails
        except requests.RequestException as e:
            raise Exception(f"Graph network error ({label}): {e}")

    logger.info(f"Fetched {email_addr} via Microsoft Graph")
    return results, new_refresh_token


# ─────────── 统一入口 ───────────

def fetch_all_emails(email_addr: str, password: str, client_id: str, refresh_token: str,
                     provider_key: str = "microsoft", client_secret: str = "",
                     limit: int = 50, fetch_mode: str = "imap",
                     proxy: str = "") -> tuple[dict, str]:
    """获取收件箱 + 垃圾邮件。返回 ({'INBOX': [...], 'JUNK': [...]}, new_refresh_token)。
    password 参数保留仅为导入格式兼容，XOAUTH2/Graph 认证均不使用它。"""
    if provider_key == "microsoft" and fetch_mode == "graph":
        return _fetch_via_graph(email_addr, client_id, refresh_token,
                                client_secret, proxy, limit)
    return _fetch_via_imap(email_addr, client_id, refresh_token,
                           provider_key, client_secret, proxy, limit)


async def check_account(email_addr: str, password: str, client_id: str, refresh_token: str,
                        provider_key: str = "microsoft", client_secret: str = "",
                        limit: int = 50, fetch_mode: str = "imap",
                        proxy: str = "") -> tuple[dict, str]:
    """异步接口。返回 (emails_by_folder, new_refresh_token)。"""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: fetch_all_emails(email_addr, password, client_id, refresh_token,
                                 provider_key, client_secret, limit=limit,
                                 fetch_mode=fetch_mode, proxy=proxy)
    )


def list_folders(email_addr: str, password: str, client_id: str, refresh_token: str,
                 provider_key: str = "microsoft", client_secret: str = "",
                 proxy: str = "") -> list[str]:
    """列出所有可用的 IMAP 文件夹（调试用）。"""
    provider = get_provider_config(provider_key)
    access_token, _ = get_access_token(client_id, refresh_token, provider_key,
                                       client_secret, proxy=proxy)
    imap = _open_imap(provider["imap_host"], provider["imap_port"], proxy=proxy)
    auth_string = build_xoauth2_auth(email_addr, access_token)
    try:
        imap.authenticate("XOAUTH2", lambda x: auth_string)
        status, folder_list = imap.list()
        folders = []
        if status == 'OK':
            for f in folder_list:
                parts = f.decode().split('"')
                if len(parts) >= 3:
                    folders.append(parts[-2])
                else:
                    folders.append(f.decode().split()[-1])
        imap.logout()
        return folders
    except Exception as e:
        raise Exception(f"List folders failed: {e}")
