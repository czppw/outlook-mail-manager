"""
OAuth2 Mail Fetcher - 通用批量邮箱取件工具
支持 Outlook/Hotmail/Gmail 等 OAuth2 IMAP 邮箱。

自动识别邮箱供应商，选择正确的 IMAP 服务器和 OAuth2 端点。
认证方式：SASL XOAUTH2（所有主流邮箱都支持）。
"""
import imaplib
import json
import base64
import email
import asyncio
import logging
from email.header import decode_header
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)

# ─────────── 供应商配置 ───────────
PROVIDERS = {
    "microsoft": {
        "name": "Microsoft",
        "domains": ["outlook.com", "hotmail.com", "live.com", "msn.com", "office365.com", "outlook.cn"],
        "imap_host": "outlook.office365.com",
        "imap_port": 993,
        "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "scope": "https://outlook.office365.com/IMAP.AccessAsUser.All offline_access",
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


def detect_provider(email_addr: str) -> str:
    """根据邮箱域名自动识别供应商。"""
    domain = email_addr.split("@")[-1].lower() if "@" in email_addr else ""
    for provider_key, provider in PROVIDERS.items():
        if domain in provider["domains"]:
            return provider_key
    # 默认用微软（很多企业邮箱也走 outlook.office365.com）
    return "microsoft"


def get_provider_config(provider_key: str) -> dict:
    """获取供应商配置。"""
    return PROVIDERS.get(provider_key, PROVIDERS["microsoft"])


def get_access_token(client_id: str, refresh_token: str, provider_key: str = "microsoft",
                     client_secret: str = "") -> tuple[str, str]:
    """用 refresh_token 换取 access_token。
    返回 (access_token, new_refresh_token)。
    微软和 Gmail 都会在每次刷新时轮换 refresh_token。
    """
    provider = get_provider_config(provider_key)

    data = {
        "client_id": client_id,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": provider["scope"],
    }
    # Gmail 需要 client_secret；微软公共客户端不需要
    if client_secret and provider.get("needs_client_secret"):
        data["client_secret"] = client_secret
    # 即使不是必须的，如果提供了也带上（有些自定义应用需要）
    elif client_secret:
        data["client_secret"] = client_secret

    body = "&".join(f"{k}={v}" for k, v in data.items())
    req = Request(provider["token_url"], data=body.encode(), method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read())
            access_token = result.get("access_token")
            new_refresh_token = result.get("refresh_token", refresh_token)
            if not access_token:
                raise Exception("No access_token in response")
            return access_token, new_refresh_token
    except HTTPError as e:
        body_text = e.read().decode() if e.fp else ""
        raise Exception(f"Token refresh failed ({e.code}): {body_text[:200]}")
    except URLError as e:
        raise Exception(f"Token refresh network error: {e.reason}")


def build_xoauth2_auth(user: str, access_token: str) -> bytes:
    """构建 SASL XOAUTH2 认证字符串。"""
    auth_str = f"user={user}\x01auth=Bearer {access_token}\x01\x01"
    return base64.b64encode(auth_str.encode()).decode().encode()


def decode_mime_header(raw: str) -> str:
    """解码 MIME 编码的邮件头。"""
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


def fetch_all_emails(email_addr: str, password: str, client_id: str, refresh_token: str,
                     provider_key: str = "microsoft", client_secret: str = "",
                     limit: int = 50) -> tuple[dict, str]:
    """获取多个文件夹的邮件。
    返回 (results_dict, new_refresh_token)。
    """
    provider = get_provider_config(provider_key)
    access_token, new_refresh_token = get_access_token(
        client_id, refresh_token, provider_key, client_secret
    )
    imap = imaplib.IMAP4_SSL(provider["imap_host"], provider["imap_port"])
    auth_string = build_xoauth2_auth(email_addr, access_token)

    try:
        imap.authenticate("XOAUTH2", lambda x: auth_string)
        logger.info(f"Authenticated as {email_addr} via {provider['name']}")
    except imaplib.IMAP4.error as e:
        raise Exception(f"XOAUTH2 auth failed: {e}")

    results = {}
    # 微软系用 JUNK，Gmail 用 [Gmail]/Spam
    if provider_key == "google":
        folders = ['INBOX', '[Gmail]/Spam']
    else:
        folders = ['INBOX', 'JUNK']

    for folder in folders:
        try:
            emails = fetch_folder_emails(imap, folder, limit=limit)
            results[folder] = emails
        except Exception as e:
            logger.warning(f"Error fetching {folder}: {e}")
            results[folder] = []

    try:
        imap.logout()
    except:
        pass

    return results, new_refresh_token


async def check_account(email_addr: str, password: str, client_id: str, refresh_token: str,
                        provider_key: str = "microsoft", client_secret: str = "",
                        limit: int = 50) -> tuple[dict, str]:
    """异步接口。返回 (emails_by_folder, new_refresh_token)。"""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        lambda: fetch_all_emails(email_addr, password, client_id, refresh_token,
                                 provider_key, client_secret, limit=limit)
    )


def list_folders(email_addr: str, password: str, client_id: str, refresh_token: str,
                 provider_key: str = "microsoft", client_secret: str = "") -> list[str]:
    """列出所有可用的 IMAP 文件夹。"""
    provider = get_provider_config(provider_key)
    access_token, _ = get_access_token(client_id, refresh_token, provider_key, client_secret)
    imap = imaplib.IMAP4_SSL(provider["imap_host"], provider["imap_port"])
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
