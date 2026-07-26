"""
IMAP fetcher with OAuth2 (XOAUTH2) for Outlook/Microsoft accounts.

Outlook IMAP server: outlook.office365.com:993
OAuth2 flow: uses refresh_token to get access_token, then authenticates via SASL XOAUTH2.
"""
import imaplib
import json
import base64
import email
import asyncio
import logging
from email.header import decode_header
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)

IMAP_HOST = "outlook.office365.com"
IMAP_PORT = 993
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"

# Default scope for IMAP access
IMAP_SCOPE = "https://outlook.office365.com/IMAP.AccessAsUser.All offline_access"


def get_access_token(client_id: str, refresh_token: str) -> tuple[str, str]:
    """Exchange refresh_token for access_token via OAuth2.
    Returns (access_token, new_refresh_token).
    Microsoft rotates refresh_tokens on each use.
    """
    data = f"client_id={client_id}&grant_type=refresh_token&refresh_token={refresh_token}&scope={IMAP_SCOPE}"
    req = Request(TOKEN_URL, data=data.encode(), method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read())
            access_token = result.get("access_token")
            # Microsoft may return a new refresh_token (rotation)
            new_refresh_token = result.get("refresh_token", refresh_token)
            if not access_token:
                raise Exception("No access_token in response")
            return access_token, new_refresh_token
    except HTTPError as e:
        body = e.read().decode() if e.fp else ""
        raise Exception(f"Token refresh failed ({e.code}): {body[:200]}")
    except URLError as e:
        raise Exception(f"Token refresh network error: {e.reason}")


def build_xoauth2_auth(user: str, access_token: str) -> bytes:
    """Build SASL XOAUTH2 authentication string."""
    auth_str = f"user={user}\x01auth=Bearer {access_token}\x01\x01"
    return base64.b64encode(auth_str.encode()).decode().encode()


def decode_mime_header(raw: str) -> str:
    """Decode MIME encoded header."""
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
    """Fetch emails from a specific folder."""
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
        # Get latest N emails
        msg_ids = msg_ids[-limit:] if len(msg_ids) > limit else msg_ids

        for msg_id in msg_ids:
            try:
                status, msg_data = imap.fetch(msg_id, '(RFC822)')
                if status != 'OK':
                    continue
                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)

                # Get plain text body
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
                    'body': body[:50000],  # Limit body size
                    'body_html': body_html[:100000],
                    'date': msg.get('Date', ''),
                })
            except Exception as e:
                logger.warning(f"Fetch single email error: {e}")

    except Exception as e:
        logger.warning(f"Fetch folder {folder} error: {e}")

    return emails


def fetch_all_emails(email_addr: str, password: str, client_id: str, refresh_token: str,
                     limit: int = 50) -> tuple[dict, str]:
    """Fetch emails from multiple folders.
    Returns (results_dict, new_refresh_token).
    """
    access_token, new_refresh_token = get_access_token(client_id, refresh_token)
    imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
    auth_string = build_xoauth2_auth(email_addr, access_token)

    try:
        imap.authenticate("XOAUTH2", lambda x: auth_string)
        logger.info(f"Authenticated as {email_addr}")
    except imaplib.IMAP4.error as e:
        raise Exception(f"XOAUTH2 auth failed: {e}")

    results = {}
    folders = ['INBOX', 'JUNK']  # 收件箱 + 垃圾邮件

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
                        limit: int = 50) -> tuple[dict, str]:
    """Async wrapper. Returns (emails_by_folder, new_refresh_token)."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        lambda: fetch_all_emails(email_addr, password, client_id, refresh_token, limit=limit)
    )


def list_folders(email_addr: str, password: str, client_id: str, refresh_token: str) -> list[str]:
    """List all available IMAP folders."""
    access_token, _ = get_access_token(client_id, refresh_token)
    imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
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
