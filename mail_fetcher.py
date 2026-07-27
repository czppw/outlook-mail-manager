"""OAuth2 mail fetching over verified IMAP TLS or Microsoft Graph."""

import asyncio
import email
import imaplib
import logging
import math
import os
import re
import ssl
import time
from datetime import datetime, timezone
from email.header import decode_header
from email.utils import parsedate_to_datetime
from urllib.parse import unquote, urlparse

import requests

logger = logging.getLogger(__name__)

IMAP_TIMEOUT = 30
HTTP_TIMEOUT = 20
MAX_EMAIL_BYTES = 10 * 1024 * 1024
GRAPH_MAX_ATTEMPTS = 4
GRAPH_BACKOFF_BASE = 0.5
GRAPH_BACKOFF_CAP = 8.0

PROVIDERS = {
    "microsoft": {
        "name": "Microsoft",
        "domains": [
            "outlook.com",
            "hotmail.com",
            "live.com",
            "msn.com",
            "office365.com",
            "outlook.cn",
        ],
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


class FolderFetchError(RuntimeError):
    """A folder had malformed messages and therefore was only partially read."""

    def __init__(self, folder: str, failed_count: int, partial_emails: list[dict]):
        self.folder = folder
        self.failed_count = failed_count
        self.partial_emails = partial_emails
        super().__init__(
            f"Folder {folder!r} contained {failed_count} message(s) that could not be parsed"
        )


class MailboxFetchError(RuntimeError):
    """A mailbox fetch returned usable messages together with folder errors."""

    def __init__(self, partial_results: dict[str, list[dict]], issues: list[str]):
        self.partial_results = partial_results
        self.issues = issues
        super().__init__("; ".join(issues))


def detect_provider(email_addr: str) -> str:
    """Detect the provider from the mailbox domain."""
    domain = email_addr.split("@")[-1].lower() if "@" in email_addr else ""
    for provider_key, provider in PROVIDERS.items():
        if domain in provider["domains"]:
            return provider_key
    return "microsoft"


def default_fetch_mode(provider_key: str) -> str:
    """Use Graph for Microsoft by default and IMAP for Google."""
    if provider_key == "microsoft":
        mode = os.environ.get("OMM_MS_FETCH_MODE", "graph").strip().lower()
        return "graph" if mode == "graph" else "imap"
    return "imap"


def get_provider_config(provider_key: str) -> dict:
    return PROVIDERS.get(provider_key, PROVIDERS["microsoft"])


def _effective_proxy(proxy: str | None = None) -> str:
    """Use the environment only when no explicit proxy decision was supplied."""
    if proxy is None:
        return os.environ.get("OMM_PROXY", "").strip()
    return proxy.strip()


def _requests_proxies(proxy: str):
    if proxy:
        return {"http": proxy, "https": proxy}
    return {"http": None, "https": None, "all": None}


def get_access_token(
    client_id: str,
    refresh_token: str,
    provider_key: str = "microsoft",
    client_secret: str = "",
    proxy: str | None = None,
    scope_override: str = "",
) -> tuple[str, str]:
    """Exchange a refresh token without retrying an ambiguous token rotation."""
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
        resp = requests.post(
            provider["token_url"],
            data=data,
            timeout=HTTP_TIMEOUT,
            proxies=_requests_proxies(_effective_proxy(proxy)),
        )
    except requests.RequestException as exc:
        raise RuntimeError("Token refresh network error") from exc

    if resp.status_code != 200:
        # Preserve useful OAuth classifications without copying response bodies,
        # which may contain credentials returned by a non-conforming endpoint.
        known_errors = {
            "invalid_request",
            "invalid_client",
            "invalid_grant",
            "invalid_scope",
            "unauthorized_client",
            "unsupported_grant_type",
        }
        try:
            error_code = resp.json().get("error", "")
        except (ValueError, AttributeError):
            error_code = ""
        suffix = f": {error_code}" if error_code in known_errors else ""
        raise RuntimeError(f"Token refresh failed ({resp.status_code}){suffix}")

    try:
        result = resp.json()
    except ValueError as exc:
        raise RuntimeError("Token refresh returned invalid JSON") from exc
    access_token = result.get("access_token")
    if not access_token:
        raise RuntimeError("No access_token in token response")
    rotated = result.get("refresh_token")
    if not isinstance(rotated, str) or not rotated.strip():
        rotated = refresh_token
    return access_token, rotated


async def refresh_access_token(
    client_id: str,
    refresh_token: str,
    provider_key: str = "microsoft",
    client_secret: str = "",
    fetch_mode: str = "imap",
    proxy: str | None = None,
) -> tuple[str, str]:
    """Refresh asynchronously so the caller can persist rotation before fetching."""
    scope_override = ""
    if provider_key == "microsoft" and fetch_mode == "graph":
        scope_override = get_provider_config("microsoft")["graph_scope"]
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: get_access_token(
            client_id,
            refresh_token,
            provider_key,
            client_secret,
            proxy=proxy,
            scope_override=scope_override,
        ),
    )


def _parse_proxy(proxy_url: str) -> dict:
    import socks

    parsed = urlparse(proxy_url)
    scheme = (parsed.scheme or "socks5").lower()
    type_map = {
        "socks5": socks.SOCKS5,
        "socks5h": socks.SOCKS5,
        "socks4": socks.SOCKS4,
        "http": socks.HTTP,
    }
    if scheme not in type_map:
        raise ValueError(
            f"Unsupported proxy scheme: {scheme} (supported: socks5/socks5h/socks4/http)"
        )
    if not parsed.hostname:
        raise ValueError("Proxy URL must include a hostname")
    return {
        "type": type_map[scheme],
        "host": parsed.hostname,
        "port": parsed.port or (8080 if scheme == "http" else 1080),
        "rdns": scheme == "socks5h",
        "username": unquote(parsed.username) if parsed.username else None,
        "password": unquote(parsed.password) if parsed.password else None,
    }


def _verified_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class _ProxyIMAP4SSL(imaplib.IMAP4_SSL):
    """Create a verified IMAP TLS connection over a SOCKS/HTTP tunnel."""

    def __init__(
        self,
        host: str,
        port: int,
        proxy_url: str,
        ssl_context: ssl.SSLContext,
        timeout: int = IMAP_TIMEOUT,
    ):
        self._proxy_url = proxy_url
        super().__init__(
            host,
            port,
            ssl_context=ssl_context,
            timeout=timeout,
        )

    def _create_socket(self, timeout):
        import socks

        proxy = _parse_proxy(self._proxy_url)
        raw_socket = socks.create_connection(
            (self.host, self.port),
            timeout=timeout or self.timeout or IMAP_TIMEOUT,
            proxy_type=proxy["type"],
            proxy_addr=proxy["host"],
            proxy_port=proxy["port"],
            proxy_rdns=proxy["rdns"],
            proxy_username=proxy["username"],
            proxy_password=proxy["password"],
        )
        try:
            return self.ssl_context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


def _open_imap(host: str, port: int, proxy: str | None = None) -> imaplib.IMAP4_SSL:
    context = _verified_ssl_context()
    effective_proxy = _effective_proxy(proxy)
    if effective_proxy:
        return _ProxyIMAP4SSL(
            host,
            port,
            effective_proxy,
            ssl_context=context,
            timeout=IMAP_TIMEOUT,
        )
    return imaplib.IMAP4_SSL(
        host,
        port,
        ssl_context=context,
        timeout=IMAP_TIMEOUT,
    )


def _close_imap(imap: imaplib.IMAP4_SSL) -> None:
    """Close an IMAP connection without masking the primary operation error."""
    try:
        imap.logout()
        return
    except Exception as exc:  # noqa: BLE001 - cleanup must not mask fetch errors
        logger.debug("IMAP logout failed during cleanup: %s", type(exc).__name__)
    try:
        shutdown = getattr(imap, "shutdown", None)
        if shutdown:
            shutdown()
    except Exception:  # noqa: BLE001 - cleanup must not mask fetch errors
        logger.warning("IMAP connection cleanup failed")


def build_xoauth2_auth(user: str, access_token: str) -> bytes:
    """Return raw SASL bytes; imaplib.authenticate performs Base64 itself."""
    return f"user={user}\x01auth=Bearer {access_token}\x01\x01".encode()


def decode_mime_header(raw: str) -> str:
    if not raw:
        return ""
    decoded = []
    for part, charset in decode_header(raw):
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(str(part))
    return "".join(decoded)


def _detect_junk_folder(imap: imaplib.IMAP4_SSL, fallback: str) -> str:
    r"""Locate a junk folder by the IMAP SPECIAL-USE attribute."""
    try:
        status, folder_list = imap.list()
        if status == "OK":
            for item in folder_list or []:
                line = (
                    item.decode(errors="replace")
                    if isinstance(item, bytes)
                    else str(item)
                )
                if "\\Junk" in line or "\\Spam" in line:
                    parts = line.split('"')
                    return parts[-2] if len(parts) >= 3 else line.split()[-1]
    except Exception:  # noqa: BLE001 - malformed LIST entries use provider fallback
        logger.warning("Junk-folder discovery failed; using provider default")
    return fallback


def _first_numeric_value(items) -> str:
    for item in items or []:
        if isinstance(item, tuple):
            value = _first_numeric_value(item)
            if value:
                return value
        elif isinstance(item, bytes):
            match = re.search(rb"\d+", item)
            if match:
                return match.group(0).decode("ascii")
        elif item is not None:
            match = re.search(r"\d+", str(item))
            if match:
                return match.group(0)
    return ""


def _read_uidvalidity(imap: imaplib.IMAP4_SSL) -> str:
    response_name, response_data = imap.response("UIDVALIDITY")
    uidvalidity = _first_numeric_value(response_data)
    if response_name != "UIDVALIDITY" or not uidvalidity:
        raise imaplib.IMAP4.error("Selected folder did not provide UIDVALIDITY")
    return uidvalidity


def _extract_rfc822_size(fetch_data) -> int:
    for item in fetch_data or []:
        header = item[0] if isinstance(item, tuple) and item else item
        if isinstance(header, str):
            header = header.encode("ascii", errors="ignore")
        if isinstance(header, bytes):
            match = re.search(rb"RFC822\.SIZE\s+(\d+)", header, re.IGNORECASE)
            if match:
                return int(match.group(1))
    raise imaplib.IMAP4.error("FETCH response did not include RFC822.SIZE")


def _extract_raw_message(fetch_data) -> bytes:
    for item in fetch_data or []:
        if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], bytes):
            return item[1]
    raise imaplib.IMAP4.error("FETCH response did not include a message body")


def _iter_message_body_parts(message):
    disposition = (message.get_content_disposition() or "").lower()
    if disposition == "attachment" or message.get_filename():
        return
    if message.is_multipart():
        payload = message.get_payload()
        if isinstance(payload, list):
            for child in payload:
                yield from _iter_message_body_parts(child)
        return
    yield message


def _decode_message(raw_email: bytes) -> dict:
    msg = email.message_from_bytes(raw_email)
    body = ""
    body_html = ""

    for part in _iter_message_body_parts(msg):
        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"}:
            continue
        if content_type == "text/plain" and body:
            continue
        if content_type == "text/html" and body_html:
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        charset = part.get_content_charset() or "utf-8"
        content = payload.decode(charset, errors="replace")
        if content_type == "text/html":
            body_html = content
        else:
            body = content

    return {
        "from": decode_mime_header(msg.get("From", "")),
        "subject": decode_mime_header(msg.get("Subject", "")),
        "body": body[:50000],
        "body_html": body_html[:100000],
        "date": msg.get("Date", ""),
    }


def _record_oversized_message(
    stats: dict[str, int] | None,
    folder: str,
    stable_uid: str,
    message_size: int,
) -> None:
    if stats is not None:
        stats["oversized"] = stats.get("oversized", 0) + 1
    logger.warning(
        "Skipping oversized email folder=%r uid=%s size=%d limit=%d",
        folder,
        stable_uid,
        message_size,
        MAX_EMAIL_BYTES,
    )


def fetch_folder_emails(
    imap: imaplib.IMAP4_SSL,
    folder: str,
    limit: int = 50,
    stats: dict[str, int] | None = None,
) -> list[dict]:
    """Fetch a folder by stable IMAP UID and report partial parsing failures."""
    status, _ = imap.select(folder, readonly=True)
    if status != "OK":
        raise imaplib.IMAP4.error(f"Cannot select folder {folder!r}")
    uidvalidity = _read_uidvalidity(imap)

    status, data = imap.uid("SEARCH", None, "ALL")
    if status != "OK":
        raise imaplib.IMAP4.error(f"UID SEARCH failed for folder {folder!r}")
    if not data or not data[0] or limit <= 0:
        return []

    message_uids = data[0].split()
    message_uids = message_uids[-limit:]
    emails = []
    parse_failures = 0

    for message_uid in message_uids:
        uid_text = (
            message_uid.decode("ascii")
            if isinstance(message_uid, bytes)
            else str(message_uid)
        )
        stable_uid = f"{uidvalidity}:{uid_text}"

        status, size_data = imap.uid("FETCH", message_uid, "(RFC822.SIZE)")
        if status != "OK":
            raise imaplib.IMAP4.error(
                f"UID FETCH RFC822.SIZE failed for folder {folder!r}"
            )
        message_size = _extract_rfc822_size(size_data)
        if message_size > MAX_EMAIL_BYTES:
            _record_oversized_message(stats, folder, stable_uid, message_size)
            continue

        status, message_data = imap.uid("FETCH", message_uid, "(BODY.PEEK[])")
        if status != "OK":
            raise imaplib.IMAP4.error(f"UID FETCH BODY failed for folder {folder!r}")
        raw_email = _extract_raw_message(message_data)
        if len(raw_email) > MAX_EMAIL_BYTES:
            _record_oversized_message(stats, folder, stable_uid, len(raw_email))
            continue
        try:
            parsed = _decode_message(raw_email)
        except Exception:  # noqa: BLE001 - isolate malformed MIME messages
            parse_failures += 1
            logger.warning(
                "Skipping malformed email folder=%r uid=%s",
                folder,
                stable_uid,
            )
            continue
        emails.append({"uid": stable_uid, **parsed})

    if parse_failures:
        raise FolderFetchError(folder, parse_failures, emails)
    return emails


def _fetch_via_imap_with_access_token(
    email_addr: str,
    access_token: str,
    provider_key: str,
    proxy: str | None,
    limit: int,
) -> dict:
    provider = get_provider_config(provider_key)
    imap = _open_imap(provider["imap_host"], provider["imap_port"], proxy=proxy)
    try:
        auth_string = build_xoauth2_auth(email_addr, access_token)
        try:
            imap.authenticate("XOAUTH2", lambda _challenge: auth_string)
        except imaplib.IMAP4.error:
            # Some servers include the SASL exchange in their error text.
            raise RuntimeError("XOAUTH2 authentication failed") from None

        logger.info("Authenticated mailbox via %s IMAP", provider["name"])
        junk_fallback = "[Gmail]/Spam" if provider_key == "google" else "JUNK"
        junk_folder = _detect_junk_folder(imap, junk_fallback)
        results = {}
        issues = []
        for label, folder in (("INBOX", "INBOX"), ("JUNK", junk_folder)):
            stats = {}
            try:
                results[label] = fetch_folder_emails(
                    imap, folder, limit=limit, stats=stats
                )
            except FolderFetchError as exc:
                results[label] = exc.partial_emails
                issues.append(
                    f"{label}: {exc.failed_count} malformed message(s) skipped"
                )
            if stats.get("oversized"):
                issues.append(
                    f"{label}: {stats['oversized']} oversized message(s) skipped"
                )
        if issues:
            raise MailboxFetchError(results, issues)
        return results
    finally:
        _close_imap(imap)


def _retry_after_seconds(response, attempt: int) -> float:
    fallback = min(GRAPH_BACKOFF_CAP, GRAPH_BACKOFF_BASE * (2**attempt))
    value = (getattr(response, "headers", None) or {}).get("Retry-After")
    if not value:
        return fallback
    try:
        seconds = float(value)
        if not math.isfinite(seconds):
            raise ValueError("Retry-After must be finite")
        return max(0.0, seconds)
    except (TypeError, ValueError):
        pass
    try:
        retry_at = parsedate_to_datetime(value)
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=timezone.utc)
        seconds = (retry_at - datetime.now(timezone.utc)).total_seconds()
        return max(0.0, seconds)
    except (TypeError, ValueError, OverflowError):
        return fallback


_PERMANENT_GRAPH_REQUEST_ERRORS = (
    requests.exceptions.SSLError,
    requests.exceptions.ProxyError,
    requests.exceptions.InvalidURL,
    requests.exceptions.InvalidSchema,
    requests.exceptions.MissingSchema,
    requests.exceptions.URLRequired,
    requests.exceptions.InvalidHeader,
    requests.exceptions.TooManyRedirects,
)


def _graph_get(url: str, headers: dict, params: dict, proxies):
    retryable_statuses = {408, 429}
    for attempt in range(GRAPH_MAX_ATTEMPTS):
        try:
            response = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=HTTP_TIMEOUT,
                proxies=proxies,
            )
            if response.status_code == 200:
                try:
                    return response.json()
                except ValueError as exc:
                    raise RuntimeError("Graph response was invalid JSON") from exc

            should_retry = (
                response.status_code in retryable_statuses
                or 500 <= response.status_code <= 599
            )
            if should_retry:
                retry_after = _retry_after_seconds(response, attempt)
                if retry_after > GRAPH_BACKOFF_CAP:
                    seconds = max(1, math.ceil(retry_after))
                    raise RuntimeError(
                        f"Graph request failed ({response.status_code}); "
                        f"retry after {seconds} seconds"
                    )
                if attempt + 1 < GRAPH_MAX_ATTEMPTS:
                    time.sleep(retry_after)
                    continue
            raise RuntimeError(f"Graph request failed ({response.status_code})")
        except _PERMANENT_GRAPH_REQUEST_ERRORS as exc:
            raise RuntimeError("Graph request configuration error") from exc
        except requests.RequestException as exc:
            if attempt + 1 >= GRAPH_MAX_ATTEMPTS:
                raise RuntimeError("Graph network error") from exc
            time.sleep(min(GRAPH_BACKOFF_CAP, GRAPH_BACKOFF_BASE * (2**attempt)))
    raise RuntimeError("Graph request failed after retries")


def _fetch_via_graph_with_access_token(
    email_addr: str,
    access_token: str,
    proxy: str | None,
    limit: int,
) -> dict:
    headers = {"Authorization": f"Bearer {access_token}"}
    proxies = _requests_proxies(_effective_proxy(proxy))
    results = {}

    for label, well_known in [("INBOX", "inbox"), ("JUNK", "junkemail")]:
        payload = _graph_get(
            f"{GRAPH_BASE}/me/mailFolders/{well_known}/messages",
            headers=headers,
            params={
                "$top": limit,
                "$orderby": "receivedDateTime desc",
                "$select": "id,subject,from,receivedDateTime,body",
            },
            proxies=proxies,
        )
        if not isinstance(payload, dict) or not isinstance(
            payload.get("value", []), list
        ):
            raise RuntimeError(  # noqa: TRY004 - normalize remote response failures
                f"Graph response for {label} was invalid"
            )
        messages = payload.get("value", [])

        folder_emails = []
        for message in messages:
            sender = (message.get("from") or {}).get("emailAddress") or {}
            from_value = (
                f"{sender.get('name', '')} <{sender.get('address', '')}>".strip()
            )
            body_obj = message.get("body") or {}
            content = body_obj.get("content") or ""
            is_html = (body_obj.get("contentType") or "").lower() == "html"
            folder_emails.append(
                {
                    "uid": message.get("id", ""),
                    "from": from_value,
                    "subject": message.get("subject") or "",
                    "body": "" if is_html else content[:50000],
                    "body_html": content[:100000] if is_html else "",
                    "date": message.get("receivedDateTime", ""),
                }
            )
        results[label] = folder_emails

    logger.info("Fetched mailbox via Microsoft Graph")
    return results


def fetch_all_emails_with_access_token(
    email_addr: str,
    access_token: str,
    provider_key: str = "microsoft",
    limit: int = 50,
    fetch_mode: str = "imap",
    proxy: str | None = None,
) -> dict:
    """Fetch with an already refreshed token, without touching refresh-token state."""
    if provider_key == "microsoft" and fetch_mode == "graph":
        return _fetch_via_graph_with_access_token(
            email_addr,
            access_token,
            proxy,
            limit,
        )
    return _fetch_via_imap_with_access_token(
        email_addr,
        access_token,
        provider_key,
        proxy,
        limit,
    )


async def check_account_with_access_token(
    email_addr: str,
    access_token: str,
    provider_key: str = "microsoft",
    limit: int = 50,
    fetch_mode: str = "imap",
    proxy: str | None = None,
) -> dict:
    """Async staged-fetch API used after the caller persists token rotation."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: fetch_all_emails_with_access_token(
            email_addr,
            access_token,
            provider_key,
            limit=limit,
            fetch_mode=fetch_mode,
            proxy=proxy,
        ),
    )


def list_folders_with_access_token(
    email_addr: str,
    access_token: str,
    provider_key: str = "microsoft",
    proxy: str | None = None,
) -> list[str]:
    """List IMAP folders with an already refreshed access token."""
    provider = get_provider_config(provider_key)
    imap = _open_imap(provider["imap_host"], provider["imap_port"], proxy=proxy)
    try:
        auth_string = build_xoauth2_auth(email_addr, access_token)
        try:
            imap.authenticate("XOAUTH2", lambda _challenge: auth_string)
        except imaplib.IMAP4.error:
            raise RuntimeError("XOAUTH2 authentication failed") from None
        status, folder_list = imap.list()
        if status != "OK":
            raise imaplib.IMAP4.error("IMAP LIST failed")
        folders = []
        for folder in folder_list or []:
            value = folder.decode(errors="replace")
            parts = value.split('"')
            folders.append(parts[-2] if len(parts) >= 3 else value.split()[-1])
        return folders
    finally:
        _close_imap(imap)


def _fetch_via_imap(
    email_addr: str,
    client_id: str,
    refresh_token: str,
    provider_key: str,
    client_secret: str,
    proxy: str | None,
    limit: int,
) -> tuple[dict, str]:
    access_token, new_refresh_token = get_access_token(
        client_id,
        refresh_token,
        provider_key,
        client_secret,
        proxy=proxy,
    )
    return (
        _fetch_via_imap_with_access_token(
            email_addr, access_token, provider_key, proxy, limit
        ),
        new_refresh_token,
    )


def _fetch_via_graph(
    email_addr: str,
    client_id: str,
    refresh_token: str,
    client_secret: str,
    proxy: str | None,
    limit: int,
) -> tuple[dict, str]:
    provider = get_provider_config("microsoft")
    access_token, new_refresh_token = get_access_token(
        client_id,
        refresh_token,
        "microsoft",
        client_secret,
        proxy=proxy,
        scope_override=provider["graph_scope"],
    )
    return (
        _fetch_via_graph_with_access_token(email_addr, access_token, proxy, limit),
        new_refresh_token,
    )


def fetch_all_emails(
    email_addr: str,
    password: str,
    client_id: str,
    refresh_token: str,
    provider_key: str = "microsoft",
    client_secret: str = "",
    limit: int = 50,
    fetch_mode: str = "imap",
    proxy: str | None = None,
) -> tuple[dict, str]:
    """Compatibility entry point used by existing scripts and integrations."""

    del password
    if provider_key == "microsoft" and fetch_mode == "graph":
        return _fetch_via_graph(
            email_addr,
            client_id,
            refresh_token,
            client_secret,
            proxy,
            limit,
        )
    return _fetch_via_imap(
        email_addr,
        client_id,
        refresh_token,
        provider_key,
        client_secret,
        proxy,
        limit,
    )


async def check_account(
    email_addr: str,
    password: str,
    client_id: str,
    refresh_token: str,
    provider_key: str = "microsoft",
    client_secret: str = "",
    limit: int = 50,
    fetch_mode: str = "imap",
    proxy: str | None = None,
) -> tuple[dict, str]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: fetch_all_emails(
            email_addr,
            password,
            client_id,
            refresh_token,
            provider_key,
            client_secret,
            limit,
            fetch_mode,
            proxy,
        ),
    )


def list_folders(
    email_addr: str,
    password: str,
    client_id: str,
    refresh_token: str,
    provider_key: str = "microsoft",
    client_secret: str = "",
    proxy: str | None = None,
) -> list[str]:
    del password
    access_token, _ = get_access_token(
        client_id,
        refresh_token,
        provider_key,
        client_secret,
        proxy=proxy,
    )
    return list_folders_with_access_token(
        email_addr, access_token, provider_key, proxy
    )
