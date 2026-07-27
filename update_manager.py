"""Signed, crash-recoverable GitHub release updater."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import venv
import zipfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from functools import total_ordering
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

REPOSITORY = "czppw/outlook-mail-manager"
PROJECT_ROOT = Path(__file__).resolve().parent
VERSION_FILENAME = "VERSION"
MANIFEST_FILENAME = "UPDATE_MANIFEST.json"
RUNTIME_MARKER_FILENAME = ".omm-runtime.json"
STATE_DIRECTORY_NAME = ".omm-update"
VENV_DIRECTORY_NAME = ".omm-venvs"
LATEST_RELEASE_API = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
USER_AGENT = "outlook-mail-manager-updater/2.0"

UPDATE_SIGNING_PUBLIC_KEY_B64 = "OQ6aadAMEgHtDAA5hXyzhW/IsylFP1xZY94uM204EpM="

CONNECT_TIMEOUT_SECONDS = 5
READ_TIMEOUT_SECONDS = 30
CACHE_TTL_SECONDS = 15 * 60
MAX_REDIRECTS = 5
MAX_API_RESPONSE_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_EXTRACTED_BYTES = 200 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 5000
PIP_TIMEOUT_SECONDS = 10 * 60
MANIFEST_SCHEMA_VERSION = 1
TRANSACTION_SCHEMA_VERSION = 1

ALLOWED_DOWNLOAD_HOSTS = frozenset(
    {
        "github.com",
        "api.github.com",
        "codeload.github.com",
        "objects.githubusercontent.com",
        "github-releases.githubusercontent.com",
    }
)
ROOT_FIXED_FILES = frozenset(
    {VERSION_FILENAME, "requirements.txt", "requirements.lock"}
)
MANAGED_DIRECTORIES = frozenset({"templates", "static"})
REQUIRED_MANAGED_FILES = frozenset(
    {
        VERSION_FILENAME,
        "requirements.txt",
        "requirements.lock",
        "app.py",
        "update_manager.py",
        "launcher.py",
    }
)
LEGACY_MANAGED_FILES = frozenset(
    {
        VERSION_FILENAME,
        "app.py",
        "build_update_manifest.py",
        "db.py",
        "email_sanitizer.py",
        "launcher.py",
        "mail_fetcher.py",
        "requirements.txt",
        "requirements.lock",
        "security.py",
        "smoke_test.py",
        "static/app.js",
        "static/style.css",
        "templates/base.html",
        "templates/edit_token.html",
        "templates/email_detail.html",
        "templates/import.html",
        "templates/inbox.html",
        "templates/index.html",
        "templates/login.html",
        "templates/password.html",
        "templates/settings.html",
        "templates/tokens.html",
        "update_manager.py",
        "web_security.py",
    }
)
PROTECTED_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        STATE_DIRECTORY_NAME,
        VENV_DIRECTORY_NAME,
        "__pycache__",
        "logs",
        "log",
        "keys",
        "secrets",
    }
)
PROTECTED_KEY_SUFFIXES = frozenset(
    {
        ".pem",
        ".key",
        ".p12",
        ".pfx",
        ".jks",
        ".keystore",
        ".der",
        ".pk8",
        ".kdbx",
    }
)
PROTECTED_KEY_NAMES = frozenset(
    {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys"}
)
WINDOWS_RESERVED_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{number}" for number in range(1, 10)),
        *(f"LPT{number}" for number in range(1, 10)),
    }
)


class UpdateError(RuntimeError):
    """Base class for update failures safe to show in the application UI."""


class VersionError(UpdateError):
    pass


class NetworkError(UpdateError):
    pass


class UnsafeArchiveError(UpdateError):
    pass


class ManifestError(UpdateError):
    pass


class UpdateInProgressError(UpdateError):
    pass


class ApplicationInstanceError(UpdateError):
    pass


class RollbackError(UpdateError):
    pass


_SEMVER_RE = re.compile(
    r"^(?:v)?"
    r"(?P<major>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)"
    r"(?:-(?P<prerelease>(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+(?P<build>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


@total_ordering
@dataclass(frozen=True, eq=False)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()
    build: tuple[str, ...] = ()

    @classmethod
    def parse(cls, value: str) -> SemVer:
        if not isinstance(value, str):
            raise VersionError("version must be a string")
        match = _SEMVER_RE.fullmatch(value)
        if match is None:
            raise VersionError(f"invalid semantic version: {value!r}")
        try:
            numbers = tuple(int(match.group(name)) for name in ("major", "minor", "patch"))
        except ValueError as exc:
            raise VersionError("semantic version numeric component is too large") from exc
        prerelease = tuple((match.group("prerelease") or "").split("."))
        build = tuple((match.group("build") or "").split("."))
        return cls(
            *numbers,
            prerelease if prerelease != ("",) else (),
            build if build != ("",) else (),
        )

    def __str__(self) -> str:
        value = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            value += "-" + ".".join(self.prerelease)
        if self.build:
            value += "+" + ".".join(self.build)
        return value

    @property
    def precedence_key(self) -> tuple[int, int, int]:
        return self.major, self.minor, self.patch

    def same_release(self, other: SemVer) -> bool:
        return str(self) == str(other)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            return NotImplemented
        return not self < other and not other < self

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            return NotImplemented
        if self.precedence_key != other.precedence_key:
            return self.precedence_key < other.precedence_key
        if not self.prerelease:
            return bool(other.prerelease)
        if not other.prerelease:
            return True
        for left, right in zip(self.prerelease, other.prerelease):
            if left == right:
                continue
            left_numeric = left.isdigit()
            right_numeric = right.isdigit()
            if left_numeric and right_numeric:
                return int(left) < int(right)
            if left_numeric != right_numeric:
                return left_numeric
            return left < right
        return len(self.prerelease) < len(other.prerelease)


@dataclass(frozen=True)
class ReleaseInfo:
    version: SemVer
    tag_name: str
    zipball_url: str
    html_url: str
    name: str
    body: str
    published_at: str


@dataclass(frozen=True)
class ManifestFile:
    path: PurePosixPath
    sha256: str
    size: int


@dataclass(frozen=True)
class UpdateManifest:
    release_version: SemVer
    files: dict[str, ManifestFile]
    delete: tuple[PurePosixPath, ...]
    raw: bytes


_release_cache: dict[str, tuple[float, ReleaseInfo]] = {}
_cache_lock = threading.Lock()
_process_update_lock = threading.Lock()
_process_instance_lock = threading.Lock()


def _read_current_version(root: Path | None = None) -> SemVer:
    version_path = (root or PROJECT_ROOT) / VERSION_FILENAME
    try:
        value = version_path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise VersionError(f"cannot read {version_path.name}: {exc}") from exc
    return SemVer.parse(value)


def get_current_version() -> str:
    return str(_read_current_version())


def _normalise_proxies(proxy: str | Mapping[str, str] | None) -> dict[str, str] | None:
    if proxy is None:
        return None
    if isinstance(proxy, str):
        proxy = proxy.strip()
        if not proxy:
            return None
        return {"http": proxy, "https": proxy}
    if not isinstance(proxy, Mapping):
        raise UpdateError("proxy must be a URL string or requests proxy mapping")
    result = {str(key): str(value) for key, value in proxy.items() if value}
    return result or None


def _proxy_cache_key(proxy: str | Mapping[str, str] | None) -> str:
    proxies = _normalise_proxies(proxy)
    cache_identity = {
        "mode": "environment" if proxy is None else "explicit",
        "proxies": proxies or {},
    }
    serialised = json.dumps(cache_identity, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialised.encode()).hexdigest()


def _make_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=2,
        connect=2,
        read=2,
        status=2,
        allowed_methods=frozenset({"GET"}),
        status_forcelist=(408, 429, 500, 502, 503, 504),
        backoff_factor=0.5,
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.headers.update(
        {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    )
    return session


def _validate_download_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise NetworkError("release downloads must use HTTPS")
    if parsed.username or parsed.password:
        raise NetworkError("release URL must not contain user information")
    if parsed.hostname is None or parsed.hostname.lower() not in ALLOWED_DOWNLOAD_HOSTS:
        raise NetworkError(f"release download host is not allowed: {parsed.hostname!r}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise NetworkError("release download URL has an invalid port") from exc
    if port not in (None, 443):
        raise NetworkError("release download URL uses a non-HTTPS port")


def _safe_get(
    session: requests.Session,
    url: str,
    proxy: str | Mapping[str, str] | None,
) -> requests.Response:
    proxies = _normalise_proxies(proxy)
    current_url = url
    for redirect_count in range(MAX_REDIRECTS + 1):
        _validate_download_url(current_url)
        try:
            response = session.get(
                current_url,
                allow_redirects=False,
                stream=True,
                timeout=(CONNECT_TIMEOUT_SECONDS, READ_TIMEOUT_SECONDS),
                proxies=proxies,
                verify=True,
            )
        except requests.RequestException as exc:
            raise NetworkError(f"GitHub request failed: {exc}") from exc
        if response.status_code not in (301, 302, 303, 307, 308):
            _validate_download_url(response.url or current_url)
            return response
        location = response.headers.get("Location")
        response.close()
        if not location:
            raise NetworkError("GitHub redirect did not include a Location header")
        if redirect_count >= MAX_REDIRECTS:
            raise NetworkError("too many redirects while downloading release")
        current_url = urljoin(current_url, location)
    raise NetworkError("too many redirects while downloading release")


def _read_limited_response(response: requests.Response, limit: int) -> bytes:
    header_value = response.headers.get("Content-Length")
    if header_value:
        try:
            declared_size = int(header_value)
        except ValueError as exc:
            raise NetworkError("invalid Content-Length from GitHub") from exc
        if declared_size < 0 or declared_size > limit:
            raise NetworkError("GitHub response exceeds the configured size limit")
    chunks: list[bytes] = []
    total = 0
    try:
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            total += len(chunk)
            if total > limit:
                raise NetworkError("GitHub response exceeds the configured size limit")
            chunks.append(chunk)
    except requests.RequestException as exc:
        raise NetworkError(f"failed while reading GitHub response: {exc}") from exc
    return b"".join(chunks)


def _release_from_payload(payload: Any) -> ReleaseInfo:
    if not isinstance(payload, dict):
        raise NetworkError("GitHub release response is not an object")
    tag_name = payload.get("tag_name")
    zipball_url = payload.get("zipball_url")
    if not isinstance(tag_name, str) or not isinstance(zipball_url, str):
        raise NetworkError("GitHub release response is missing tag_name or zipball_url")
    version = SemVer.parse(tag_name)
    _validate_download_url(zipball_url)
    return ReleaseInfo(
        version=version,
        tag_name=tag_name,
        zipball_url=zipball_url,
        html_url=str(payload.get("html_url") or ""),
        name=str(payload.get("name") or tag_name),
        body=str(payload.get("body") or ""),
        published_at=str(payload.get("published_at") or ""),
    )


def _fetch_latest_release(
    proxy: str | Mapping[str, str] | None = None,
    *,
    use_cache: bool = True,
) -> ReleaseInfo:
    cache_key = _proxy_cache_key(proxy)
    now = time.monotonic()
    if use_cache:
        with _cache_lock:
            cached = _release_cache.get(cache_key)
            if cached is not None and now - cached[0] < CACHE_TTL_SECONDS:
                return cached[1]
    session = _make_session()
    session.trust_env = proxy is None
    response: requests.Response | None = None
    try:
        response = _safe_get(session, LATEST_RELEASE_API, proxy)
        if response.status_code != 200:
            raise NetworkError(
                f"GitHub releases API returned HTTP {response.status_code}"
            )
        raw = _read_limited_response(response, MAX_API_RESPONSE_BYTES)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise NetworkError("GitHub releases API returned invalid JSON") from exc
        release = _release_from_payload(payload)
    finally:
        if response is not None:
            response.close()
        session.close()
    with _cache_lock:
        _release_cache[cache_key] = (now, release)
    return release


def check_for_update(
    proxy: str | Mapping[str, str] | None = None,
    *,
    use_cache: bool = True,
) -> dict[str, Any]:
    current = _read_current_version()
    latest = _fetch_latest_release(proxy, use_cache=use_cache)
    return {
        "current_version": str(current),
        "latest_version": str(latest.version),
        "update_available": latest.version > current,
        "release_name": latest.name,
        "release_notes": latest.body,
        "published_at": latest.published_at,
        "html_url": latest.html_url,
    }


def _download_zipball(
    url: str,
    destination: Path,
    proxy: str | Mapping[str, str] | None,
) -> None:
    session = _make_session()
    session.trust_env = proxy is None
    response: requests.Response | None = None
    try:
        response = _safe_get(session, url, proxy)
        if response.status_code != 200:
            raise NetworkError(f"release download returned HTTP {response.status_code}")
        header_value = response.headers.get("Content-Length")
        if header_value:
            try:
                declared_size = int(header_value)
            except ValueError as exc:
                raise NetworkError("invalid release Content-Length") from exc
            if declared_size < 0 or declared_size > MAX_ARCHIVE_BYTES:
                raise NetworkError("release archive exceeds the compressed size limit")
        downloaded = 0
        with destination.open("xb") as output:
            try:
                for chunk in response.iter_content(chunk_size=128 * 1024):
                    if not chunk:
                        continue
                    downloaded += len(chunk)
                    if downloaded > MAX_ARCHIVE_BYTES:
                        raise NetworkError(
                            "release archive exceeds the compressed size limit"
                        )
                    output.write(chunk)
            except requests.RequestException as exc:
                raise NetworkError(f"failed while downloading release: {exc}") from exc
            output.flush()
            os.fsync(output.fileno())
        if downloaded == 0:
            raise NetworkError("release archive is empty")
    finally:
        if response is not None:
            response.close()
        session.close()


def _archive_path(info: zipfile.ZipInfo) -> PurePosixPath:
    name = info.filename
    if not name or "\x00" in name or "\\" in name:
        raise UnsafeArchiveError(f"unsafe archive path: {name!r}")
    posix_path = PurePosixPath(name)
    windows_path = PureWindowsPath(name)
    if posix_path.is_absolute() or windows_path.is_absolute() or windows_path.drive:
        raise UnsafeArchiveError(f"absolute archive path is not allowed: {name!r}")
    if any(part in ("", ".", "..") for part in posix_path.parts):
        raise UnsafeArchiveError(f"archive path traversal is not allowed: {name!r}")
    for part in posix_path.parts:
        base_name = part.split(".", 1)[0].upper()
        if (
            ":" in part
            or part.rstrip(" .") != part
            or base_name in WINDOWS_RESERVED_NAMES
        ):
            raise UnsafeArchiveError(
                f"Windows-unsafe archive path is not allowed: {name!r}"
            )
    return posix_path


def _is_link_or_special(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)


def _is_protected_path(path: PurePosixPath) -> bool:
    lowered = tuple(part.lower() for part in path.parts)
    if any(part in PROTECTED_DIRECTORY_NAMES for part in lowered):
        return True
    name = lowered[-1]
    if name in {RUNTIME_MARKER_FILENAME, MANIFEST_FILENAME.lower()}:
        return True
    if name == ".env" or name.startswith(".env."):
        return True
    if name == "data.db" or name.startswith(("data.db-", "data.db.")):
        return True
    if name.endswith((".db", ".sqlite", ".sqlite3", ".log")):
        return True
    if name in PROTECTED_KEY_NAMES:
        return True
    return any(name.endswith(suffix) for suffix in PROTECTED_KEY_SUFFIXES)


def _parse_managed_path(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ManifestError(f"invalid managed path: {value!r}")
    path = PurePosixPath(value)
    windows_path = PureWindowsPath(value)
    if path.is_absolute() or windows_path.is_absolute() or windows_path.drive:
        raise ManifestError(f"absolute managed path is not allowed: {value!r}")
    if any(part in ("", ".", "..") for part in path.parts) or _is_protected_path(path):
        raise ManifestError(f"protected or unsafe managed path: {value!r}")
    for part in path.parts:
        base_name = part.split(".", 1)[0].upper()
        if ":" in part or part.rstrip(" .") != part or base_name in WINDOWS_RESERVED_NAMES:
            raise ManifestError(f"Windows-unsafe managed path: {value!r}")
    if len(path.parts) == 1:
        if path.name not in ROOT_FIXED_FILES and path.suffix != ".py":
            raise ManifestError(f"unmanaged root file: {value!r}")
    elif path.parts[0] not in MANAGED_DIRECTORIES:
        raise ManifestError(f"unmanaged directory: {value!r}")
    return path


def _canonical_manifest_payload(payload: dict[str, Any]) -> bytes:
    unsigned = {key: value for key, value in payload.items() if key != "signature"}
    return json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _verify_manifest_signature(payload: dict[str, Any]) -> None:
    signature_object = payload.get("signature")
    if not isinstance(signature_object, dict) or set(signature_object) != {
        "algorithm",
        "value",
    }:
        raise ManifestError("manifest signature object is invalid")
    if signature_object.get("algorithm") != "ed25519":
        raise ManifestError("manifest signature algorithm must be ed25519")
    if UPDATE_SIGNING_PUBLIC_KEY_B64.startswith("REPLACE_"):
        raise ManifestError("production update signing public key is not configured")
    try:
        public_bytes = base64.b64decode(UPDATE_SIGNING_PUBLIC_KEY_B64, validate=True)
        signature = base64.b64decode(signature_object["value"], validate=True)
    except (TypeError, ValueError, binascii.Error) as exc:
        raise ManifestError("manifest signature encoding is invalid") from exc
    if len(public_bytes) != 32 or len(signature) != 64:
        raise ManifestError("manifest Ed25519 key or signature length is invalid")
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(
            signature, _canonical_manifest_payload(payload)
        )
    except (InvalidSignature, ValueError) as exc:
        raise ManifestError("manifest signature verification failed") from exc


def _parse_manifest(raw: bytes) -> UpdateManifest:
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ManifestError("update manifest exceeds the size limit")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestError("update manifest is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "release_version",
        "files",
        "delete",
        "signature",
    }:
        raise ManifestError("update manifest has an invalid top-level schema")
    if payload["schema_version"] != MANIFEST_SCHEMA_VERSION:
        raise ManifestError("unsupported update manifest schema version")
    _verify_manifest_signature(payload)
    release_version = SemVer.parse(payload["release_version"])
    raw_files = payload["files"]
    raw_delete = payload["delete"]
    if not isinstance(raw_files, dict) or not isinstance(raw_delete, list):
        raise ManifestError("manifest files or delete field has an invalid type")
    files: dict[str, ManifestFile] = {}
    collision_keys: set[str] = set()
    for raw_path, record in raw_files.items():
        path = _parse_managed_path(raw_path)
        key = path.as_posix()
        collision_key = key.casefold()
        if collision_key in collision_keys:
            raise ManifestError(f"duplicate managed path: {key}")
        collision_keys.add(collision_key)
        if not isinstance(record, dict) or set(record) != {"sha256", "size"}:
            raise ManifestError(f"invalid file record for {key}")
        digest = record["sha256"]
        size = record["size"]
        if (
            not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or size > MAX_EXTRACTED_BYTES
        ):
            raise ManifestError(f"invalid hash or size for {key}")
        files[key] = ManifestFile(path, digest, size)
    missing = REQUIRED_MANAGED_FILES - files.keys()
    if missing:
        raise ManifestError("manifest is missing required files: " + ", ".join(sorted(missing)))
    deleted: list[PurePosixPath] = []
    for raw_path in raw_delete:
        path = _parse_managed_path(raw_path)
        key = path.as_posix()
        if key in files or key in REQUIRED_MANAGED_FILES:
            raise ManifestError(f"manifest cannot delete required or replaced file: {key}")
        collision_key = key.casefold()
        if collision_key in collision_keys:
            raise ManifestError(f"duplicate managed or deleted path: {key}")
        collision_keys.add(collision_key)
        deleted.append(path)
    if sum(item.size for item in files.values()) > MAX_EXTRACTED_BYTES:
        raise ManifestError("manifest extracted size exceeds the configured limit")
    return UpdateManifest(release_version, files, tuple(deleted), raw)


def _validated_archive_members(
    archive: zipfile.ZipFile,
) -> dict[str, zipfile.ZipInfo]:
    infos = archive.infolist()
    if not infos or len(infos) > MAX_ARCHIVE_MEMBERS:
        raise UnsafeArchiveError("release archive has an invalid number of entries")
    roots: set[str] = set()
    seen: set[str] = set()
    members: dict[str, zipfile.ZipInfo] = {}
    total_size = 0
    for info in infos:
        path = _archive_path(info)
        roots.add(path.parts[0])
        collision_key = path.as_posix().casefold().rstrip("/")
        if collision_key in seen:
            raise UnsafeArchiveError(f"duplicate archive path: {info.filename!r}")
        seen.add(collision_key)
        if info.flag_bits & 0x1:
            raise UnsafeArchiveError("encrypted archive members are not allowed")
        if _is_link_or_special(info):
            raise UnsafeArchiveError(
                f"links and special files are not allowed: {info.filename!r}"
            )
        if info.file_size < 0:
            raise UnsafeArchiveError("archive member has an invalid size")
        if not info.is_dir():
            total_size += info.file_size
            if total_size > MAX_EXTRACTED_BYTES:
                raise UnsafeArchiveError("release exceeds the extracted size limit")
        if len(path.parts) > 1 and not info.is_dir():
            relative = PurePosixPath(*path.parts[1:]).as_posix()
            members[relative] = info
    if len(roots) != 1:
        raise UnsafeArchiveError("release archive must contain one top-level directory")
    return members


def _read_archive_member(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int
) -> bytes:
    if info.file_size > limit:
        raise UnsafeArchiveError(f"archive member exceeds size limit: {info.filename}")
    result = bytearray()
    try:
        with archive.open(info) as source:
            while chunk := source.read(128 * 1024):
                result.extend(chunk)
                if len(result) > limit:
                    raise UnsafeArchiveError(
                        f"archive member exceeds size limit: {info.filename}"
                    )
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise UnsafeArchiveError(f"failed to read archive member: {info.filename}") from exc
    if len(result) != info.file_size:
        raise UnsafeArchiveError(f"archive size mismatch: {info.filename}")
    return bytes(result)


def _stage_archive(archive_path: Path, stage_root: Path) -> UpdateManifest:
    try:
        archive = zipfile.ZipFile(archive_path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise UnsafeArchiveError("downloaded release is not a valid ZIP archive") from exc
    try:
        members = _validated_archive_members(archive)
        manifest_info = members.get(MANIFEST_FILENAME)
        if manifest_info is None:
            raise ManifestError(f"release does not contain {MANIFEST_FILENAME}")
        manifest_raw = _read_archive_member(archive, manifest_info, MAX_MANIFEST_BYTES)
        manifest = _parse_manifest(manifest_raw)
        for key, record in manifest.files.items():
            info = members.get(key)
            if info is None:
                raise ManifestError(f"release archive is missing manifest file: {key}")
            if info.file_size != record.size:
                raise ManifestError(f"release archive size does not match manifest: {key}")
            destination = stage_root.joinpath(*record.path.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            written = 0
            try:
                with archive.open(info) as source, destination.open("xb") as output:
                    while chunk := source.read(128 * 1024):
                        written += len(chunk)
                        if written > record.size:
                            raise ManifestError(f"release file exceeds manifest size: {key}")
                        digest.update(chunk)
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
            except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                raise UnsafeArchiveError(f"failed to extract {key}") from exc
            if written != record.size or digest.hexdigest() != record.sha256:
                raise ManifestError(f"release file hash verification failed: {key}")
        _atomic_write_bytes(stage_root / MANIFEST_FILENAME, manifest.raw)
        return manifest
    finally:
        archive.close()


def _is_symlink_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction and is_junction())


def _validate_destination(root: Path, relative: PurePosixPath) -> Path:
    destination = root.joinpath(*relative.parts)
    current = root
    for part in relative.parts[:-1]:
        current /= part
        if current.exists() and (_is_symlink_or_junction(current) or not current.is_dir()):
            raise UpdateError(f"unsafe destination parent: {current}")
    if destination.exists() and (
        _is_symlink_or_junction(destination) or not destination.is_file()
    ):
        raise UpdateError(f"unsafe destination file: {destination}")
    return destination


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _atomic_write_bytes(destination: Path, content: bytes) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.tmp-", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
        _fsync_directory(destination.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_write_json(destination: Path, payload: dict[str, Any]) -> None:
    content = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    _atomic_write_bytes(destination, content)


def _atomic_install(source: Path, destination: Path) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.update-", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output, source.open("rb") as input_file:
            shutil.copyfileobj(input_file, output, length=128 * 1024)
            output.flush()
            os.fsync(output.fileno())
        try:
            mode = stat.S_IMODE(source.stat().st_mode)
            os.chmod(temporary, mode & 0o755 or 0o644)
        except OSError:
            pass
        os.replace(temporary, destination)
        _fsync_directory(destination.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _state_directory(root: Path) -> Path:
    return root / STATE_DIRECTORY_NAME


def _journal_path(root: Path) -> Path:
    return _state_directory(root) / "transaction.json"


def _ensure_control_directories(root: Path) -> None:
    for directory in (_state_directory(root), root / VENV_DIRECTORY_NAME):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if _is_symlink_or_junction(directory) or not directory.is_dir():
            raise UpdateError(f"unsafe updater control directory: {directory}")
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass


def _lock_file(
    path: Path,
    process_lock: threading.Lock,
    error_type: type[UpdateError],
) -> Iterator[None]:
    if not process_lock.acquire(blocking=False):
        raise error_type("another process or thread already holds this lock")
    handle = None
    locked = False
    try:
        if path.exists() and _is_symlink_or_junction(path):
            raise UpdateError(f"unsafe lock file: {path}")
        handle = path.open("a+b")
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except OSError as exc:
            raise error_type("another process already holds this lock") from exc
        yield
    finally:
        if handle is not None:
            if locked:
                try:
                    handle.seek(0)
                    if os.name == "nt":
                        import msvcrt

                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
            handle.close()
        process_lock.release()


@contextmanager
def _update_lock(root: Path | None = None) -> Iterator[None]:
    project_root = root or PROJECT_ROOT
    _ensure_control_directories(project_root)
    yield from _lock_file(
        _state_directory(project_root) / "update.lock",
        _process_update_lock,
        UpdateInProgressError,
    )


@contextmanager
def application_instance_lock() -> Iterator[None]:
    """Hold for the whole app lifespan to reject a second worker/process."""

    root = PROJECT_ROOT
    _ensure_control_directories(root)
    yield from _lock_file(
        _state_directory(root) / "application.lock",
        _process_instance_lock,
        ApplicationInstanceError,
    )


def _proxy_environment(proxy: str | Mapping[str, str] | None) -> dict[str, str]:
    environment = os.environ.copy()
    proxies = _normalise_proxies(proxy)
    proxy_variables = (
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "PIP_PROXY",
    )
    if not proxies:
        if proxy is not None:
            for name in proxy_variables:
                environment.pop(name, None)
        return environment
    http_proxy = proxies.get("http") or proxies.get("https")
    https_proxy = proxies.get("https") or proxies.get("http")
    if http_proxy:
        environment["HTTP_PROXY"] = http_proxy
        environment["http_proxy"] = http_proxy
    if https_proxy:
        environment["HTTPS_PROXY"] = https_proxy
        environment["https_proxy"] = https_proxy
        environment["PIP_PROXY"] = https_proxy
    environment.pop("ALL_PROXY", None)
    environment.pop("all_proxy", None)
    return environment


def _venv_python(venv_root: Path) -> Path:
    windows = venv_root / "Scripts" / "python.exe"
    return windows if os.name == "nt" else venv_root / "bin" / "python"


def _uses_socks_proxy(proxy: str | Mapping[str, str] | None) -> bool:
    proxies = _normalise_proxies(proxy) or {}
    return any(
        urlparse(value).scheme.lower() in {"socks4", "socks5", "socks5h"}
        for value in proxies.values()
    )


def _bootstrap_socks_module(venv_root: Path) -> None:
    """Make PySocks available to bare pip before the locked install runs."""

    try:
        import socks
    except ImportError as exc:
        raise UpdateError("SOCKS proxy support is not installed in the current runtime") from exc
    source = Path(socks.__file__).resolve()
    if source.name.casefold() != "socks.py" or not source.is_file():
        raise UpdateError("current PySocks installation cannot be used to bootstrap pip")
    if os.name == "nt":
        site_packages = venv_root / "Lib" / "site-packages"
    else:
        site_packages = (
            venv_root
            / "lib"
            / f"python{sys.version_info.major}.{sys.version_info.minor}"
            / "site-packages"
        )
    site_packages.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, site_packages / "socks.py")


def _prepare_new_venv(
    root: Path,
    version: SemVer,
    transaction_id: str,
    requirements_lock: Path,
    proxy: str | Mapping[str, str] | None,
) -> tuple[Path, Path]:
    venv_parent = root / VENV_DIRECTORY_NAME
    staging = venv_parent / f".{version}-{transaction_id}.tmp"
    final = venv_parent / str(version)
    if final.exists():
        raise UpdateError(f"target runtime environment already exists: {final.name}")
    shutil.rmtree(staging, ignore_errors=True)
    try:
        venv.EnvBuilder(with_pip=True, clear=False).create(staging)
        python = _venv_python(staging)
        if not python.is_file():
            raise UpdateError("new virtual environment does not contain Python")
        if _uses_socks_proxy(proxy):
            _bootstrap_socks_module(staging)
        subprocess.run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--require-hashes",
                "-r",
                str(requirements_lock),
            ],
            check=True,
            timeout=PIP_TIMEOUT_SECONDS,
            env=_proxy_environment(proxy),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        shutil.rmtree(staging, ignore_errors=True)
        raise UpdateError(f"dependency installation failed: {exc}") from exc
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return staging, final


def _load_installed_ownership(root: Path) -> set[str]:
    manifest_path = root / MANIFEST_FILENAME
    if not manifest_path.exists():
        return set(LEGACY_MANAGED_FILES)
    try:
        raw = manifest_path.read_bytes()
    except OSError as exc:
        raise ManifestError("cannot read installed update manifest") from exc
    return set(_parse_manifest(raw).files)


def _planned_created_directories(
    root: Path, destinations: list[Path]
) -> list[PurePosixPath]:
    planned: set[PurePosixPath] = set()
    for destination in destinations:
        current = destination.parent
        while current != root and not current.exists():
            relative = current.relative_to(root)
            planned.add(PurePosixPath(*relative.parts))
            current = current.parent
    return sorted(planned, key=lambda path: (len(path.parts), path.as_posix()))


def _runtime_marker(version: SemVer, final_venv: Path | None, root: Path) -> bytes:
    python_relative = ""
    if final_venv is not None:
        python_relative = _venv_python(final_venv).relative_to(root).as_posix()
    else:
        try:
            from launcher import select_python_executable

            selected = select_python_executable(root).absolute()
            relative = selected.relative_to(root.absolute())
            if relative.parts and relative.parts[0] == VENV_DIRECTORY_NAME:
                python_relative = PurePosixPath(*relative.parts).as_posix()
        except (ImportError, OSError, ValueError):
            pass
    payload = {
        "schema_version": 1,
        "version": str(version),
        "python": python_relative,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _journal_transaction_directory(root: Path, transaction_id: str) -> Path:
    if re.fullmatch(r"[0-9a-f]{32}", transaction_id) is None:
        raise RollbackError("transaction journal contains an invalid identifier")
    return _state_directory(root) / "transactions" / transaction_id


def _journal_target_path(value: str) -> PurePosixPath:
    if value in {MANIFEST_FILENAME, RUNTIME_MARKER_FILENAME}:
        return PurePosixPath(value)
    return _parse_managed_path(value)


def _read_journal(root: Path) -> dict[str, Any] | None:
    path = _journal_path(root)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RollbackError("update transaction journal is unreadable") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != TRANSACTION_SCHEMA_VERSION:
        raise RollbackError("update transaction journal schema is invalid")
    return payload


def _write_journal(root: Path, journal: dict[str, Any]) -> None:
    _atomic_write_json(_journal_path(root), journal)


def _cleanup_orphan_work(root: Path) -> None:
    if _journal_path(root).exists():
        return
    transactions = _state_directory(root) / "transactions"
    if transactions.exists():
        for child in transactions.iterdir():
            if child.is_dir() and not _is_symlink_or_junction(child):
                shutil.rmtree(child, ignore_errors=True)
    venv_parent = root / VENV_DIRECTORY_NAME
    if venv_parent.exists():
        for child in venv_parent.iterdir():
            if child.name.startswith(".") and child.name.endswith(".tmp") and child.is_dir():
                shutil.rmtree(child, ignore_errors=True)


def _remove_transaction_artifacts(
    root: Path, transaction_id: str, *, remove_journal: bool
) -> None:
    if remove_journal:
        _journal_path(root).unlink(missing_ok=True)
        _fsync_directory(_state_directory(root))
    transaction = _journal_transaction_directory(root, transaction_id)
    shutil.rmtree(transaction, ignore_errors=True)


def _recover_interrupted_update_locked(root: Path) -> bool:
    journal = _read_journal(root)
    if journal is None:
        _cleanup_orphan_work(root)
        return False
    transaction_id = journal.get("transaction_id")
    if not isinstance(transaction_id, str):
        raise RollbackError("transaction journal identifier is missing")
    transaction = _journal_transaction_directory(root, transaction_id)
    if journal.get("phase") == "committed":
        _remove_transaction_artifacts(root, transaction_id, remove_journal=True)
        _cleanup_orphan_work(root)
        return False
    raw_targets = journal.get("target_paths")
    raw_present = journal.get("originally_present")
    raw_directories = journal.get("created_directories", [])
    if not isinstance(raw_targets, list) or not isinstance(raw_present, list):
        raise RollbackError("transaction journal target list is invalid")
    targets = [_journal_target_path(value) for value in raw_targets]
    present = {str(value) for value in raw_present}
    failures: list[str] = []
    backup_root = transaction / "backup"
    for relative in reversed(targets):
        key = relative.as_posix()
        destination = root.joinpath(*relative.parts)
        try:
            if key in present:
                backup = backup_root.joinpath(*relative.parts)
                if not backup.is_file():
                    raise FileNotFoundError(f"missing backup for {key}")
                destination.parent.mkdir(parents=True, exist_ok=True)
                _atomic_install(backup, destination)
            elif destination.exists() or destination.is_symlink():
                if destination.is_dir() and not destination.is_symlink():
                    raise IsADirectoryError(destination)
                destination.unlink()
        except OSError as exc:
            failures.append(f"{key}: {exc}")
    new_venv = journal.get("new_venv")
    if new_venv:
        expected_prefix = f"{VENV_DIRECTORY_NAME}/"
        if not isinstance(new_venv, str) or not new_venv.startswith(expected_prefix):
            failures.append("invalid new_venv path")
        else:
            candidate = root.joinpath(*PurePosixPath(new_venv).parts)
            if candidate.parent == root / VENV_DIRECTORY_NAME:
                shutil.rmtree(candidate, ignore_errors=True)
    if isinstance(raw_directories, list):
        for value in reversed(raw_directories):
            try:
                relative = _parse_managed_path(f"{value}/placeholder").parent
                root.joinpath(*relative.parts).rmdir()
            except (ManifestError, OSError):
                pass
    if failures:
        raise RollbackError("update rollback was incomplete: " + "; ".join(failures))
    _remove_transaction_artifacts(root, transaction_id, remove_journal=True)
    _cleanup_orphan_work(root)
    return True


def recover_interrupted_update() -> bool:
    """Restore the pre-update snapshot when an uncommitted journal exists."""

    root = PROJECT_ROOT
    with _update_lock(root):
        return _recover_interrupted_update_locked(root)


def _prepare_transaction(
    root: Path,
    transaction: Path,
    target_paths: list[PurePosixPath],
    created_directories: list[PurePosixPath],
    current: SemVer,
    expected: SemVer,
    new_venv: Path | None,
) -> dict[str, Any]:
    backup_root = transaction / "backup"
    backup_root.mkdir(parents=True)
    present: list[str] = []
    for relative in target_paths:
        destination = root.joinpath(*relative.parts)
        if destination.exists():
            if _is_symlink_or_junction(destination) or not destination.is_file():
                raise UpdateError(f"unsafe transaction target: {destination}")
            present.append(relative.as_posix())
            backup = backup_root.joinpath(*relative.parts)
            backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(destination, backup)
            with backup.open("r+b") as source:
                os.fsync(source.fileno())
    return {
        "schema_version": TRANSACTION_SCHEMA_VERSION,
        "transaction_id": transaction.name,
        "phase": "prepared",
        "from_version": str(current),
        "to_version": str(expected),
        "target_paths": [path.as_posix() for path in target_paths],
        "originally_present": present,
        "created_directories": [path.as_posix() for path in created_directories],
        "new_venv": new_venv.relative_to(root).as_posix() if new_venv else "",
    }


def apply_update(
    expected_version: str,
    proxy: str | Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Download, verify and transactionally apply exactly the expected release."""

    expected = SemVer.parse(expected_version)
    root = PROJECT_ROOT
    with _update_lock(root):
        _recover_interrupted_update_locked(root)
        current = _read_current_version(root)
        if expected <= current:
            raise VersionError(f"refusing non-upgrade update from {current} to {expected}")
        release = _fetch_latest_release(proxy, use_cache=False)
        if not release.version.same_release(expected):
            raise VersionError(
                f"latest GitHub release is {release.version}, not expected {expected}"
            )

        transaction_id = uuid.uuid4().hex
        transaction = _state_directory(root) / "transactions" / transaction_id
        stage_root = transaction / "stage"
        transaction.mkdir(parents=True)
        stage_root.mkdir()
        archive_path = transaction / "release.zip"
        journal_written = False
        venv_staging: Path | None = None
        venv_final: Path | None = None
        try:
            _download_zipball(release.zipball_url, archive_path, proxy)
            manifest = _stage_archive(archive_path, stage_root)
            if (
                not manifest.release_version.same_release(expected)
                or manifest.release_version <= current
            ):
                raise VersionError(
                    f"release manifest is {manifest.release_version}, expected newer {expected}"
                )
            staged_version = _read_current_version(stage_root)
            if not staged_version.same_release(expected):
                raise VersionError(
                    f"release VERSION is {staged_version}, expected {expected}"
                )

            owned = _load_installed_ownership(root)
            file_paths = [record.path for record in manifest.files.values()]
            for relative in file_paths:
                destination = _validate_destination(root, relative)
                if destination.exists() and relative.as_posix() not in owned:
                    raise ManifestError(
                        f"release would overwrite unknown local file: {relative.as_posix()}"
                    )
            for relative in manifest.delete:
                _validate_destination(root, relative)
                if relative.as_posix() not in owned:
                    raise ManifestError(
                        f"release would delete unknown local file: {relative.as_posix()}"
                    )

            dependency_files = ("requirements.txt", "requirements.lock")
            requirements_changed = any(
                not (root / name).exists()
                or (root / name).read_bytes() != (stage_root / name).read_bytes()
                for name in dependency_files
            )
            if requirements_changed:
                venv_staging, venv_final = _prepare_new_venv(
                    root,
                    expected,
                    transaction_id,
                    stage_root / "requirements.lock",
                    proxy,
                )

            special_paths = [
                PurePosixPath(MANIFEST_FILENAME),
                PurePosixPath(RUNTIME_MARKER_FILENAME),
            ]
            target_paths = sorted(
                {*file_paths, *manifest.delete, *special_paths},
                key=PurePosixPath.as_posix,
            )
            destinations = [root.joinpath(*path.parts) for path in file_paths]
            created_directories = _planned_created_directories(root, destinations)
            journal = _prepare_transaction(
                root,
                transaction,
                target_paths,
                created_directories,
                current,
                expected,
                venv_final,
            )
            _write_journal(root, journal)
            journal_written = True

            if venv_staging is not None and venv_final is not None:
                os.replace(venv_staging, venv_final)
                _fsync_directory(venv_final.parent)
                venv_staging = None
            journal["phase"] = "applying"
            _write_journal(root, journal)

            for relative in created_directories:
                root.joinpath(*relative.parts).mkdir(exist_ok=True)

            for relative in manifest.delete:
                destination = root.joinpath(*relative.parts)
                if destination.exists():
                    destination.unlink()
                    _fsync_directory(destination.parent)

            critical = {"app.py", "update_manager.py", VERSION_FILENAME}
            ordinary = sorted(
                (path for path in file_paths if path.as_posix() not in critical),
                key=PurePosixPath.as_posix,
            )
            for relative in ordinary:
                _atomic_install(
                    stage_root.joinpath(*relative.parts), root.joinpath(*relative.parts)
                )
            _atomic_install(stage_root / MANIFEST_FILENAME, root / MANIFEST_FILENAME)
            _atomic_write_bytes(
                root / RUNTIME_MARKER_FILENAME,
                _runtime_marker(expected, venv_final, root),
            )
            for name in ("app.py", "update_manager.py"):
                _atomic_install(stage_root / name, root / name)
            _atomic_install(stage_root / VERSION_FILENAME, root / VERSION_FILENAME)

            journal["phase"] = "committed"
            _write_journal(root, journal)
        except Exception as update_error:
            if journal_written:
                try:
                    _recover_interrupted_update_locked(root)
                except RollbackError as rollback_error:
                    raise rollback_error from update_error
            else:
                if venv_staging is not None:
                    shutil.rmtree(venv_staging, ignore_errors=True)
                shutil.rmtree(transaction, ignore_errors=True)
            raise

        _remove_transaction_artifacts(root, transaction_id, remove_journal=True)
        _cleanup_orphan_work(root)
        return {
            "updated": True,
            "from_version": str(current),
            "to_version": str(expected),
            "restart_required": True,
        }


def restart_current_process() -> None:
    """Exec the current command with the committed marker-selected interpreter."""

    from launcher import select_python_executable

    python = select_python_executable(PROJECT_ROOT)
    os.execv(str(python), [str(python), *sys.argv])


__all__ = [
    "ApplicationInstanceError",
    "ManifestError",
    "NetworkError",
    "RollbackError",
    "SemVer",
    "UnsafeArchiveError",
    "UpdateError",
    "UpdateInProgressError",
    "VersionError",
    "application_instance_lock",
    "apply_update",
    "check_for_update",
    "get_current_version",
    "recover_interrupted_update",
    "restart_current_process",
]
