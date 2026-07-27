"""Credential encryption helpers."""

from __future__ import annotations

import base64
import binascii
import os
import threading
from functools import lru_cache
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

ENCRYPTED_PREFIX = "enc:v1:"
DEFAULT_KEY_FILE = ".omm_secret.key"

_cache_lock = threading.RLock()


class CredentialDecryptionError(ValueError):
    """Raised when encrypted data cannot be opened with the configured key."""


class CredentialKeyUnavailableError(CredentialDecryptionError):
    """Raised when encrypted data exists but its key source is missing."""


def _fernet_key(value: str | bytes) -> bytes:
    raw = value.encode("ascii") if isinstance(value, str) else value
    raw = raw.strip()
    try:
        decoded = base64.b64decode(raw, altchars=b"-_", validate=True)
    except (binascii.Error, UnicodeError, ValueError) as exc:
        raise ValueError("OMM_SECRET_KEY must be a URL-safe base64 Fernet key") from exc
    if len(decoded) != 32:
        raise ValueError("OMM_SECRET_KEY must decode to exactly 32 random bytes")
    return base64.urlsafe_b64encode(decoded)


def key_file_path(db_path: str) -> Path:
    configured = os.environ.get("OMM_SECRET_KEY_FILE")
    if configured:
        return Path(configured).expanduser().resolve()
    if db_path == ":memory:":
        return (Path.cwd() / DEFAULT_KEY_FILE).resolve()
    return Path(db_path).expanduser().resolve().parent / DEFAULT_KEY_FILE


def key_source_exists(db_path: str) -> bool:
    return (
        os.environ.get("OMM_SECRET_KEY") is not None or key_file_path(db_path).is_file()
    )


def _read_or_create_key(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        key = path.read_bytes().strip()
    except FileNotFoundError:
        generated = Fernet.generate_key()
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            key = path.read_bytes().strip()
        else:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(generated + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            key = generated
    if os.name != "nt":
        os.chmod(path, 0o600)
    return _fernet_key(key)


@lru_cache(maxsize=32)
def _load_key_cached(env_key: str | None, key_path: str) -> bytes:
    if env_key is not None:
        return _fernet_key(env_key)
    return _read_or_create_key(Path(key_path))


@lru_cache(maxsize=32)
def _cipher_cached(env_key: str | None, key_path: str) -> Fernet:
    return Fernet(_load_key_cached(env_key, key_path))


def _cache_identity(db_path: str) -> tuple[str | None, str]:
    return os.environ.get("OMM_SECRET_KEY"), str(key_file_path(db_path))


def load_key(db_path: str) -> bytes:
    with _cache_lock:
        return _load_key_cached(*_cache_identity(db_path))


def _cipher(db_path: str) -> Fernet:
    with _cache_lock:
        return _cipher_cached(*_cache_identity(db_path))


def clear_key_cache() -> None:
    with _cache_lock:
        _cipher_cached.cache_clear()
        _load_key_cached.cache_clear()


def is_encrypted(value: object) -> bool:
    return isinstance(value, str) and value.startswith(ENCRYPTED_PREFIX)


def encrypt_value(value: str | None, db_path: str) -> str | None:
    if value is None or value == "":
        return value
    if is_encrypted(value):
        decrypt_value(value, db_path)
        return value
    token = _cipher(db_path).encrypt(value.encode("utf-8")).decode("ascii")
    return ENCRYPTED_PREFIX + token


def decrypt_value(value: str | None, db_path: str) -> str | None:
    if value is None or value == "" or not is_encrypted(value):
        return value
    token = value[len(ENCRYPTED_PREFIX) :]
    try:
        return _cipher(db_path).decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeError, ValueError) as exc:
        raise CredentialDecryptionError(
            "Credential decryption failed; verify OMM_SECRET_KEY or OMM_SECRET_KEY_FILE"
        ) from exc
