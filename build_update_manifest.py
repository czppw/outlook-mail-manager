"""Build and sign UPDATE_MANIFEST.json for a GitHub release tag."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MANIFEST_FILENAME = "UPDATE_MANIFEST.json"
MANIFEST_SCHEMA_VERSION = 1
ROOT_FIXED_FILES = frozenset({"VERSION", "requirements.txt", "requirements.lock"})
MANAGED_DIRECTORIES = frozenset({"templates", "static"})
PROTECTED_NAMES = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        ".omm-update",
        ".omm-venvs",
        ".omm-runtime.json",
        "__pycache__",
        "data.db",
    }
)


def canonical_manifest_payload(manifest: dict[str, Any]) -> bytes:
    payload = {key: value for key, value in manifest.items() if key != "signature"}
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _is_managed(path: PurePosixPath) -> bool:
    lowered = tuple(part.lower() for part in path.parts)
    if any(part in PROTECTED_NAMES for part in lowered):
        return False
    if len(path.parts) == 1:
        return path.name in ROOT_FIXED_FILES or path.suffix == ".py"
    return path.parts[0] in MANAGED_DIRECTORIES


def _git_tracked_files(root: Path) -> list[PurePosixPath]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    paths = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        text = raw.decode("utf-8")
        path = PurePosixPath(text.replace("\\", "/"))
        if _is_managed(path):
            paths.append(path)
    return sorted(set(paths), key=PurePosixPath.as_posix)


def _load_previous_files(path: Path | None) -> set[str]:
    if path is None or not path.exists():
        return set()
    payload = json.loads(path.read_text(encoding="utf-8"))
    files = payload.get("files", {}) if isinstance(payload, dict) else {}
    if not isinstance(files, dict):
        raise TypeError("previous manifest has an invalid files object")
    return {str(name) for name in files}


def _file_record(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(128 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return {"sha256": digest.hexdigest(), "size": size}


def load_private_key(path: Path) -> Ed25519PrivateKey:
    raw = path.read_bytes().strip()
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except ValueError:
        try:
            seed = base64.b64decode(raw, validate=True)
        except ValueError as exc:
            raise ValueError("private key must be PKCS8 PEM or a base64 32-byte seed") from exc
        if len(seed) != 32:
            raise ValueError("raw Ed25519 private key seed must be 32 bytes")
        key = Ed25519PrivateKey.from_private_bytes(seed)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("private key is not Ed25519")
    return key


def public_key_base64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def build_manifest(
    root: Path,
    private_key: Ed25519PrivateKey,
    *,
    version: str | None = None,
    previous_manifest: Path | None = None,
    tracked_paths: list[PurePosixPath] | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    release_version = version or (root / "VERSION").read_text(encoding="ascii").strip()
    paths = tracked_paths if tracked_paths is not None else _git_tracked_files(root)
    files: dict[str, dict[str, Any]] = {}
    for relative in sorted(paths, key=PurePosixPath.as_posix):
        if not _is_managed(relative):
            continue
        source = root.joinpath(*relative.parts)
        if not source.is_file():
            raise ValueError(f"tracked managed file does not exist: {relative.as_posix()}")
        files[relative.as_posix()] = _file_record(source)

    required = {
        "VERSION",
        "requirements.txt",
        "requirements.lock",
        "app.py",
        "update_manager.py",
        "launcher.py",
    }
    missing = required - files.keys()
    if missing:
        raise ValueError("managed release is missing: " + ", ".join(sorted(missing)))

    previous_files = _load_previous_files(previous_manifest)
    deleted = sorted(previous_files - files.keys())
    manifest: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "release_version": release_version,
        "files": files,
        "delete": deleted,
    }
    signature = private_key.sign(canonical_manifest_payload(manifest))
    manifest["signature"] = {
        "algorithm": "ed25519",
        "value": base64.b64encode(signature).decode("ascii"),
    }
    return manifest


def write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def generate_key(private_path: Path, public_path: Path) -> None:
    if private_path.exists() or public_path.exists():
        raise FileExistsError("refusing to overwrite an existing signing key")
    key = Ed25519PrivateKey.generate()
    private_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass
    public_path.write_text(public_key_base64(key) + "\n", encoding="ascii")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    key_parser = subparsers.add_parser("generate-key")
    key_parser.add_argument("--private-key", type=Path, required=True)
    key_parser.add_argument("--public-key", type=Path, required=True)

    build_parser = subparsers.add_parser("build")
    build_parser.add_argument("--root", type=Path, default=Path.cwd())
    build_parser.add_argument("--private-key", type=Path, required=True)
    build_parser.add_argument("--output", type=Path, default=Path(MANIFEST_FILENAME))
    build_parser.add_argument("--previous-manifest", type=Path)
    build_parser.add_argument("--version")

    args = parser.parse_args()
    if args.command == "generate-key":
        generate_key(args.private_key, args.public_key)
        return
    key = load_private_key(args.private_key)
    manifest = build_manifest(
        args.root,
        key,
        version=args.version,
        previous_manifest=args.previous_manifest,
    )
    write_manifest(args.output, manifest)
    print(f"public key: {public_key_base64(key)}")
    print(f"manifest: {args.output}")


if __name__ == "__main__":
    main()
