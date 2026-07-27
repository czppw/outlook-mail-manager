"""Select the active virtual environment and start the application."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path, PurePosixPath

RUNTIME_MARKER_FILENAME = ".omm-runtime.json"
VERSION_FILENAME = "VERSION"
VENV_DIRECTORY_NAME = ".omm-venvs"
MAX_MARKER_BYTES = 16 * 1024


def _project_root(root: str | Path | None = None) -> Path:
    return Path(root).resolve() if root is not None else Path(__file__).resolve().parent


def _read_version(root: Path) -> str:
    try:
        return (root / VERSION_FILENAME).read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        return ""


def _is_executable_file(path: Path) -> bool:
    return path.is_file() and (os.name == "nt" or os.access(path, os.X_OK))


def _marker_python(root: Path) -> Path | None:
    marker_path = root / RUNTIME_MARKER_FILENAME
    try:
        if marker_path.stat().st_size > MAX_MARKER_BYTES:
            return None
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(marker, dict) or marker.get("schema_version") != 1:
        return None
    if marker.get("version") != _read_version(root):
        return None
    raw_path = marker.get("python")
    if not isinstance(raw_path, str) or not raw_path or "\\" in raw_path:
        return None
    relative = PurePosixPath(raw_path)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or len(relative.parts) < 3
        or relative.parts[0] != VENV_DIRECTORY_NAME
    ):
        return None
    candidate = root.joinpath(*relative.parts)
    return candidate if _is_executable_file(candidate) else None


def _default_python(root: Path) -> Path:
    if os.name == "nt":
        candidates = (
            root / "venv" / "Scripts" / "python.exe",
            root / ".venv" / "Scripts" / "python.exe",
        )
    else:
        candidates = (
            root / "venv" / "bin" / "python",
            root / ".venv" / "bin" / "python",
        )
    return next((path for path in candidates if _is_executable_file(path)), Path(sys.executable))


def select_python_executable(root: str | Path | None = None) -> Path:
    project_root = _project_root(root)
    return _marker_python(project_root) or _default_python(project_root)


def main() -> None:
    root = _project_root()
    python = select_python_executable(root)
    os.execv(str(python), [str(python), str(root / "app.py"), *sys.argv[1:]])


if __name__ == "__main__":
    main()
