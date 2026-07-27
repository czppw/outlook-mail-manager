from __future__ import annotations

import base64
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path, PurePosixPath
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import build_update_manifest
import launcher
import update_manager

TEST_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
TEST_PUBLIC_KEY_B64 = base64.b64encode(
    TEST_PRIVATE_KEY.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
).decode()


class FakeResponse:
    def __init__(
        self, status_code=200, content=b"", headers=None, url="https://api.github.com/"
    ):
        self.status_code = status_code
        self.content = content
        self.headers = headers or {}
        self.url = url
        self.closed = False

    def iter_content(self, chunk_size=1):
        for offset in range(0, len(self.content), chunk_size):
            yield self.content[offset : offset + chunk_size]

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.closed = False

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if not self.responses:
            raise AssertionError("unexpected network request")
        return self.responses.pop(0)

    def close(self):
        self.closed = True


def release_info(version="1.1.0"):
    parsed = update_manager.SemVer.parse(version)
    return update_manager.ReleaseInfo(
        version=parsed,
        tag_name=f"v{version}",
        zipball_url="https://api.github.com/repos/czppw/outlook-mail-manager/zipball/v1.1.0",
        html_url="https://github.com/czppw/outlook-mail-manager/releases/tag/v1.1.0",
        name=f"Release {version}",
        body="notes",
        published_at="2026-07-27T00:00:00Z",
    )


def write_project(root: Path, *, requirements="requests>=2.31\n"):
    root.mkdir(parents=True)
    files = {
        "VERSION": "1.0.0\n",
        "app.py": "APP = 'old'\n",
        "db.py": "DB = 'old'\n",
        "launcher.py": "LAUNCHER = 'old'\n",
        "mail_fetcher.py": "FETCHER = 'old'\n",
        "requirements.txt": requirements,
        "requirements.lock": requirements,
        "update_manager.py": "UPDATER = 'old'\n",
        "templates/index.html": "old template",
        "static/style.css": "old style",
        "static/obsolete.js": "remove me",
    }
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode())
    encoded = {name: content.encode() for name, content in files.items()}
    (root / update_manager.MANIFEST_FILENAME).write_text(
        json.dumps(signed_manifest(encoded, version="1.0.0")), encoding="utf-8"
    )


def release_files(version="1.1.0", requirements="requests>=2.31\n"):
    return {
        "VERSION": f"{version}\n".encode(),
        "app.py": b"APP = 'new'\n",
        "db.py": b"DB = 'new'\n",
        "launcher.py": b"LAUNCHER = 'new'\n",
        "mail_fetcher.py": b"FETCHER = 'new'\n",
        "new_feature.py": b"FEATURE = True\n",
        "requirements.txt": requirements.encode(),
        "requirements.lock": requirements.encode(),
        "update_manager.py": b"UPDATER = 'new'\n",
        "templates/index.html": b"new template",
        "templates/nested/new.html": b"new nested template",
        "static/style.css": b"new style",
    }


def signed_manifest(files, version="1.1.0", delete=None, private_key=TEST_PRIVATE_KEY):
    records = {
        name: {"sha256": update_manager.hashlib.sha256(content).hexdigest(), "size": len(content)}
        for name, content in sorted(files.items())
    }
    manifest = {
        "schema_version": 1,
        "release_version": version,
        "files": records,
        "delete": sorted(delete or []),
    }
    signature = private_key.sign(update_manager._canonical_manifest_payload(manifest))
    manifest["signature"] = {
        "algorithm": "ed25519",
        "value": base64.b64encode(signature).decode(),
    }
    return manifest


def make_release_zip(
    destination: Path,
    *,
    version="1.1.0",
    requirements="requests>=2.31\n",
    delete=None,
    private_key=TEST_PRIVATE_KEY,
    archive_overrides=None,
    extra_entries=None,
):
    files = release_files(version, requirements)
    manifest = signed_manifest(files, version, delete, private_key)
    archived = {**files, **(archive_overrides or {})}
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        root = "czppw-outlook-mail-manager-release"
        for name, content in archived.items():
            archive.writestr(f"{root}/{name}", content)
        archive.writestr(
            f"{root}/{update_manager.MANIFEST_FILENAME}",
            json.dumps(manifest, indent=2, sort_keys=True).encode(),
        )
        for entry in extra_entries or []:
            if isinstance(entry, zipfile.ZipInfo):
                archive.writestr(entry, b"link target")
            else:
                name, content = entry
                archive.writestr(name, content)
    return manifest


class SemVerTests(unittest.TestCase):
    def test_semver_precedence_and_strict_parsing(self):
        parse = update_manager.SemVer.parse
        self.assertLess(parse("1.0.0-alpha"), parse("1.0.0-alpha.1"))
        self.assertLess(parse("1.0.0-rc.1"), parse("1.0.0"))
        self.assertLess(parse("1.0.9"), parse("1.1.0"))
        self.assertEqual(parse("1.0.0+build.1"), parse("1.0.0+build.2"))
        self.assertEqual(str(parse("v2.3.4-rc.1+linux")), "2.3.4-rc.1+linux")
        for value in ("1", "1.0", "01.0.0", "1.0.0-01", "1.0.0 ", "V1.0.0"):
            with self.subTest(value=value), self.assertRaises(update_manager.VersionError):
                parse(value)


class NetworkTests(unittest.TestCase):
    def setUp(self):
        update_manager._release_cache.clear()

    def test_latest_release_uses_proxy_timeout_retries_and_cache(self):
        payload = json.dumps(
            {
                "tag_name": "v1.1.0",
                "zipball_url": "https://api.github.com/repos/czppw/outlook-mail-manager/zipball/v1.1.0",
                "html_url": "https://github.com/czppw/outlook-mail-manager/releases/tag/v1.1.0",
                "name": "Release 1.1.0",
                "body": "notes",
                "published_at": "2026-07-27T00:00:00Z",
            }
        ).encode()
        sessions = [
            FakeSession([FakeResponse(content=payload, url=update_manager.LATEST_RELEASE_API)]),
            FakeSession([FakeResponse(content=payload, url=update_manager.LATEST_RELEASE_API)]),
        ]
        proxy = {"https": "socks5h://user:pass@127.0.0.1:1080"}
        with (
            mock.patch.object(update_manager, "_make_session", side_effect=sessions),
            mock.patch.object(update_manager.time, "monotonic", side_effect=[100, 999, 1001]),
        ):
            first = update_manager._fetch_latest_release(proxy)
            cached = update_manager._fetch_latest_release(proxy)
            expired = update_manager._fetch_latest_release(proxy)
        self.assertIs(first, cached)
        self.assertEqual(str(expired.version), "1.1.0")
        _, kwargs = sessions[0].calls[0]
        self.assertEqual(kwargs["proxies"], proxy)
        self.assertFalse(sessions[0].trust_env)
        self.assertEqual(kwargs["timeout"], (5, 30))
        self.assertTrue(kwargs["verify"])
        self.assertFalse(kwargs["allow_redirects"])
        real_session = update_manager._make_session()
        try:
            self.assertEqual(real_session.headers["User-Agent"], update_manager.USER_AGENT)
            self.assertEqual(real_session.get_adapter("https://").max_retries.total, 2)
        finally:
            real_session.close()

    def test_unapproved_redirect_is_not_followed(self):
        response = FakeResponse(
            status_code=302,
            headers={"Location": "https://attacker.example/release.zip"},
            url=update_manager.LATEST_RELEASE_API,
        )
        session = FakeSession([response])
        with self.assertRaises(update_manager.NetworkError):
            update_manager._safe_get(session, update_manager.LATEST_RELEASE_API, None)
        self.assertEqual(len(session.calls), 1)

    def test_download_passes_string_proxy(self):
        response = FakeResponse(
            content=b"zip-content",
            url="https://codeload.github.com/czppw/outlook-mail-manager/zip/v1.1.0",
        )
        session = FakeSession([response])
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            update_manager, "_make_session", return_value=session
        ):
            destination = Path(directory) / "release.zip"
            update_manager._download_zipball(
                response.url, destination, "http://127.0.0.1:7890"
            )
        self.assertEqual(
            session.calls[0][1]["proxies"],
            {"http": "http://127.0.0.1:7890", "https": "http://127.0.0.1:7890"},
        )


class ManifestAndArchiveTests(unittest.TestCase):
    def test_valid_signed_manifest_allows_new_root_module(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "release.zip"
            make_release_zip(archive)
            stage = root / "stage"
            stage.mkdir()
            with mock.patch.object(
                update_manager, "UPDATE_SIGNING_PUBLIC_KEY_B64", TEST_PUBLIC_KEY_B64
            ):
                manifest = update_manager._stage_archive(archive, stage)
            self.assertIn("new_feature.py", manifest.files)
            self.assertEqual((stage / "new_feature.py").read_bytes(), b"FEATURE = True\n")

    def test_rejects_invalid_signature_and_hash_mismatch(self):
        other_key = Ed25519PrivateKey.from_private_bytes(b"x" * 32)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bad_signature = root / "signature.zip"
            bad_hash = root / "hash.zip"
            make_release_zip(bad_signature, private_key=other_key)
            make_release_zip(
                bad_hash,
                archive_overrides={"app.py": b"tampered after signing\n"},
            )
            with mock.patch.object(
                update_manager, "UPDATE_SIGNING_PUBLIC_KEY_B64", TEST_PUBLIC_KEY_B64
            ):
                for archive in (bad_signature, bad_hash):
                    stage = root / f"stage-{archive.stem}"
                    stage.mkdir()
                    with self.subTest(archive=archive.name), self.assertRaises(
                        update_manager.ManifestError
                    ):
                        update_manager._stage_archive(archive, stage)

    def test_rejects_traversal_absolute_path_symlink_and_oversize(self):
        symlink = zipfile.ZipInfo("czppw-outlook-mail-manager-release/static/link")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        attacks = [
            ("czppw-outlook-mail-manager-release/../../escaped.txt", b"bad"),
            ("/absolute.txt", b"bad"),
            ("C:/windows/path.txt", b"bad"),
            ("czppw-outlook-mail-manager-release/static/style.css:payload", b"bad"),
            symlink,
        ]
        for index, attack in enumerate(attacks):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive = root / "attack.zip"
                make_release_zip(archive, extra_entries=[attack])
                stage = root / "stage"
                stage.mkdir()
                with mock.patch.object(
                    update_manager, "UPDATE_SIGNING_PUBLIC_KEY_B64", TEST_PUBLIC_KEY_B64
                ), self.assertRaises(update_manager.UnsafeArchiveError):
                    update_manager._stage_archive(archive, stage)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "large.zip"
            make_release_zip(archive)
            stage = root / "stage"
            stage.mkdir()
            with (
                mock.patch.object(update_manager, "MAX_EXTRACTED_BYTES", 5),
                mock.patch.object(
                    update_manager, "UPDATE_SIGNING_PUBLIC_KEY_B64", TEST_PUBLIC_KEY_B64
                ),
                self.assertRaises(update_manager.UnsafeArchiveError),
            ):
                update_manager._stage_archive(archive, stage)


class ApplyUpdateTests(unittest.TestCase):
    def _patch_apply(self, project: Path, archive: Path, version="1.1.0"):
        def copy_archive(url, destination, proxy):
            self.assertTrue(destination.is_relative_to(project / update_manager.STATE_DIRECTORY_NAME))
            shutil.copyfile(archive, destination)

        return (
            mock.patch.object(update_manager, "PROJECT_ROOT", project),
            mock.patch.object(
                update_manager, "UPDATE_SIGNING_PUBLIC_KEY_B64", TEST_PUBLIC_KEY_B64
            ),
            mock.patch.object(
                update_manager, "_fetch_latest_release", return_value=release_info(version)
            ),
            mock.patch.object(
                update_manager, "_download_zipball", side_effect=copy_archive
            ),
        )

    def test_signed_update_adds_deletes_and_preserves_unknown_local_data(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            project = parent / "project"
            write_project(project)
            preserved = {
                "data.db": b"database",
                ".env": b"secret",
                "server.pem": b"key",
                "local_script.py": b"unknown",
                "templates/custom-local.html": b"custom",
                "static/user-local.css": b"custom css",
            }
            for name, content in preserved.items():
                path = project / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            archive = parent / "release.zip"
            make_release_zip(archive, delete=["static/obsolete.js"])
            patches = self._patch_apply(project, archive)
            with patches[0], patches[1], patches[2] as fetch, patches[3]:
                result = update_manager.apply_update(
                    "1.1.0", {"https": "http://127.0.0.1:7890"}
                )
            fetch.assert_called_once_with(
                {"https": "http://127.0.0.1:7890"}, use_cache=False
            )
            self.assertTrue(result["updated"])
            self.assertEqual((project / "VERSION").read_text(), "1.1.0\n")
            self.assertEqual((project / "new_feature.py").read_bytes(), b"FEATURE = True\n")
            self.assertFalse((project / "static/obsolete.js").exists())
            for name, content in preserved.items():
                self.assertEqual((project / name).read_bytes(), content)
            self.assertTrue((project / update_manager.MANIFEST_FILENAME).is_file())
            self.assertTrue((project / update_manager.RUNTIME_MARKER_FILENAME).is_file())
            self.assertFalse((project / update_manager.STATE_DIRECTORY_NAME / "transaction.json").exists())

    def test_signed_manifest_cannot_overwrite_or_delete_unknown_file(self):
        for mode in ("overwrite", "delete"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                project = parent / "project"
                write_project(project)
                (project / "local_script.py").write_text("local", encoding="utf-8")
                archive = parent / "release.zip"
                files = release_files()
                delete = []
                if mode == "overwrite":
                    files["local_script.py"] = b"release"
                else:
                    delete = ["local_script.py"]
                manifest = signed_manifest(files, delete=delete)
                with zipfile.ZipFile(archive, "w") as output:
                    prefix = "czppw-outlook-mail-manager-release"
                    for name, content in files.items():
                        output.writestr(f"{prefix}/{name}", content)
                    output.writestr(f"{prefix}/UPDATE_MANIFEST.json", json.dumps(manifest))
                patches = self._patch_apply(project, archive)
                with patches[0], patches[1], patches[2], patches[3], self.assertRaisesRegex(
                    update_manager.ManifestError, "unknown local file"
                ):
                    update_manager.apply_update("1.1.0")
                self.assertEqual((project / "local_script.py").read_text(), "local")

    def test_keyboard_interrupt_leaves_journal_and_recovery_restores_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            project = parent / "project"
            write_project(project)
            archive = parent / "release.zip"
            make_release_zip(archive, delete=["static/obsolete.js"])
            real_atomic_install = update_manager._atomic_install

            def crash_on_app(source, destination):
                if destination == project / "app.py":
                    raise KeyboardInterrupt("simulated process termination")
                return real_atomic_install(source, destination)

            patches = self._patch_apply(project, archive)
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                mock.patch.object(
                    update_manager, "_atomic_install", side_effect=crash_on_app
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                update_manager.apply_update("1.1.0")
            journal = project / update_manager.STATE_DIRECTORY_NAME / "transaction.json"
            self.assertTrue(journal.is_file())
            self.assertEqual((project / "db.py").read_text(), "DB = 'new'\n")
            with (
                mock.patch.object(update_manager, "PROJECT_ROOT", project),
                mock.patch.object(
                    update_manager, "UPDATE_SIGNING_PUBLIC_KEY_B64", TEST_PUBLIC_KEY_B64
                ),
            ):
                self.assertTrue(update_manager.recover_interrupted_update())
            self.assertEqual((project / "VERSION").read_text(), "1.0.0\n")
            self.assertEqual((project / "db.py").read_text(), "DB = 'old'\n")
            self.assertEqual((project / "app.py").read_text(), "APP = 'old'\n")
            self.assertTrue((project / "static/obsolete.js").is_file())
            self.assertFalse((project / "new_feature.py").exists())
            self.assertFalse(journal.exists())

    def test_requirements_use_new_versioned_venv_and_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            project = parent / "project"
            write_project(project)
            current_python = project / "venv" / "current-python-sentinel"
            current_python.parent.mkdir()
            current_python.write_text("untouched", encoding="utf-8")
            archive = parent / "release.zip"
            make_release_zip(archive, requirements="requests==2.34.2\nnew-package==1.0\n")

            def fake_venv_create(_builder, destination):
                python = update_manager._venv_python(Path(destination))
                python.parent.mkdir(parents=True)
                python.write_text("python", encoding="utf-8")

            patches = self._patch_apply(project, archive)
            proxy = "socks5h://127.0.0.1:1080"
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                mock.patch.object(update_manager.venv.EnvBuilder, "create", fake_venv_create),
                mock.patch.object(update_manager.subprocess, "run") as run,
            ):
                update_manager.apply_update("1.1.0", proxy)
            final_venv = project / update_manager.VENV_DIRECTORY_NAME / "1.1.0"
            final_python = update_manager._venv_python(final_venv)
            self.assertTrue(final_python.is_file())
            self.assertEqual(current_python.read_text(), "untouched")
            command = run.call_args.args[0]
            self.assertIn(update_manager.VENV_DIRECTORY_NAME, command[0])
            self.assertNotEqual(Path(command[0]), Path(sys.executable))
            self.assertIn("--require-hashes", command)
            self.assertTrue(command[-1].endswith("requirements.lock"))
            self.assertEqual(run.call_args.kwargs["env"]["HTTPS_PROXY"], proxy)
            site_packages = (
                final_venv / "Lib" / "site-packages"
                if os.name == "nt"
                else final_venv
                / "lib"
                / f"python{sys.version_info.major}.{sys.version_info.minor}"
                / "site-packages"
            )
            self.assertTrue((site_packages / "socks.py").is_file())
            marker = json.loads(
                (project / update_manager.RUNTIME_MARKER_FILENAME).read_text()
            )
            self.assertEqual(marker["version"], "1.1.0")
            self.assertEqual(Path(marker["python"]), final_python.relative_to(project))
            self.assertEqual(launcher.select_python_executable(project), final_python)

    def test_explicit_direct_mode_clears_proxy_environment_for_pip(self):
        with mock.patch.dict(
            os.environ,
            {
                "HTTP_PROXY": "http://environment-proxy.invalid:8080",
                "HTTPS_PROXY": "http://environment-proxy.invalid:8080",
                "ALL_PROXY": "socks5://environment-proxy.invalid:1080",
                "PIP_PROXY": "http://environment-proxy.invalid:8080",
            },
            clear=True,
        ):
            environment = update_manager._proxy_environment("")
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "PIP_PROXY"):
            self.assertNotIn(name, environment)

    def test_failed_dependency_install_removes_new_venv_and_keeps_source(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            project = parent / "project"
            write_project(project)
            archive = parent / "release.zip"
            make_release_zip(archive, requirements="different==1\n")

            def fake_venv_create(_builder, destination):
                python = update_manager._venv_python(Path(destination))
                python.parent.mkdir(parents=True)
                python.write_text("python", encoding="utf-8")

            patches = self._patch_apply(project, archive)
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                mock.patch.object(update_manager.venv.EnvBuilder, "create", fake_venv_create),
                mock.patch.object(
                    update_manager.subprocess,
                    "run",
                    side_effect=subprocess.CalledProcessError(1, ["pip"]),
                ),
                self.assertRaisesRegex(update_manager.UpdateError, "dependency installation failed"),
            ):
                update_manager.apply_update("1.1.0")
            self.assertEqual((project / "VERSION").read_text(), "1.0.0\n")
            self.assertEqual((project / "app.py").read_text(), "APP = 'old'\n")
            venv_parent = project / update_manager.VENV_DIRECTORY_NAME
            self.assertEqual(list(venv_parent.iterdir()), [])

    def test_critical_files_are_replaced_last(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            project = parent / "project"
            write_project(project)
            archive = parent / "release.zip"
            make_release_zip(archive)
            installed = []
            real_atomic_install = update_manager._atomic_install

            def record_install(source, destination):
                installed.append(destination.name)
                return real_atomic_install(source, destination)

            patches = self._patch_apply(project, archive)
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                mock.patch.object(
                    update_manager, "_atomic_install", side_effect=record_install
                ),
            ):
                update_manager.apply_update("1.1.0")
            self.assertEqual(installed[-3:], ["app.py", "update_manager.py", "VERSION"])


class LockAndLauncherTests(unittest.TestCase):
    def test_application_instance_lock_is_cross_process(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project"
            project.mkdir()
            code = (
                "import pathlib,sys,time,update_manager;"
                "update_manager.PROJECT_ROOT=pathlib.Path(sys.argv[1]);"
                "lock=update_manager.application_instance_lock();lock.__enter__();"
                "print('ready',flush=True);time.sleep(30)"
            )
            environment = os.environ.copy()
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            child = subprocess.Popen(
                [sys.executable, "-c", code, str(project)],
                cwd=Path(update_manager.__file__).parent,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertEqual(child.stdout.readline().strip(), "ready")
                with (
                    mock.patch.object(update_manager, "PROJECT_ROOT", project),
                    self.assertRaises(update_manager.ApplicationInstanceError),
                    update_manager.application_instance_lock(),
                ):
                    pass
            finally:
                child.terminate()
                child.wait(timeout=5)

    def test_restart_uses_committed_marker_interpreter(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project"
            project.mkdir()
            (project / "VERSION").write_text("1.1.0\n", encoding="ascii")
            final_venv = project / ".omm-venvs" / "1.1.0"
            python = update_manager._venv_python(final_venv)
            python.parent.mkdir(parents=True)
            python.write_text("python", encoding="utf-8")
            marker = {
                "schema_version": 1,
                "version": "1.1.0",
                "python": python.relative_to(project).as_posix(),
            }
            (project / launcher.RUNTIME_MARKER_FILENAME).write_text(json.dumps(marker))
            with (
                mock.patch.object(update_manager, "PROJECT_ROOT", project),
                mock.patch.object(sys, "argv", ["app.py", "--port", "8899"]),
                mock.patch.object(update_manager.os, "execv") as execv,
            ):
                update_manager.restart_current_process()
            execv.assert_called_once_with(
                str(python), [str(python), "app.py", "--port", "8899"]
            )

    def test_launcher_falls_back_to_project_venv_for_stale_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "VERSION").write_text("1.0.0", encoding="ascii")
            default = (
                project / "venv" / "Scripts" / "python.exe"
                if os.name == "nt"
                else project / "venv" / "bin" / "python"
            )
            default.parent.mkdir(parents=True)
            default.write_text("python", encoding="utf-8")
            (project / launcher.RUNTIME_MARKER_FILENAME).write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "version": "9.9.9",
                        "python": ".omm-venvs/9.9.9/bin/python",
                    }
                )
            )
            self.assertEqual(launcher.select_python_executable(project), default)


class ManifestBuilderTests(unittest.TestCase):
    def test_builder_hashes_files_signs_and_calculates_deletions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = release_files()
            files["launcher.py"] = Path(launcher.__file__).read_bytes()
            files["update_manager.py"] = Path(update_manager.__file__).read_bytes()
            for name, content in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            previous = root / "previous.json"
            previous.write_text(
                json.dumps({"files": {"static/removed.js": {}, "app.py": {}}})
            )
            tracked = [PurePosixPath(name) for name in files]
            manifest = build_update_manifest.build_manifest(
                root,
                TEST_PRIVATE_KEY,
                version="1.1.0",
                previous_manifest=previous,
                tracked_paths=tracked,
            )
            self.assertEqual(manifest["delete"], ["static/removed.js"])
            self.assertEqual(
                manifest["files"]["new_feature.py"]["sha256"],
                update_manager.hashlib.sha256(files["new_feature.py"]).hexdigest(),
            )
            raw = json.dumps(manifest).encode()
            with mock.patch.object(
                update_manager, "UPDATE_SIGNING_PUBLIC_KEY_B64", TEST_PUBLIC_KEY_B64
            ):
                parsed = update_manager._parse_manifest(raw)
            self.assertEqual(str(parsed.release_version), "1.1.0")

    def test_generate_key_writes_loadable_private_and_public_files(self):
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / "release-signing.pem"
            public = Path(directory) / "release-signing.pub"
            build_update_manifest.generate_key(private, public)
            loaded = build_update_manifest.load_private_key(private)
            self.assertEqual(
                public.read_text().strip(),
                build_update_manifest.public_key_base64(loaded),
            )


if __name__ == "__main__":
    unittest.main()
