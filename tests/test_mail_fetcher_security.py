import asyncio
import imaplib
import json
import logging
import os
import sys
import types
import unittest
from email.message import EmailMessage
from unittest import mock

import requests

import mail_fetcher


class FakeResponse:
    def __init__(
        self,
        status_code=200,
        payload=None,
        headers=None,
        raw_body=None,
        chunks=None,
    ):
        self.status_code = status_code
        self._payload = {"value": []} if payload is None else payload
        self.headers = headers or {}
        self.raw_body = (
            json.dumps(self._payload).encode("utf-8")
            if raw_body is None
            else raw_body
        )
        self.chunks = chunks
        self.closed = False
        self.iterated = False

    def json(self):
        return self._payload

    def iter_content(self, chunk_size=1):
        self.iterated = True
        if self.chunks is not None:
            yield from self.chunks
            return
        for offset in range(0, len(self.raw_body), chunk_size):
            yield self.raw_body[offset : offset + chunk_size]

    def close(self):
        self.closed = True


class FakeFolderIMAP:
    def __init__(self, raw_messages=None, uidvalidity=b"777", search_uids=None):
        self.raw_messages = raw_messages or {}
        self.uidvalidity = uidvalidity
        self.search_uids = search_uids
        self.calls = []

    def select(self, folder, readonly=False):
        self.calls.append(("SELECT", folder, readonly))
        return "OK", [b"1"]

    def response(self, name):
        self.calls.append(("RESPONSE", name))
        return "UIDVALIDITY", [self.uidvalidity]

    def uid(self, command, *args):
        self.calls.append((command, *args))
        if command == "SEARCH":
            if self.search_uids is not None:
                return "OK", [self.search_uids]
            values = b" ".join(str(uid).encode("ascii") for uid in self.raw_messages)
            return "OK", [values]
        if command != "FETCH":
            raise AssertionError(f"Unexpected UID command: {command}")

        uid = int(args[0])
        query = args[1]
        value = self.raw_messages[uid]
        if query == "(RFC822.SIZE)":
            size = value if isinstance(value, int) else len(value)
            return "OK", [f"1 (UID {uid} RFC822.SIZE {size})".encode("ascii")]
        if query == "(BODY.PEEK[])":
            if isinstance(value, int):
                raise AssertionError("Oversized messages must not be downloaded")
            return "OK", [(f"1 (UID {uid} BODY[] {{{len(value)}}})".encode(), value)]
        raise AssertionError(f"Unexpected FETCH query: {query}")


class MailFetcherSecurityTests(unittest.TestCase):
    def test_imap_tls_context_verifies_direct_and_proxy_connections(self):
        class Context:
            check_hostname = False
            verify_mode = None

        direct_context = Context()
        with (
            mock.patch.object(
                mail_fetcher.ssl,
                "create_default_context",
                return_value=direct_context,
            ),
            mock.patch.object(mail_fetcher.imaplib, "IMAP4_SSL") as direct,
        ):
            mail_fetcher._open_imap("imap.example.test", 993)

        self.assertTrue(direct_context.check_hostname)
        self.assertEqual(direct_context.verify_mode, mail_fetcher.ssl.CERT_REQUIRED)
        direct.assert_called_once_with(
            "imap.example.test",
            993,
            ssl_context=direct_context,
            timeout=mail_fetcher.IMAP_TIMEOUT,
        )

        proxy_context = Context()
        with (
            mock.patch.object(
                mail_fetcher.ssl,
                "create_default_context",
                return_value=proxy_context,
            ),
            mock.patch.object(mail_fetcher, "_ProxyIMAP4SSL") as proxied,
        ):
            mail_fetcher._open_imap(
                "imap.example.test",
                993,
                proxy="socks5h://proxy.example.test:1080",
            )

        self.assertTrue(proxy_context.check_hostname)
        self.assertEqual(proxy_context.verify_mode, mail_fetcher.ssl.CERT_REQUIRED)
        proxied.assert_called_once_with(
            "imap.example.test",
            993,
            "socks5h://proxy.example.test:1080",
            ssl_context=proxy_context,
            timeout=mail_fetcher.IMAP_TIMEOUT,
        )

    def test_xoauth2_callback_bytes_are_not_preencoded(self):
        auth = mail_fetcher.build_xoauth2_auth("user@example.test", "access-secret")
        self.assertEqual(
            auth,
            b"user=user@example.test\x01auth=Bearer access-secret\x01\x01",
        )

    def test_proxy_uses_pysocks_parameter_names_and_dns_mode(self):
        calls = []

        class RawSocket:
            closed = False

            def close(self):
                self.closed = True

        raw_socket = RawSocket()

        def create_connection(destination, **kwargs):
            calls.append((destination, kwargs))
            return raw_socket

        fake_socks = types.SimpleNamespace(
            SOCKS5=2,
            SOCKS4=1,
            HTTP=3,
            create_connection=create_connection,
        )

        class Context:
            def wrap_socket(self, sock, server_hostname):
                return (sock, server_hostname)

        connection = object.__new__(mail_fetcher._ProxyIMAP4SSL)
        connection.host = "imap.example.test"
        connection.port = 993
        connection.timeout = mail_fetcher.IMAP_TIMEOUT
        connection.ssl_context = Context()

        with mock.patch.dict(sys.modules, {"socks": fake_socks}):
            connection._proxy_url = "socks5h://user%40x:p%3Ass@proxy.test:1081"
            wrapped = connection._create_socket(7)
            parsed_socks5 = mail_fetcher._parse_proxy("socks5://proxy.test:1080")
            parsed_socks5h = mail_fetcher._parse_proxy("socks5h://proxy.test:1080")

        self.assertEqual(wrapped, (raw_socket, "imap.example.test"))
        self.assertEqual(calls[0][0], ("imap.example.test", 993))
        self.assertEqual(
            calls[0][1],
            {
                "timeout": 7,
                "proxy_type": 2,
                "proxy_addr": "proxy.test",
                "proxy_port": 1081,
                "proxy_rdns": True,
                "proxy_username": "user@x",
                "proxy_password": "p:ss",
            },
        )
        self.assertFalse(parsed_socks5["rdns"])
        self.assertTrue(parsed_socks5h["rdns"])

    def test_uid_fetch_uses_uidvalidity_limits_size_and_skips_attachments(self):
        message = EmailMessage()
        message["From"] = "Sender <sender@example.test>"
        message["Subject"] = "UID test"
        message.set_content("visible body")
        message.add_attachment("attachment secret", filename="secret.txt")
        raw = message.as_bytes()
        imap = FakeFolderIMAP(
            raw_messages={501: raw, 502: mail_fetcher.MAX_EMAIL_BYTES + 1}
        )

        result = mail_fetcher.fetch_folder_emails(imap, "INBOX", limit=10)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["uid"], "777:501")
        self.assertIn("visible body", result[0]["body"])
        self.assertNotIn("attachment secret", result[0]["body"])
        self.assertIn(("SEARCH", None, "ALL"), imap.calls)
        self.assertIn(("FETCH", b"501", "(RFC822.SIZE)"), imap.calls)
        self.assertIn(("FETCH", b"501", "(BODY.PEEK[])"), imap.calls)
        self.assertIn(("FETCH", b"502", "(RFC822.SIZE)"), imap.calls)
        self.assertNotIn(("FETCH", b"502", "(BODY.PEEK[])"), imap.calls)

    def test_imap_rechecks_actual_body_size_after_declared_size(self):
        class MisreportingIMAP(FakeFolderIMAP):
            def uid(self, command, *args):
                if command == "FETCH" and args[1] == "(RFC822.SIZE)":
                    self.calls.append((command, *args))
                    return "OK", [b"1 (UID 7 RFC822.SIZE 1)"]
                return super().uid(command, *args)

        raw = b"x" * 17
        imap = MisreportingIMAP({7: raw})
        stats = {}
        with mock.patch.object(mail_fetcher, "MAX_EMAIL_BYTES", 16):
            result = mail_fetcher.fetch_folder_emails(
                imap, "INBOX", limit=10, stats=stats
            )

        self.assertEqual(result, [])
        self.assertEqual(stats, {"oversized": 1})
        self.assertIn(("FETCH", b"7", "(BODY.PEEK[])"), imap.calls)

    def test_nested_attached_message_is_not_used_as_outer_body(self):
        attached = EmailMessage()
        attached["From"] = "inside@example.test"
        attached["Subject"] = "attached secret"
        attached.set_content("ATTACHED-SECRET-BODY")
        outer = EmailMessage()
        outer["From"] = "sender@example.test"
        outer["Subject"] = "outer"
        outer.make_mixed()
        outer.add_attachment(attached)

        decoded = mail_fetcher._decode_message(outer.as_bytes())

        self.assertEqual(decoded["body"], "")
        self.assertEqual(decoded["body_html"], "")
        self.assertNotIn("ATTACHED-SECRET-BODY", str(decoded))

    def test_select_search_and_fetch_connection_errors_propagate(self):
        class SelectFailure(FakeFolderIMAP):
            def select(self, folder, readonly=False):
                raise imaplib.IMAP4.abort("connection lost during SELECT")

        class SearchFailure(FakeFolderIMAP):
            def uid(self, command, *args):
                if command == "SEARCH":
                    raise imaplib.IMAP4.abort("connection lost during SEARCH")
                return super().uid(command, *args)

        class FetchFailure(FakeFolderIMAP):
            def uid(self, command, *args):
                if command == "FETCH":
                    raise imaplib.IMAP4.abort("connection lost during FETCH")
                return super().uid(command, *args)

        for connection in (
            SelectFailure({1: b"message"}),
            SearchFailure({1: b"message"}),
            FetchFailure({1: b"message"}),
        ):
            with (
                self.subTest(connection=type(connection).__name__),
                self.assertRaises(imaplib.IMAP4.abort),
            ):
                mail_fetcher.fetch_folder_emails(connection, "INBOX")

    def test_malformed_message_is_counted_and_folder_is_not_reported_successful(self):
        imap = FakeFolderIMAP({9: b"malformed"})
        with (
            mock.patch.object(
                mail_fetcher,
                "_decode_message",
                side_effect=ValueError("bad MIME"),
            ),
            self.assertRaises(mail_fetcher.FolderFetchError) as caught,
        ):
            mail_fetcher.fetch_folder_emails(imap, "INBOX")

        self.assertEqual(caught.exception.failed_count, 1)
        self.assertEqual(caught.exception.partial_emails, [])

    def test_imap_connection_is_closed_on_authentication_failure(self):
        class Connection:
            logout_called = False

            def authenticate(self, mechanism, callback):
                callback(b"")
                raise imaplib.IMAP4.error("server echoed access-token-sentinel")

            def logout(self):
                self.logout_called = True

        connection = Connection()
        with (
            mock.patch.object(mail_fetcher, "_open_imap", return_value=connection),
            self.assertRaisesRegex(
                RuntimeError, "XOAUTH2 authentication failed"
            ) as caught,
        ):
            mail_fetcher._fetch_via_imap_with_access_token(
                "user@example.test",
                "access-secret",
                "microsoft",
                "",
                1,
            )
        self.assertTrue(connection.logout_called)
        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn("access-token-sentinel", str(caught.exception))

    def test_imap_shutdown_is_used_when_logout_fails(self):
        class Connection:
            shutdown_called = False

            def logout(self):
                raise OSError("socket already broken")

            def shutdown(self):
                self.shutdown_called = True

        connection = Connection()
        mail_fetcher._close_imap(connection)
        self.assertTrue(connection.shutdown_called)

    def test_graph_retries_429_408_and_5xx_with_finite_backoff(self):
        responses = [
            FakeResponse(429, headers={"Retry-After": "2"}),
            FakeResponse(503),
            FakeResponse(200),
            FakeResponse(408),
            FakeResponse(200),
        ]
        with (
            mock.patch.object(
                mail_fetcher.requests, "get", side_effect=responses
            ) as get,
            mock.patch.object(mail_fetcher.time, "sleep") as sleep,
        ):
            result = mail_fetcher._fetch_via_graph_with_access_token(
                "user@example.test",
                "access-secret",
                "",
                5,
            )

        self.assertEqual(result, {"INBOX": [], "JUNK": []})
        self.assertEqual(get.call_count, 5)
        self.assertEqual(
            [call.args[0] for call in sleep.call_args_list], [2.0, 1.0, 0.5]
        )

        failures = [
            FakeResponse(500) for _attempt in range(mail_fetcher.GRAPH_MAX_ATTEMPTS)
        ]
        with (
            mock.patch.object(
                mail_fetcher.requests,
                "get",
                side_effect=failures,
            ) as get,
            mock.patch.object(mail_fetcher.time, "sleep"),
            self.assertRaisesRegex(RuntimeError, r"Graph request failed \(500\)"),
        ):
            mail_fetcher._graph_get("https://graph.test", {}, {}, None)
        self.assertEqual(get.call_count, mail_fetcher.GRAPH_MAX_ATTEMPTS)

    def test_graph_retries_transient_network_error(self):
        success = FakeResponse(200)
        with (
            mock.patch.object(
                mail_fetcher.requests,
                "get",
                side_effect=[requests.Timeout("slow"), success],
            ) as get,
            mock.patch.object(mail_fetcher.time, "sleep") as sleep,
        ):
            payload = mail_fetcher._graph_get("https://graph.test", {}, {}, None)
        self.assertEqual(payload, {"value": []})
        self.assertEqual(get.call_count, 2)
        sleep.assert_called_once_with(mail_fetcher.GRAPH_BACKOFF_BASE)

    def test_graph_does_not_retry_permanent_request_errors(self):
        permanent_errors = (
            requests.exceptions.SSLError("certificate failed"),
            requests.exceptions.ProxyError("proxy rejected"),
            requests.exceptions.InvalidURL("bad URL"),
            requests.exceptions.InvalidSchema("bad schema"),
        )
        for error in permanent_errors:
            with (
                self.subTest(error=type(error).__name__),
                mock.patch.object(
                    mail_fetcher.requests, "get", side_effect=error
                ) as get,
                mock.patch.object(mail_fetcher.time, "sleep") as sleep,
                self.assertRaisesRegex(RuntimeError, "configuration error"),
            ):
                mail_fetcher._graph_get("https://graph.test", {}, {}, None)
            get.assert_called_once()
            sleep.assert_not_called()

    def test_graph_long_retry_after_returns_retry_later_without_sleeping(self):
        throttled = FakeResponse(429, headers={"Retry-After": "60"})
        with (
            mock.patch.object(
                mail_fetcher.requests, "get", return_value=throttled
            ) as get,
            mock.patch.object(mail_fetcher.time, "sleep") as sleep,
            self.assertRaisesRegex(RuntimeError, "retry after 60 seconds"),
        ):
            mail_fetcher._graph_get("https://graph.test", {}, {}, None)
        get.assert_called_once()
        sleep.assert_not_called()

    def test_staged_async_apis_refresh_then_fetch_without_refreshing_again(self):
        with mock.patch.object(
            mail_fetcher,
            "get_access_token",
            return_value=("access-secret", "rotated-refresh-secret"),
        ) as refresh:
            tokens = asyncio.run(
                mail_fetcher.refresh_access_token(
                    "client-id",
                    "refresh-secret",
                    provider_key="microsoft",
                    fetch_mode="graph",
                    proxy="http://proxy.test:8080",
                )
            )

        self.assertEqual(tokens, ("access-secret", "rotated-refresh-secret"))
        self.assertIn(
            "Mail.Read",
            refresh.call_args.kwargs["scope_override"],
        )

        expected = {"INBOX": [], "JUNK": []}
        with (
            mock.patch.object(
                mail_fetcher,
                "_fetch_via_graph_with_access_token",
                return_value=expected,
            ) as fetch,
            mock.patch.object(
                mail_fetcher,
                "get_access_token",
                side_effect=AssertionError("staged fetch must not refresh"),
            ),
        ):
            actual = asyncio.run(
                mail_fetcher.check_account_with_access_token(
                    "user@example.test",
                    "access-secret",
                    fetch_mode="graph",
                )
            )
        self.assertEqual(actual, expected)
        fetch.assert_called_once_with(
            "user@example.test",
            "access-secret",
            None,
            50,
        )

    def test_empty_rotated_token_is_ignored_and_empty_proxy_means_direct(self):
        response = FakeResponse(
            payload={"access_token": "access-secret", "refresh_token": ""}
        )
        with (
            mock.patch.dict(
                os.environ, {"OMM_PROXY": "http://environment-proxy.test:8080"}
            ),
            mock.patch.object(
                mail_fetcher.requests, "post", return_value=response
            ) as post,
        ):
            tokens = mail_fetcher.get_access_token(
                "client-id", "existing-refresh", proxy=""
            )
            direct_proxies = post.call_args.kwargs["proxies"]
            mail_fetcher.get_access_token("client-id", "existing-refresh", proxy=None)
            environment_proxies = post.call_args.kwargs["proxies"]

        self.assertEqual(tokens, ("access-secret", "existing-refresh"))
        self.assertEqual(
            direct_proxies, {"http": None, "https": None, "all": None}
        )
        self.assertEqual(
            environment_proxies,
            {
                "http": "http://environment-proxy.test:8080",
                "https": "http://environment-proxy.test:8080",
            },
        )

    def test_partial_imap_fetch_preserves_valid_messages_and_reports_oversized(self):
        message = EmailMessage()
        message["From"] = "sender@example.test"
        message["Subject"] = "valid"
        message.set_content("body")

        class Connection(FakeFolderIMAP):
            def authenticate(self, mechanism, callback):
                callback(b"")
                return "OK", []

            def list(self):
                return "OK", []

            def logout(self):
                return "BYE", []

        connection = Connection(
            {1: message.as_bytes(), 2: mail_fetcher.MAX_EMAIL_BYTES + 1}
        )
        with (
            mock.patch.object(mail_fetcher, "_open_imap", return_value=connection),
            self.assertRaises(mail_fetcher.MailboxFetchError) as caught,
        ):
            mail_fetcher._fetch_via_imap_with_access_token(
                "user@example.test", "access-secret", "microsoft", "", 10
            )

        self.assertEqual(len(caught.exception.partial_results["INBOX"]), 1)
        self.assertEqual(len(caught.exception.partial_results["JUNK"]), 1)
        self.assertTrue(any("oversized" in issue for issue in caught.exception.issues))

    def test_tokens_are_not_written_to_logs(self):
        records = []

        class Handler(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())

        handler = Handler()
        mail_fetcher.logger.addHandler(handler)
        old_level = mail_fetcher.logger.level
        mail_fetcher.logger.setLevel(logging.INFO)
        try:
            with mock.patch.object(
                mail_fetcher.requests,
                "get",
                side_effect=[FakeResponse(200), FakeResponse(200)],
            ):
                mail_fetcher._fetch_via_graph_with_access_token(
                    "user@example.test",
                    "access-token-sentinel",
                    "",
                    1,
                )
        finally:
            mail_fetcher.logger.setLevel(old_level)
            mail_fetcher.logger.removeHandler(handler)

        joined = "\n".join(records)
        self.assertNotIn("access-token-sentinel", joined)
        self.assertNotIn("refresh-token-sentinel", joined)


if __name__ == "__main__":
    unittest.main()
