"""Small ASGI security middleware used by the web application."""

from collections import deque


class RequestBodyLimitMiddleware:
    def __init__(self, app, max_bytes: int = 2 * 1024 * 1024):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") not in {
            "POST",
            "PUT",
            "PATCH",
        }:
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        raw_length = headers.get(b"content-length")
        if raw_length:
            try:
                if int(raw_length) > self.max_bytes:
                    await self._reject(send)
                    return
            except ValueError:
                await self._reject(send)
                return

        buffered = deque()
        total = 0
        while True:
            message = await receive()
            buffered.append(message)
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > self.max_bytes:
                    await self._reject(send)
                    return
                if not message.get("more_body", False):
                    break
            elif message["type"] == "http.disconnect":
                break

        async def replay_receive():
            if buffered:
                return buffered.popleft()
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _reject(send):
        body = b'{"error":"Request body too large"}'
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json; charset=utf-8"),
                    (b"content-length", str(len(body)).encode()),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


class SecurityHeadersMiddleware:
    _HEADERS = (
        (b"x-content-type-options", b"nosniff"),
        (b"referrer-policy", b"no-referrer"),
        (b"x-frame-options", b"DENY"),
        (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
        (
            b"content-security-policy",
            (
                b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                b"img-src 'self' data:; frame-src 'self'; object-src 'none'; base-uri 'self'; "
                b"form-action 'self'; frame-ancestors 'none'"
            ),
        ),
    )

    def __init__(self, app, enable_hsts: bool = True):
        self.app = app
        self.enable_hsts = enable_hsts

    async def __call__(self, scope, receive, send):
        path = scope.get("path", "") if scope["type"] == "http" else ""
        prevent_caching = scope["type"] == "http" and not (
            path == "/healthz" or path.startswith("/static/")
        )

        async def wrapped_send(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                existing = {key.lower() for key, _ in headers}
                for key, value in self._HEADERS:
                    if key not in existing:
                        headers.append((key, value))
                if self.enable_hsts and b"strict-transport-security" not in existing:
                    headers.append(
                        (
                            b"strict-transport-security",
                            b"max-age=31536000; includeSubDomains",
                        )
                    )
                if prevent_caching:
                    self._ensure_directive_header(
                        headers,
                        b"cache-control",
                        b"no-store",
                        b"no-store, private",
                    )
                    self._ensure_directive_header(
                        headers,
                        b"pragma",
                        b"no-cache",
                        b"no-cache",
                    )
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, wrapped_send)

    @staticmethod
    def _ensure_directive_header(
        headers: list[tuple[bytes, bytes]],
        name: bytes,
        required_directive: bytes,
        default_value: bytes,
    ) -> None:
        values = [value for key, value in headers if key.lower() == name]
        for value in values:
            directives = {
                part.strip().split(b"=", 1)[0].lower()
                for part in value.split(b",")
            }
            if required_directive in directives:
                return
        headers[:] = [(key, value) for key, value in headers if key.lower() != name]
        headers.append((name, default_value))
