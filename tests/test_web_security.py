from __future__ import annotations

from fastapi.testclient import TestClient

from web_security import SecurityHeadersMiddleware


def _client(headers: list[tuple[bytes, bytes]] | None = None) -> TestClient:
    async def app(scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": list(headers or []),
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    return TestClient(SecurityHeadersMiddleware(app, enable_hsts=False))


def test_sensitive_responses_disable_browser_and_shared_caches():
    with _client() as client:
        response = client.get("/settings")

    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["pragma"] == "no-cache"


def test_static_and_health_responses_keep_their_cache_policy_untouched():
    with _client() as client:
        static_response = client.get("/static/app.js")
        health_response = client.get("/healthz")

    assert "cache-control" not in static_response.headers
    assert "pragma" not in static_response.headers
    assert "cache-control" not in health_response.headers
    assert "pragma" not in health_response.headers


def test_stricter_existing_cache_headers_are_preserved():
    existing = [
        (b"cache-control", b"no-store, private, must-revalidate"),
        (b"pragma", b"no-cache"),
    ]
    with _client(existing) as client:
        response = client.get("/email/1")

    assert response.headers["cache-control"] == (
        "no-store, private, must-revalidate"
    )
    assert response.headers["pragma"] == "no-cache"


def test_weaker_existing_cache_headers_are_replaced():
    existing = [
        (b"cache-control", b"private, max-age=60"),
        (b"pragma", b"custom-extension"),
    ]
    with _client(existing) as client:
        response = client.get("/tokens")

    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["pragma"] == "no-cache"
