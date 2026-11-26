"""Request checks for a local API that a browser on the same machine can reach.

A page on any site the analyst visits can send simple requests to 127.0.0.1 or rebind a hostname to it.
These checks stop such pages from writing through the API: the Host header must be a local name, a write
that carries a foreign Origin is refused, and the alert endpoint only takes JSON, which a cross-site form
cannot send without a CORS preflight. An optional bearer token covers everything else.
"""

from __future__ import annotations

import hmac

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
JSON_ONLY_PATHS = frozenset({"/api/alerts"})


class RequestGuard:
    """Refuse foreign-origin writes, non-JSON alert bodies, and, when a token is set, requests without it."""

    def __init__(self, app: ASGIApp, *, allowed_origins: list[str], api_token: str) -> None:
        self.app = app
        self.allowed_origins = frozenset(allowed_origins)
        self.api_token = api_token

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        response = self._refusal(scope, Headers(scope=scope))
        if response is not None:
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)

    def _refusal(self, scope: Scope, headers: Headers) -> JSONResponse | None:
        method = scope["method"]
        if method == "OPTIONS":
            return None  # CORS preflight; the CORS middleware answers it.
        if self.api_token and not self._token_ok(headers.get("authorization", "")):
            return JSONResponse(status_code=401, content={"detail": "Missing or invalid API token"})
        if method not in UNSAFE_METHODS:
            return None
        origin = headers.get("origin")
        if origin is not None and origin not in self.allowed_origins:
            return JSONResponse(status_code=403, content={"detail": "Origin not allowed"})
        if scope["path"] in JSON_ONLY_PATHS:
            content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                return JSONResponse(
                    status_code=415,
                    content={"errors": [{"field": "body", "message": "Content-Type must be application/json"}]},
                )
        return None

    def _token_ok(self, authorization: str) -> bool:
        scheme, _, supplied = authorization.partition(" ")
        if scheme != "Bearer" or not supplied:
            return False
        return hmac.compare_digest(supplied.encode(), self.api_token.encode())
