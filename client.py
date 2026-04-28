"""Async HTTP client built on httpx with logging and retry helpers."""
from __future__ import annotations

import time
from typing import Any

import httpx


class APIClient:
    """Thin async wrapper around httpx.AsyncClient."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 10,
        verify_ssl: bool = True,
        follow_redirects: bool = False,
        headers: dict[str, str] | None = None,
        user_agent: str = "apiguard/0.1",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        default_headers = {"User-Agent": user_agent}
        if headers:
            default_headers.update(headers)

        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            verify=verify_ssl,
            follow_redirects=follow_redirects,
            headers=default_headers,
        )

    # ------------------------------------------------------------------ #
    # Request helpers                                                      #
    # ------------------------------------------------------------------ #

    async def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json: Any = None,
        data: Any = None,
        content: bytes | None = None,
        auth: tuple[str, str] | None = None,
    ) -> tuple[httpx.Response, float]:
        """Send a request and return (response, elapsed_seconds)."""
        t0 = time.perf_counter()
        resp = await self._client.request(
            method.upper(),
            path,
            headers=headers,
            params=params,
            json=json,
            data=data,
            content=content,
            auth=auth,
        )
        elapsed = time.perf_counter() - t0
        return resp, elapsed

    async def get(self, path: str, **kw: Any) -> tuple[httpx.Response, float]:
        return await self.request("GET", path, **kw)

    async def post(self, path: str, **kw: Any) -> tuple[httpx.Response, float]:
        return await self.request("POST", path, **kw)

    async def put(self, path: str, **kw: Any) -> tuple[httpx.Response, float]:
        return await self.request("PUT", path, **kw)

    async def patch(self, path: str, **kw: Any) -> tuple[httpx.Response, float]:
        return await self.request("PATCH", path, **kw)

    async def delete(self, path: str, **kw: Any) -> tuple[httpx.Response, float]:
        return await self.request("DELETE", path, **kw)

    # ------------------------------------------------------------------ #
    # Context manager                                                      #
    # ------------------------------------------------------------------ #

    async def __aenter__(self) -> "APIClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self._client.__aexit__(*args)

    async def aclose(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------ #
    # Utility                                                              #
    # ------------------------------------------------------------------ #

    def clone_with_headers(self, extra: dict[str, str]) -> "APIClient":
        """Return a new client with extra default headers merged in."""
        merged = dict(self._client.headers)
        merged.update(extra)
        c = APIClient.__new__(APIClient)
        c.base_url = self.base_url
        c._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self._client.timeout,
            verify=self._client._transport._pool._ssl_context is not None
            if hasattr(self._client, "_transport") else True,
            follow_redirects=self._client.follow_redirects,
            headers=merged,
        )
        return c

    @staticmethod
    def fmt_request(resp: httpx.Response) -> str:
        req = resp.request
        lines = [f"{req.method} {req.url}"]
        for k, v in req.headers.items():
            lines.append(f"  {k}: {v}")
        if req.content:
            lines.append("")
            lines.append(f"  {req.content[:500].decode(errors='replace')}")
        return "\n".join(lines)

    @staticmethod
    def fmt_response(resp: httpx.Response, max_body: int = 500) -> str:
        lines = [f"HTTP {resp.status_code}"]
        for k, v in resp.headers.items():
            lines.append(f"  {k}: {v}")
        lines.append("")
        lines.append(f"  {resp.text[:max_body]}")
        return "\n".join(lines)
