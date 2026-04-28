"""Auth checks: JWT manipulation, BOLA/IDOR, missing auth enforcement."""
from __future__ import annotations

import base64
import json
from typing import Any

import httpx

from apiguard.checks.base import BaseCheck
from apiguard.core.models import Severity


def _b64pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def _decode_jwt_header(token: str) -> dict[str, Any]:
    try:
        header_b64 = token.split(".")[0]
        return json.loads(base64.urlsafe_b64decode(_b64pad(header_b64)))
    except Exception:
        return {}


def _forge_alg_none(token: str) -> str:
    """Replace alg with 'none' and strip signature."""
    parts = token.split(".")
    if len(parts) < 2:
        return token
    header = json.loads(base64.urlsafe_b64decode(_b64pad(parts[0])))
    header["alg"] = "none"
    new_header = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    return f"{new_header}.{parts[1]}."


def _forge_hs256_with_public_key(token: str) -> str | None:
    """Attempt RS256→HS256 confusion (requires public key in config)."""
    # Placeholder — real impl would need the PEM key from config.
    return None


class AuthCheck(BaseCheck):
    id          = "auth"
    name        = "Authentication & Authorisation"
    description = "JWT weaknesses, missing auth, BOLA/IDOR"
    tags        = ["owasp-api1", "owasp-api2"]

    async def run(self) -> None:
        cfg = self.config.check_cfg("auth")
        token: str = self.config.auth.get("token", "")
        endpoints = self.config.endpoints

        await self._check_unauthenticated_access(endpoints)

        if token:
            await self._check_alg_none(token, endpoints)
            await self._check_weak_secret(token)

        if endpoints:
            await self._check_bola(endpoints)

    # ------------------------------------------------------------------ #

    async def _check_unauthenticated_access(
        self, endpoints: list[dict]
    ) -> None:
        """Hit protected endpoints without any auth header."""
        protected = [e for e in endpoints if e.get("auth_required", True)]
        for ep in protected[:5]:  # sample first 5
            method = ep.get("method", "GET")
            path   = ep.get("path", "/")
            try:
                resp, _ = await self.client.request(
                    method, path,
                    headers={"Authorization": ""},   # strip auth
                )
                if resp.status_code < 400:
                    self.add_finding(
                        Severity.HIGH,
                        "Endpoint accessible without authentication",
                        f"{method} {path} returned {resp.status_code} with no token.",
                        endpoint=path,
                        request=self.client.fmt_request(resp),
                        response=self.client.fmt_response(resp),
                        remediation="Enforce auth middleware on all protected routes.",
                    )
            except httpx.RequestError as exc:
                self.add_error(f"Request error on {path}: {exc}")

    async def _check_alg_none(self, token: str, endpoints: list[dict]) -> None:
        """Send a JWT with alg=none to see if the server accepts it."""
        forged = _forge_alg_none(token)
        test_endpoints = endpoints[:3] if endpoints else [{"method": "GET", "path": "/"}]

        for ep in test_endpoints:
            path = ep.get("path", "/")
            method = ep.get("method", "GET")
            try:
                resp, _ = await self.client.request(
                    method, path,
                    headers={"Authorization": f"Bearer {forged}"},
                )
                if resp.status_code < 400:
                    self.add_finding(
                        Severity.CRITICAL,
                        "JWT alg=none accepted",
                        (
                            f"Server accepted a JWT with alg=none on {method} {path} "
                            f"(HTTP {resp.status_code}). Attackers can forge any token."
                        ),
                        endpoint=path,
                        request=self.client.fmt_request(resp),
                        response=self.client.fmt_response(resp),
                        remediation=(
                            "Reject tokens where alg is 'none'. "
                            "Whitelist only expected algorithms (e.g. RS256, ES256)."
                        ),
                    )
                else:
                    self.add_pass("JWT alg=none rejected", f"{method} {path} → {resp.status_code}")
            except httpx.RequestError as exc:
                self.add_error(f"alg=none probe failed for {path}: {exc}")

    async def _check_weak_secret(self, token: str) -> None:
        """Decode the JWT header and warn if HS256 is used (brute-forceable)."""
        header = _decode_jwt_header(token)
        alg = header.get("alg", "")
        if alg.startswith("HS"):
            self.add_finding(
                Severity.MEDIUM,
                "Symmetric JWT algorithm in use (HMAC)",
                (
                    f"Token uses {alg}. HMAC secrets can be brute-forced offline. "
                    "Consider RS256 or ES256 for public APIs."
                ),
                remediation="Migrate to an asymmetric algorithm (RS256 / ES256).",
            )

    async def _check_bola(self, endpoints: list[dict]) -> None:
        """Check for Broken Object Level Authorisation by ID tampering."""
        id_endpoints = [
            e for e in endpoints
            if any(seg.lstrip("{").rstrip("}").lower() in ("id", "user_id", "uid", "account_id")
                   for seg in e.get("path", "").split("/"))
        ]
        if not id_endpoints:
            return

        other_token = self.config.auth.get("other_user_token", "")
        if not other_token:
            self.add_finding(
                Severity.INFO,
                "BOLA check skipped — no second user token configured",
                (
                    "To test BOLA/IDOR, add 'auth.other_user_token' to your config "
                    "with a token belonging to a different user."
                ),
                remediation="Provide a second user token for automated BOLA testing.",
            )
            return

        for ep in id_endpoints[:3]:
            path = ep.get("path", "/")
            method = ep.get("method", "GET")
            try:
                resp, _ = await self.client.request(
                    method, path,
                    headers={"Authorization": f"Bearer {other_token}"},
                )
                if resp.status_code == 200:
                    self.add_finding(
                        Severity.HIGH,
                        "Potential BOLA — cross-user resource access",
                        (
                            f"User B's token accessed {method} {path} successfully "
                            f"(HTTP {resp.status_code}). "
                            "Verify whether the resource belongs to User A."
                        ),
                        endpoint=path,
                        request=self.client.fmt_request(resp),
                        response=self.client.fmt_response(resp),
                        remediation=(
                            "Enforce object-level ownership checks in every handler, "
                            "not just at the route level."
                        ),
                    )
            except httpx.RequestError as exc:
                self.add_error(f"BOLA probe failed for {path}: {exc}")
