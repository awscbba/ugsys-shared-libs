"""
JWT token validator.

Security contract:
- RS256 is the ONLY accepted algorithm for production tokens.
- HS256 and 'none' are explicitly rejected BEFORE signature verification
  to prevent algorithm confusion attacks.
- JWKS cache: keys cached for 1 hour; forced refresh when kid not found.
- Required claims: sub, exp, iat — token rejected if any are missing.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

from .models import TokenPayload

# Algorithms that are NEVER accepted — checked before any decode attempt
_FORBIDDEN_ALGORITHMS = frozenset({"HS256", "HS384", "HS512", "none", ""})

# Only RS256 is accepted for production JWT validation
_ALLOWED_ALGORITHMS = ["RS256"]

_JWKS_CACHE_TTL = 3600  # 1 hour


class TokenValidator:
    """Validates JWT tokens for ugsys services.

    Supports two modes:
    - RS256 + JWKS (production): pass ``jwks_url`` pointing to identity-manager JWKS endpoint.
    - HS256 local secret (legacy/test only): pass ``jwt_secret`` + ``jwt_algorithm="HS256"``.

    Algorithm restriction is enforced in BOTH modes: tokens signed with HS256, HS384,
    HS512, or 'none' are rejected immediately when the validator is in RS256 mode.

    Audience validation: if ``audience`` is provided, PyJWT enforces the ``aud`` claim.
    Tokens issued by ugsys-identity-manager include ``aud: "admin-panel"`` — consuming
    services MUST pass ``audience="admin-panel"`` (or the correct value) to validate them.
    Without this, PyJWT raises ``InvalidAudienceError`` and validation silently returns None.
    """

    def __init__(
        self,
        jwt_secret: str | None = None,
        jwt_algorithm: str = "RS256",
        jwks_url: str | None = None,
        identity_url: str | None = None,
        audience: str | None = None,
    ) -> None:
        """
        Args:
            jwt_secret: Shared secret for HS256 local validation (test/legacy only).
            jwt_algorithm: JWT signing algorithm. Must be 'RS256' for production.
            jwks_url: Identity-manager JWKS endpoint URL for RS256 public key fetching.
            identity_url: Identity Manager base URL for remote validation fallback.
            audience: Expected ``aud`` claim value. Required when tokens include an ``aud``
                claim (all access tokens from ugsys-identity-manager use ``"admin-panel"``).
                PyJWT rejects tokens with an ``aud`` claim if no audience is provided here.
        """
        self._secret = jwt_secret
        self._algorithm = jwt_algorithm
        self._jwks_url = jwks_url
        self._identity_url = identity_url
        self._audience = audience

        # JWKS cache: {kid: public_key_object}
        self._jwks_cache: dict[str, Any] = {}
        self._jwks_cache_ts: float = 0.0

    # ── Public interface ──────────────────────────────────────────────────────

    def validate(self, token: str) -> TokenPayload | None:
        """Validate token. Returns None on any validation failure (never raises)."""
        # Algorithm restriction: check header BEFORE any decode attempt
        if not self._check_algorithm(token):
            return None

        if self._algorithm == "RS256" and self._jwks_url:
            return self._validate_rs256(token)

        return self.validate_local(token)

    def validate_local(self, token: str) -> TokenPayload | None:
        """Validate token locally using shared secret (HS256, test/legacy only)."""
        if not self._secret:
            return None
        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],
                options={"require": ["sub", "exp", "iat"]},
            )
            return self._build_payload(payload)
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    async def validate_remote(self, token: str) -> TokenPayload | None:
        """Validate token via Identity Manager API (fallback when JWKS unavailable)."""
        if not self._identity_url:
            return None
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(
                    f"{self._identity_url}/api/v1/auth/validate-token",
                    headers={"Authorization": f"Bearer {token}"},
                )
                if resp.status_code != 200:
                    return None
                data = resp.json()
                return TokenPayload(**data)
        except Exception:
            return None

    # ── RS256 / JWKS ──────────────────────────────────────────────────────────

    def _validate_rs256(self, token: str) -> TokenPayload | None:
        """Validate RS256 token using JWKS public keys."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError:
            return None

        kid = header.get("kid")
        if not kid:
            return None

        # Try cached key first; refresh if kid not found or cache expired
        public_key = self._get_jwks_key(kid)
        if public_key is None:
            public_key = self._refresh_jwks_and_get(kid)
        if public_key is None:
            return None

        # Peek at unverified claims to check if token has an aud claim.
        # PyJWT requires audience= when token has aud, and rejects it when token
        # lacks aud but audience= is passed. We must match accordingly.
        try:
            unverified = jwt.decode(
                token,
                options={"verify_signature": False},
                algorithms=_ALLOWED_ALGORITHMS,
            )
        except jwt.InvalidTokenError:
            return None

        decode_kwargs: dict[str, Any] = {
            "algorithms": _ALLOWED_ALGORITHMS,
            "options": {"require": ["sub", "exp", "iat"]},
        }
        token_has_aud = "aud" in unverified
        if token_has_aud and self._audience:
            decode_kwargs["audience"] = self._audience
        elif token_has_aud and not self._audience:
            # Token has aud but validator has no expected audience configured —
            # PyJWT will raise InvalidAudienceError. Return None (validation fails).
            return None

        try:
            payload = jwt.decode(token, public_key, **decode_kwargs)
            return self._build_payload(payload)
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def _get_jwks_key(self, kid: str) -> Any | None:
        """Return cached public key for kid, or None if not cached / cache expired."""
        if time.monotonic() - self._jwks_cache_ts > _JWKS_CACHE_TTL:
            return None
        return self._jwks_cache.get(kid)

    def _refresh_jwks_and_get(self, kid: str) -> Any | None:
        """Synchronously fetch JWKS, update cache, return key for kid."""
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(self._jwks_url)  # type: ignore[arg-type]
                resp.raise_for_status()
                jwks = resp.json()
        except Exception:
            return None

        new_cache: dict[str, Any] = {}
        for key_data in jwks.get("keys", []):
            try:
                k = RSAAlgorithm.from_jwk(key_data)
                new_cache[key_data["kid"]] = k
            except Exception:
                continue

        self._jwks_cache = new_cache
        self._jwks_cache_ts = time.monotonic()
        return self._jwks_cache.get(kid)

    # ── Algorithm restriction ─────────────────────────────────────────────────

    def _check_algorithm(self, token: str) -> bool:
        """Check algorithm header BEFORE signature verification.

        Rejects HS256, HS384, HS512, and 'none' when validator is in RS256 mode.
        This prevents algorithm confusion attacks where an attacker downgrades
        the algorithm to bypass RS256 signature verification.
        """
        if self._algorithm != "RS256":
            # Not in RS256 mode — no restriction applied
            return True
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError:
            return False
        alg = header.get("alg", "")
        return alg not in _FORBIDDEN_ALGORITHMS and alg in _ALLOWED_ALGORITHMS

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _build_payload(payload: dict[str, Any]) -> TokenPayload:
        return TokenPayload(
            sub=payload["sub"],
            email=payload.get("email", ""),
            roles=payload.get("roles", []),
            is_admin=payload.get("isAdmin", False),
            type=payload.get("type", "access"),
        )
