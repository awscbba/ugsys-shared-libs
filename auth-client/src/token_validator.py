"""
JWT token validator.
Validates tokens locally (via shared secret) or remotely (via Identity Manager API).
"""

import httpx
import jwt

from .models import TokenPayload


class TokenValidator:
    """Validates JWT tokens for ugsys services."""

    def __init__(
        self,
        jwt_secret: str | None = None,
        jwt_algorithm: str = "HS256",
        identity_url: str | None = None,
    ):
        """
        Args:
            jwt_secret: Shared secret for local validation (preferred for performance).
            jwt_algorithm: JWT signing algorithm.
            identity_url: Identity Manager base URL for remote validation fallback.
        """
        self._secret = jwt_secret
        self._algorithm = jwt_algorithm
        self._identity_url = identity_url

    def validate_local(self, token: str) -> TokenPayload | None:
        """Validate token locally using shared secret. Fast path."""
        if not self._secret:
            return None
        try:
            payload = jwt.decode(token, self._secret, algorithms=[self._algorithm])
            return TokenPayload(
                sub=payload["sub"],
                email=payload.get("email", ""),
                roles=payload.get("roles", []),
                is_admin=payload.get("isAdmin", False),
                type=payload.get("type", "access"),
            )
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    async def validate_remote(self, token: str) -> TokenPayload | None:
        """Validate token via Identity Manager API. Used when shared secret is unavailable."""
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

    def validate(self, token: str) -> TokenPayload | None:
        """Validate token — local first, remote fallback."""
        result = self.validate_local(token)
        return result
