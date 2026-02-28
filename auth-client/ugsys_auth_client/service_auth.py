"""
Service-to-service authentication client.
Handles client_credentials token acquisition and caching.
"""

from datetime import UTC, datetime, timedelta

import httpx

from .models import ServiceCredentials


class ServiceAuthClient:
    """
    Acquires and caches service tokens from Identity Manager.
    Use one instance per service (singleton pattern).
    """

    def __init__(self, credentials: ServiceCredentials):
        self._creds = credentials
        self._token: str | None = None
        self._expires_at: datetime | None = None

    async def get_token(self) -> str:
        """Return a valid service token, refreshing if expired."""
        now = datetime.now(UTC)
        if self._token and self._expires_at and self._expires_at > now:
            return self._token

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{self._creds.identity_url}/api/v1/auth/service-token",
                json={
                    "client_id": self._creds.client_id,
                    "client_secret": self._creds.client_secret,
                },
            )
            resp.raise_for_status()
            data = resp.json()

        self._token = data["access_token"]
        self._expires_at = now + timedelta(seconds=data.get("expires_in", 3600) - 60)
        return self._token

    async def get_headers(self) -> dict[str, str]:
        """Return Authorization headers ready to attach to outbound requests."""
        token = await self.get_token()
        return {"Authorization": f"Bearer {token}"}
