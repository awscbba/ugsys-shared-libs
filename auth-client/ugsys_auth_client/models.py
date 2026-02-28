"""Shared auth models used across all ugsys services."""

from pydantic import BaseModel


class TokenPayload(BaseModel):
    """Decoded JWT token payload."""

    sub: str  # user_id
    email: str
    roles: list[str] = []
    is_admin: bool = False
    type: str = "access"  # access | refresh | service


class ServiceCredentials(BaseModel):
    """Credentials for service-to-service authentication."""

    client_id: str
    client_secret: str
    identity_url: str
