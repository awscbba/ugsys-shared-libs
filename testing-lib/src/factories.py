"""
Test data factories for ugsys services.
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import jwt


def make_token(
    user_id: str | None = None,
    email: str = "test@example.com",
    roles: list[str] | None = None,
    is_admin: bool = False,
    secret: str = "test-secret",
    token_type: str = "access",
    expires_in_hours: int = 1,
) -> str:
    """Generate a signed JWT for testing."""
    payload = {
        "sub": user_id or str(uuid4()),
        "email": email,
        "roles": roles or [],
        "isAdmin": is_admin,
        "type": token_type,
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(hours=expires_in_hours),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


class UserFactory:
    """Factory for creating test user dicts."""

    @staticmethod
    def build(**overrides: Any) -> dict:
        """Build a user dict without persisting."""
        defaults = {
            "id": str(uuid4()),
            "email": f"user-{uuid4().hex[:6]}@example.com",
            "firstName": "Test",
            "lastName": "User",
            "isAdmin": False,
            "isActive": True,
            "roles": [],
            "createdAt": datetime.now(UTC).isoformat(),
        }
        return {**defaults, **overrides}

    @staticmethod
    def build_admin(**overrides: Any) -> dict:
        """Build an admin user dict."""
        return UserFactory.build(isAdmin=True, roles=["admin"], **overrides)
