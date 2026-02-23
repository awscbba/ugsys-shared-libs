"""
Mock implementations of shared service clients for unit testing.
"""

from typing import Any

from .factories import UserFactory, make_token


class MockEventPublisher:
    """In-memory event publisher for tests. Captures published events."""

    def __init__(self):
        self.published: list[Any] = []

    def publish(self, event) -> bool:
        self.published.append(event)
        return True

    def publish_batch(self, events) -> bool:
        self.published.extend(events)
        return True

    def reset(self):
        self.published.clear()


class MockIdentityClient:
    """Mock for the Identity Manager HTTP client."""

    def __init__(self, user: dict | None = None):
        self._user = user or UserFactory.build()

    async def validate_token(self, token: str) -> dict | None:
        return self._user

    async def get_user(self, user_id: str) -> dict | None:
        if self._user.get("id") == user_id:
            return self._user
        return None

    async def get_service_token(self) -> str:
        return make_token(email="service@internal", token_type="service")
