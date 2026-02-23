"""
Standardized event envelope for all ugsys EventBridge events.
Every service publishes events using this schema.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class EventMetadata(BaseModel):
    """Standard metadata attached to every event."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    event_version: str = "1.0"
    source_service: str
    correlation_id: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class UgsysEvent(BaseModel):
    """
    Standard event envelope.

    Example:
        event = UgsysEvent(
            detail_type="identity.user.created",
            source="ugsys.identity-manager",
            metadata=EventMetadata(source_service="identity-manager"),
            payload={"user_id": "123", "email": "user@example.com"},
        )
    """

    detail_type: str  # e.g. "identity.user.created"
    source: str  # e.g. "ugsys.identity-manager"
    metadata: EventMetadata
    payload: dict[str, Any]

    def to_eventbridge_entry(self, event_bus_name: str) -> dict:
        """Serialize to the format expected by boto3 EventBridge put_events."""
        import json

        return {
            "Source": self.source,
            "DetailType": self.detail_type,
            "Detail": json.dumps(
                {
                    "metadata": self.metadata.model_dump(),
                    "payload": self.payload,
                }
            ),
            "EventBusName": event_bus_name,
        }
