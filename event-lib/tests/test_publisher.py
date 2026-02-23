"""Tests for EventPublisher and UgsysEvent."""

import json
from unittest.mock import MagicMock

import pytest

from src.event_schemas import EventMetadata, UgsysEvent
from src.publisher import EventPublisher


def _make_event(detail_type: str = "identity.user.created") -> UgsysEvent:
    return UgsysEvent(
        detail_type=detail_type,
        source="ugsys.identity-manager",
        metadata=EventMetadata(source_service="identity-manager"),
        payload={"user_id": "user-123", "email": "user@example.com"},
    )


class TestUgsysEvent:
    def test_to_eventbridge_entry_structure(self):
        event = _make_event()
        entry = event.to_eventbridge_entry("ugsys-platform-bus")

        assert entry["Source"] == "ugsys.identity-manager"
        assert entry["DetailType"] == "identity.user.created"
        assert entry["EventBusName"] == "ugsys-platform-bus"

        detail = json.loads(entry["Detail"])
        assert detail["payload"]["user_id"] == "user-123"
        assert "metadata" in detail
        assert detail["metadata"]["source_service"] == "identity-manager"

    def test_metadata_has_event_id_and_timestamp(self):
        event = _make_event()
        assert event.metadata.event_id != ""
        assert event.metadata.timestamp != ""


class TestEventPublisher:
    def setup_method(self):
        self.mock_client = MagicMock()
        self.mock_client.put_events.return_value = {"FailedEntryCount": 0, "Entries": []}
        self.publisher = EventPublisher(
            event_bus_name="ugsys-platform-bus",
            source_service="identity-manager",
            client=self.mock_client,
        )

    def test_publish_single_event_calls_put_events(self):
        event = _make_event()
        result = self.publisher.publish(event)

        assert result is True
        self.mock_client.put_events.assert_called_once()
        call_args = self.mock_client.put_events.call_args[1]["Entries"]
        assert len(call_args) == 1

    def test_publish_batch_splits_into_chunks_of_10(self):
        events = [_make_event(f"test.event.{i}") for i in range(25)]
        result = self.publisher.publish_batch(events)

        assert result is True
        # 25 events → 3 batches (10, 10, 5)
        assert self.mock_client.put_events.call_count == 3

    def test_publish_returns_false_on_partial_failure(self):
        self.mock_client.put_events.return_value = {"FailedEntryCount": 1, "Entries": []}
        result = self.publisher.publish(_make_event())
        assert result is False

    def test_publish_returns_false_on_exception(self):
        self.mock_client.put_events.side_effect = Exception("AWS error")
        result = self.publisher.publish(_make_event())
        assert result is False
