"""
EventBridge publisher.
Wraps boto3 put_events with batching, error handling, and structured logging.
"""

import logging

import boto3

from .event_schemas import UgsysEvent

logger = logging.getLogger(__name__)

_MAX_BATCH_SIZE = 10  # EventBridge limit


class EventPublisher:
    """
    Publishes events to an EventBridge custom bus.

    Usage:
        publisher = EventPublisher(
            event_bus_name="ugsys-platform-bus",
            source_service="identity-manager",
        )
        await publisher.publish(event)
    """

    def __init__(
        self,
        event_bus_name: str,
        source_service: str,
        region: str = "us-east-1",
        client: object | None = None,
    ):
        self._bus = event_bus_name
        self._source_service = source_service
        self._client = client or boto3.client("events", region_name=region)

    def publish(self, event: UgsysEvent) -> bool:
        """Publish a single event. Returns True on success."""
        return self.publish_batch([event])

    def publish_batch(self, events: list[UgsysEvent]) -> bool:
        """
        Publish multiple events in batches of 10 (EventBridge limit).
        Returns True if all batches succeeded.
        """
        success = True
        for i in range(0, len(events), _MAX_BATCH_SIZE):
            batch = events[i : i + _MAX_BATCH_SIZE]
            entries = [e.to_eventbridge_entry(self._bus) for e in batch]
            try:
                response = self._client.put_events(Entries=entries)
                failed = response.get("FailedEntryCount", 0)
                if failed > 0:
                    logger.error(
                        "EventBridge put_events partial failure",
                        extra={"failed_count": failed, "batch_size": len(batch)},
                    )
                    success = False
            except Exception as exc:
                logger.exception(
                    "EventBridge put_events error",
                    extra={"error": str(exc), "batch_size": len(batch)},
                )
                success = False
        return success
