"""
WRAITH Message Bus
Pub/Sub system that connects all agents.
Agent A emits an event → Agent B receives it and activates.
"""

from collections import defaultdict
from datetime import datetime


class MessageBus:
    def __init__(self):
        self._subscribers = defaultdict(list)
        self._log = []

    def subscribe(self, event: str, handler):
        """Subscribe a handler function to an event."""
        self._subscribers[event].append(handler)

    def emit(self, event: str, data: dict = None):
        """Emit an event to all subscribers."""
        entry = {
            "event": event,
            "timestamp": datetime.now().isoformat(),
            "data": data or {}
        }
        self._log.append(entry)

        for handler in self._subscribers.get(event, []):
            try:
                handler(data)
            except Exception as e:
                pass  # Don't let handler errors crash the bus

    def get_log(self) -> list:
        """Return the full event log."""
        return self._log

    def get_events(self, event_type: str) -> list:
        """Return all events of a specific type."""
        return [e for e in self._log if e["event"] == event_type]
