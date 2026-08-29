"""Sliding-window state with bounded memory for streaming detectors."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field

from pti.schema import FlowRecord


@dataclass
class WindowEvent:
    ts: float
    rec: FlowRecord


class TimeWindow:
    def __init__(self, duration_s: float, max_events: int = 200_000) -> None:
        self.duration_s = duration_s
        self.max_events = max_events
        self._events: deque[WindowEvent] = deque()

    def add(self, rec: FlowRecord) -> None:
        self._events.append(WindowEvent(rec.ts, rec))
        cutoff = rec.ts - self.duration_s
        while self._events and self._events[0].ts < cutoff:
            self._events.popleft()
        while len(self._events) > self.max_events:
            self._events.popleft()

    @property
    def events(self) -> deque[WindowEvent]:
        return self._events

    def records(self) -> list[FlowRecord]:
        return [e.rec for e in self._events]

    def __len__(self) -> int:
        return len(self._events)


class KeyedWindows:
    def __init__(self, duration_s: float, max_keys: int = 50_000, max_per_key: int = 256) -> None:
        self.duration_s = duration_s
        self.max_keys = max_keys
        self.max_per_key = max_per_key
        self._by_key: dict[str, deque[FlowRecord]] = defaultdict(deque)

    def add(self, key: str, rec: FlowRecord) -> deque[FlowRecord]:
        dq = self._by_key[key]
        dq.append(rec)
        cutoff = rec.ts - self.duration_s
        while dq and dq[0].ts < cutoff:
            dq.popleft()
        while len(dq) > self.max_per_key:
            dq.popleft()
        if len(self._by_key) > self.max_keys:
            # drop oldest keys (insertion order in 3.7+)
            overflow = len(self._by_key) - self.max_keys
            for drop_key in list(self._by_key.keys())[:overflow]:
                del self._by_key[drop_key]
        return dq
