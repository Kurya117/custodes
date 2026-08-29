"""Read-only ingest: JSONL flow records from a file, stdin, or in-memory iterator.

No sockets are opened toward traffic sources. The ingest path is strictly
consume-only.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

from pti.schema import FlowRecord


def parse_line(line: str) -> FlowRecord | None:
    line = line.strip()
    if not line:
        return None
    try:
        payload = json.loads(line)
        return FlowRecord.model_validate(payload)
    except (json.JSONDecodeError, ValueError):
        return None


def iter_jsonl(path: str | Path | None) -> Iterator[FlowRecord]:
    if path is None or str(path) == "-":
        stream = sys.stdin
        for line in stream:
            rec = parse_line(line)
            if rec is not None:
                yield rec
        return
    with Path(path).open("r", encoding="utf-8") as fh:
        for line in fh:
            rec = parse_line(line)
            if rec is not None:
                yield rec


def iter_records(records: Iterable[FlowRecord]) -> Iterator[FlowRecord]:
    yield from records
