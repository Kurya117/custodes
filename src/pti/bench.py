"""Throughput demonstration against a synthetic one-way flow stream."""

from __future__ import annotations

import time
from pathlib import Path

from pti.pipeline import Pipeline
from pti.simulator import mix_stream


def run_bench(n: int = 50_000, model_path: Path | None = None) -> dict:
    pipe = Pipeline(model_path=model_path)
    t0 = time.perf_counter()
    for rec in mix_stream(n, seed=1):
        pipe.process(rec)
    elapsed = time.perf_counter() - t0
    fps = n / max(elapsed, 1e-9)
    # Rough metadata bitrate: ~400 bytes JSON-equivalent per flow on the wire-ish
    mbps = (fps * 400 * 8) / 1_000_000
    by_class: dict[str, int] = {}
    for a in pipe.alerts:
        key = a.threat_class.value
        by_class[key] = by_class.get(key, 0) + 1
    return {
        "target_note": "Sustained synthetic JSONL-equivalent flow metadata ingest",
        "flows": n,
        "seconds": round(elapsed, 4),
        "flows_per_sec": round(fps, 1),
        "approx_mbps_metadata": round(mbps, 2),
        "alerts": len(pipe.alerts),
        "alerts_by_class": by_class,
        "ml_enabled": pipe.clf.ready,
    }
