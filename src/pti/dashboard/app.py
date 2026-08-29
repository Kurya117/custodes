"""Read-only visualisation of streaming alerts. No control channel back to the network."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

from pti.ingest import iter_jsonl
from pti.pipeline import Pipeline
from pti.simulator import mix_stream

STATIC = Path(__file__).parent / "static"


class Stats(BaseModel):
    flows: int
    alert_count: int
    flows_per_sec: float
    by_class: dict[str, int]
    running: bool
    elapsed_s: float


def create_app(
    source: str | None,
    generate_n: int,
    model_path: Path | None,
    pace: float,
) -> FastAPI:
    app = FastAPI(title="Passive Threat Intel", docs_url=None, redoc_url=None)
    lock = threading.Lock()
    state = {
        "pipe": Pipeline(model_path=model_path),
        "running": True,
        "t0": time.perf_counter(),
        "by_class": {},
    }

    def ingest_loop() -> None:
        records = mix_stream(generate_n or 15_000) if generate_n or not source else iter_jsonl(source)
        for rec in records:
            alerts = state["pipe"].process(rec)
            if alerts:
                with lock:
                    for a in alerts:
                        k = a.threat_class.value
                        state["by_class"][k] = state["by_class"].get(k, 0) + 1
            if pace:
                time.sleep(pace)
        state["running"] = False

    threading.Thread(target=ingest_loop, daemon=True).start()

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    @app.get("/api/alerts")
    def alerts(limit: int = 80) -> dict:
        items = list(state["pipe"].alerts)[-limit:]
        items.reverse()
        return {"alerts": [a.to_record() for a in items]}

    @app.get("/api/stats")
    def stats() -> Stats:
        elapsed = time.perf_counter() - state["t0"]
        flows = state["pipe"].flows_seen
        return Stats(
            flows=flows,
            alert_count=len(state["pipe"].alerts),
            flows_per_sec=round(flows / max(elapsed, 1e-9), 1),
            by_class=dict(state["by_class"]),
            running=state["running"],
            elapsed_s=round(elapsed, 3),
        )

    return app


def serve(
    host: str,
    port: int,
    source: str | None,
    generate_n: int,
    model_path: Path | None,
    pace: float,
) -> None:
    import uvicorn

    app = create_app(source, generate_n, model_path, pace)
    uvicorn.run(app, host=host, port=port, log_level="info")
