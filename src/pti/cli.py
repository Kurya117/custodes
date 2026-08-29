from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from pti.ingest import iter_jsonl
from pti.pipeline import Pipeline
from pti.simulator import mix_stream, write_jsonl
from pti.train import DEFAULT_MODEL, train


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pti", description="Passive one-way threat intelligence pipeline")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_sim = sub.add_parser("simulate", help="Write labelled JSONL replay")
    p_sim.add_argument("--out", type=Path, default=Path("data/replay.jsonl"))
    p_sim.add_argument("-n", type=int, default=20_000)
    p_sim.add_argument("--seed", type=int, default=7)

    p_train = sub.add_parser("train", help="Train sklearn classifier on synthetic data")
    p_train.add_argument("--out", type=Path, default=DEFAULT_MODEL)
    p_train.add_argument("-n", type=int, default=12_000)

    p_run = sub.add_parser("run", help="Stream ingest -> alerts (stdout JSONL)")
    p_run.add_argument("--source", type=str, default="data/replay.jsonl")
    p_run.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    p_run.add_argument("--dashboard", action="store_true")
    p_run.add_argument("--host", default="127.0.0.1")
    p_run.add_argument("--port", type=int, default=8080)
    p_run.add_argument("--pace", type=float, default=0.0, help="Sleep seconds per flow (0 = as-fast-as-possible)")
    p_run.add_argument("--generate", type=int, default=0, help="If set, generate N flows instead of reading --source")

    p_bench = sub.add_parser("bench", help="Measure sustained flows/sec")
    p_bench.add_argument("-n", type=int, default=50_000)
    p_bench.add_argument("--model", type=Path, default=DEFAULT_MODEL)

    args = parser.parse_args(argv)
    if args.cmd == "simulate":
        count = write_jsonl(args.out, args.n, seed=args.seed)
        print(f"wrote {count} records to {args.out}")
        return 0
    if args.cmd == "train":
        path = train(args.out, n=args.n)
        print(f"model saved to {path}")
        print((path.with_suffix(".metrics.txt")).read_text(encoding="utf-8"))
        return 0
    if args.cmd == "run":
        if args.dashboard:
            from pti.dashboard.app import serve

            serve(
                host=args.host,
                port=args.port,
                source=None if args.generate else args.source,
                generate_n=args.generate,
                model_path=args.model if args.model.exists() else None,
                pace=args.pace,
            )
            return 0
        model = args.model if args.model.exists() else None
        pipe = Pipeline(model_path=model)
        records = mix_stream(args.generate) if args.generate else iter_jsonl(args.source)
        t0 = time.perf_counter()
        n = 0
        for rec in records:
            n += 1
            for alert in pipe.process(rec):
                sys.stdout.write(json.dumps(alert.to_record()) + "\n")
            if args.pace:
                time.sleep(args.pace)
        elapsed = time.perf_counter() - t0
        print(
            json.dumps({"flows": n, "alerts": len(pipe.alerts), "seconds": round(elapsed, 4),
                        "flows_per_sec": round(n / max(elapsed, 1e-9), 1)}),
            file=sys.stderr,
        )
        return 0
    if args.cmd == "bench":
        from pti.bench import run_bench

        result = run_bench(n=args.n, model_path=args.model if args.model.exists() else None)
        print(json.dumps(result, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
