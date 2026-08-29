"""Train a histogram gradient-boosting classifier on synthetic labelled flows."""

from __future__ import annotations

import random
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from pti.ml import FEATURE_NAMES, vectorize
from pti.schema import ThreatClass
from pti.simulator import generate_record

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL = ROOT / "models" / "flow_hgb.joblib"


def build_dataset(n: int = 12_000, seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    rng = random.Random(seed)
    classes = [t.value for t in ThreatClass]
    xs = []
    ys = []
    ts = 1_700_000_000.0
    for i in range(n):
        kind = classes[i % len(classes)]
        rec = generate_record(rng, ts, kind)
        xs.append(vectorize(rec))
        ys.append(kind)
        ts += 0.05
    return np.vstack(xs), np.array(ys)


def train(model_path: Path = DEFAULT_MODEL, n: int = 12_000) -> Path:
    x, y = build_dataset(n)
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.25, random_state=42, stratify=y
    )
    clf = HistGradientBoostingClassifier(max_depth=6, learning_rate=0.08, max_iter=120)
    clf.fit(x_train, y_train)
    pred = clf.predict(x_test)
    report = classification_report(y_test, pred)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": clf, "classes": list(clf.classes_), "features": FEATURE_NAMES, "report": report}, model_path)
    metrics_path = model_path.with_suffix(".metrics.txt")
    metrics_path.write_text(report, encoding="utf-8")
    return model_path
