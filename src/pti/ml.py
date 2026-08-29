"""Optional sklearn classifier trained on synthetic labelled flows.

Used as a second opinion fused with specialised streaming detectors.
Never required for the pipeline to produce alerts (rules still fire).
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np

from pti.features import ngram_rarity, numeric_ratio, string_entropy
from pti.schema import FlowRecord, ThreatClass

FEATURE_NAMES = [
    "dst_port",
    "bytes_fwd",
    "bytes_rev",
    "pkts_fwd",
    "pkts_rev",
    "duration_ms",
    "is_syn",
    "is_udp",
    "dns_qlen",
    "dns_entropy",
    "dns_rarity",
    "dns_numeric",
    "has_tls",
    "pkt_mean",
    "pkt_count",
    "iat_mean",
    "byte_ratio",
]


def vectorize(rec: FlowRecord) -> np.ndarray:
    qname = rec.dns_qname or ""
    sld = qname.split(".")[0] if qname else ""
    sizes = rec.pkt_sizes or [0]
    iats = rec.iat_ms or [0.0]
    is_syn = 1.0 if "S" in rec.tcp_flags.upper() and "A" not in rec.tcp_flags.upper() else 0.0
    ratio = rec.bytes_fwd / max(rec.bytes_rev, 1)
    return np.array(
        [
            float(rec.dst_port),
            float(rec.bytes_fwd),
            float(rec.bytes_rev),
            float(rec.pkts_fwd),
            float(rec.pkts_rev),
            float(rec.duration_ms),
            is_syn,
            1.0 if rec.protocol.upper() == "UDP" else 0.0,
            float(len(qname)),
            string_entropy(sld),
            ngram_rarity(sld, 3),
            numeric_ratio(sld),
            1.0 if rec.tls_ja3 or rec.tls_ja4 else 0.0,
            float(sum(sizes) / len(sizes)),
            float(len(rec.pkt_sizes or [])),
            float(sum(iats) / len(iats)),
            float(ratio),
        ],
        dtype=np.float64,
    )


class FlowClassifier:
    def __init__(self, model_path: Path | None = None) -> None:
        self.model = None
        self.classes_: list[str] = []
        if model_path and model_path.exists():
            payload = joblib.load(model_path)
            self.model = payload["model"]
            self.classes_ = list(payload["classes"])

    @property
    def ready(self) -> bool:
        return self.model is not None

    def predict_proba(self, rec: FlowRecord) -> dict[str, float]:
        if self.model is None:
            return {}
        x = vectorize(rec).reshape(1, -1)
        probs = self.model.predict_proba(x)[0]
        return {cls: float(p) for cls, p in zip(self.classes_, probs)}

    def top_threat(self, rec: FlowRecord, min_p: float = 0.45) -> tuple[ThreatClass, float] | None:
        dist = self.predict_proba(rec)
        if not dist:
            return None
        best_cls, best_p = max(dist.items(), key=lambda kv: kv[1])
        if best_cls == ThreatClass.BENIGN.value or best_p < min_p:
            return None
        try:
            return ThreatClass(best_cls), best_p
        except ValueError:
            return None
