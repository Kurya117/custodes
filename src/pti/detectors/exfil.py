"""Data exfiltration: asymmetric volume and outbound/inbound byte ratios."""

from __future__ import annotations

from pti.schema import Alert, FlowRecord, ThreatClass, severity_from_confidence
from pti.windows import KeyedWindows


class ExfilDetector:
    name = "exfil"

    def __init__(
        self,
        window_s: float = 30.0,
        min_out_bytes: int = 400_000,
        min_ratio: float = 12.0,
        min_confidence: float = 0.55,
    ) -> None:
        self.by_pair = KeyedWindows(window_s, max_keys=20_000, max_per_key=80)
        self.min_out_bytes = min_out_bytes
        self.min_ratio = min_ratio
        self.min_confidence = min_confidence
        self.window_s = window_s

    def observe(self, rec: FlowRecord) -> list[Alert]:
        key = f"{rec.src_ip}->{rec.dst_ip}"
        hist = self.by_pair.add(key, rec)
        out_b = sum(r.bytes_fwd for r in hist)
        in_b = sum(r.bytes_rev for r in hist)
        ratio = out_b / max(in_b, 1)
        if out_b < self.min_out_bytes or ratio < self.min_ratio:
            return []
        conf = min(0.99, 0.5 + min(math_log_ratio(ratio), 0.4))
        if out_b > 2_000_000:
            conf = min(0.99, conf + 0.15)
        if conf < self.min_confidence:
            return []
        return [
            Alert(
                timestamp=rec.ts,
                flow_id=rec.flow_id,
                src_ip=rec.src_ip,
                dst_ip=rec.dst_ip,
                threat_class=ThreatClass.DATA_EXFILTRATION,
                severity=severity_from_confidence(conf, ThreatClass.DATA_EXFILTRATION),
                confidence=round(conf, 4),
                detector=self.name,
                evidence={
                    "bytes_out": out_b,
                    "bytes_in": in_b,
                    "out_in_ratio": round(ratio, 2),
                    "flows": len(hist),
                },
                window_start=rec.ts - self.window_s,
                window_end=rec.ts,
            )
        ]


def math_log_ratio(ratio: float) -> float:
    import math

    return min(0.45, math.log10(max(ratio, 1.0)) / 4.0)
