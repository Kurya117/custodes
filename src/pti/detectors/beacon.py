"""Botnet C2 beaconing via inter-arrival regularity toward few destinations."""

from __future__ import annotations

from pti.features import coefficient_of_variation, periodicity_score
from pti.schema import Alert, FlowRecord, ThreatClass, severity_from_confidence
from pti.windows import KeyedWindows


class BeaconDetector:
    name = "beacon"

    def __init__(self, window_s: float = 120.0, min_confidence: float = 0.55) -> None:
        self.pairs = KeyedWindows(window_s, max_keys=20_000, max_per_key=64)
        self.min_confidence = min_confidence

    def observe(self, rec: FlowRecord) -> list[Alert]:
        key = f"{rec.src_ip}->{rec.dst_ip}:{rec.dst_port}"
        hist = self.pairs.add(key, rec)
        if len(hist) < 6:
            return []
        times = [r.ts for r in hist]
        iats = [t1 - t0 for t0, t1 in zip(times, times[1:]) if t1 > t0]
        if len(iats) < 5:
            return []
        score = periodicity_score(iats)
        cv = coefficient_of_variation(iats)
        mean_iat = sum(iats) / len(iats)
        # Beacons: regular, not too fast (not a flood), not one-shot browsing
        if score >= 0.72 and 2.0 <= mean_iat <= 90.0 and cv < 0.35:
            conf = min(0.99, 0.45 + score * 0.5)
            if conf < self.min_confidence:
                return []
            return [
                Alert(
                    timestamp=rec.ts,
                    flow_id=rec.flow_id,
                    src_ip=rec.src_ip,
                    dst_ip=rec.dst_ip,
                    threat_class=ThreatClass.BOTNET_C2_BEACON,
                    severity=severity_from_confidence(conf, ThreatClass.BOTNET_C2_BEACON),
                    confidence=round(conf, 4),
                    detector=self.name,
                    evidence={
                        "periodicity": round(score, 3),
                        "iat_cv": round(cv, 3),
                        "mean_iat_s": round(mean_iat, 3),
                        "observations": len(hist),
                        "dst_port": rec.dst_port,
                    },
                    window_start=times[0],
                    window_end=rec.ts,
                )
            ]
        return []
