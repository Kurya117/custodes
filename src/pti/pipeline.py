"""Streaming inference pipeline: ingest -> features/detectors -> alerts.

Alerts are emitted incrementally with bounded detector windows (seconds),
not as an end-of-run batch report.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterator
from pathlib import Path

from pti.detectors import (
    BeaconDetector,
    DDoSDetector,
    DnsDetector,
    ExfilDetector,
    ScanDetector,
    TlsMalwareDetector,
)
from pti.ml import FlowClassifier
from pti.schema import Alert, FlowRecord, ThreatClass, severity_from_confidence


class Pipeline:
    def __init__(
        self,
        model_path: Path | None = None,
        on_alert: Callable[[Alert], None] | None = None,
        dedupe_s: float = 4.0,
    ) -> None:
        self.detectors = [
            DDoSDetector(),
            BeaconDetector(),
            DnsDetector(),
            TlsMalwareDetector(),
            ScanDetector(),
            ExfilDetector(),
        ]
        self.clf = FlowClassifier(model_path)
        self.on_alert = on_alert
        self.dedupe_s = dedupe_s
        self._recent: deque[tuple[float, str, str]] = deque(maxlen=20_000)
        self.alerts: deque[Alert] = deque(maxlen=5_000)
        self.flows_seen = 0

    def process(self, rec: FlowRecord) -> list[Alert]:
        self.flows_seen += 1
        emitted: list[Alert] = []
        for det in self.detectors:
            for alert in det.observe(rec):
                if self._is_dup(alert):
                    continue
                self._remember(alert)
                emitted.append(alert)
        ml_hit = None
        if self.clf.ready and self._ml_candidate(rec):
            ml_hit = self.clf.top_threat(rec)
        if ml_hit is not None:
            threat, p = ml_hit
            already = any(a.threat_class == threat for a in emitted)
            if not already:
                alert = Alert(
                    timestamp=rec.ts,
                    flow_id=rec.flow_id,
                    src_ip=rec.src_ip,
                    dst_ip=rec.dst_ip,
                    threat_class=threat,
                    severity=severity_from_confidence(p, threat),
                    confidence=round(min(0.99, p), 4),
                    detector="ml_classifier",
                    evidence={"ml_probability": round(p, 4), "source": "sklearn_hist_gbdt"},
                )
                if not self._is_dup(alert):
                    self._remember(alert)
                    emitted.append(alert)
        for alert in emitted:
            self.alerts.append(alert)
            if self.on_alert:
                self.on_alert(alert)
        return emitted

    def _ml_candidate(self, rec: FlowRecord) -> bool:
        if rec.dns_qname or rec.tls_ja3 or rec.tls_ja4:
            return True
        if rec.bytes_fwd >= 50_000:
            return True
        return self.flows_seen % 40 == 0

    def run(self, records: Iterator[FlowRecord]) -> list[Alert]:
        all_alerts: list[Alert] = []
        for rec in records:
            all_alerts.extend(self.process(rec))
        return all_alerts

    def _is_dup(self, alert: Alert) -> bool:
        key = f"{alert.threat_class.value}|{alert.src_ip}|{alert.dst_ip}"
        cutoff = alert.timestamp - self.dedupe_s
        for ts, k, _fid in self._recent:
            if ts >= cutoff and k == key:
                return True
        return False

    def _remember(self, alert: Alert) -> None:
        self._recent.append(
            (alert.timestamp, f"{alert.threat_class.value}|{alert.src_ip}|{alert.dst_ip}", alert.flow_id)
        )
