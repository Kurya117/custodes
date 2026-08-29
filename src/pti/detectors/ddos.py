"""Volumetric / protocol DDoS from flow-level rate and source-IP entropy."""

from __future__ import annotations

from pti.features import shannon_entropy
from pti.schema import Alert, FlowRecord, ThreatClass, severity_from_confidence
from pti.windows import TimeWindow

AMP_PORTS = {53, 123, 19, 161, 389, 11211, 1900}


class DDoSDetector:
    name = "ddos"

    def __init__(
        self,
        window_s: float = 5.0,
        syn_rate_threshold: float = 80.0,
        udp_rate_threshold: float = 60.0,
        min_confidence: float = 0.55,
    ) -> None:
        self.window = TimeWindow(window_s)
        self.syn_rate_threshold = syn_rate_threshold
        self.udp_rate_threshold = udp_rate_threshold
        self.min_confidence = min_confidence
        self._seen = 0

    def observe(self, rec: FlowRecord) -> list[Alert]:
        self.window.add(rec)
        self._seen += 1
        n = len(self.window)
        if n < 40:
            return []
        # Full window scan is O(n); subsample once the window is hot.
        if n > 80 and self._seen % 24 != 0:
            return []
        recs = self.window.records()
        dur = max(self.window.duration_s, 0.001)
        syns = [r for r in recs if "S" in r.tcp_flags.upper() and "A" not in r.tcp_flags.upper()]
        syn_rate = len(syns) / dur
        udp = [r for r in recs if r.protocol.upper() == "UDP"]
        udp_rate = len(udp) / dur
        srcs = [r.src_ip for r in recs]
        src_entropy = shannon_entropy(srcs)
        unique_src = len(set(srcs))
        unique_ratio = unique_src / max(len(srcs), 1)

        alerts: list[Alert] = []
        if syn_rate >= self.syn_rate_threshold:
            conf = min(0.99, 0.55 + (syn_rate / self.syn_rate_threshold) * 0.2 + unique_ratio * 0.15)
            if conf >= self.min_confidence:
                alerts.append(self._alert(rec, ThreatClass.DDOS_SYN_FLOOD, conf, {
                    "syn_rate": round(syn_rate, 2),
                    "src_entropy": round(src_entropy, 3),
                    "unique_src_ratio": round(unique_ratio, 3),
                    "window_flows": n,
                }))
        amp = [r for r in udp if r.dst_port in AMP_PORTS or r.src_port in AMP_PORTS]
        amp_bytes = sum(r.bytes_fwd + r.bytes_rev for r in amp)
        if udp_rate >= self.udp_rate_threshold and amp:
            conf = min(0.99, 0.58 + (udp_rate / self.udp_rate_threshold) * 0.18)
            if conf >= self.min_confidence:
                alerts.append(self._alert(rec, ThreatClass.DDOS_UDP_AMPLIFICATION, conf, {
                    "udp_rate": round(udp_rate, 2),
                    "amp_flows": len(amp),
                    "amp_bytes": amp_bytes,
                    "src_entropy": round(src_entropy, 3),
                }))
        if unique_ratio > 0.85 and n > 80 and src_entropy > 5.5:
            flood_rate = n / dur
            if flood_rate > 150:
                conf = min(0.99, 0.5 + unique_ratio * 0.3)
                if conf >= self.min_confidence:
                    alerts.append(self._alert(rec, ThreatClass.DDOS_SPOOFED_FLOOD, conf, {
                        "flow_rate": round(flood_rate, 2),
                        "src_entropy": round(src_entropy, 3),
                        "unique_src_ratio": round(unique_ratio, 3),
                    }))
        return alerts

    def _alert(self, rec: FlowRecord, threat: ThreatClass, conf: float, evidence: dict) -> Alert:
        return Alert(
            timestamp=rec.ts,
            flow_id=rec.flow_id,
            src_ip=rec.src_ip,
            dst_ip=rec.dst_ip,
            threat_class=threat,
            severity=severity_from_confidence(conf, threat),
            confidence=round(conf, 4),
            detector=self.name,
            evidence=evidence,
            window_start=rec.ts - self.window.duration_s,
            window_end=rec.ts,
        )
