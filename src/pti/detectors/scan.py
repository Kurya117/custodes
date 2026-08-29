"""Reconnaissance / port scanning: fan-out across ports or hosts."""

from __future__ import annotations

from pti.schema import Alert, FlowRecord, ThreatClass, severity_from_confidence
from pti.windows import KeyedWindows


class ScanDetector:
    name = "scan"

    def __init__(
        self,
        window_s: float = 8.0,
        min_ports: int = 25,
        min_hosts: int = 20,
        min_confidence: float = 0.55,
    ) -> None:
        self.by_src = KeyedWindows(window_s, max_keys=30_000, max_per_key=400)
        self.min_ports = min_ports
        self.min_hosts = min_hosts
        self.min_confidence = min_confidence
        self.window_s = window_s

    def observe(self, rec: FlowRecord) -> list[Alert]:
        hist = self.by_src.add(rec.src_ip, rec)
        if len(hist) < self.min_ports and len(hist) < self.min_hosts:
            return []
        ports = {r.dst_port for r in hist}
        hosts = {r.dst_ip for r in hist}
        syns = sum(1 for r in hist if "S" in r.tcp_flags.upper() and r.pkts_rev == 0)
        fan_ports = len(ports)
        fan_hosts = len(hosts)
        alerts: list[Alert] = []
        if fan_ports >= self.min_ports:
            conf = min(0.99, 0.45 + min(fan_ports, 200) / 250)
            if syns / max(len(hist), 1) > 0.5:
                conf = min(0.99, conf + 0.1)
            if conf >= self.min_confidence:
                alerts.append(self._alert(rec, conf, {
                    "unique_dst_ports": fan_ports,
                    "unique_dst_hosts": fan_hosts,
                    "syn_no_reply": syns,
                    "window_flows": len(hist),
                }))
        elif fan_hosts >= self.min_hosts and fan_ports <= 5:
            conf = min(0.99, 0.5 + min(fan_hosts, 200) / 300)
            if conf >= self.min_confidence:
                alerts.append(self._alert(rec, conf, {
                    "unique_dst_ports": fan_ports,
                    "unique_dst_hosts": fan_hosts,
                    "horizontal_scan": True,
                    "window_flows": len(hist),
                }))
        return alerts

    def _alert(self, rec: FlowRecord, conf: float, evidence: dict) -> Alert:
        return Alert(
            timestamp=rec.ts,
            flow_id=rec.flow_id,
            src_ip=rec.src_ip,
            dst_ip=rec.dst_ip,
            threat_class=ThreatClass.RECON_PORT_SCAN,
            severity=severity_from_confidence(conf, ThreatClass.RECON_PORT_SCAN),
            confidence=round(conf, 4),
            detector=self.name,
            evidence=evidence,
            window_start=rec.ts - self.window_s,
            window_end=rec.ts,
        )
