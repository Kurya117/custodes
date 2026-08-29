"""DGA domains and DNS tunnelling from query names, length, and record types."""

from __future__ import annotations

from pti.features import ngram_rarity, numeric_ratio, string_entropy
from pti.schema import Alert, FlowRecord, ThreatClass, severity_from_confidence

TUNNEL_QTYPES = {"TXT", "NULL", "CNAME", "MX"}


class DnsDetector:
    name = "dns"

    def __init__(self, min_confidence: float = 0.55) -> None:
        self.min_confidence = min_confidence

    def observe(self, rec: FlowRecord) -> list[Alert]:
        if not rec.dns_qname:
            return []
        qname = rec.dns_qname.lower().rstrip(".")
        labels = qname.split(".")
        sld = labels[0] if labels else qname
        ent = string_entropy(sld)
        rarity = ngram_rarity(sld, 3)
        num = numeric_ratio(sld)
        qlen = len(qname)
        alerts: list[Alert] = []

        dga_score = 0.0
        if len(sld) >= 10 and ent >= 3.4:
            dga_score += 0.35
        if rarity >= 0.45:
            dga_score += 0.3
        if num >= 0.25:
            dga_score += 0.2
        if len(sld) >= 16:
            dga_score += 0.15
        if dga_score >= 0.55:
            conf = min(0.99, dga_score)
            if conf >= self.min_confidence:
                alerts.append(
                    Alert(
                        timestamp=rec.ts,
                        flow_id=rec.flow_id,
                        src_ip=rec.src_ip,
                        dst_ip=rec.dst_ip,
                        threat_class=ThreatClass.DGA_DOMAIN,
                        severity=severity_from_confidence(conf, ThreatClass.DGA_DOMAIN),
                        confidence=round(conf, 4),
                        detector=self.name,
                        evidence={
                            "qname": qname[:120],
                            "label_entropy": round(ent, 3),
                            "ngram_rarity": round(rarity, 3),
                            "numeric_ratio": round(num, 3),
                            "sld_len": len(sld),
                        },
                    )
                )

        tunnel = 0.0
        qtype = (rec.dns_qtype or "A").upper()
        if qlen >= 60:
            tunnel += 0.4
        if qtype in TUNNEL_QTYPES:
            tunnel += 0.35
        if qlen >= 90:
            tunnel += 0.2
        if rec.bytes_fwd > 400 and rec.dst_port == 53:
            tunnel += 0.15
        if tunnel >= 0.55:
            conf = min(0.99, tunnel)
            if conf >= self.min_confidence:
                alerts.append(
                    Alert(
                        timestamp=rec.ts,
                        flow_id=rec.flow_id,
                        src_ip=rec.src_ip,
                        dst_ip=rec.dst_ip,
                        threat_class=ThreatClass.DNS_TUNNEL,
                        severity=severity_from_confidence(conf, ThreatClass.DNS_TUNNEL),
                        confidence=round(conf, 4),
                        detector=self.name,
                        evidence={
                            "qname": qname[:120],
                            "qlen": qlen,
                            "qtype": qtype,
                            "bytes_fwd": rec.bytes_fwd,
                        },
                    )
                )
        return alerts
