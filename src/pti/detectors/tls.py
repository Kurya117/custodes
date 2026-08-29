"""Encrypted-session malware from TLS/QUIC metadata (no decryption)."""

from __future__ import annotations

from pti.features import coefficient_of_variation, string_entropy
from pti.schema import Alert, FlowRecord, ThreatClass, severity_from_confidence

# Synthetic "known-bad" JA3/JA4 fingerprints used by the simulator (hash prefixes).
BAD_JA3_PREFIXES = {"a1b2c3d4", "deadbeef", "c2malwar"}
BAD_JA4_PREFIXES = {"t13d", "q13d_bad"}


def _prefix(value: str | None, n: int = 8) -> str:
    if not value:
        return ""
    return value.lower()[:n]


class TlsMalwareDetector:
    name = "tls"

    def __init__(self, min_confidence: float = 0.55) -> None:
        self.min_confidence = min_confidence

    def observe(self, rec: FlowRecord) -> list[Alert]:
        if rec.dst_port not in (443, 853, 8443) and not rec.tls_ja3 and not rec.tls_ja4:
            return []
        if not rec.tls_ja3 and not rec.tls_ja4 and not rec.pkt_sizes:
            return []

        ja3 = _prefix(rec.tls_ja3)
        ja4 = _prefix(rec.tls_ja4, 8)
        sizes = rec.pkt_sizes or []
        iats = rec.iat_ms or []
        mean_size = sum(sizes) / len(sizes) if sizes else 0.0
        size_cv = coefficient_of_variation([float(s) for s in sizes]) if len(sizes) >= 2 else 0.0
        sni_ent = string_entropy(rec.tls_sni or "")
        alpn = (rec.tls_alpn or "").lower()

        score = 0.0
        evidence: dict = {
            "tls_version": rec.tls_version,
            "alpn": rec.tls_alpn,
            "sni": rec.tls_sni,
            "ja3_prefix": ja3,
            "ja4_prefix": ja4,
            "mean_pkt_size": round(mean_size, 1),
            "size_cv": round(size_cv, 3),
            "sni_entropy": round(sni_ent, 3),
        }
        if ja3 in BAD_JA3_PREFIXES or any(ja3.startswith(p) for p in BAD_JA3_PREFIXES):
            score += 0.55
            evidence["ja3_blocklist"] = True
        if any(ja4.startswith(p) for p in BAD_JA4_PREFIXES) or ja4 in BAD_JA4_PREFIXES:
            score += 0.25
            evidence["ja4_blocklist"] = True
        # Small, regular packets with odd ALPN / missing SNI is C2-like.
        if rec.tls_sni is None and rec.dst_port == 443:
            score += 0.15
        if alpn in {"h2c2", "mal", ""} and rec.tls_ja3:
            score += 0.1
        if sizes and mean_size < 180 and size_cv < 0.25 and len(sizes) >= 4:
            score += 0.2
        if iats and coefficient_of_variation(iats) < 0.2 and len(iats) >= 4:
            score += 0.1

        if score < self.min_confidence:
            return []
        conf = min(0.99, score)
        return [
            Alert(
                timestamp=rec.ts,
                flow_id=rec.flow_id,
                src_ip=rec.src_ip,
                dst_ip=rec.dst_ip,
                threat_class=ThreatClass.MALWARE_ENCRYPTED,
                severity=severity_from_confidence(conf, ThreatClass.MALWARE_ENCRYPTED),
                confidence=round(conf, 4),
                detector=self.name,
                evidence=evidence,
            )
        ]
