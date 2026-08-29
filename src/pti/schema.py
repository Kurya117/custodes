"""Standardized alert and flow-record schemas for read-only ingest."""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ThreatClass(str, Enum):
    BENIGN = "benign"
    DDOS_SYN_FLOOD = "ddos_syn_flood"
    DDOS_UDP_AMPLIFICATION = "ddos_udp_amplification"
    DDOS_SPOOFED_FLOOD = "ddos_spoofed_flood"
    BOTNET_C2_BEACON = "botnet_c2_beacon"
    DGA_DOMAIN = "dga_domain"
    DNS_TUNNEL = "dns_tunnel"
    MALWARE_ENCRYPTED = "malware_encrypted"
    RECON_PORT_SCAN = "recon_port_scan"
    DATA_EXFILTRATION = "data_exfiltration"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FlowRecord(BaseModel):
    """One observed flow slice or packet-derived metadata record.

    Both forward and reverse byte counts may be present because a link
    diode copies *the wire* in one direction into the enclave — that is
    still strictly read-only with no path back to production.
    """

    ts: float
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "TCP"
    bytes_fwd: int = 0
    bytes_rev: int = 0
    pkts_fwd: int = 1
    pkts_rev: int = 0
    tcp_flags: str = ""
    duration_ms: float = 0.0
    dns_qname: str | None = None
    dns_qtype: str | None = None
    dns_rcode: str | None = None
    tls_sni: str | None = None
    tls_ja3: str | None = None
    tls_ja4: str | None = None
    tls_version: str | None = None
    tls_alpn: str | None = None
    pkt_sizes: list[int] = Field(default_factory=list)
    iat_ms: list[float] = Field(default_factory=list)
    label: str | None = None

    @property
    def flow_id(self) -> str:
        return f"{self.src_ip}:{self.src_port}>{self.dst_ip}:{self.dst_port}/{self.protocol}"


class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float
    flow_id: str
    src_ip: str
    dst_ip: str
    threat_class: ThreatClass
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    detector: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    window_start: float | None = None
    window_end: float | None = None

    def to_record(self) -> dict[str, Any]:
        return self.model_dump()


def severity_from_confidence(confidence: float, threat: ThreatClass) -> Severity:
    volumetric = {
        ThreatClass.DDOS_SYN_FLOOD,
        ThreatClass.DDOS_UDP_AMPLIFICATION,
        ThreatClass.DDOS_SPOOFED_FLOOD,
        ThreatClass.DATA_EXFILTRATION,
    }
    if threat in volumetric and confidence >= 0.75:
        return Severity.CRITICAL
    if confidence >= 0.85:
        return Severity.CRITICAL
    if confidence >= 0.7:
        return Severity.HIGH
    if confidence >= 0.5:
        return Severity.MEDIUM
    return Severity.LOW
