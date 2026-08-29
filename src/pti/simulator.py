"""One-way synthetic IP metadata generator (flows, DNS, TLS fingerprints).

Produces labelled JSONL for training, replay, and throughput benches.
Does not open connections or complete handshakes with any live host.
"""

from __future__ import annotations

import json
import random
import string
from collections.abc import Iterator
from pathlib import Path

from pti.schema import FlowRecord, ThreatClass

BENIGN_DOMAINS = [
    "cdn.example.net",
    "update.windows.com",
    "github.com",
    "ntp.ubuntu.com",
    "ocsp.digicert.com",
    "login.microsoftonline.com",
    "safebrowsing.googleapis.com",
]
BENIGN_JA3 = ["e7d705a3286e19ea42f587b344ee6865", "ada70206e40642a3e46a6dbf35d12c4a"]
MAL_JA3 = ["a1b2c3d4e5f678901234567890abcdef", "deadbeefcafebabe0123456789abcdef"]


def _ip(rng: random.Random, prefix: str = "10") -> str:
    return f"{prefix}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _pub(rng: random.Random) -> str:
    return f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _dga(rng: random.Random, n: int = 16) -> str:
    alphabet = string.ascii_lowercase + string.digits
    label = "".join(rng.choice(alphabet) for _ in range(n))
    return f"{label}.xyz"


def _tunnel_qname(rng: random.Random) -> str:
    payload = "".join(rng.choice(string.hexdigits.lower()) for _ in range(rng.randint(70, 140)))
    return f"{payload}.tunnel.example"


def generate_record(rng: random.Random, ts: float, kind: str) -> FlowRecord:
    src = _ip(rng)
    if kind == ThreatClass.BENIGN.value:
        dst = _pub(rng)
        port = rng.choice([80, 443, 53, 123, 22, 8080])
        proto = "UDP" if port in (53, 123) else "TCP"
        rec = FlowRecord(
            ts=ts,
            src_ip=src,
            dst_ip=dst,
            src_port=rng.randint(1024, 65535),
            dst_port=port,
            protocol=proto,
            bytes_fwd=rng.randint(200, 4000),
            bytes_rev=rng.randint(200, 8000),
            pkts_fwd=rng.randint(2, 20),
            pkts_rev=rng.randint(2, 25),
            tcp_flags="PA" if proto == "TCP" else "",
            duration_ms=rng.uniform(20, 800),
            label=kind,
        )
        if port == 53:
            rec.dns_qname = rng.choice(BENIGN_DOMAINS)
            rec.dns_qtype = "A"
            rec.dns_rcode = "NOERROR"
        if port == 443:
            rec.tls_sni = rng.choice(BENIGN_DOMAINS)
            rec.tls_ja3 = rng.choice(BENIGN_JA3)
            rec.tls_ja4 = "t13d1516h2_8daaf6152771"
            rec.tls_version = "TLS1.3"
            rec.tls_alpn = "h2"
            rec.pkt_sizes = [rng.randint(200, 1400) for _ in range(6)]
            rec.iat_ms = [rng.uniform(1, 40) for _ in range(6)]
        return rec

    if kind == ThreatClass.DDOS_SYN_FLOOD.value:
        victim = "203.0.113.10"
        return FlowRecord(
            ts=ts,
            src_ip=_pub(rng),
            dst_ip=victim,
            src_port=rng.randint(1024, 65535),
            dst_port=80,
            protocol="TCP",
            bytes_fwd=40,
            bytes_rev=0,
            pkts_fwd=1,
            pkts_rev=0,
            tcp_flags="S",
            duration_ms=0,
            label=kind,
        )

    if kind == ThreatClass.DDOS_UDP_AMPLIFICATION.value:
        return FlowRecord(
            ts=ts,
            src_ip=_pub(rng),
            dst_ip="203.0.113.10",
            src_port=53,
            dst_port=rng.randint(1024, 65535),
            protocol="UDP",
            bytes_fwd=rng.randint(2000, 4096),
            bytes_rev=0,
            pkts_fwd=1,
            pkts_rev=0,
            label=kind,
        )

    if kind == ThreatClass.DDOS_SPOOFED_FLOOD.value:
        return FlowRecord(
            ts=ts,
            src_ip=_pub(rng),
            dst_ip="203.0.113.10",
            src_port=rng.randint(1024, 65535),
            dst_port=rng.choice([80, 443, 53]),
            protocol=rng.choice(["TCP", "UDP"]),
            bytes_fwd=rng.randint(40, 200),
            bytes_rev=0,
            pkts_fwd=1,
            pkts_rev=0,
            tcp_flags="S",
            label=kind,
        )

    if kind == ThreatClass.BOTNET_C2_BEACON.value:
        bot = "10.0.4.20"
        c2 = "198.51.100.66"
        return FlowRecord(
            ts=ts,
            src_ip=bot,
            dst_ip=c2,
            src_port=rng.randint(40000, 50000),
            dst_port=443,
            protocol="TCP",
            bytes_fwd=rng.randint(180, 260),
            bytes_rev=rng.randint(120, 200),
            pkts_fwd=4,
            pkts_rev=3,
            tcp_flags="PA",
            duration_ms=80,
            tls_sni=None,
            tls_ja3=MAL_JA3[0],
            tls_ja4="t13d_badc2",
            tls_version="TLS1.2",
            pkt_sizes=[120, 130, 125, 128],
            iat_ms=[40, 41, 39, 42],
            label=kind,
        )

    if kind == ThreatClass.DGA_DOMAIN.value:
        return FlowRecord(
            ts=ts,
            src_ip=src,
            dst_ip="8.8.8.8",
            src_port=rng.randint(1024, 65535),
            dst_port=53,
            protocol="UDP",
            bytes_fwd=90,
            bytes_rev=40,
            pkts_fwd=1,
            pkts_rev=1,
            dns_qname=_dga(rng, rng.randint(14, 22)),
            dns_qtype="A",
            dns_rcode="NXDOMAIN",
            label=kind,
        )

    if kind == ThreatClass.DNS_TUNNEL.value:
        qn = _tunnel_qname(rng)
        return FlowRecord(
            ts=ts,
            src_ip=src,
            dst_ip="198.51.100.53",
            src_port=rng.randint(1024, 65535),
            dst_port=53,
            protocol="UDP",
            bytes_fwd=len(qn) + 40,
            bytes_rev=20,
            pkts_fwd=1,
            pkts_rev=1,
            dns_qname=qn,
            dns_qtype="TXT",
            dns_rcode="NOERROR",
            label=kind,
        )

    if kind == ThreatClass.MALWARE_ENCRYPTED.value:
        return FlowRecord(
            ts=ts,
            src_ip=src,
            dst_ip="198.51.100.77",
            src_port=rng.randint(1024, 65535),
            dst_port=443,
            protocol="TCP",
            bytes_fwd=800,
            bytes_rev=400,
            pkts_fwd=6,
            pkts_rev=5,
            tcp_flags="PA",
            tls_sni=None,
            tls_ja3=MAL_JA3[1],
            tls_ja4="t13d_badc2",
            tls_version="TLS1.2",
            tls_alpn="mal",
            pkt_sizes=[110, 115, 108, 112, 109],
            iat_ms=[30, 31, 29, 30, 32],
            label=kind,
        )

    if kind == ThreatClass.RECON_PORT_SCAN.value:
        scanner = "192.0.2.50"
        return FlowRecord(
            ts=ts,
            src_ip=scanner,
            dst_ip="10.0.0." + str(rng.randint(1, 20)),
            src_port=rng.randint(40000, 60000),
            dst_port=rng.randint(1, 1024),
            protocol="TCP",
            bytes_fwd=40,
            bytes_rev=0,
            pkts_fwd=1,
            pkts_rev=0,
            tcp_flags="S",
            duration_ms=0,
            label=kind,
        )

    # DATA_EXFILTRATION
    return FlowRecord(
        ts=ts,
        src_ip="10.0.8.9",
        dst_ip="198.51.100.200",
        src_port=rng.randint(1024, 65535),
        dst_port=443,
        protocol="TCP",
        bytes_fwd=rng.randint(80_000, 200_000),
        bytes_rev=rng.randint(200, 800),
        pkts_fwd=rng.randint(80, 200),
        pkts_rev=rng.randint(4, 12),
        tcp_flags="PA",
        duration_ms=400,
        tls_sni="files.drop.example",
        tls_ja3=BENIGN_JA3[0],
        tls_version="TLS1.3",
        label=kind,
    )


def mix_stream(
    n: int,
    seed: int = 7,
    start_ts: float = 1_700_000_000.0,
    attack_frac: float = 0.22,
) -> Iterator[FlowRecord]:
    """Mixed stream with short attack *bursts* so windowed detectors can fire."""
    rng = random.Random(seed)
    attacks = [t.value for t in ThreatClass if t != ThreatClass.BENIGN]
    ts = start_ts
    produced = 0
    beacon_i = 0
    while produced < n:
        remaining = n - produced
        if rng.random() < attack_frac and remaining > 8:
            kind = rng.choice(attacks)
            burst = min(remaining, _burst_len(kind, rng))
            for j in range(burst):
                if kind == ThreatClass.BOTNET_C2_BEACON.value:
                    rec = generate_record(rng, ts + beacon_i * 12.0, kind)
                    beacon_i += 1
                    ts = rec.ts + rng.uniform(0.001, 0.01)
                else:
                    rec = generate_record(rng, ts, kind)
                    ts += _dt(kind, rng)
                yield rec
                produced += 1
                if produced >= n:
                    return
        else:
            rec = generate_record(rng, ts, ThreatClass.BENIGN.value)
            ts += rng.uniform(0.002, 0.04)
            yield rec
            produced += 1


def _burst_len(kind: str, rng: random.Random) -> int:
    if kind in (
        ThreatClass.DDOS_SYN_FLOOD.value,
        ThreatClass.DDOS_UDP_AMPLIFICATION.value,
        ThreatClass.DDOS_SPOOFED_FLOOD.value,
    ):
        return rng.randint(500, 1200)
    if kind == ThreatClass.RECON_PORT_SCAN.value:
        return rng.randint(40, 90)
    if kind == ThreatClass.DATA_EXFILTRATION.value:
        return rng.randint(8, 16)
    if kind == ThreatClass.BOTNET_C2_BEACON.value:
        return rng.randint(6, 10)
    return rng.randint(8, 20)


def _dt(kind: str, rng: random.Random) -> float:
    if kind in (
        ThreatClass.DDOS_SYN_FLOOD.value,
        ThreatClass.DDOS_UDP_AMPLIFICATION.value,
        ThreatClass.DDOS_SPOOFED_FLOOD.value,
        ThreatClass.RECON_PORT_SCAN.value,
    ):
        return rng.uniform(0.0004, 0.002)
    if kind == ThreatClass.DATA_EXFILTRATION.value:
        return rng.uniform(0.05, 0.2)
    return rng.uniform(0.01, 0.06)


def write_jsonl(path: Path, n: int, seed: int = 7) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as fh:
        for rec in mix_stream(n, seed=seed):
            fh.write(json.dumps(rec.model_dump()) + "\n")
            count += 1
    return count
