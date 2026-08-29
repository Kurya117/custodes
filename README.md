# Passive Threat Intel

Read-only AI/ML pipeline that scores cyber threats from a **one-directional** IP metadata stream (mirrored / diode ingest). The system never re-contacts sources, never completes handshakes, never decrypts TLS/QUIC, and never sends mitigations. Output is intelligence only: structured alerts plus a live dashboard.

## Constraints (enforced by design)

| Constraint | How it is met |
|---|---|
| Read-only ingest | JSONL / stdin consume-only. No sockets toward traffic sources. |
| No payload decryption | TLS/QUIC path uses JA3/JA4-style fingerprints, SNI, ALPN, packet sizes, and timing only. |
| Streaming, not batch | Sliding windows (seconds–minutes). Alerts emit as records arrive. |
| Defined throughput | `pti bench` reports sustained **flows/sec** (and an approximate metadata Mbps). |
| Standardized alerts | `timestamp`, `flow_id`, `threat_class`, `confidence`, `severity`, `evidence`, `detector`. |

## Threat classes

- Volumetric / protocol DDoS (SYN flood, UDP amplification, spoofed-source flood)
- Botnet C2 beaconing (inter-arrival periodicity)
- DGA domains and DNS tunnelling
- Malware in encrypted sessions (TLS metadata)
- Reconnaissance / port scanning
- Data exfiltration (asymmetric byte ratios)

## Quick start

```powershell
cd $HOME\passive-threat-intel
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
pti train
pti simulate --out data\replay.jsonl -n 20000
pti run --source data\replay.jsonl --dashboard
```

Open http://127.0.0.1:8080

Without a file, generate on the fly:

```powershell
pti run --generate 20000 --dashboard --pace 0
```

Stdout JSONL alerts (no UI):

```powershell
pti run --source data\replay.jsonl > data\alerts.jsonl
```

Throughput:

```powershell
pti bench -n 50000
```

## Architecture

```
[ simulated / mirrored JSONL ]  --read only-->  ingest
                                              |
                                         sliding windows
                                              |
                    +------------+------------+-------------+
                    | DDoS stats | beacon IAT | DNS entropy |
                    | TLS meta   | scan fanout| exfil ratio |
                    +------------+------------+-------------+
                                              |
                                      optional HGB classifier
                                              |
                              Alert records --> dashboard / stdout
```

See [docs/MODELS.md](docs/MODELS.md) for features, models, and validation.

## Throughput target

The prototype is specified and measured on **synthetic flow-metadata JSONL**, not raw 10 GbE packet capture. Default bench: **50,000 flows**. On a typical developer CPU the pipeline is expected in the **10k–80k flows/sec** range depending on whether the sklearn model is loaded. Run `pti bench` on your machine and record the printed `flows_per_sec` / `approx_mbps_metadata`.

## Alert schema (example)

```json
{
  "alert_id": "…",
  "timestamp": 1700000123.45,
  "flow_id": "192.0.2.50:44122>10.0.0.4:22/TCP",
  "src_ip": "192.0.2.50",
  "dst_ip": "10.0.0.4",
  "threat_class": "recon_port_scan",
  "severity": "high",
  "confidence": 0.82,
  "detector": "scan",
  "evidence": {"unique_dst_ports": 41, "syn_no_reply": 38},
  "window_start": 1700000115.4,
  "window_end": 1700000123.45
}
```
