# Models, features, and validation

This prototype uses **specialised streaming detectors** (primary) plus an optional **sklearn HistGradientBoostingClassifier** trained on synthetic labelled flow metadata.

All features are derived from passively observed records: 5-tuple, byte/packet counts, TCP flags, DNS query names/types, and TLS ClientHello-equivalent metadata (SNI, JA3/JA4, ALPN, first-N packet sizes and inter-arrival times). Payloads are never decrypted.

## Ingest record

See `pti.schema.FlowRecord`. A production diode would map NetFlow/IPFIX/sFlow plus a metadata tap (e.g. Zeek `dns.log` / `ssl.log`, JA4 from a passive probe) onto this schema. The simulator emits the same schema so the pipeline can be exercised without a live span port.

## Detector models

### 1. Volumetric / protocol DDoS (`detectors/ddos.py`)

- **Window:** 5 s global sliding window.
- **Features:** SYN-only rate, UDP rate, unique-source ratio, Shannon entropy of source IPs, amplification-port membership `{53,123,19,161,389,11211,1900}`, bytes on amp ports.
- **Logic:** Thresholds on rate + entropy. High unique-source ratio + high entropy ⇒ spoofed flood. SYN-without-ACK storms ⇒ SYN flood. UDP + amp ports ⇒ reflection/amplification.
- **Why not probes:** Counting SYNs vs SYN-ACKs uses *observed* reverse-direction copies on the mirrored link, not an active handshake from the detector.

### 2. Botnet C2 beaconing (`detectors/beacon.py`)

- **Window:** 120 s per `src→dst:port`.
- **Features:** inter-arrival times (IAT), coefficient of variation, periodicity score `1 / (1 + 4·CV)`, mean IAT.
- **Logic:** Regular IATs (CV < 0.35), mean IAT in 2–90 s, ≥6 observations. Distinguishes beacons from floods (too fast) and browsing (irregular).

### 3. DGA and DNS tunnelling (`detectors/dns.py`)

- **Features:** SLD length, Shannon entropy of the SLD, 3-gram rarity (vowel-less / all-vowel grams), numeric ratio, full QNAME length, QTYPE (`TXT`/`NULL`/…), UDP bytes on 53.
- **DGA:** high entropy + rare n-grams + long/numeric labels.
- **Tunnel:** long QNAME and/or tunnel-typical QTYPEs and oversized DNS payloads.

### 4. Encrypted malware (`detectors/tls.py`)

- **Features only:** JA3 / JA4 prefixes, SNI present?, SNI entropy, ALPN, mean packet size, size CV, IAT CV. **No record plaintext.**
- **Logic:** match against a small known-bad fingerprint set (simulator uses planted prefixes `a1b2c3d4`, `deadbeef`, `t13d_bad`) plus C2-like size/timing (small, regular packets, missing SNI).

### 5. Reconnaissance (`detectors/scan.py`)

- **Window:** 8 s per source IP.
- **Features:** unique destination ports, unique destination hosts, SYN with no reverse packets (observed).
- **Logic:** vertical scan if many ports; horizontal scan if many hosts and few ports.

### 6. Data exfiltration (`detectors/exfil.py`)

- **Window:** 30 s per `src→dst`.
- **Features:** sum `bytes_fwd`, sum `bytes_rev`, outbound/inbound ratio.
- **Logic:** large outbound volume and ratio ≥ 12. Reverse bytes still come from the mirrored link, not from querying the destination.

## Supervised classifier (`ml.py` / `train.py`)

- **Model:** `sklearn.ensemble.HistGradientBoostingClassifier` (`max_depth=6`, `learning_rate=0.08`, `max_iter=120`).
- **Labels:** ten-way (`benign` + nine threat enum values). Data is **synthetic** from `simulator.generate_record` (balanced by construction).
- **Feature vector (17):** dst_port, bytes_fwd/rev, pkts_fwd/rev, duration_ms, is_syn, is_udp, dns_qlen, dns_entropy, dns_rarity, dns_numeric, has_tls, pkt_mean, pkt_count, iat_mean, byte_ratio.
- **Split:** 75/25 stratified `train_test_split`.
- **Artifact:** `models/flow_hgb.joblib` plus `models/flow_hgb.metrics.txt` (classification report).
- **Fusion:** streaming detectors fire first (interpretable evidence). The classifier may add an alert when it is confident and the specialised detector did not already emit the same class (deduped by `src,dst,class` for 4 s).

This is **not** a substitute for models trained on operational captures (CIC-IDS, Zeek logs from the enclave, etc.). Swap `train.py` to read labelled JSONL from a real diode and keep `vectorize()` unchanged.

## Validation approach

1. Unit tests for entropy/periodicity and alert schema (`tests/test_schema_features.py`).
2. Streaming test: alerts appear **before** the iterator is exhausted (`tests/test_pipeline.py`).
3. Held-out classification report written at train time.
4. End-to-end `pti bench -n 50000` for latency/throughput (wall-clock flows/sec). Bounded latency is the window duration of the firing detector (5 s DDoS, 8 s scan, 30 s exfil, 120 s beacon), not a batch over the full file.

## Threats to validity

Synthetic traffic is separable by construction (planted JA3, regular 12 s beacons, random DGA labels). Real encrypted C2, domain-generation, and scan/worm mixtures need operational training data and likely sequence models (e.g. 1D-CNN on packet-size sequences) — still metadata-only.
