import random

from pti.features import ngram_rarity, periodicity_score, string_entropy
from pti.schema import Alert, FlowRecord, Severity, ThreatClass
from pti.simulator import generate_record


def test_alert_schema_roundtrip():
    a = Alert(
        timestamp=1.0,
        flow_id="a:1>b:2/TCP",
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        threat_class=ThreatClass.DDOS_SYN_FLOOD,
        severity=Severity.HIGH,
        confidence=0.9,
        detector="ddos",
        evidence={"syn_rate": 100},
    )
    rec = a.to_record()
    assert rec["threat_class"] == "ddos_syn_flood"
    assert rec["confidence"] == 0.9
    assert "syn_rate" in rec["evidence"]


def test_dga_entropy_higher_than_english():
    assert string_entropy("kj3m9xqz8pl2w") > string_entropy("microsoft")
    assert ngram_rarity("qjxkwzmpqjxk") > ngram_rarity("google")


def test_periodicity_regular_vs_jitter():
    regular = [12.0] * 8
    jitter = [2.0, 40.0, 7.0, 19.0, 3.0, 55.0]
    assert periodicity_score(regular) > periodicity_score(jitter)


def test_generate_all_classes():
    rng = random.Random(0)
    for t in ThreatClass:
        rec = generate_record(rng, 0.0, t.value)
        assert isinstance(rec, FlowRecord)
        assert rec.label == t.value
