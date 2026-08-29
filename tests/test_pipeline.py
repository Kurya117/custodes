from pti.pipeline import Pipeline
from pti.schema import ThreatClass
from pti.simulator import mix_stream


def test_streaming_pipeline_emits_alerts_incrementally():
    pipe = Pipeline()
    seen = 0
    classes = set()
    for rec in mix_stream(8_000, seed=3):
        alerts = pipe.process(rec)
        if alerts:
            seen += len(alerts)
            classes.update(a.threat_class for a in alerts)
            # incremental: alerts exist before the stream ends
            if seen >= 5 and len(classes) >= 3:
                break
    assert seen >= 5
    assert ThreatClass.DDOS_SYN_FLOOD in classes or ThreatClass.DDOS_SPOOFED_FLOOD in classes
    assert pipe.flows_seen < 8_000  # not an end-of-run-only report
