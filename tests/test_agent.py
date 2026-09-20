import pytest
from src.threat_engine import ThreatHunterEngine

def test_entropy_computation():
    engine = ThreatHunterEngine()
    assert engine.compute_shannon_entropy("aaaaaa") == 0.0
    # High entropy random-looking string
    assert engine.compute_shannon_entropy("SQBFAFgAIAAoAE4AZQB3AC0ATwBi") > 3.0

def test_critical_credential_dump_detection():
    engine = ThreatHunterEngine()
    event = {
        "event_id": "TEST-01",
        "command_line": "procdump.exe -ma lsass.exe lsass.dmp",
        "lateral_connections": 5
    }
    report = engine.evaluate_security_event(event)
    assert report["threat_severity"] == "CRITICAL"
    assert "ISOLATE_HOST" in report["automated_containment_action"]
