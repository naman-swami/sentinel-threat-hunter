import os
import pytest
from threat_intel.mitre_attack_mapper import ThreatHuntingEngine

def test_powershell_encoded_detection():
    res = ThreatHuntingEngine.evaluate_process_event(
        image="powershell.exe",
        cmdline="powershell -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
    )
    assert res["threat_level"] == "CRITICAL"
    mitre_ids = [d["mitre_id"] for d in res["detections"]]
    assert "T1059.001" in mitre_ids

def test_benign_git_command():
    res = ThreatHuntingEngine.evaluate_process_event(
        image="git.exe",
        cmdline="git status"
    )
    assert res["threat_level"] == "BENIGN"
    assert len(res["detections"]) == 0
