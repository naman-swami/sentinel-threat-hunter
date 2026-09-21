"""
Sentinel Threat Hunting & MITRE ATT&CK Correlation Engine
Calculates Shannon entropy of execution strings and maps tactics to the MITRE ATT&CK matrix.
"""
import math
from typing import Dict, Any, List

class ThreatHuntingEngine:
    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 2)

    @classmethod
    def evaluate_process_event(cls, image: str, cmdline: str) -> Dict[str, Any]:
        entropy = cls.calculate_shannon_entropy(cmdline)
        findings = []

        # MITRE T1059: Command and Scripting Interpreter
        if "powershell" in image.lower() and ("-enc" in cmdline.lower() or "-encodedcommand" in cmdline.lower()):
            findings.append({
                "mitre_id": "T1059.001",
                "tactic": "EXECUTION",
                "severity": "CRITICAL",
                "title": "Base64 Encoded PowerShell Command Execution",
                "shannon_entropy": entropy
            })

        # Obfuscation indicator: Shannon entropy > 4.5
        if entropy > 4.5:
            findings.append({
                "mitre_id": "T1027",
                "tactic": "DEFENSE_EVASION",
                "severity": "HIGH",
                "title": "High Entropy Obfuscated Command Line Detected",
                "shannon_entropy": entropy
            })

        threat_level = "CRITICAL" if any(f["severity"] == "CRITICAL" for f in findings) else "ELEVATED" if findings else "BENIGN"

        return {
            "image": image,
            "entropy": entropy,
            "threat_level": threat_level,
            "detections": findings
        }
