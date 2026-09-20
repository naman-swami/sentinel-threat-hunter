import json
import argparse
from src.threat_engine import ThreatHunterEngine

def main():
    parser = argparse.ArgumentParser(description="Sentinel Threat Hunter CLI")
    parser.add_argument("--demo", action="store_true", help="Run simulated endpoint threat detection audit")
    args = parser.parse_args()

    engine = ThreatHunterEngine()
    sample_event = {
        "event_id": "SEC-LOG-89102",
        "hostname": "FIN-WORKSTATION-04",
        "command_line": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA=",
        "lateral_connections": 4
    }

    report = engine.evaluate_security_event(sample_event)
    print("="*60)
    print(" SENTINEL CYBER THREAT HUNTING INCIDENT REPORT")
    print("="*60)
    print(json.dumps(report, indent=2))
    print("="*60)

if __name__ == "__main__":
    main()
