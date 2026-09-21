import argparse
import json
import os
from threat_intel.mitre_attack_mapper import ThreatHuntingEngine

def main():
    parser = argparse.ArgumentParser(description="Sentinel Threat Hunter CLI")
    parser.add_argument("--demo", action="store_true", help="Hunt in sample Sysmon event stream")
    args = parser.parse_args()

    data_file = os.path.join(os.path.dirname(__file__), "fixtures", "logs", "sysmon_event_stream.json")

    if args.demo:
        with open(data_file, "r") as f:
            events = json.load(f)
        print("=== SENTINEL SOC THREAT HUNTING AUDIT REPORT ===\n")
        for ev in events:
            res = ThreatHuntingEngine.evaluate_process_event(ev["image"], ev["command_line"])
            print(f"Process: {ev['image']} (User: {ev['user']})")
            print(f"  Command: {ev['command_line']}")
            print(f"  Shannon Entropy: {res['entropy']} | Threat Tier: {res['threat_level']}")
            for d in res["detections"]:
                print(f"    * [{d['severity']}] {d['mitre_id']} ({d['tactic']}): {d['title']}")
            print("-" * 50)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
