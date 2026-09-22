# Sentinel SOC Threat Hunter

> **Enterprise Threat Intelligence & Sysmon Behavioral Correlation Engine**  
> Operationalizing MITRE ATT&CK® Tactic Mappings and Shannon Entropy Payload Detection for Security Operations Centers.

---

### Terminal Session Preview

```console
$ python hunt.py --demo
[2026-09-22 12:40:01] [*] Ingesting Sysmon Event ID 1 stream from fixtures/logs/sysmon_event_stream.json...
[2026-09-22 12:40:01] [+] Process: powershell.exe (PID: 4912) | Parent: cmd.exe
[2026-09-22 12:40:01] [!] Obfuscation Detected: Shannon Entropy = 4.82 bits/byte (Threshold > 4.5)
[2026-09-22 12:40:01] [!] Payload: -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA...
[2026-09-22 12:40:01] [ALERT] MITRE ATT&CK Match:
                      - T1059.001 (Command and Scripting Interpreter: PowerShell)
                      - T1027     (Obfuscated/Compressed Information)
[2026-09-22 12:40:01] [ACTION REQUIRED] Recommended Triage: ISOLATE ENDPOINT (Host: WORKSTATION-09)
```

---

### Threat Detection Matrix

| Technique ID | Technique Name | Detection Heuristic | Severity | Action Trigger |
| :--- | :--- | :--- | :--- | :--- |
| **T1059.001** | PowerShell Execution | Execution of unmanaged `powershell.exe` with execution policy bypass flags | High | Log & Alert |
| **T1027** | Encrypted/Obfuscated Payload | Shannon Entropy $H(X) = -\sum p(x) \log_2 p(x) > 4.5$ on command line | Critical | Host Isolation |
| **T1082** | System Information Discovery | Rapid sequence reconnaissance commands (`whoami`, `systeminfo`, `net user`) | Medium | SOC Analyst Queue |

---

### Security Operations Playbook Integration

This agent directly feeds into SOC containment runbooks. When payload entropy exceeds $4.5$, the engine triggers an automatic severity escalation according to [SECURITY.md](SECURITY.md) guidelines:

1. **Endpoint Quarantine**: Isolates network interface via API while preserving memory state for volatility forensics.
2. **Credential Revocation**: Marks active Kerberos TGT tickets for the executing service principal as compromised.
3. **Artifact Logging**: Retains raw Sysmon Event ID 1 telemetry in accordance with NIST SP 800-86 standards.

---

### Verification & Testing

```bash
# Execute unit detection test suite
pytest tests/ -v

# Inspect full explainability trail
cat EXPLAINABILITY.md
```

### Manifest Specifications

Compliant with OpenGAP 0.1.0 specifications. Model parameters, behavioral charters, and framework export packages are detailed in [agent.yaml](agent.yaml) and [SOUL.md](SOUL.md).
