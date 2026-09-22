# Enterprise Security Architecture & Vulnerability Disclosure

## 1. Coordinated Vulnerability Disclosure (CVD) Policy
The Sentinel project adheres to Coordinated Vulnerability Disclosure principles in alignment with **NIST Special Publication 800-61 Rev. 2 (Computer Security Incident Handling Guide)** and **ISO/IEC 29147:2018 (Information technology — Security techniques — Vulnerability disclosure)**.

### Reporting a Vulnerability
If you discover a security vulnerability within Sentinel's threat detection algorithms, parser logic, or dependencies:
1. **Do NOT open a public GitHub issue**.
2. Encrypt your report using the SOC PGP Public Key and email `security@naman-swami.dev` (or open a confidential GitHub Security Advisory).
3. Include detailed steps to reproduce: sample Sysmon event logs, malicious command-line payloads, and expected vs. actual detection output.
4. The maintainer will acknowledge receipt within **24 hours** and deliver a remediation patch or mitigation advisory within **7 business days**.

### Safe Harbor
Security researchers conducting good-faith security analysis against Sentinel's detection models will not be subjected to legal action under the Computer Fraud and Abuse Act (CFAA), provided they:
- Do not access, modify, or exfiltrate private production customer log streams.
- Do not degrade system availability or execute denial-of-service (DoS) payloads against telemetry intake endpoints.
- Allow reasonable time for patch release prior to public disclosure.

---

## 2. SOC Telemetry Handling & Data Sanitization Standards
Sentinel ingests high-volume endpoint telemetry, predominantly **Sysmon Event ID 1 (Process Creation)** and **Linux Auditd/eBPF** streams. To protect corporate privacy and maintain compliance with **GDPR (Article 32)** and **SOC 2 Type II**:

- **Command-Line PII Scrubbing**: All process command lines are passed through a deterministic redaction pipeline prior to long-term indexing. Sensitive parameters including passwords (`-p`, `--password`), API keys, and bearer tokens are masked with `[REDACTED_SECRET]`.
- **User Principal Sanitization**: User SID and Active Directory samAccountName identifiers are pseudonymized with SHA-256 salted hashes unless explicit incident escalation is authorized.
- **Memory Footprint**: Sysmon log streams ingested via `fixtures/logs/` are evaluated in volatile memory buffers and flushed immediately after Shannon entropy analysis and MITRE correlation.

---

## 3. Threat Hunting Model & Detection Thresholds
The detection engine enforces strict mathematical heuristics to prevent analyst alert fatigue:
1. **Shannon Entropy Baseline**:
   $$H(X) = -\sum_{i=1}^n p(x_i) \log_2 p(x_i)$$
   - *Baseline Normal Commands*: $H(X) \in [2.5, 4.0]$ bits per byte.
   - *Alert Threshold*: $H(X) > 4.5$ bits per byte (triggers base64/XOR obfuscation inspection).
2. **MITRE ATT&CK Enterprise Matrix Mapping**:
   - **T1059.001 (Command & Scripting Interpreter: PowerShell)**: Detects `-enc`, `-EncodedCommand`, `-w hidden`, `-ep bypass`.
   - **T1027 (Obfuscated/Compressed Information)**: Detects payload compression and dynamic environment variable concatenation.
   - **T1082 (System Information Discovery)**: Flags automated enumeration scripts querying system state.

---

## 4. Incident Response Escalation Runbook
When an endpoint exhibits $H(X) > 4.5$ combined with a high-severity MITRE ATT&CK technique:
1. **P1 Containment**: The agent triggers API isolation of the affected workstation or server.
2. **Volatile Artifact Preservation**: Collects live memory dump, network socket connections (`netstat`), and parent-child process ancestry.
3. **Active Directory Action**: Revokes Kerberos Ticket-Granting Tickets (TGT) for the compromised user account.
4. **Post-Mortem**: Logs full forensic timeline to [EXPLAINABILITY.md](EXPLAINABILITY.md) for SOC incident debriefing.
