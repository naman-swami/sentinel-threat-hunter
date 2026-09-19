# Explainability — sentinel-threat-hunter

## Decision Reasoning
Sentinel correlates alerts by extracting indicators of compromise (hashes, IPs, domain patterns), clustering temporal telemetry into attack chains, and mapping observed adversary behaviors to MITRE ATT&CK technique IDs.

## Data Sources and Inputs Used
Curated threat intelligence feeds (MISP, AlienVault OTX, CISA alerts), network telemetry (Syslog, PCAP flows, NetFlow), endpoint EDR telemetry (Sysmon, auditd), and MITRE ATT&CK enterprise matrices.

## Confidence Scoring Methodology
Before returning a final recommendation or analysis, sentinel-threat-hunter assigns an internal confidence score (0–100%) based on:
1. **Source Grounding**: High (90–100%) when corroborated by primary authoritative standards and deterministic checks.
2. **Structural Completeness**: Moderate (75–89%) when operating on partial context or heuristic inferences.
3. If confidence falls below 85%, sentinel-threat-hunter will explicitly prepend a disclaimer to the user.

## Source Attribution Protocol
When relying on specific named standards, statutory codes, or operational benchmarks, sentinel-threat-hunter explicitly cites the governing framework or canonical specification rather than presenting deductions as ungrounded truths.

## Bias Awareness
sentinel-threat-hunter actively accounts for domain-specific operational biases:
- **Baseline Skew**: Avoids over-indexing on standard common scenarios at the expense of rare edge cases.
- **Reporting Disparity**: Recognizes that historical telemetry and training data may underrepresent frontier or non-standard architectures.
- **Jurisdictional & Demographic Neutrality**: Strives to maintain universal, objective evaluation standards across varying environments.

## Limitation Taxonomy per Domain
- Zero-Day Payloads: Purely novel, unobserved exploit techniques without behavioral anomalies may evade signature checks.
- Encrypted Traffic: Cannot inspect TLS-encrypted packet payloads without enterprise SSL decryption proxy endpoints.
- Active Exploitation: Cannot perform offensive penetration testing or reverse-exploitation against external command servers.
- Forensic Scope: Relies strictly on forwarded log telemetry and cannot conduct physical hardware forensics.

## Uncertainty Quantification Approach
When indicators exhibit low reputation confidence or low signal-to-noise ratios (e.g., dynamic cloud IP addresses), Sentinel tags findings with low confidence (<0.70), advises against automatic IP blocking, and initiates manual SOC analyst verification.
