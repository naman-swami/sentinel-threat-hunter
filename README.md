# Sentinel SOC Threat Hunter & MITRE ATT&CK Engine

[![OpenGAP](https://img.shields.io/badge/OpenGAP-0.1.0-blue.svg)](agent.yaml)
[![Cybersecurity](https://img.shields.io/badge/Domain-SOC_Threat_Hunting-darkred.svg)](docs/mitre_attack_enterprise_ref.md)
[![Standard](https://img.shields.io/badge/Standard-MITRE_ATT%26CK-blue.svg)](docs/mitre_attack_enterprise_ref.md)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](requirements.txt)
[![CI](https://img.shields.io/badge/CI-Passing-brightgreen.svg)](.github/workflows/ci.yml)

An enterprise security operations center (SOC) threat hunting engine performing Shannon entropy payload analysis and MITRE ATT&CK behavioral correlation on Sysmon endpoint streams.

```
                    ┌─────────────────────────┐
                    │ Sysmon Event ID 1 Logs  │
                    │ (Image, CommandLine)    │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ threat_intel/mitre_map  │
                    └────────────┬────────────┘
                                 │
                 ┌───────────────┴───────────────┐
                 ▼                               ▼
      ┌─────────────────────┐         ┌─────────────────────┐
      │  Shannon Entropy    │         │  MITRE ATT&CK Match │
      │  (Entropy > 4.5)    │         │ (T1059.001 / T1027) │
      └──────────┬──────────┘         └──────────┬──────────┘
                 │                               │
                 └───────────────┬───────────────┘
                                 ▼
                    ┌─────────────────────────┐
                    │ Incident Triage Level   │
                    │ (CRITICAL / ISOLATE)    │
                    └─────────────────────────┘
```

## Features

- **Shannon Entropy Analysis**: Detects base64, XOR, or encrypted strings hiding malicious payloads.
- **MITRE ATT&CK Matrix Mapping**: Correlates process execution directly to tactics (Execution, Defense Evasion).
- **Sysmon Telemetry Grounding**: Pre-configured with benchmark suspicious endpoint logs.

## Directory Structure

```
sentinel-threat-hunter/
├── agent.yaml                       # OpenGAP 0.1.0 Manifest
├── EXPLAINABILITY.md                # 7-checkpoint threat intelligence provenance
├── threat_intel/
│   └── mitre_attack_mapper.py       # Shannon entropy and MITRE ATT&CK matcher
├── fixtures/
│   └── logs/
│       └── sysmon_event_stream.json # Benchmark Sysmon endpoint logs
├── docs/
│   └── mitre_attack_enterprise_ref.md # ATT&CK framework reference
├── tests/
│   └── test_agent.py                # Threat detection test suite
├── main.py                          # SOC analyst CLI
└── requirements.txt
```

## Quick Start

```bash
# Run threat hunting tests
pytest tests/ -v

# Analyze benchmark Sysmon event stream
python main.py --demo
```
