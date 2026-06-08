# WRAITH — AI Security Swarm

> The world's first civilian AI security swarm. Free, open source, legal by design.

**13 AI agents. 50+ security tools. Self-evolving intelligence. $0 to start.**

## What's New in v3.0

- **Attack Intelligence Engine** — Graph-based attack path reasoning with MITRE ATT&CK mapping
- **Threat Intelligence** — Multi-source aggregation (NVD/CVE, Certificate Transparency, breach data)
- **Zero-Day Prediction** — Bayesian reasoning to predict unknown vulnerabilities from tech stacks
- **Compliance Engine** — Auto-map findings to 8 frameworks (OWASP, NIST, ISO 27001, SOC 2, PCI DSS, HIPAA, GDPR, CIS)
- **Risk Calculator** — FAIR quantitative risk analysis with breach cost estimates
- **Full Scanner + Forge Agents** — TCP port scanning, banner grabbing, CVE cross-referencing, exploit chains

## Install

```bash
git clone https://github.com/Daylyt-kb/WRAITH.git
cd WRAITH/public
pip install -r requirements.txt
python cipher.py --check-tools
python cipher.py -t example.com -m recon --authorized
```

## Usage

```bash
# Quick recon scan
python cipher.py -t example.com -m recon --authorized

# Full scan with all agents
python cipher.py -t example.com -m full --authorized

# Check tool availability
python cipher.py --check-tools

# Interactive mode
python cipher.py --interactive
```

## The 13 Agents

### Free Tier (9 agents)
1. **Commander** — The brain. Coordinates all agents.
2. **Ghost** — Reconnaissance. DNS, subdomains, WHOIS, tech fingerprinting.
3. **Specter** — OSINT. Emails, certificate transparency, breach records.
4. **Scanner** — Port scanning. Nmap integration, service detection, version fingerprinting.
5. **Forge** — Vulnerability discovery. CVE cross-referencing, exploit chains.
6. **Mirror** — Web analysis. Headers, cookies, CSP, CORS, SSL/TLS.
7. **Neuron** — The learner. Self-evolving memory from every scan.
8. **Searcher** — Deep search. Shodan, Censys, public databases.
9. **Ledger** — Report generator. PDF reports, severity ratings, remediation.

### Pro Tier (4 additional agents)
10. **Breach** — Active exploitation testing. SSRF, SQLi, XSS, auth bypass.
11. **Phantom** — Dark web monitoring. Credential leaks, brand mentions.
12. **Sentinel** — Continuous monitoring. 24/7 watch, alerts on changes.
13. **Orchestrator** — Enterprise campaign manager. Multi-target operations.

## Core Modules

| Module | Purpose |
|--------|---------|
| `core/attack_graph.py` | Graph-based attack path reasoning with MITRE ATT&CK mapping |
| `core/threat_intel.py` | Multi-source threat intelligence aggregation |
| `core/prediction_engine.py` | Zero-day vulnerability prediction via Bayesian reasoning |
| `core/compliance_mapper.py` | 8-framework compliance mapping |
| `core/risk_calculator.py` | FAIR quantitative risk analysis |
| `core/sandbox.py` | Docker-based Kali Linux sandbox environments |
| `core/kali_vm.py` | On-demand VM provisioning with tool auto-installation |
| `core/ai_provider.py` | Universal AI interface (8+ LLM providers) |
| `core/memory.py` | Self-evolving SQLite-backed knowledge system |

## Requirements
- Python 3.9+
- Linux/macOS/WSL (Kali Linux recommended for built-in security tools)
- Optional: OPENROUTER_API_KEY for AI-powered analysis
- Optional: Docker for sandboxed tool execution

## Legal
Only test systems you own or have written authorization for. WRAITH enforces consent at the architectural level.
