# WRAITH — AI Security Swarm (Public Repo)

## What is WRAITH

WRAITH is the **world's first civilian AI security swarm**. Not a single tool — 13 specialized AI agents that work together autonomously to find security vulnerabilities in any target: websites, networks, apps, servers, cloud infrastructure.

**This is the open-source repo.** The CLI-based security scanner that anyone can install and run. A separate private repo contains the web platform (FastAPI + Vue 3 + Supabase + PayStack).

## Repository

```
wraith/
├── public/   → github.com/Daylyt-kb/WRAITH (open source, pip install)
└── private/  → github.com/Daylyt-kb/private-WRAITH-ripo-for-storage- (pro platform)
```

## Quick Start

```bash
git clone https://github.com/Daylyt-kb/WRAITH.git
cd WRAITH/public
pip install -r requirements.txt
python cipher.py --check-tools
python cipher.py -t example.com -m recon --authorized
```

## What Needs Building

| Component | Public | Private |
|-----------|--------|---------|
| CLI entry point (`cipher.py`) | ✅ Needed | ❌ No |
| All 13 agents | ✅ Needed | ✅ Needed |
| Core modules (attack_graph, threat_intel, prediction, compliance, risk) | ✅ Needed | ✅ Needed |
| FastAPI backend | ❌ No | ✅ Needed |
| Vue 3 SPA frontend | ❌ No | ✅ Needed |
| SENTINEL npm/pip package | ❌ No | ✅ Needed |
| Supabase migrations | ❌ No | ✅ Needed |
| PayStack integration | ❌ No | ✅ Needed |
| Tests (80%+ coverage) | ✅ Needed | ✅ Needed |
| PyArmor/PyInstaller distribution | ✅ Needed | ❌ No |

## Rules

- MikiCall OFF LIMITS
- All secrets via env vars
- No Co-Authored-By:CLAUDE
- Push to GitHub when fully done and tested
- Only port non-pro features from private to public

## Auto-Execution Mode

When user says "build", "finish", "continue", or "execute":
1. Read the plan file at `~/.claude/plans/` (latest one)
2. Spawn parallel agents for ALL remaining tasks simultaneously
3. Each agent writes code, verifies imports, commits atomically
4. Do NOT stop to ask for permission — just build
5. After all agents complete, run full test suite
6. Push to GitHub when tests pass

### What to Build (in order):
1. ScannerAgent + ForgeAgent (complete stubs at `agents/scanner.py`, `agents/forge.py`)
2. Test suite (`tests/`)
3. Distribution setup (setup.py, PyArmor config, PyInstaller spec)
4. Push to GitHub

### Commit Convention:
- `feat: attack intelligence engine — graph reasoning, exploit chaining`
- `feat: threat intel + prediction engine — multi-source aggregation, zero-day prediction`
- `feat: compliance + risk engine — 8-framework mapping, FAIR analysis`
- `feat: agent upgrades + test suite — all stubs complete, 60+ tests`
- `feat: distribution — setup.py, PyArmor, PyInstaller`

### Verification Commands:
```bash
# Python imports
cd C:\Users\Kebro\Documents\wraith\public
python -c "from core.attack_graph import AttackGraph; from core.threat_intel import ThreatIntel; from core.prediction_engine import PredictionEngine; from core.compliance_mapper import ComplianceMapper; from core.risk_calculator import RiskCalculator; from agents.scanner import ScannerAgent; from agents.forge import ForgeAgent; print('ALL OK')"

# Tests
python -m pytest tests/ -v --cov

# CLI
python cipher.py --check-tools
python cipher.py --help
```
