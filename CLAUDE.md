# WRAITH Public — BUILD THIS

## EXISTING CODE (don't rebuild this)
- `agents/` — ghost, specter, scanner, forge, neuron, ledger, mirror, breach, commander (9 agents, all built)
- `core/` — ai_provider, config, license, sandbox, scope, consent, bus, logger, learner, memory, tier_manager, kali_tools, plugin, ai_provider_v2
- `cipher.py` — CLI entry point
- `web_ui.py` — Flask web UI entry point
- `web/app.py` — Flask + Socket.IO web app
- `web/templates/` — dashboard, terminal, agents, reports, settings HTML templates
- `web/static/` — CSS, JS
- `tests/test_core.py` — 48 tests
- `sandboxes/` — Dockerfiles for recon, exploit, web, osint, kali-base

## WHAT TO BUILD (in this order)

### Step 1: Plan
Run `/gsd-plan-phase`. Write plan to PLAN.md.

### Step 2: Distribution Package
Create `setup.py`:
```python
from setuptools import setup, find_packages
setup(
    name="wraith-security",
    version="2.0.0",
    packages=find_packages(),
    install_requires=open("requirements.txt").read().splitlines(),
    entry_points={
        "console_scripts": [
            "wraith=wraith.cli:main",
            "wraith-web=wraith.web:main",
            "wraith-telegram=wraith.telegram:main",
        ],
    },
)
```
Create `wraith/cli.py` — Click-based CLI with commands: `init`, `scan`, `web`, `telegram`, `status`, `memory`, `update`, `consent`
Create `pyarmor_config.json` — PyArmor obfuscation config
Create `wraith.spec` — PyInstaller spec
**Verify:** `pip install -e .` works, `wraith --help` works

### Step 3: Memory System Enhancement
Enhance `core/memory.py`:
- Add LightRAG: `from lightrag import LightRAG`
- After each scan, extract patterns → store in `~/.wraith/memory.db`
- `wraith init` asks: "Help WRAITH get smarter? Share anonymized patterns (y/n)"
- If yes: sync to `https://api.wraith.security/v1/ingest` (POST anonymized data)
- Export format: `{tool_effectiveness: [...], vulnerability_patterns: [...], common_techniques: [...]}` — NO user IDs, NO target specifics
**Verify:** `wraith init` → scan → `wraith memory` shows stats

### Step 4: Agent Upgrades
Update each agent in `agents/`:
- Import: `from core.memory import WraithMemory`
- After scan: `memory.record_task({task_type, target_type, tools_used, outcome, techniques, patterns_found})`
- Before scan: `memory.get_recommended_approach(target_type)` → use recommendations
**Verify:** Run full scan → check `wraith memory` shows new task recorded

### Step 5: Web UI Enhancement
Enhance `web/app.py` and templates:
- Add memory stats page at `/memory`
- Dark terminal aesthetic: bg #0a0a0f, text #e0e0e0, accent #ff1a1a, font 'Courier New'
- Mobile responsive CSS
**Verify:** `wraith web` → all pages load on mobile and desktop

### Step 6: CLI Commands
Ensure all work:
- `wraith` — interactive mode
- `wraith scan <target>` — quick scan
- `wraith scan <target> --full` — full scan with all agents
- `wraith web` — start web UI
- `wraith status` — system status
- `wraith memory` — memory stats
- `wraith update` — update to latest version
- `wraith consent` — manage consent settings
**Verify:** Each command runs without errors

### Step 7: Auto-Update
In `wraith/cli.py`:
- On startup, check `https://api.wraith.security/v1/version` (non-blocking, <1s)
- `wraith update` — download latest from PyPI, install, restart
**Verify:** `wraith update --check` shows current version

### Step 8: Tests + Ship
- `python -m pytest tests/ -v` — ALL 48+ tests pass
- Write tests for new features (memory, CLI, auto-update)
- Target: 80%+ coverage
- PyArmor: `pyarmor gen -r wraith/ -d dist/`
- PyInstaller: `pyinstaller wraith.spec`
- **Verify:** Install `dist/wraith-security-2.0.0.tar.gz` on clean machine → works

### Step 9: Push to GitHub
```bash
cd C:\Users\Kebro\Documents/wraith/public
git add -A
git commit -m "feat: WRAITH v2.0 — AI security swarm, compiled distribution, self-evolving memory"
git push origin main
git tag v2.0.0
git push origin v2.0.0
```

## Rules
- MikiCall OFF LIMITS
- All secrets via env vars
- No Co-Authored-By:CLAUDE
- Every commit message starts with "feat:", "fix:", "chore:", or "test:"
- If tests fail → fix before moving to next step
- Push to GitHub when ALL steps done and ALL tests pass
