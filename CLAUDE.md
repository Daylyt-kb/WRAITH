# WRAITH Public — Claude Code Build Instructions

## Project

WRAITH is an open source AI security swarm. 9 AI agents that scan, analyze, and secure infrastructure. Self-hosted, bring your own AI. Distributed as compiled/obfuscated package.

## Workflow: Use GSD

1. `/gsd-plan-phase` — Plan each phase
2. `/gsd-execute-phase` — Build it
3. `/gsd-review-phase` — Adversarial review
4. `/gsd-verify-work` — Tests pass

## What to Build

### Phase 1: Distribution Package
- `setup.py` for `pip install wraith-security`
- PyArmor obfuscate ALL source
- PyInstaller binaries (Windows, macOS, Linux)
- Entry points: `wraith`, `wraith web`, `wraith telegram`
- `wraith init` — first-run setup

### Phase 2: Self-Evolving Memory
- `~/.wraith/memory.db` (SQLite)
- Anonymized pattern collection after scans
- Sync to `https://api.wraith.security/v1/ingest`
- NO user IDs, NO target specifics in exported data

### Phase 3: Agent Upgrades
- All 9 agents use memory system
- All agents use sandbox for tools
- All agents log to audit system

### Phase 4: Web UI
- Dark terminal aesthetic
- Dashboard, scan progress (WebSocket), history, settings
- Mobile responsive, no auth (local)

### Phase 5: CLI
`wraith`, `wraith scan <target>`, `wraith web`, `wraith status`, `wraith memory`, `wraith update`, `wraith consent`

### Phase 6: Auto-Update
- Check versions on startup
- `wraith update` installs latest

## Verification

After each phase:
1. `python -m pytest tests/ -v` — all pass
2. `wraith init` — works
3. `wraith scan localhost --authorized` — works
4. `wraith web` — loads at http://localhost:7734
5. Memory.db stores anonymized data correctly

## Rules

- Read ALL existing code first
- Don't break what works
- Production quality
- All secrets via env vars — never hardcoded
- No "Co-Authored-By: Claude"
- PyArmor-compatible code
- Cross-platform
- Works offline with Ollama
- MikiCall is OFF LIMITS
