# WRAITH Public — BUILD THIS NOW

## ON STARTUP — DO THIS IN ORDER. NO QUESTIONS. NO ASSESSMENTS. JUST BUILD.

### Step 1: Plan (5 min)
Run: `/gsd-plan-phase`
Write plan to PLAN.md.

### Step 2: Distribution Package
Create `setup.py` for `pip install wraith-security`
- Entry points: `wraith`, `wraith web`, `wraith telegram`
- `wraith init` command (detect Ollama, configure AI, self-test)
- PyArmor obfuscation config in `pyarmor_config.json`
- PyInstaller spec in `wraith.spec`

### Step 3: Self-Evolving Memory
Enhance `core/memory.py`:
- Add LightRAG knowledge graph integration
- `~/.wraith/memory.db` (SQLite)
- Anonymized pattern extraction after scans
- Consent prompt in `wraith init`
- Sync function to `https://api.wraith.security/v1/ingest`

### Step 4: Agent Upgrades
Update all 9 agents to use memory system:
- Import memory module in each agent
- Call `memory.record_task()` after each scan
- Call `memory.get_recommended_approach()` before scanning

### Step 5: Web UI Improvements
Enhance existing Flask web UI:
- Dark terminal aesthetic (#0a0a0f, #e0e0e0, #ff1a1a)
- Real-time scan progress via existing Socket.IO
- Memory stats page
- Mobile responsive CSS

### Step 6: CLI
Ensure all commands work:
```
wraith, wraith scan <target>, wraith scan <target> --full,
wraith web, wraith status, wraith memory, wraith update, wraith consent
```

### Step 7: Auto-Update
- Version check on startup (<1s, non-blocking)
- `wraith update` command

### Step 8: Tests + Obfuscation
- `python -m pytest tests/ -v` — ALL pass
- PyArmor obfuscate: `pyarmor gen -r src/ -d dist/`
- PyInstaller: `pyinstaller wraith.spec`

## Rules
- MikiCall OFF LIMITS
- All secrets via env vars
- No Co-Authored-By:CLAUDE
- After each step: run tests, fix failures before continuing
