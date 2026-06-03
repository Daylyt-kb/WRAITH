# WRAITH Public — BUILD THIS

## ON STARTUP: Do these steps in order. No questions. No assessments.

### Step 1: Distribution Package
Create `setup.py` — `pip install wraith-security`
- Entry points: `wraith`, `wraith web`, `wraith telegram`
- `wraith init` command (detect Ollama, configure, self-test)
- PyArmor config: `pyarmor_config.json`
- PyInstaller spec: `wraith.spec`
- **Verify:** `pip install -e .` works

### Step 2: Memory System
Enhance `core/memory.py`:
- LightRAG knowledge graph
- `~/.wraith/memory.db`
- Anonymized pattern extraction
- Consent prompt in `wraith init`
- Sync to `https://api.wraith.security/v1/ingest`
- **Verify:** Scan target → check memory.db

### Step 3: Upgrade All 9 Agents
Each agent imports memory, calls `record_task()` after scan, `get_recommended_approach()` before scan

### Step 4: Web UI
Enhance existing Flask UI:
- Dark terminal aesthetic
- Memory stats page
- Mobile responsive
- **Verify:** `wraith web` loads

### Step 5: CLI
All commands work: `wraith`, `wraith scan`, `wraith web`, `wraith status`, `wraith memory`, `wraith update`

### Step 6: Auto-Update
Version check on startup, `wraith update` command

### Step 7: Tests + Ship
- `pytest tests/ -v` — ALL pass
- PyArmor obfuscate
- PyInstaller binary

## Rules
- MikiCall OFF LIMITS
- Secrets via env vars only
- No Co-Authored-By:CLAUDE
- Fix test failures before moving to next step
