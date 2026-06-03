# WRAITH Public — Claude Code Build Instructions

## ⚠️ ON STARTUP — BUILD IMMEDIATELY (NO QUESTIONS)

1. Read `FEEDBACK.md`
2. Read `.claude/rules/global.md`
3. Extract corrections from conversation history → append to FEEDBACK.md
4. **START BUILDING. Don't ask what to build. Just build.**

## What to Build (Priority Order)

### 1. Distribution Package (`setup.py` + PyArmor + PyInstaller)
- Create `setup.py` for `pip install wraith-security`
- PyArmor obfuscate ALL source code
- PyInstaller binaries for Windows, macOS, Linux
- Entry points: `wraith`, `wraith web`, `wraith telegram`
- `wraith init` — first-run setup (detect Ollama, configure AI, self-test)
- **Verify:** `pip install -e .` works, `wraith --help` shows usage

### 2. Self-Evolving Memory System
- Enhance `core/memory.py` with LightRAG knowledge graph
- `~/.wraith/memory.db` (SQLite)
- After each scan → extract anonymized patterns → store
- `wraith init` asks consent: "Help WRAITH get smarter? (y/n)"
- Periodic sync to `https://api.wraith.security/v1/ingest`
- **Verify:** Scan a target, check memory.db has anonymized data

### 3. Agent Upgrades (All 9 Agents)
- All agents use memory system
- All agents use sandbox for tool execution
- All agents log to audit system
- **Verify:** Full scan with all agents completes

### 4. Web UI
- Dark terminal aesthetic (#0a0a0f bg, #e0e0e0 text, #ff1a1a accent)
- Dashboard: recent scans, findings, agent status
- Real-time scan progress (WebSocket)
- Scan history, settings page
- Mobile responsive, no auth (local use)
- **Verify:** `wraith web` → http://localhost:7734 loads

### 5. CLI
```
wraith                          # Interactive
wraith scan <target>            # Quick scan
wraith scan <target> --full     # Full scan
wraith web                      # Web UI
wraith status                   # Status
wraith memory                   # Memory stats
wraith update                   # Update
wraith consent                  # Consent settings
```
- **Verify:** All commands work

### 6. Auto-Update
- Check versions on startup (<1s, non-blocking)
- `wraith update` installs latest
- **Verify:** `wraith update --check` shows version

## After EVERY Phase

1. `python -m pytest tests/ -v` — ALL pass
2. `bandit -r .` — no issues
3. No `Co-Authored-By:CLAUDE`
4. No hardcoded secrets

## Rules

- MikiCall OFF LIMITS
- All secrets via env vars
- Production quality — no crashes
- Cross-platform: Windows, macOS, Linux
- Works offline with Ollama
