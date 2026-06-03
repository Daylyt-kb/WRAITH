# WRAITH Public — Build Instructions

## Project

WRAITH is an open source AI security swarm. 9 AI agents that scan, analyze, and secure infrastructure. Self-hosted, bring your own AI.

## What to Build

### Phase 1: Distribution Package
- Create `setup.py` for `pip install wraith-security`
- PyArmor obfuscate ALL source before distribution
- PyInstaller binaries for Windows, macOS, Linux
- Entry points: `wraith` (CLI), `wraith web` (Web UI), `wraith telegram` (bot)
- `wraith init` — first-run setup: detect Ollama, configure AI, self-test

### Phase 2: Self-Evolving Memory
- Build `~/.wraith/memory.db` (SQLite)
- After each scan, store anonymized patterns: target type, tools used, effectiveness, techniques
- `wraith init` asks: "Help WRAITH get smarter? Share anonymized patterns (y/n)"
- If yes: periodic sync to WRAITH central API (https://api.wraith.security/v1/ingest)
- Export format: `{tool_effectiveness, vulnerability_patterns, common_techniques}` — NO user IDs, NO target specifics

### Phase 3: Agent Upgrades
- All 9 agents must use the memory system
- All agents use sandbox for tool execution
- All agents log to audit system
- Agents communicate via message bus

### Phase 4: Web UI
- Dark terminal aesthetic
- Dashboard: recent scans, findings, agent status
- Real-time scan progress (WebSocket)
- Scan history with filters
- Settings: AI provider config, memory preferences
- Mobile responsive
- No auth (local use only)

### Phase 5: CLI
```
wraith                          # Interactive mode
wraith scan <target>            # Quick scan
wraith scan <target> --full     # Full scan
wraith web                      # Start web UI
wraith status                   # System status
wraith memory                   # Memory stats
wraith update                   # Update
wraith consent                  # Manage consent
```

### Phase 6: Auto-Update
- Check for new versions on startup (non-blocking)
- `wraith update` downloads and installs latest
- Works with pip and binary distributions

## Rules

- Read ALL existing code before changing anything
- Don't break existing functionality
- Production quality — no crashes, proper error handling
- All secrets via env vars — never hardcoded
- No "Co-Authored-By: Claude" anywhere
- PyArmor-compatible code (no dynamic imports that break obfuscation)
- Cross-platform: Windows, macOS, Linux
- Works fully offline with Ollama
- All tests must pass (48+ existing)

## Verification

After each phase:
1. Run `python -m pytest tests/ -v` — all tests pass
2. Run `wraith init` — setup works
3. Run `wraith scan localhost --authorized` — scan works
4. Run `wraith web` — web UI loads at http://localhost:7734
5. Check memory.db — anonymized data is stored correctly
