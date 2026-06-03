# WRAITH Public — Claude Code Build Instructions

## ⚠️ FIRST: Session Startup (DO THIS BEFORE ANYTHING ELSE)

1. Read `FEEDBACK.md` — ALL corrections, preferences, lessons learned from Daylyt
2. Read `AGENTS.md` — Multi-agent workflow instructions
3. Read `.claude/rules/global.md` — Global rules
4. Read `.claude/rules/api.md` — API route rules (if working on backend)
5. **Extract every correction, preference, and lesson from the conversation history**
6. **Format it for FEEDBACK.md** — Add anything new you learn in this session
7. **Reload FEEDBACK.md in future sessions** — It's your persistent memory

## Project

WRAITH is an open source AI security swarm. 9 AI agents that scan infrastructure. Self-hosted, bring your own AI. Distributed as compiled/obfuscated `pip install wraith-security`.

## Mandatory Tools — USE THESE

### GSD (Get-Shit-Done) — Project Management
**Location:** `~/.claude/skills/get-shit-done/`

For EVERY major feature, use this workflow:
1. `/gsd-plan-phase` — Write detailed plan to `PLAN.md`. Include files to change, functions to create, test approach.
2. `/gsd-execute-phase` — Build the feature. Follow the plan exactly.
3. `/gsd-review-phase` — Adversarial review. Use a subagent in fresh context to review the diff against the plan. Find gaps, not style issues.
4. `/gsd-verify-work` — Run tests. Manual verification. Confirm it works.

### Everything Claude Code — Workflow System
**Location:** `~/.claude/everything-claude-code/`

- Use AGENTS.md for parallel subagent work
- Use `.claude/rules/` for path-specific rules (already set up)
- Use `.claude/skills/` for domain knowledge
- Use hooks for automatic actions (linting, testing)

### Superpowers — Extended Capabilities
**Location:** `~/.claude/skills/superpowers/`

- Use for complex reasoning tasks
- Use for code architecture decisions
- Use for debugging hard problems

### UI/UX Pro Max — Design
**Location:** `~/.claude/skills/ui-ux-pro-max/`

- Use when building the web UI
- Use for landing page design
- Use for component design system

### Claude Mem — Memory
**Location:** `~/.claude/plugins/claude-mem/`

- Claude automatically remembers context across sessions
- Store important decisions, architecture choices, gotchas
- Use `/memory` to review and edit

### LightRAG — Knowledge Graph
**Location:** Installing via `pip install lightrag-hku`

- Use for the self-evolving memory system
- Store vulnerability patterns as a knowledge graph
- Enable fast pattern matching across all users' scans

## What to Build (6 Phases)

### Phase 1: Distribution Package
- `setup.py` for `pip install wraith-security`
- PyArmor obfuscate ALL source code
- PyInstaller binaries (Windows, macOS, Linux)
- Entry points: `wraith`, `wraith web`, `wraith telegram`
- `wraith init` — first-run setup (detect Ollama, configure AI, self-test)
- **Verify:** `pip install -e .` works, `wraith --help` works

### Phase 2: Self-Evolving Memory System
- Enhance `core/memory.py` with LightRAG knowledge graph
- `~/.wraith/memory.db` (SQLite + LightRAG)
- After each scan → extract anonymized patterns → store
- `wraith init` asks consent: "Help WRAITH get smarter?"
- Periodic sync to `https://api.wraith.security/v1/ingest`
- Export format: `{tool_effectiveness, vulnerability_patterns, common_techniques}` — NO user IDs, NO target specifics
- **Verify:** Scan a target, check memory.db, confirm anonymized data

### Phase 3: Agent Upgrades
- All 9 agents use memory system (LightRAG)
- All agents use sandbox for tool execution
- All agents log to audit system
- Agents communicate via message bus
- **Verify:** Full scan with all agents completes, audit log populated

### Phase 4: Web UI (Use UI/UX Pro Max skill)
- Use UI/UX Pro Max for design guidance
- Dark terminal aesthetic (bg #0a0a0f, text #e0e0e0, accent #ff1a1a)
- Dashboard: recent scans, findings, agent status
- Real-time scan progress (WebSocket)
- Scan history with filters
- Settings: AI provider, memory preferences
- Mobile responsive
- No auth (local use only)
- **Verify:** `wraith web` → http://localhost:7734 loads, all pages work

### Phase 5: CLI
```
wraith                          # Interactive mode
wraith scan <target>            # Quick scan
wraith scan <target> --full     # Full scan with all agents
wraith web                      # Start web UI
wraith status                   # System status
wraith memory                   # Memory stats
wraith update                   # Update to latest
wraith consent                  # Manage consent settings
```
- **Verify:** All commands work, `--help` shows usage

### Phase 6: Auto-Update
- Check for new versions on startup (non-blocking, <1s)
- `wraith update` downloads and installs latest version
- Works with pip and binary distributions
- **Verify:** `wraith update --check` shows current version

## Verification (After EVERY Phase)

1. `python -m pytest tests/ -v` — ALL tests pass (48+ existing)
2. `wraith init` — setup completes without errors
3. `wraith scan localhost --authorized` — scan completes
4. `wraith web` — loads at http://localhost:7734
5. No `Co-Authored-By: Claude` anywhere in codebase
6. No hardcoded secrets (grep for `sk_`, `password`, `secret`, `key` — only env vars)

## Rules

- Read ALL existing code before changing anything
- Don't break existing functionality — upgrade, don't replace
- Production quality — clean code, docstrings, error handling, no crashes
- All secrets via env vars — never hardcoded, never in MD files
- PyArmor-compatible code (no dynamic imports that break obfuscation)
- Cross-platform: Windows, macOS, Linux
- Works fully offline with Ollama
- All tests must pass (48+ existing) + write tests for new features
- **MikiCall project is OFF LIMITS — do not touch**

## Distribution Flow

Public repo (this) → builds compiled package → people install via pip → WRAITH runs locally → anonymized memory flows to private repo → private repo gets smarter → better Pro product

This is the flywheel. Build it right.
