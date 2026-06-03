# WRAITH Public — Claude Build Instructions

## Your Job

You are building the **open source public version** of WRAITH. This is the compiled/obfuscated package that people install on their own machines. They bring their own AI model. They use it like Claude Code — powerful but they can't see the backend.

## What to Build

### 1. Compiled/Obfuscated Distribution Package

The public repo must be distributable as a compiled package:
- Create `setup.py` for PyPI distribution (`pip install wraith-security`)
- Use PyArmor to obfuscate ALL Python source code before distribution
- Create compiled binaries for Windows, macOS, Linux (using PyInstaller or similar)
- The `wraith` CLI command should work out of the box after `pip install`
- Users should NOT be able to read the source code — it's compiled/obfuscated
- Entry point: `wraith` command → opens interactive CLI
- Entry point: `wraith web` → starts web UI
- Entry point: `wraith telegram` → starts Telegram bot

### 2. Installation Experience

When someone runs `pip install wraith-security`:
- All dependencies auto-install
- `wraith` command becomes available globally
- First run: `wraith init` — sets up config, detects Ollama, guides through setup
- `wraith init` should:
  - Detect if Ollama is installed → auto-configure
  - If no Ollama, ask for API key (OpenRouter, Groq, etc.)
  - Create `~/.wraith/` config directory
  - Run self-test to verify everything works
  - Show welcome message with quick start

### 3. Self-Evolving Memory (With Consent)

Build the memory collection system:
- On first run, ask user: "Help WRAITH get smarter? Share anonymized scan patterns (y/n)"
- If yes: collect anonymized data after each scan:
  - Target type (website, API, network, AI agent) — NOT the actual target
  - Tools used and their effectiveness
  - Vulnerability patterns found (anonymized)
  - Time taken, success/failure
  - Techniques that worked
- Store locally in SQLite (`~/.wraith/memory.db`)
- Periodically sync anonymized patterns to WRAITH central API (private repo backend)
- This makes the ENTIRE WRAITH ecosystem smarter — free users contribute to pro users

### 4. Agent System

Upgrade all 9 agents to be production-quality:
- Each agent should use the self-evolving memory
- Each agent should use the sandbox system for tool execution
- Each agent should log to the audit system
- Agents should be able to communicate with each other via the message bus

### 5. Web UI

Build a beautiful dark-themed web UI:
- Dashboard showing recent scans, findings, agent status
- Real-time scan progress (WebSocket)
- Scan history with filters
- Settings page (AI provider config, memory preferences)
- Responsive design, works on mobile
- No auth needed (local use only)

### 6. CLI

Build a powerful CLI:
```
wraith                          # Interactive mode
wraith scan <target>            # Quick scan
wraith scan <target> --full     # Full scan with all agents
wraith web                      # Start web UI
wraith status                   # Show system status
wraith memory                   # Show memory stats
wraith update                   # Update to latest version
wraith consent                  # Manage consent settings
```

### 7. Update System

Build an auto-update mechanism:
- Check for new versions on startup (non-blocking)
- `wraith update` downloads and installs latest version
- Works with both pip and binary distributions

### 8. Tests

- All existing tests must pass
- Write tests for new features
- Target: 80%+ code coverage

## Rules

- Read ALL existing code before changing anything
- Don't break existing functionality
- Production quality — no crashes, proper error handling
- All secrets via environment variables — never hardcoded
- No "Co-Authored-By: Claude" anywhere
- Code must be PyArmor-compatible (no dynamic imports that break obfuscation)
- Cross-platform: Windows, macOS, Linux
- Works fully offline with Ollama
