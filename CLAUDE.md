# WRAITH v2.0 — AI SECURITY SWARM (Public/Open Source)

## VISION

WRAITH is the world's first civilian AI security swarm. 13 AI agents that work together to find security vulnerabilities. Runs on your laptop, free AI models, zero cost.

This is the **open-source public repo**. Free tier. CLI tool + Flask web UI.

## WHAT'S HERE

- `cipher.py` — CLI entry point (run `python3 cipher.py --interactive`)
- `agents/` — 13 AI security agents (open source, readable Python)
- `core/` — Shared modules (AI, config, memory, scope, consent)
- `web/` — Flask web UI (free tier dashboard)
- `web_ui.py` — Flask runner
- `tests/` — Test suite
- `sandboxes/` — Docker configs for isolated scanning
- `telegram_bot.py` — Telegram bot integration
- `install.sh` — One-command installer

## WHAT'S NOT HERE

- No `api/` (FastAPI backend is in the private repo)
- No `web/src/` (Vue SPA is in the private repo)
- No `packages/` (SENTINEL is in the private repo)
- No `supabase/` (database migrations are in the private repo)
- No `netlify.toml` (frontend deployment is in the private repo)
- No `systemd/` (VPS deployment is in the private repo)

## INSTALL

```bash
git clone https://github.com/Daylyt-kb/WRAITH.git
cd WRAITH
cp .env.example .env
bash install.sh
python3 cipher.py --interactive
```

## USAGE

```bash
# Interactive mode (Commander agent)
python3 cipher.py --interactive

# Quick scan
python3 cipher.py -t example.com -m recon --authorized

# Full scan
python3 cipher.py -t example.com -m full --authorized

# OSINT only
python3 cipher.py -t example.com -m osint --authorized

# Check available tools
python3 cipher.py --check-tools

# Web UI
python3 web_ui.py  # → http://localhost:7734
```

## AGENTS (9 free, 4 pro)

Free tier agents: Ghost, Scanner, Specter, Forge, Neuron, Ledger, Mirror, Searcher, Commander
Pro agents: Breach, Phantom, Sentinel, Orchestrator (available in the Pro platform)

## TEST

```bash
python -m pytest tests/ -v
```

## RULES

- Only test systems you own or have authorization for
- WRAITH is legal-by-design
- MikiCall is OFF LIMITS
- No Co-Authored-By in commits
