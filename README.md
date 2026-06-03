# WRAITH — Open Source AI Security Swarm

> **The world's first autonomous AI security platform. Self-hosted. Bring your own AI.**

WRAITH is a swarm of 9 AI agents that work together to scan, analyze, and secure your infrastructure. Give it a mission in plain English — it plans, provisions tools, executes, and learns from every scan.

**This is the open source core.** It runs entirely on your machine. No cloud. No API keys required (works with Ollama for free).

## Quick Start

```bash
git clone https://github.com/Daylyt-kb/WRAITH.git
cd WRAITH
pip install -r requirements.txt
python -m pytest tests/ -v
python web_ui.py  # http://localhost:7734
```

## AI Setup (Free)

```bash
# Option 1: Ollama (free, offline, recommended)
ollama pull llama3.1
# WRAITH auto-detects Ollama — no config needed

# Option 2: Any API key
cp .env.example .env
# Add OPENROUTER_API_KEY, GROQ_API_KEY, etc.
```

## What's Included

- **9 AI Agents:** GHOST, SPECTER, SCANNER, BREACH, FORGE, MIRROR, NEURON, LEDGER, COMMANDER
- **12+ AI Providers:** Ollama, OpenRouter, Groq, Gemini, Anthropic, OpenAI, Mistral, DeepSeek, Together, Perplexity, LM Studio, Custom
- **Docker Sandboxes:** Isolated Kali Linux containers for safe tool execution
- **20+ Kali Tools:** nmap, sqlmap, nikto, gobuster, ffuf, metasploit, and more
- **Plugin System:** Auto-discovering agent architecture
- **Self-Evolving Memory:** Learns from every scan, gets smarter over time
- **Web UI:** Flask + Socket.IO real-time dashboard
- **CLI:** Full command-line interface
- **Telegram Bot:** Remote scanning via Telegram
- **Legal by Design:** Authorization gates, scope enforcement, audit logging
- **48+ Tests:** All passing

## What's NOT Here (Pro)

The following require WRAITH Pro (separate private product):
- PHANTOM (dark web monitoring)
- ORCHESTRATOR (multi-target campaigns)  
- SENTINEL (24/7 continuous monitoring + personal agent)
- Hosted AI (no API key needed)
- PDF reports & compliance mapping
- User auth (Supabase + OAuth)
- Payment processing (PayStack)
- Code protection & license enforcement

## Architecture

```
User → Web UI / CLI / Telegram → COMMANDER
  → Scope Check → Agent Selection → Sandbox Provisioning
  → Tool Execution → Memory Update → Report → User
```

## License

MIT — free forever.

## Legal

**Authorized security testing only.** Every scan requires explicit consent. Only test systems you own or have written permission to test.

---

*Built by [Kebron Isaias](https://github.com/Daylyt-kb) · Open Source · Legal by Design*
