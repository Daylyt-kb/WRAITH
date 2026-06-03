# 👻 WRAITH — Open Source AI Security Swarm

> **The world's first autonomous AI security platform. Self-hosted. Bring your own AI.**

## What Is WRAITH?

WRAITH is a swarm of **9 AI agents** that work together to scan, analyze, and secure your infrastructure. Give it a mission in plain English — it plans, provisions tools from Kali Linux, executes, and learns from every scan.

Think of it as a **$200K security team that runs on your laptop for free**.  

And it gets smarter every single day — for every user, forever.

## What It Does

- **Scans your website, app, network, or AI agent** for vulnerabilities
- **Uses real Kali Linux tools** — nmap, sqlmap, metasploit, nikto, gobuster, and 15+ more
- **Runs in isolated Docker sandboxes** — safe, clean, no trace on your machine
- **Learns from every scan** — its memory grows, its recommendations improve, its detection gets sharper
- **Works with any AI model** — Ollama (free, offline), OpenRouter, GPT-4, Claude, Gemini, Groq, and 8+ more
- **Grows with the community** — anonymized patterns from all users make WRAITH smarter for everyone

## Quick Start

```bash
# 1. Clone
git clone https://github.com/Daylyt-kb/WRAITH.git
cd WRAITH

# 2. Install
pip install -r requirements.txt

# 3. (Optional) Set up AI — or use Ollama for free
cp .env.example .env
# Edit .env if you have an API key. Or just use Ollama — WRAITH detects it automatically.

# 4. Test
python -m pytest tests/ -v

# 5. Run
python web_ui.py          # Web UI at http://localhost:7734
# or
python cipher.py --interactive  # CLI mode
```

### With Ollama (Free, No API Key)

```bash
ollama pull llama3.1
python web_ui.py
# Done. WRAITH uses your local AI.
```

## Usage Examples

```bash
# Web UI
python web_ui.py

# CLI — plain English
python cipher.py --interactive
> scan mywebsite.com
> full test example.com

# CLI — direct
python cipher.py -t example.com -m recon --authorized
python cipher.py -t example.com -m full --authorized

# Telegram bot
python telegram_bot.py
```

## The Agents

| Agent | Purpose |
|-------|---------|
| GHOST | Network recon — maps every open door |
| SPECTER | OSINT — hunts what the internet already knows |
| SCANNER | Vulnerability detection — finds the weaknesses |
| BREACH | Controlled exploitation — proves it's real |
| FORGE | Script generation — writes custom tools on the fly |
| MIRROR | AI red team — tests AI agents for prompt injection & more |
| NEURON | Self-learning — ingests CVEs, ATT&CK, ExploitDB 24/7 |
| LEDGER | Reports — translates findings to plain English |
| SEARCHER | Web search — security intelligence gathering |
| COMMANDER | The brain — understands your English, orchestrates everything |

## Requirements

- Python 3.11+
- Docker (for sandboxed tool execution — recommended but optional)
- An AI model: Ollama (free, offline) OR any API key (OpenRouter, Groq, Gemini, etc.)

## Legal

**Authorized security testing only.**  

WRAITH enforces authorization at the architecture level. Before any scan, you must confirm:
- You OWN the system, OR
- You have WRITTEN PERMISSION to test it

Unauthorized scanning is illegal under the CFAA (USA), Computer Misuse Act (UK), and equivalent laws worldwide.

## Contributing

Fork → Branch → Test → PR. All tests must pass. Write tests for new features.

## License

MIT — free forever. Use it, modify it, share it. Make it yours.

---

*Built by [Kebron Isaias](https://github.com/Daylyt-kb) · Open Source · Legal by Design*
*WRAITH — The ghost in your machine that keeps you safe.*
