# WRAITH — Open Source Vision

## What This Is

WRAITH is the **open source core** of the world's first autonomous AI security swarm. This is the self-hosted version that people install on their own machines. They bring their own AI model (Ollama for free, or any API key).

## What It Includes

- **9 AI Agents:** GHOST, SPECTER, SCANNER, BREACH, FORGE, MIRROR, NEURON, LEDGER, COMMANDER
- **12+ AI Providers:** Ollama, OpenRouter, Groq, Gemini, Anthropic, OpenAI, Mistral, DeepSeek, Together, Perplexity, LM Studio, Custom
- **Docker Sandboxes:** Isolated Kali Linux containers for safe tool execution
- **20+ Kali Tools:** nmap, sqlmap, nikto, gobuster, ffuf, metasploit, and more
- **Plugin System:** Auto-discovering agent architecture
- **Self-Evolving Memory:** Learns from every scan, contributes anonymized patterns to the global WRAITH network
- **Web UI:** Flask + Socket.IO real-time dashboard
- **CLI:** Full command-line interface
- **Telegram Bot:** Remote scanning via Telegram
- **Legal by Design:** Authorization gates, scope enforcement, audit logging

## Distribution

This repo is distributed as a **compiled/obfuscated package**:
- `pip install wraith-security` (PyPI)
- Compiled binaries for Windows, macOS, Linux
- Users run `wraith` command — works like Claude Code
- Source code is NOT visible to end users (PyArmor obfuscation)

## Self-Evolving Memory Contribution

Even the open source version makes WRAITH smarter:
- Anonymized scan patterns are collected (with user consent)
- Patterns feed into the private repo's knowledge base
- The paid version gets smarter because of free users
- This is the flywheel: free users → more data → smarter WRAITH → better product

## What's NOT Here (Private Repo)

- PHANTOM, ORCHESTRATOR, SENTINEL agents
- Supabase auth + OAuth
- PayStack payments
- Web dashboard (browser-based)
- SENTINEL npm/pip agent package
- Code protection / license enforcement

## Legal

MIT License. Authorized security testing only. Every scan requires explicit consent.
