# WRAITH — Public Repository (Open Source)

## What This Repo Is

This is the **open source core** of WRAITH. It's a self-hosted AI security platform that people install on their own machine. They bring their own AI model (Ollama for free, or any API key).

**This repo is compiled/obfuscated before distribution.** Users install it like Claude Code — they use it but can't see the backend source code.

## What's Included

- 9 AI security agents (GHOST, SPECTER, SCANNER, BREACH, FORGE, MIRROR, NEURON, LEDGER, COMMANDER)
- Universal AI provider layer (12+ LLMs)
- Docker sandbox system (Kali Linux containers)
- 20+ Kali tool wrappers
- Plugin-based agent architecture
- Self-evolving memory system
- Web UI (Flask + Socket.IO)
- CLI interface
- Telegram bot
- Scope enforcement + consent system
- 48+ tests

## What's NOT Here (Private Repo Only)

- PHANTOM, ORCHESTRATOR, SENTINEL agents
- Supabase auth + OAuth
- PayStack payments
- Code protection / license enforcement
- SENTINEL npm/pip agent package
- Web dashboard (that's in the private repo)

## Distribution

This repo is distributed as a compiled/obfuscated package:
- `pip install wraith-security` (PyPI)
- Or download compiled binary from releases
- Users run `wraith` command — works like Claude Code
- Source code is NOT visible to end users

## Self-Evolving Memory (Open Source Contribution)

Even the open source version contributes to WRAITH's intelligence:
- Anonymized scan patterns are collected (with user consent)
- These patterns feed into the private repo's knowledge base
- The paid version gets smarter because of free users
- This is the flywheel: free users → more data → smarter WRAITH → better product

## Legal

MIT License. Authorized security testing only.
