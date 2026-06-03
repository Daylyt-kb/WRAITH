# WRAITH — Build Instructions for Claude Code

## FIRST: Read These Files in Order

1. `VISION.md` — The complete vision. Read it ALL. This is what we're building.
2. `ARCHITECTURE.md` — Technical architecture (create this if it doesn't exist)
3. Then read EVERY file in `core/`, `agents/`, `tests/`, `sandboxes/`, `web/`
4. Then read `cipher.py`, `web_ui.py`, `telegram_bot.py`

## What WRAITH Must Become

WRAITH is the world's first autonomous AI cyber operations platform.

Not a scanner. Not a wrapper. A **living, self-evolving system** that replaces
entire security teams. It thinks, plans, attacks, defends, learns, and evolves.

### The 5 Pillars

**1. AUTONOMOUS SWARM** — 13 AI agents that work together. One finds a vuln,
another writes the exploit, another generates the report, another learns from it.

**2. FULL KALI ARSENAL** — The ENTIRE Kali Linux toolkit. 20+ tools. Each wrapped
with risk levels, install commands, parsed output, sandbox integration.

**3. OWN SANDBOX/VM** — Spins up isolated Docker containers and VMs on demand.
Installs tools it needs, runs them, captures results, DESTROYS the environment.
Ephemeral attack infrastructure. No trace. Includes full Kali Linux and Ubuntu
sandboxes for complex operations.

**4. SELF-EVOLVING MEMORY** — This is the secret weapon:
   - Per-user learning: remembers how each user works, what they test, how they remediate
   - Cross-user intelligence (anonymized): when one user discovers something, everyone benefits
   - Task-solving memory: remembers HOW it solved every task, compounds over time
   - Adaptive tool selection: learns which tools work best for which targets
   - The open source version contributes anonymized patterns to the private version
   - Gets smarter every single day, forever

**5. SENTINEL 24/7 AGENT (PRO)** — Users install a lightweight agent on their machine
(npm/pip). It connects to their WRAITH account, monitors their perimeter 24/7,
uses their local AI (Ollama/LM Studio) or falls back to OpenRouter. Every SENTINEL
agent makes the entire WRAITH ecosystem smarter. Crowd-sourced intelligence.

### The Agents

| Agent | Tier | Purpose |
|-------|------|---------|
| GHOST | Free | Network recon — maps every open door |
| SPECTER | Free | OSINT — hunts what the internet knows |
| SCANNER | Free | Vulnerability detection |
| BREACH | Free | Controlled exploitation — proves it's real |
| FORGE | Free | Script generation — writes custom tools |
| MIRROR | Free | AI red team — tests AI systems |
| NEURON | Free | Self-learning — ingests CVEs, ATT&CK, ExploitDB 24/7 |
| LEDGER | Free | Reports — translates findings |
| SEARCHER | Free | Web search — security intelligence |
| COMMANDER | Free | The brain — orchestrates everything |
| PHANTOM | PRO | Dark web monitoring |
| ORCHESTRATOR | PRO | Multi-target campaigns |
| SENTINEL | PRO | 24/7 continuous monitoring + personal agent |

### Free Tier Psychology (Gamification)

- 2-3 scans per day, max 2 days per week (~6 scans/week free)
- Each verified invite = +10 bonus scans
  - Bonus scans expire in 2 days OR spread across a month (user chooses)
  - Max 50 bonus scans from invites at any time
  - Invited user must complete their first scan for bonus to activate
- This creates urgency, FOMO, and viral growth without abuse

### Paid Tier Features

- Unlimited scans
- All 13 agents
- Hosted AI (owl-alpha on OpenRouter) — no API key needed
- PDF reports with compliance mapping
- Dark web monitoring (PHANTOM)
- Continuous monitoring (SENTINEL agent for their machine)
- Self-evolving memory (full per-user)
- Advanced sandbox/VM management
- Priority support
- PayStack payments ($49/mo)

### SENTINEL Agent (The Killer Feature)

Users install on their machine:
```bash
npm install -g wraith-sentinel
# or
pip install wraith-sentinel
```

It:
- Connects to their WRAITH account
- Monitors their perimeter 24/7
- Watches for new CVEs affecting their stack
- Uses THEIR local AI (Ollama, LM Studio) for processing
- Falls back to OpenRouter if local AI is too slow
- Learns their environment over time
- Alerts via Telegram, email, dashboard
- Contributes anonymized intelligence to the WRAITH network

### Self-Evolving Memory System

This is what makes WRAITH impossible to replicate:

1. **Per-user task memory:** Stores how each user phrases requests, what they test,
   how they remediate. Builds a profile over time.

2. **Cross-user pattern learning (anonymized):** When any user discovers a new
   technique or pattern, it flows into the global knowledge base.

3. **Task-solving chains:** Records the full chain of how each task was solved:
   tools used, sequence, results, time taken. Reuses successful chains.

4. **Adaptive tool selection:** Learns which tools work best for which target types.
   Gets faster and more accurate with every scan.

5. **Open source → Private flow:** The open source version contributes anonymized
   learning patterns to the private version. Free users make the paid version smarter.

6. **Persistent storage:** Memory stored in Supabase (cloud) + SQLite (local fallback).
   Survives restarts, updates, migrations.

### Code Protection (CRITICAL)

Pro features must be protected from reverse engineering:
- Pro code in PRIVATE repo only
- License key validation with HMAC signatures
- Encrypted configuration (AES-256) — keys NEVER in plain text in any file
- PyArmor obfuscation for critical pro modules
- API-based features that can't be stolen (SENTINEL cloud coordination)
- ALL secrets via environment variables — never in code, never in MD files
- Build process encrypts pro modules, decrypts at runtime with valid license
- No hardcoded keys, tokens, or credentials anywhere in the codebase

### Legal Consent System

Every user signs a digital authorization form at login:
- Confirms they own or have written permission to test targets
- Acknowledges CFAA, Computer Misuse Act, and equivalent laws
- Grants WRAITH permission to scan specified specified targets
- Creates immutable audit trail with timestamp
- Stored in Supabase with user ID, IP, and signature hash

## What You Must Do

### Phase 0: Research
- Study competitors: Metasploit Pro, Burp Suite Pro, Nessus, Qualys, Cobalt Strike
- Research pricing models, auth systems, code protection strategies
- Research self-evolving AI memory systems
- Research SENTINEL-style agent architectures
- Write findings to `RESEARCH.md`

### Phase 1: Architecture
- Create `ARCHITECTURE.md` with your technical decisions
- Design the self-evolving memory system
- Design the SENTINEL agent architecture
- Design the sandbox/VM management system
- Design the code protection system

### Phase 2: Core Systems
- Build the self-evolving memory module (`core/memory.py`)
- Build the SENTINEL agent (`agents/sentinel.py` — the full version)
- Build the sandbox/VM manager (`core/sandbox.py` — enhanced)
- Build the code protection module (`core/protection.py`)
- Build the legal consent system (`core/consent_form.py`)
- Build the free tier gamification system (`core/tier_manager.py`)

### Phase 3: Auth & Payments
- Build Supabase auth integration (`core/auth.py`)
- Build PayStack payment integration (`core/payments.py`)
- Build the digital consent form flow
- Build user profile management
- Build license key system

### Phase 4: Agent Upgrades
- Upgrade ALL agents to use the new systems
- Each agent should use self-evolving memory
- Each agent should use the enhanced sandbox system
- Each agent should log to the audit system
- PHANTOM: dark web monitoring
- ORCHESTRATOR: multi-target campaigns
- SENTINEL: 24/7 monitoring + personal agent

### Phase 5: Web UI
- Build auth pages (login, signup, OAuth callbacks, consent form)
- Build payment pages (pricing, checkout, subscription management)
- Build dashboard with real-time monitoring
- Build SENTINEL management page
- Build memory/knowledge base viewer
- Build settings page with AI provider configuration
- Dark terminal aesthetic throughout

### Phase 6: SENTINEL Agent (npm + pip packages)
- Create `wraith-sentinel` npm package
- Create `wraith-sentinel` pip package
- Auto-connect to WRAITH account
- Local AI detection (Ollama, LM Studio, etc.)
- Perimeter monitoring
- Alert system

### Phase 7: Tests & Deploy
- Write tests for ALL new systems
- All 48+ existing tests must still pass
- Update README.md for public repo
- Create internal docs for private repo
- Git commit after each phase
- Push to appropriate repos (public vs private)

## Rules

- **Read ALL existing code before changing anything**
- **Don't break what works** — upgrade, don't replace
- **Production quality** — clean code, docstrings, error handling, no crashes
- **Legal by design** — authorization gates before any dangerous operation
- **Works offline** — with Ollama/local models
- **No hardcoded secrets** — ever — all via environment variables
- **No "Co-Authored-By: Claude"** anywhere
- **Two repos** — know what's public and what's private
- **Code protection** — pro features in private repo only, encrypted, obfuscated
- **Full autonomy** — you decide architecture, pricing, features, everything
- **Build until 100% complete** — don't stop at 80%
- **MikiCall project is OFF LIMITS** — do not touch anything related to MikiCall

## Repos

- **Public:** `github.com/Daylyt-kb/WRAITH` — open source core
- **Private:** `github.com/Daylyt-kb/private-cipher-ripo-for-storage-` — pro features

## Credentials

ALL credentials go in `.env` in the PRIVATE repo only.
Available: PayStack keys, Supabase URL + keys, OpenRouter API key,
Gmail SMTP app password, Cloudflare Turnstile keys, Hetzner VPS.
NEVER put real credentials in the public repo or in any MD file.
