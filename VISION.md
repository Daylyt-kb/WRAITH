# WRAITH — The Complete Vision

## What WRAITH Is

WRAITH is not a tool. It's not a scanner. It's not a dashboard.

**WRAITH is an autonomous AI cyber operations platform that replaces entire security teams.**

It thinks. It plans. It attacks. It defends. It learns. It evolves.

And it does all of this better than any human hacker, faster than any SOC team, and cheaper than any enterprise tool.

## The World We're Building

Today:
- A Fortune 500 company pays $500K/year for a security team of 20 people
- A startup pays $50K/year for a pentest that takes 2 weeks and finds 30% of issues
- A solo developer has ZERO access to professional security testing
- Black hat hackers operate freely because defense is always reactive

With WRAITH:
- A solo developer has a $200K security team for free
- A startup gets continuous, autonomous security testing 24/7
- A Fortune 500 replaces their SOC with 3 people overseeing WRAITH
- Defense becomes autonomous, proactive, and faster than any attacker

**This is the future of cybersecurity. And we're building it first.**

## What Makes WRAITH Unrepeatable

### 1. Autonomous AI Swarm (Not One AI — Thirteen)
WRAITH deploys 13 specialized AI agents that work as a swarm:
- **GHOST** maps every open door (network recon)
- **SPECTER** hunts what the internet already knows (OSINT)
- **SCANNER** finds every weakness (vulnerability detection)
- **BREACH** proves it's real (controlled exploitation)
- **FORGE** writes custom tools when none exist
- **MIRROR** tests AI systems for attacks (AI red team)
- **NEURON** learns 24/7 from CVEs, ATT&CK, ExploitDB
- **LEDGER** writes professional reports
- **SEARCHER** gathers security intelligence from the web
- **COMMANDER** understands plain English and orchestrates everything
- **PHANTOM** [PRO] monitors the dark web for leaks
- **ORCHESTRATOR** [PRO] runs multi-target campaigns
- **SENTINEL** [PRO] watches your infrastructure 24/7

### 2. Full Kali Linux Arsenal
WRAITH doesn't just call nmap. It has the ENTIRE Kali toolkit:
nmap, masscan, sqlmap, nikto, gobuster, ffuf, amass, subfinder, httpx,
dnsenum, fierce, theHarvester, sherlock, recon-ng, spiderfoot, searchsploit,
msfconsole, hashcat, john, hydra, wpscan, xsser, aircrack-ng, kismet, wifite.

Each tool is wrapped with risk levels, install commands, parsed output, and sandbox integration.

### 3. Own Sandbox / Virtual Machine
WRAITH spins up isolated Docker containers and VMs on demand:
- **Recon sandbox:** nmap, masscan, amass, subfinder, httpx
- **Web hacking sandbox:** sqlmap, nikto, gobuster, ffuf, wpscan
- **Exploit sandbox:** metasploit, exploitdb
- **OSINT sandbox:** theHarvester, sherlock, recon-ng, spiderfoot
- **Wireless sandbox:** aircrack-ng, kismet, wifite (requires VM)
- **Custom sandbox:** Full Kali Linux or Ubuntu — install ANY tool

Tools are installed on-demand, executed in isolation, and the environment is DESTROYED after use. Ephemeral attack infrastructure. No trace.

### 4. Works With ANY LLM
Anthropic, OpenAI, Google, Groq, Mistral, DeepSeek, Ollama, LM Studio,
OpenRouter, Together AI, Perplexity, or any OpenAI-compatible endpoint.
Each agent can use a different model. Works fully offline with Ollama.

### 5. Self-Evolving Memory (The Secret Weapon)
This is what makes WRAITH impossible to catch up with:

**Per-user learning:** Every user who interacts with WRAITH teaches it something new.
- How they phrase requests
- What targets they test
- What vulnerabilities they care about
- How they remediate findings
- What tools they prefer

**Cross-user intelligence (anonymized):** WRAITH learns from ALL users simultaneously.
When one user discovers a new technique, EVERYONE benefits.
When one user finds a new CVE pattern, WRAITH updates its knowledge base.

**Task-solving memory:** WRAITH remembers HOW it solved every task.
- "Last time I tested a WordPress site, I used wpscan → found XSS → used sqlmap → got shell"
- "Last time I tested an AI agent, I used MIRROR → found prompt injection → crafted escape"
- This memory is permanent and compounds over time.

**Adaptive tool selection:** WRAITH learns which tools work best for which targets.
It gets FASTER and MORE ACCURATE with every scan.

**The open source version contributes to the private version:**
Even free users make WRAITH smarter. Their anonymized patterns flow into the private repo's knowledge base. The paid version gets smarter because of the free users. This is the flywheel.

### 6. SENTINEL — 24/7 Personal Security Agent (PRO)
This is the killer feature:

Users install a lightweight WRAITH agent on their machine (via npm/pip):
```bash
npm install -g wraith-sentinel
# or
pip install wraith-sentinel
```

It connects to their WRAITH account and:
- Monitors their perimeter 24/7
- Watches for new CVEs affecting their stack
- Detects unauthorized access attempts
- Scans their infrastructure on schedule
- Alerts them via Telegram, email, or dashboard
- Uses THEIR local AI (Ollama, LM Studio) for processing
- Falls back to OpenRouter if local AI is too slow
- Learns their environment and gets smarter over time

**The user's own hardware becomes part of WRAITH's distributed intelligence network.**
Every SENTINEL agent makes the entire WRAITH ecosystem smarter.

### 7. Legal by Design
- Digital authorization consent form signed at login
- Cryptographic scope enforcement
- Immutable audit logging
- Rate limiting
- Non-destructive canary payloads only
- Every action is recorded and attributable

## Business Model

### Free Tier (Open Source)
- 2-3 scans per day, max 2 days per week (~6 scans/week)
- Each verified invite = +10 bonus scans
  - Bonus scans expire in 2 days OR can be spread across a month (user's choice)
  - Max 50 bonus scans from invites at any time
  - Invited user must complete their first scan for the bonus to activate
- 9 core agents only
- Community support
- Users bring their own AI model (Ollama free, or API key)

### Pro Tier ($49/month via PayStack)
- Unlimited scans
- All 13 agents including PHANTOM, ORCHESTRATOR, SENTINEL
- Hosted AI (owl-alpha on OpenRouter) — no API key needed
- PDF reports with compliance mapping
- Dark web monitoring
- Continuous monitoring (SENTINEL agent)
- Priority support
- Self-evolving memory (full)
- Advanced sandbox/VM management

### Enterprise (Custom)
- White labeling
- Custom agent development
- SLA guarantees
- Dedicated support
- On-premise deployment option

## The Flywheel Effect

```
Free users → More data → Smarter WRAITH → Better Pro product → More revenue
    ↓                                                    ↓
More users ← Better free product ← More development ←────┘
```

The free version is the trojan horse. Every free user makes the paid version smarter.
The paid version funds the free version's development.
SENTINEL agents create a distributed intelligence network that no competitor can replicate.

## Repositories

### Public: github.com/Daylyt-kb/WRAITH
- Open source core (MIT license)
- 9 agents, basic features
- Self-hosted, bring your own AI
- The gateway drug

### Private: github.com/Daylyt-kb/private-cipher-ripo-for-storage-
- Pro features, 3 additional agents
- Auth system, payments, SENTINEL
- Self-evolving memory system
- Code protection & license enforcement
- Supabase schema & credentials
- Netlify connects HERE for paid product landing

## Code Protection Strategy

The pro features must be protected from reverse engineering. Implementation:
- Pro code lives in the PRIVATE repo only
- License key validation with HMAC signatures
- Encrypted configuration (AES-256) — keys never in plain text
- PyArmor obfuscation for critical modules
- API-based features that can't be stolen (SENTINEL cloud features)
- Environment variables for ALL secrets — never in code, never in MD files
- Build process encrypts pro modules, decrypts at runtime with valid license

## Legal Protection

Every user must sign a digital authorization consent form:
- Confirms they own or have permission to test targets
- Acknowledges CFAA, Computer Misuse Act, and equivalent laws
- Grants WRAITH permission to scan specified targets
- Creates immutable audit trail
- Stored in Supabase with timestamp and user signature

## The 100-Year Vision

WRAITH becomes the default security layer for the internet.
Every website, every app, every AI agent, every device runs WRAITH.
It's the immune system of the digital world.

No human can keep up with AI-generated threats.
Only AI can fight AI.
WRAITH is that AI.

We're not building a product. We're building the future of cybersecurity.
