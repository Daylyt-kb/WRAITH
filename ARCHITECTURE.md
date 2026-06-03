# WRAITH — Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        WRAITH PLATFORM                          │
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │  Web UI  │  │   CLI    │  │ Telegram │  │ SENTINEL │       │
│  │ (Flask+  │  │(cipher.  │  │   Bot    │  │  Agent   │       │
│  │Socket.IO)│  │  py)     │  │          │  │(npm/pip) │       │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘       │
│       │              │              │              │             │
│  ┌────┴──────────────┴──────────────┴──────────────┴─────┐      │
│  │                    API LAYER                           │      │
│  │  /auth/*  /payments/*  /agents/*  /sandbox/*         │      │
│  │  /memory/*  /consent/*  /missions/*  /reports/*       │      │
│  └───────────────────────┬───────────────────────────────┘      │
│                          │                                      │
│  ┌───────────────────────┴───────────────────────────────┐      │
│  │                   CORE ENGINE                          │      │
│  │                                                        │      │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │      │
│  │  │  COMMANDER   │  │  AI Provider │  │   Memory    │   │      │
│  │  │ (Orchestrator│  │  (12+ LLMs)  │  │  (Self-     │   │      │
│  │  │  + Planner)  │  │              │  │  Evolving)  │   │      │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘   │      │
│  │         │                │                │           │      │
│  │  ┌──────┴────────────────┴────────────────┴──────┐   │      │
│  │  │              AGENT SWARM                       │   │      │
│  │  │                                                │   │      │
│  │  │  GHOST  SPECTER  SCANNER  BREACH  FORGE      │   │      │
│  │  │  MIRROR  NEURON  LEDGER  SEARCHER             │   │      │
│  │  │  PHANTOM  ORCHESTRATOR  SENTINEL [PRO]        │   │      │
│  │  └───────────────────────┬───────────────────────┘   │      │
│  │                          │                           │      │
│  │  ┌───────────────────────┴───────────────────────┐   │      │
│  │  │            SANDBOX / VM LAYER                  │   │      │
│  │  │                                                │   │      │
│  │  │  Docker Containers:  recon, web, exploit,     │   │      │
│  │  │  osint, wireless, custom                      │   │      │
│  │  │                                                │   │      │
│  │  │  Full VMs:  Kali Linux, Ubuntu (on demand)    │   │      │
│  │  │                                                │   │      │
│  │  │  Tool Install → Execute → Capture → Destroy   │   │      │
│  │  └───────────────────────────────────────────────┘   │      │
│  │                                                        │      │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │      │
│  │  │   License   │  │    Auth     │  │   Payment   │   │      │
│  │  │  (HMAC +    │  │  (Supabase  │  │  (PayStack  │   │      │
│  │  │  Encrypted) │  │  + OAuth)   │  │  + Webhook) │   │      │
│  │  └─────────────┘  └─────────────┘  └─────────────┘   │      │
│  │                                                        │      │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │      │
│  │  │   Consent   │  │    Code     │  │    Audit    │   │      │
│  │  │   (Legal    │  │  Protection │  │   (Immut-   │   │      │
│  │  │   Form)     │  │  (AES-256)  │  │   able Log) │   │      │
│  │  └─────────────┘  └─────────────┘  └─────────────┘   │      │
│  └────────────────────────────────────────────────────────┘      │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   DATA LAYER                             │    │
│  │                                                         │    │
│  │  Supabase (Cloud)        SQLite (Local Fallback)        │    │
│  │  ├── profiles            ├── users                      │    │
│  │  ├── licenses            ├── scans                      │    │
│  │  ├── missions            ├── memory                     │    │
│  │  ├── memory              ├── consent_records            │    │
│  │  ├── consent_records     └── audit_log                  │    │
│  │  ├── audit_log                                          │    │
│  │  ├── invites                                            │    │
│  │  └── agent_knowledge                                     │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
wraith/
├── CLAUDE.md              # Build instructions (this file)
├── VISION.md              # The complete vision
├── ARCHITECTURE.md        # Technical architecture (this file)
├── RESEARCH.md            # Competitor/pricing research (you create)
├── PLAN.md                # Your build plan (you create)
├── README.md              # Public-facing README
├── cipher.py              # CLI entry point
├── web_ui.py              # Web entry point
├── telegram_bot.py        # Telegram bot
├── config.yaml            # Configuration (no secrets)
├── requirements.txt       # Python dependencies
├── install.sh             # Auto-install script
├── run.sh                 # One-command startup
├── .env.example           # Environment template (no real values)
├── .gitignore             # Must exclude .env, wraith_output/
├── netlify.toml            # Netlify config
│
├── core/                  # Infrastructure
│   ├── __init__.py
│   ├── config.py          # YAML config loader with env substitution
│   ├── logger.py          # Structured JSON logging
│   ├── bus.py             # Async message bus (pub/sub)
│   ├── ai_provider.py     # Universal AI provider (12+ LLMs)
│   ├── sandbox.py         # Docker/VM sandbox manager
│   ├── kali_tools.py      # 20+ Kali tool wrappers
│   ├── plugin.py          # Plugin-based agent discovery
│   ├── scope.py           # Scope validator + consent manager
│   ├── license.py         # License gate (HMAC + encrypted)
│   ├── auth.py            # Supabase auth (OAuth, magic links)
│   ├── payments.py        # PayStack integration
│   ├── memory.py          # Self-evolving memory system ← NEW
│   ├── protection.py      # Code protection (AES-256 + PyArmor) ← NEW
│   ├── consent_form.py    # Digital legal consent form ← NEW
│   ├── tier_manager.py    # Free tier gamification ← NEW
│   └── supabase_store.py  # Supabase storage layer
│
├── agents/                # AI security agents
│   ├── __init__.py
│   ├── base.py            # Base agent class (WraithAgent)
│   ├── ghost.py           # Network recon
│   ├── specter_scanner_forge.py  # SPECTER + SCANNER + FORGE
│   ├── breach.py          # Controlled exploitation
│   ├── mirror.py          # AI red team
│   ├── neuron.py          # Self-learning knowledge base
│   ├── neuron_ledger.py   # NEURON + LEDGER combined
│   ├── commander.py       # Orchestration brain
│   ├── searcher.py        # Web search intelligence
│   ├── phantom.py         # [PRO] Dark web monitoring
│   ├── orchestrator.py    # [PRO] Multi-target campaigns
│   └── sentinel.py        # [PRO] 24/7 monitoring + personal agent
│
├── sandboxes/             # Docker environments
│   ├── Dockerfile.kali-base     # Base Kali image
│   ├── Dockerfile.recon         # Recon tools
│   ├── Dockerfile.web           # Web hacking tools
│   ├── Dockerfile.exploit       # Exploitation tools
│   ├── Dockerfile.osint         # OSINT tools
│   ├── Dockerfile.wireless      # Wireless tools (VM)
│   ├── Dockerfile.ubuntu        # Ubuntu base (custom tools)
│   └── docker-compose.yaml      # Orchestration
│
├── web/                   # Web application
│   ├── __init__.py
│   ├── app.py             # Flask + Socket.IO
│   ├── auth_routes.py     # Auth endpoints ← NEW
│   ├── payment_routes.py  # Payment endpoints ← NEW
│   ├── static/
│   │   ├── css/main.css   # Dark terminal aesthetic
│   │   └── js/app.js      # xterm.js + dashboard
│   └── templates/
│       ├── base.html
│       ├── index.html     # Landing/dashboard
│       ├── login.html     # Login/signup ← NEW
│       ├── consent.html   # Legal consent form ← NEW
│       ├── pricing.html   # Pricing page ← NEW
│       ├── dashboard.html # Main dashboard
│       ├── terminal.html  # Real-time terminal
│       ├── agents.html    # Agent management
│       ├── reports.html   # Scan reports
│       ├── memory.html    # Knowledge base viewer ← NEW
│       └── settings.html  # Settings
│
├── landing/               # Netlify landing page
│   ├── index.html         # Main landing
│   ├── compare.html       # Free vs Pro comparison
│   ├── waitlist.html      # Waitlist/signup form
│   ├── wraith_logo.svg    # Full logo
│   └── wraith_icon.svg    # Icon only
│
├── sentinel/              # SENTINEL agent (npm + pip) ← NEW
│   ├── package.json       # npm package config
│   ├── setup.py           # pip package config
│   ├── sentinel/
│   │   ├── __init__.py
│   │   ├── agent.py       # Main SENTINEL agent
│   │   ├── monitor.py     # Perimeter monitoring
│   │   ├── ai_local.py    # Local AI detection (Ollama, LM Studio)
│   │   ├── ai_cloud.py    # Cloud AI fallback (OpenRouter)
│   │   ├── alerts.py      # Alert system (Telegram, email)
│   │   └── client.py      # WRAITH API client
│   └── README.md
│
└── tests/                 # Test suite
    └── test_core.py       # 48+ tests
```

## Data Flow

### Scan Request Flow
```
User → Web UI/CLI/Telegram → COMMANDER → Scope Check → Consent Check
  → Agent Selection → Sandbox Provisioning → Tool Execution
  → Result Collection → Memory Update → Report Generation
  → User Notification
```

### Self-Evolving Memory Flow
```
Every Scan → Extract Patterns → Anonymize → Store in Memory DB
  → Update Agent Knowledge → Improve Future Scans
  → (Open Source) → Anonymized Patterns → Private Repo Knowledge Base
```

### SENTINEL Flow
```
User installs SENTINEL → Connects to WRAITH account
  → Detects local AI (Ollama/LM Studio) → Uses local for processing
  → Falls back to OpenRouter if local too slow
  → Monitors perimeter 24/7 → Detects threats
  → Alerts user + Contributes anonymized intelligence to WRAITH network
```

### Payment Flow
```
User → Pricing Page → Select Plan → PayStack Checkout
  → Webhook Verification → License Generation
  → Account Upgrade → Pro Features Unlocked
```

## Security Model

### Code Protection
1. Pro code in private repo only
2. License keys validated with HMAC-SHA256
3. Config encrypted with AES-256-GCM
4. PyArmor obfuscation on critical modules
5. Runtime decryption with valid license only
6. API keys NEVER in code — always env vars

### Legal Protection
1. Digital consent form at signup
2. Scope enforcement at architecture level
3. Immutable audit logging
4. Rate limiting per tier
5. Non-destructive payloads only

### Auth Security
1. Supabase Auth (Google/GitHub OAuth + magic links)
2. Session management with expiry
3. Email change cooldown (7 days)
4. Rate limiting on auth endpoints
5. Row Level Security in Supabase

## Free Tier Gamification

```
Base: 2-3 scans/day, max 2 days/week
Invite bonus: +10 scans per verified invite
  - Expires in 2 days OR spread across month (user choice)
  - Max 50 bonus scans at any time
  - Invited user must complete 1 scan to activate bonus
Caps: Prevents abuse while encouraging viral growth
```

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11+, Flask, Socket.IO |
| AI | 12+ providers via universal adapter |
| Auth | Supabase Auth (OAuth, magic links) |
| Database | Supabase (cloud) + SQLite (local) |
| Payments | PayStack (KES currency) |
| Sandboxes | Docker + Kali Linux + Ubuntu VMs |
| Frontend | HTML/CSS/JS, xterm.js, dark terminal |
| SENTINEL | Node.js + Python dual package |
| Deployment | Netlify (landing), VPS (API), Docker |
| Code Protection | PyArmor + AES-256 + HMAC |
| Testing | pytest, 48+ tests |
