# WRAITH — Feedback & Lessons Learned

**Load this file at the start of every Claude Code session.**
**Read it before doing anything else.**

---

## Project Overview

WRAITH (renamed from CIPHER) is the world's first autonomous AI cyber operations platform. Two repositories:
- **Public** (`wraith/public/`): Open source core, compiled/obfuscated distribution (`pip install wraith-security`)
- **Private** (`wraith/private/`): Full web platform with auth, payments, SENTINEL agent

---

## Corrections & Preferences (from Daylyt)

### How to Prompt Claude Code
1. **VISION + freedom, NOT step-by-step instructions** — Tell Claude what WRAITH must BECOME, not what was built
2. **Don't tell Claude what already exists** — Let it read the code and figure it out
3. **Be specific about verification criteria** — Always say "verify by running X" after each phase
4. **CLAUDE.md must be SHORT** — Only include what Claude can't figure out by reading code. Ruthlessly prune.
5. **Use GSD workflow** — `/gsd-plan-phase` → `/gsd-execute-phase` → `/gsd-review-phase` → `/gsd-verify-work`
6. **"Just build" means execute without asking questions** — Don't confirm, don't hesitate, just run the commands
7. **"Learn online" means RUN the command and iterate from errors** — Test empirically, no speculation
8. **Give Claude the big picture** — 100-year vision, not just features. Let it make smart decisions.

### Code & Architecture
9. **No "Co-Authored-By:CLAUDE"** anywhere in code or commits
10. **ALL secrets via environment variables** — Never hardcoded, never in MD files
11. **Code protection is critical** — Pro features in private repo only, PyArmor obfuscation, AES-256 encrypted config
12. **Nobody sees the backend** — Public repo is compiled/obfuscated like Claude Code. Private repo runs on your servers.
13. **MikiCall project is OFF LIMITS** — Do not touch anything related to MikiCall
14. **owl-alpha is for paid tier only** — Open source users bring their own API/Ollama

### Product & Business
15. **Free tier psychology** — 2-3 scans/day, max 2 days/week. Each verified invite = +10 bonus scans (expire in 2 days OR spread across month, user's choice). Max 50 bonus. Invited user must complete 1 scan to activate.
16. **Self-evolving memory** — Per-user learning + cross-user anonymized intelligence. Open source version feeds patterns to private repo. This is the flywheel.
17. **SENTINEL agent** — Users install via `npm install -g wraith-sentinel` or `pip install wraith-sentinel`. Connects to their WRAITH account, monitors their PC 24/7, uses their local AI (Ollama/LM Studio), falls back to OpenRouter.
18. **Legal consent** — Digital authorization form signed at login before any scanning. Jurisdiction-specific laws. Immutable audit trail.
19. **Netlify connects to private repo only** — Public repo has no netlify.toml, no cloud config, no landing page

### Design & Branding
20. **Logo = sharp W monogram, aggressive, intimidating** — NOT a baby toy. NOT "MRA". Dark background, blood red accent, glowing eyes.
21. **Dark terminal aesthetic** — bg #0a0a0f, text #e0e0e0, accent #ff1a1a. Font: 'Courier New', monospace.
22. **Mobile responsive** — All frontend pages must work on mobile

### Repository Structure
23. **Two separate repos** — `wraith/public/` (9 core agents, no auth/payments) and `wraith/private/` (all 13 agents, auth, payments, protection)
24. **Public repo has no pro agents** — No PHANTOM, ORCHESTRATOR, SENTINEL in public
25. **Public repo has no cloud config** — No supabase_store.py, no auth.py, no payments.net in public

### What to Build First (Priority Order)
26. **Database schema** — Supabase with RLS, all tables, all policies
27. **Backend API** — FastAPI, all routes, WebSocket for real-time scans
28. **Web dashboard** — All pages, dark terminal aesthetic
29. **SENTINEL agent** — npm + pip packages
30. **Payments** — PayStack integration
31. **Tests** — All passing, 80%+ coverage
32. **Deploy** — Netlify (frontend) + Hetzner VPS (backend) + Supabase (database)

---

## Things to Do Differently Next Time

1. **Start with the database schema** — Everything depends on it. Get it right first.
2. **Use parallel subagents** — Database, backend, frontend, SENTINEL, tests can all be built in parallel
3. **Verify after EVERY phase** — Don't wait until the end. Test as you go.
4. **Keep CLAUDE.md under 100 lines** — If it's longer, Claude ignores half of it.
5. **Give exact SQL, exact API routes, exact file paths** — Specificity beats cleverness.
6. **Include verification commands** — "Run `pytest tests/ -v` and confirm all pass" not just "test it".
7. **Don't repeat yourself** — If it's in a rule file, don't also put it in CLAUDE.md. Reference it.
8. **Use the tools** — GSD for project management, superpowers for hard problems, UI/UX Pro Max for design, LightRAG for knowledge graph, claude-mem for memory.

---

## Key Technical Decisions

- **Backend:** FastAPI (Python), async where possible
- **Frontend:** React or Vue, dark terminal aesthetic
- **Database:** Supabase (PostgreSQL) with Row Level Security
- **Auth:** Supabase Auth (Google OAuth, GitHub OAuth, magic links)
- **Payments:** PayStack ($49/mo Pro subscription)
- **AI:** Universal provider layer (12+ LLMs), owl-alpha for paid tier
- **Sandbox:** Docker containers (Kali Linux profiles) + full VMs for complex ops
- **Memory:** SQLite (local) + LightRAG (knowledge graph) + Supabase (cloud sync)
- **Deployment:** Netlify (frontend), Hetzner VPS 77.42.82.252 (backend), Cloudflare (CDN)
- **Code protection:** PyArmor obfuscation, AES-256-GCM encrypted config, HMAC-SHA256 license keys

---

## The Flywheel

```
Free users (public repo) → anonymized patterns → private repo knowledge base
    ↓                                                           ↓
More users ← better free product ← more revenue ← better Pro product
```

Every free user makes the paid version smarter. Every paid user funds more development. SENTINEL agents create a distributed intelligence network that no competitor can replicate.

---

## Session Startup Checklist

Before doing anything else:
1. Read this FEEDBACK.md file
2. Read CLAUDE.md in the repo you're working on
3. Read AGENTS.md for multi-agent workflow
4. Check `.claude/rules/` for path-specific rules
5. Use GSD workflow for every major feature
6. Verify after every phase
