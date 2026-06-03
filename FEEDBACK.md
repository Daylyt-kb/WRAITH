# WRAITH — Corrections & Preferences

## Prompting Rules
- CLAUDE.md must be SHORT (< 50 lines). Only build steps.
- "ON STARTUP — DO THIS IN ORDER. NO QUESTIONS. NO ASSESSMENTS. JUST BUILD."
- Numbered steps with exact file names
- Verification after each step
- Don't tell Claude what exists — let it read code
- "Just build" = execute without asking

## Code Rules
- No "Co-Authored-By:CLAUDE"
- ALL secrets via env vars
- MikiCall OFF LIMITS
- owl-alpha paid only

## Product
- Free: 2 scans/day, 2 days/week, +10/invite (max 50)
- Memory: per-user + cross-user anonymized, open source → private
- SENTINEL: npm/pip, 24/7, local AI
- Consent: digital form at login
- Netlify → private only
- Logo: sharp W monogram, dark + blood red
- Frontend: dark terminal, mobile responsive

## Architecture
- Backend: FastAPI | Frontend: Vue 3 + Pinia
- Database: Supabase + RLS | Auth: Supabase Auth
- Payments: PayStack $49/mo | AI: 12+ LLMs
- Deploy: Netlify + Hetzner VPS + Cloudflare
