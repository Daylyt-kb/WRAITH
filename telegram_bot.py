"""
WRAITH Telegram Bot
Zero hosting cost. Runs on your laptop.
Users send a message → WRAITH scans → results back in Telegram.

Setup (one time):
1. Message @BotFather on Telegram → /newbot → get your token
2. Set env: export TELEGRAM_BOT_TOKEN="your-token"
3. Run: python3 telegram_bot.py

Commands users can send:
  /start       — welcome message
  /scan <target>  — run recon on a target (must confirm auth)
  /osint <target> — OSINT sweep
  /full <target>  — full swarm
  /cves         — show latest critical CVEs from NEURON
  /help         — command list

Authorization flow:
  The bot ASKS for confirmation before scanning anything.
  Users must reply "yes I own this target" to proceed.
  All other responses are blocked.
"""

import os
import sys
import json
import time
import threading
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

from agents.ghost import GhostAgent
from agents.specter_scanner_forge import SpecterAgent, ScannerAgent
from agents.neuron import NeuronAgent
from agents.neuron_ledger import LedgerAgent
from core.bus import MessageBus
from core.scope import ScopeValidator
from core.ai_provider import AIProvider

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
API_BASE = f"https://api.telegram.org/bot{BOT_TOKEN}"

# Per-user session state
sessions = {}


# ── Telegram API wrappers ──────────────────────────────────────────────────────

def tg_get(method: str, params: dict = None) -> dict:
    url = f"{API_BASE}/{method}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "WRAITH-Bot/1.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def tg_post(method: str, data: dict) -> dict:
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        f"{API_BASE}/{method}",
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "WRAITH-Bot/1.0"}
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def send(chat_id: int, text: str, parse_mode: str = ""):
    payload = {"chat_id": chat_id, "text": text[:4096]}
    if parse_mode:
        payload["parse_mode"] = parse_mode
    try:
        tg_post("sendMessage", payload)
    except Exception as e:
        print(f"  [BOT] Send error: {e}")


def send_typing(chat_id: int):
    try:
        tg_post("sendChatAction", {"chat_id": chat_id, "action": "typing"})
    except Exception:
        pass


# ── Command handlers ───────────────────────────────────────────────────────────

def handle_start(chat_id: int, user: str):
    send(chat_id, f"""
🔴 WRAITH Security Swarm

Welcome, {user}. I'm an AI security agent.

Commands:
/scan <domain>  — surface recon
/osint <domain> — open source intel
/full <domain>  — complete swarm
/cves           — latest critical CVEs
/help           — this message

⚠️ LEGAL: Only scan targets you own or have authorization to test. I will always ask you to confirm before scanning.

Built by Kebron Isaias | github.com/Daylyt-kb/wraith
""".strip())


def handle_help(chat_id: int):
    send(chat_id, """
WRAITH Commands:

/scan example.com   — port scan, tech fingerprint, headers
/osint example.com  — emails, subdomains, cert transparency
/full example.com   — everything above + vuln scan
/cves               — latest critical CVEs from NEURON

Authorization: you must confirm ownership/permission before any scan fires.

Only test systems you own or have written permission to test.
""".strip())


def handle_cves(chat_id: int):
    send_typing(chat_id)
    try:
        neuron = NeuronAgent()
        cves = neuron.get_critical_cves(days_back=7, limit=5)
        if not cves:
            send(chat_id, "No critical CVEs in local database yet. Run /full scan to trigger NEURON ingest.")
            return
        lines = ["🔴 Recent Critical CVEs\n"]
        for c in cves:
            lines.append(f"• {c['id']} [{c['severity']}] score:{c['score']}\n  {c['description'][:120]}...")
        send(chat_id, "\n".join(lines))
    except Exception as e:
        send(chat_id, f"CVE fetch error: {e}")


def handle_scan_request(chat_id: int, user_id: int, target: str, mode: str):
    """Ask for authorization before scanning."""
    sessions[user_id] = {
        "state": "awaiting_auth",
        "target": target,
        "mode": mode,
        "chat_id": chat_id
    }
    send(chat_id, f"""
⚠️ AUTHORIZATION REQUIRED

Target: {target}
Mode: {mode.upper()}

Do you own this system, or do you have written permission to test it?

Reply: yes — to confirm and start scan
Reply: no  — to cancel
""".strip())


def handle_auth_response(chat_id: int, user_id: int, text: str):
    """Handle yes/no response to authorization prompt."""
    session = sessions.get(user_id, {})
    if session.get("state") != "awaiting_auth":
        return False

    if text.strip().lower() in ("yes", "y", "yes i own this", "authorized"):
        target = session["target"]
        mode = session["mode"]
        sessions[user_id] = {"state": "scanning"}
        send(chat_id, f"✓ Authorization confirmed. Deploying swarm on {target}...")
        threading.Thread(
            target=run_mission_telegram,
            args=(chat_id, user_id, target, mode),
            daemon=True
        ).start()
        return True
    elif text.strip().lower() in ("no", "n", "cancel"):
        sessions.pop(user_id, None)
        send(chat_id, "Scan cancelled. Only test systems you own.")
        return True
    else:
        send(chat_id, "Please reply 'yes' to confirm authorization or 'no' to cancel.")
        return True

    return False


def run_mission_telegram(chat_id: int, user_id: int, target: str, mode: str):
    """Run a scan mission and stream results back to the user."""
    bus = MessageBus()
    scope = ScopeValidator(target)
    ai = AIProvider()  # uses whatever env key is set
    results = {}

    def progress(msg: str):
        send(chat_id, msg)
        time.sleep(0.3)

    try:
        # GHOST
        if mode in ("scan", "osint", "full"):
            send_typing(chat_id)
            progress("🔍 GHOST: Mapping attack surface...")
            ghost_result = GhostAgent(bus).run(target, scope)
            results["recon"] = ghost_result
            progress(f"✓ GHOST: {ghost_result.get('summary', 'complete')}")

        # SPECTER
        if mode in ("osint", "full"):
            send_typing(chat_id)
            progress("🌐 SPECTER: OSINT sweep...")
            specter_result = SpecterAgent(bus).run(target, scope)
            results["osint"] = specter_result
            progress(f"✓ SPECTER: {specter_result.get('summary', 'complete')}")

        # SCANNER
        if mode == "full":
            send_typing(chat_id)
            progress("🛡️ SCANNER: Hunting vulnerabilities...")
            scanner_result = ScannerAgent(bus).run(target, scope)
            results["scan"] = scanner_result
            progress(f"✓ SCANNER: {scanner_result.get('summary', 'complete')}")

        # LEDGER report
        send_typing(chat_id)
        mission_id = f"tg_{int(time.time())}_{target.replace('.','_')}"
        report = LedgerAgent(bus).generate(target, results, mission_id, ai.api_key)

        # Store learnings in NEURON
        all_findings = report.get("findings", [])
        NeuronAgent(bus).store_mission_learning(mission_id, target, all_findings)

        # Format summary for Telegram
        counts = report.get("finding_counts", {})
        risk = report.get("risk_level", "UNKNOWN")

        summary_lines = [
            f"📋 WRAITH Report — {target}",
            f"Risk Level: {risk}",
            f"",
            f"Findings:",
            f"  🔴 Critical: {counts.get('critical', 0)}",
            f"  🟠 High:     {counts.get('high', 0)}",
            f"  🟡 Medium:   {counts.get('medium', 0)}",
            f"  🟢 Low:      {counts.get('low', 0)}",
            f"  ⚪ Info:     {counts.get('info', 0)}",
            f"",
        ]

        # Top findings
        critical_high = [
            f for f in all_findings
            if f.get("severity") in ("critical", "high")
        ][:5]

        if critical_high:
            summary_lines.append("Top findings:")
            for f in critical_high:
                sev = f.get("severity", "").upper()
                title = f.get("title", "")[:80]
                summary_lines.append(f"  [{sev}] {title}")

        summary_lines.append(f"\nExecutive summary:")
        summary_lines.append(report.get("executive_summary", "")[:400])

        send(chat_id, "\n".join(summary_lines))

        # Save full report
        output_dir = Path("./wraith_output")
        output_dir.mkdir(exist_ok=True)
        report_path = output_dir / f"{mission_id}_report.md"
        with open(report_path, "w") as f:
            f.write(report.get("markdown", ""))

        send(chat_id, f"Full report saved: {report_path}\n\nScan another target with /scan <domain>")

    except Exception as e:
        send(chat_id, f"❌ Mission error: {str(e)[:200]}\nTry again or use the web UI.")
    finally:
        sessions.pop(user_id, None)


# ── Main polling loop ──────────────────────────────────────────────────────────

def handle_update(update: dict):
    msg = update.get("message") or update.get("edited_message")
    if not msg:
        return

    chat_id = msg["chat"]["id"]
    user_id = msg["from"]["id"]
    user_name = msg["from"].get("first_name", "user")
    text = msg.get("text", "").strip()

    if not text:
        return

    print(f"  [BOT] {user_name}: {text[:60]}")

    # Check if awaiting auth
    if handle_auth_response(chat_id, user_id, text):
        return

    # Commands
    parts = text.split(None, 1)
    cmd = parts[0].lower().lstrip("/").split("@")[0]
    arg = parts[1].strip() if len(parts) > 1 else ""

    if cmd == "start":
        handle_start(chat_id, user_name)
    elif cmd == "help":
        handle_help(chat_id)
    elif cmd == "cves":
        handle_cves(chat_id)
    elif cmd in ("scan", "recon"):
        if not arg:
            send(chat_id, "Usage: /scan <domain>\nExample: /scan mywebsite.com")
        else:
            handle_scan_request(chat_id, user_id, arg, "scan")
    elif cmd == "osint":
        if not arg:
            send(chat_id, "Usage: /osint <domain>\nExample: /osint mycompany.com")
        else:
            handle_scan_request(chat_id, user_id, arg, "osint")
    elif cmd == "full":
        if not arg:
            send(chat_id, "Usage: /full <domain>\nExample: /full mysite.com")
        else:
            handle_scan_request(chat_id, user_id, arg, "full")
    else:
        send(chat_id, "Unknown command. Use /help")


def run():
    if not BOT_TOKEN:
        print("ERROR: Set TELEGRAM_BOT_TOKEN environment variable")
        print("Get a token from @BotFather on Telegram → /newbot")
        sys.exit(1)

    print("=" * 50)
    print("  WRAITH Telegram Bot")
    print("  Polling for messages...")
    print("  Ctrl+C to stop")
    print("=" * 50)

    # Verify token
    try:
        me = tg_get("getMe")
        bot_name = me["result"]["username"]
        print(f"  Bot: @{bot_name}")
        print(f"  Share this link: https://t.me/{bot_name}")
    except Exception as e:
        print(f"  Token error: {e}")
        sys.exit(1)

    offset = 0
    while True:
        try:
            resp = tg_get("getUpdates", {"offset": offset, "timeout": 30, "limit": 10})
            for update in resp.get("result", []):
                offset = update["update_id"] + 1
                handle_update(update)
        except KeyboardInterrupt:
            print("\nBot stopped.")
            break
        except urllib.error.URLError as e:
            print(f"  Network error: {e}. Retrying in 5s...")
            time.sleep(5)
        except Exception as e:
            print(f"  Error: {e}")
            time.sleep(2)


if __name__ == "__main__":
    run()
