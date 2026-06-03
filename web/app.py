"""
WRAITH v2.0 — Web Application with Socket.IO
Flask + Socket.IO for real-time terminal streaming.
Extracted from monolithic web_ui.py.
"""

import os
import sys
import json
import time
import threading
from pathlib import Path
from datetime import datetime

# Add parent dir to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit

from agents.ghost import GhostAgent
from agents.specter_scanner_forge import SpecterAgent, ScannerAgent, ForgeAgent
from agents.neuron import NeuronAgent
from agents.neuron_ledger import LedgerAgent
from agents.mirror import MirrorAgent
from agents.breach import BreachAgent
from agents.commander import Commander
from core.bus import MessageBus
from core.scope import ScopeValidator
from core.ai_provider import AIProvider, PROVIDERS
from core.license import LicenseManager

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = os.environ.get("WRAITH_SECRET_KEY", "wraith-v2-god-tier")
socketio = SocketIO(app, cors_allowed_origins="*")

# In-memory mission store
missions = {}
active_mission = {"id": None, "log": [], "status": "idle"}
license_mgr = LicenseManager()

config = {
    # Priority: OpenRouter (free tier) > Groq > Gemini > Anthropic > OpenAI
    "api_key": os.environ.get("OPENROUTER_API_KEY", "") or os.environ.get("GROQ_API_KEY", "") or os.environ.get("GEMINI_API_KEY", "") or os.environ.get("ANTHROPIC_API_KEY", "") or os.environ.get("OPENAI_API_KEY", ""),
    "provider": "",
    "model": "",
}


def get_ai():
    """Get AI provider. Defaults to OpenRouter free tier."""
    ai = AIProvider(config["api_key"], config["provider"], config["model"])
    # If using OpenRouter without explicit model, use openrouter/auto (free)
    if ai.provider == "openrouter" and not config.get("model"):
        ai.model = "openrouter/auto"
    return ai


# ═══════════════════════════════════════════════════════════════
# PAGE ROUTES
# ═══════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/terminal")
def terminal():
    return render_template("terminal.html")


@app.route("/agents")
def agents_page():
    from core.plugin import PluginRegistry
    registry = PluginRegistry()
    registry.discover()
    agent_list = []
    for aid in registry.list_agents():
        meta = registry.get_metadata(aid)
        if meta:
            meta["id"] = aid
            meta["pro_available"] = license_mgr.is_pro(aid)
            agent_list.append(meta)
    return render_template("agents.html", agents=agent_list)


@app.route("/reports")
def reports_page():
    return render_template("reports.html")


@app.route("/settings")
def settings_page():
    return render_template("settings.html")


# ═══════════════════════════════════════════════════════════════
# API ROUTES
# ═══════════════════════════════════════════════════════════════

@app.route("/api/mission", methods=["POST"])
def start_mission():
    data = request.get_json()
    target = data.get("target", "").strip()
    mode = data.get("mode", "recon")
    authorized = data.get("authorized", False)

    if not target:
        return jsonify({"error": "No target specified"}), 400
    if not authorized:
        return jsonify({"error": "Authorization required"}), 403

    mission_id = f"m_{int(time.time())}_{target.replace('.', '_')}"
    missions[mission_id] = {
        "id": mission_id,
        "target": target,
        "mode": mode,
        "status": "running",
        "log": [],
        "findings": [],
        "report": "",
        "error": "",
    }

    thread = threading.Thread(
        target=run_mission_background,
        args=(mission_id, target, mode),
        daemon=True,
    )
    thread.start()

    return jsonify({"mission_id": mission_id})


@app.route("/api/mission/<mission_id>/status")
def mission_status(mission_id):
    m = missions.get(mission_id)
    if not m:
        return jsonify({"error": "Mission not found"}), 404
    return jsonify({
        "status": m["status"],
        "log": m["log"],
        "findings": m["findings"],
        "report": m["report"],
        "error": m["error"],
    })


@app.route("/api/commander", methods=["POST"])
def commander_chat():
    data = request.get_json()
    message = data.get("message", "")
    if not message:
        return jsonify({"error": "No message"}), 400

    bus = MessageBus()
    cmd = Commander(api_key=config["api_key"])
    agents = {
        "ghost": GhostAgent(bus),
        "specter": SpecterAgent(bus),
        "scanner": ScannerAgent(bus),
        "forge": ForgeAgent(bus, api_key=config["api_key"]),
        "ledger": LedgerAgent(bus),
    }

    try:
        response = cmd.process(message, agents, bus)
        return jsonify({"response": response})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ai-status")
def ai_status():
    ai = get_ai()
    s = ai.status()
    s["all_providers"] = PROVIDERS
    return jsonify(s)


@app.route("/api/set-key", methods=["POST"])
def set_key():
    data = request.get_json()
    key = (data.get("key") or "").strip()
    explicit_provider = data.get("provider", "")
    if not key:
        return jsonify({"ok": False, "error": "No key"}), 400
    detected = explicit_provider or AIProvider.detect_from_key(key)
    info = PROVIDERS.get(detected, {})
    config["api_key"] = key
    config["provider"] = detected
    config["model"] = info.get("default_model", "")
    return jsonify({"ok": True, "provider": detected, "provider_name": info.get("name", detected), "model": config["model"]})


@app.route("/api/test-key", methods=["POST"])
def test_key():
    data = request.get_json()
    key = data.get("key") or config["api_key"]
    provider = data.get("provider", "")
    if not key:
        return jsonify({"ok": False, "error": "No key"}), 400
    detected = provider or AIProvider.detect_from_key(key)
    ai = AIProvider(key, detected)
    try:
        resp = ai.complete("Reply: WRAITH ONLINE", max_tokens=20)
        if resp.startswith("[AI]"):
            return jsonify({"ok": False, "error": resp})
        return jsonify({"ok": True, "response": resp, "provider": detected})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)[:150]})


@app.route("/api/agents")
def api_agents():
    from core.plugin import PluginRegistry
    registry = PluginRegistry()
    registry.discover()
    agent_list = []
    for aid in registry.list_agents():
        meta = registry.get_metadata(aid)
        if meta:
            meta["id"] = aid
            meta["available"] = not meta.get("pro_only") or license_mgr.is_pro(aid)
            agent_list.append(meta)
    return jsonify({"agents": agent_list})


@app.route("/api/tools")
def api_tools():
    from core.kali_tools import check_tools
    return jsonify(check_tools())


@app.route("/api/license/status")
def license_status():
    return jsonify(license_mgr.get_status())


@app.route("/api/license/activate", methods=["POST"])
def license_activate():
    data = request.get_json()
    key = data.get("key", "").strip()
    if not key:
        return jsonify({"error": "No license key"}), 400
    result = license_mgr.activate(key)
    return jsonify(result)


@app.route("/api/neuron/stats")
def neuron_stats():
    try:
        n = NeuronAgent()
        return jsonify(n.stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/neuron/cves")
def neuron_cves():
    try:
        n = NeuronAgent()
        cves = n.get_critical_cves(days_back=30, limit=20)
        return jsonify({"cves": cves, "count": len(cves)})
    except Exception as e:
        return jsonify({"error": str(e), "cves": []}), 500


@app.route("/api/neuron/search")
def neuron_search():
    keyword = request.args.get("q", "").strip()
    if not keyword:
        return jsonify({"error": "No keyword"}), 400
    try:
        n = NeuronAgent()
        return jsonify(n.search(keyword))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════
# SOCKET.IO EVENTS
# ═══════════════════════════════════════════════════════════════

@socketio.on("connect")
def handle_connect():
    emit("connected", {"status": "WRAITH v2.0 Web UI connected"})


@socketio.on("start_mission")
def handle_start_mission(data):
    """Real-time mission start via WebSocket."""
    target = data.get("target", "").strip()
    mode = data.get("mode", "recon")
    authorized = data.get("authorized", False)

    if not target or not authorized:
        emit("error", {"message": "Target and authorization required"})
        return

    mission_id = f"m_{int(time.time())}_{target.replace('.', '_')}"
    missions[mission_id] = {
        "id": mission_id,
        "target": target,
        "mode": mode,
        "status": "running",
        "log": [],
        "findings": [],
        "report": "",
        "error": "",
    }

    emit("mission_started", {"mission_id": mission_id})

    thread = threading.Thread(
        target=run_mission_websocket,
        args=(mission_id, target, mode),
        daemon=True,
    )
    thread.start()


# ═══════════════════════════════════════════════════════════════
# BACKGROUND MISSION RUNNERS
# ═══════════════════════════════════════════════════════════════

def run_mission_background(mission_id: str, target: str, mode: str):
    """Run a mission in background (HTTP polling mode)."""
    m = missions[mission_id]

    def log(msg, t="info"):
        m["log"].append({"msg": msg, "type": t, "ts": datetime.now().isoformat()})

    try:
        bus = MessageBus()
        results = {}
        ai = get_ai()

        if mode in ("recon", "full", "breach"):
            log("[GHOST] Mapping attack surface...", "cmd")
            result = GhostAgent(bus).run(target, None)
            results["recon"] = result
            m["findings"].extend(result.get("findings", []))
            log(f"[GHOST] {result.get('summary', 'Complete')}", "success")

        if mode in ("osint", "full"):
            log("[SPECTER] Running OSINT sweep...", "cmd")
            result = SpecterAgent(bus).run(target, None)
            results["osint"] = result
            m["findings"].extend(result.get("findings", []))
            log(f"[SPECTER] {result.get('summary', 'Complete')}", "success")

        if mode in ("scan", "full", "breach"):
            log("[SCANNER] Hunting vulnerabilities...", "cmd")
            result = ScannerAgent(bus).run(target, None)
            results["scan"] = result
            m["findings"].extend(result.get("findings", []))
            log(f"[SCANNER] {result.get('summary', 'Complete')}", "success")

        if mode == "breach":
            log("[BREACH] Starting controlled exploitation...", "cmd")
            try:
                scope = ScopeValidator(target)
                scanner_findings = results.get("scan", {}).get("findings", [])
                breach_result = BreachAgent(bus, api_key=ai.api_key).run(
                    target, scope, scanner_findings=scanner_findings, require_approval=False
                )
                results["breach"] = breach_result
                m["findings"].extend(breach_result.get("findings", []))
                log(f"[BREACH] {breach_result.get('summary', 'Complete')}", "success")
            except Exception as be:
                log(f"[BREACH] Error: {be}", "error")

        log("[LEDGER] Generating report...", "cmd")
        report = LedgerAgent(bus).generate(target, results, mission_id, ai.api_key)

        output_dir = Path("./wraith_output")
        output_dir.mkdir(exist_ok=True)
        report_file = output_dir / f"{mission_id}_report.md"
        with open(report_file, "w") as f:
            f.write(report.get("markdown", ""))

        m["report"] = report.get("markdown", "")
        m["risk_level"] = report.get("risk_level", "")
        m["status"] = "complete"
        log(f"Mission complete. Report: {report_file}", "success")

    except Exception as e:
        m["status"] = "error"
        m["error"] = str(e)
        m["log"].append({"msg": f"Mission failed: {e}", "type": "error"})


def run_mission_websocket(mission_id: str, target: str, mode: str):
    """Run a mission with real-time WebSocket updates."""
    m = missions[mission_id]

    def log_and_emit(msg, t="info"):
        m["log"].append({"msg": msg, "type": t, "ts": datetime.now().isoformat()})
        socketio.emit("log", {"msg": msg, "type": t, "mission_id": mission_id})

    try:
        bus = MessageBus()
        results = {}
        ai = get_ai()

        if mode in ("recon", "full", "breach"):
            log_and_emit("[GHOST] Mapping attack surface...", "cmd")
            result = GhostAgent(bus).run(target, None)
            results["recon"] = result
            m["findings"].extend(result.get("findings", []))
            socketio.emit("findings", {"findings": result.get("findings", []), "mission_id": mission_id})
            log_and_emit(f"[GHOST] {result.get('summary', 'Complete')}", "success")

        if mode in ("osint", "full"):
            log_and_emit("[SPECTER] Running OSINT sweep...", "cmd")
            result = SpecterAgent(bus).run(target, None)
            results["osint"] = result
            m["findings"].extend(result.get("findings", []))
            socketio.emit("findings", {"findings": result.get("findings", []), "mission_id": mission_id})
            log_and_emit(f"[SPECTER] {result.get('summary', 'Complete')}", "success")

        if mode in ("scan", "full", "breach"):
            log_and_emit("[SCANNER] Hunting vulnerabilities...", "cmd")
            result = ScannerAgent(bus).run(target, None)
            results["scan"] = result
            m["findings"].extend(result.get("findings", []))
            socketio.emit("findings", {"findings": result.get("findings", []), "mission_id": mission_id})
            log_and_emit(f"[SCANNER] {result.get('summary', 'Complete')}", "success")

        log_and_emit("[LEDGER] Generating report...", "cmd")
        report = LedgerAgent(bus).generate(target, results, mission_id, ai.api_key)

        output_dir = Path("./wraith_output")
        output_dir.mkdir(exist_ok=True)
        report_file = output_dir / f"{mission_id}_report.md"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(report.get("markdown", ""))

        m["report"] = report.get("markdown", "")
        m["status"] = "complete"
        socketio.emit("mission_complete", {"mission_id": mission_id, "report": m["report"]})
        log_and_emit(f"Mission complete. Report: {report_file}", "success")

    except Exception as e:
        m["status"] = "error"
        m["error"] = str(e)
        socketio.emit("mission_error", {"mission_id": mission_id, "error": str(e)})


# ═══════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════

def main():
    port = int(os.environ.get("WRAITH_PORT", 7734))
    print(f"\n{'='*50}")
    print(f"  WRAITH Web UI v2.0")
    print(f"  http://localhost:{port}")
    print(f"{'='*50}")
    if config["api_key"]:
        print(f"  AI: ON ({config['provider'] or 'auto-detected'})")
    else:
        print("  AI: OFF (set API key in Settings)")
    print(f"{'='*50}\n")
    socketio.run(app, host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    main()
