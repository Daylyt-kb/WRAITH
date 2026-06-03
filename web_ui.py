"""
WRAITH v2.0 — Web UI Entry Point
Backward-compatible wrapper. Delegates to web/app.py (Flask + Socket.IO).
Agents used: GhostAgent, SpecterAgent, ScannerAgent, ForgeAgent, BreachAgent (breach exploitation),
MirrorAgent, LedgerAgent, Commander (from agents package via web/app.py).
Run: python web_ui.py  →  http://localhost:7734
"""

import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from web.app import app, socketio, config

def main():
    port = int(os.environ.get("WRAITH_PORT", 7734))
    print("\n" + "=" * 50)
    print("  WRAITH Web UI v2.0")
    print(f"  http://localhost:{port}")
    print("=" * 50)
    if config["api_key"]:
        print(f"  AI Mode: ON ({config['provider'] or 'auto-detected'})")
    else:
        print("  AI Mode: OFF (set API key in Settings)")
    print("  WebSocket: Enabled (Socket.IO)")
    print("  Legal: Only scan targets you own or have authorization for")
    print("=" * 50 + "\n")
    socketio.run(app, host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    main()
