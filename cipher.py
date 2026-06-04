#!/usr/bin/env python3
"""
WRAITH — Browser-Native AI Security Agent (CLI Edition)
The world's first civilian AI security swarm.
Zero cost. Runs on your laptop. Legal by design.
"""

import os
import sys
import json
import time
import argparse
import subprocess
from datetime import datetime
from pathlib import Path

# ── Try to import optional deps gracefully ──
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.table import Table
    from rich.text import Text
    from rich import print as rprint
    RICH = True
except ImportError:
    RICH = False

try:
    import anthropic
    AI = True
except ImportError:
    AI = False

from agents.commander import Commander
from agents.ghost import GhostAgent
from agents.scanner import ScannerAgent
from agents.specter import SpecterAgent
from agents.forge import ForgeAgent
from agents.neuron import NeuronAgent
from agents.ledger import LedgerAgent
from core.scope import ScopeValidator
from core.bus import MessageBus
from core.consent import ConsentManager

console = Console() if RICH else None


BANNER = r"""
  ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗ 
 ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗
 ██║     ██║██████╔╝███████║█████╗  ██████╔╝
 ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗
 ╚██████╗██║██║     ██║  ██║███████╗██║  ██║
  ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

  The World's First Civilian AI Security Swarm
  Legal by design. Brutal by capability.
  v0.1.0 — Built with zero budget, infinite vision.
"""


def print_banner():
    if RICH:
        console.print(BANNER, style="bold red")
        console.print("  [dim]github.com/your-handle/wraith[/dim]\n")
    else:
        print(BANNER)


def check_dependencies():
    """Check which Kali tools are available on the system."""
    tools = {
        "nmap": "Network mapper — port scanning",
        "amass": "Subdomain enumeration",
        "nikto": "Web server scanner",
        "gobuster": "Directory/DNS brute forcer",
        "whatweb": "Web technology fingerprinter",
        "theHarvester": "Email/subdomain OSINT",
        "nuclei": "Vulnerability template scanner",
        "ffuf": "Web fuzzer",
        "curl": "HTTP client (baseline)",
        "whois": "Domain registration lookup",
        "dig": "DNS query tool",
        "host": "DNS lookup utility",
    }
    available = {}
    missing = {}
    for tool, desc in tools.items():
        result = subprocess.run(
            ["which", tool],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            available[tool] = desc
        else:
            missing[tool] = desc
    return available, missing


def print_tool_status(available, missing):
    if RICH:
        table = Table(title="Tool Arsenal Status", show_header=True)
        table.add_column("Tool", style="bold")
        table.add_column("Status")
        table.add_column("Purpose")
        for tool, desc in available.items():
            table.add_row(tool, "[green]✓ Ready[/green]", desc)
        for tool, desc in missing.items():
            table.add_row(tool, "[dim]✗ Not installed[/dim]", desc)
        console.print(table)
    else:
        print("\n=== TOOL STATUS ===")
        for t in available:
            print(f"  [✓] {t}")
        for t in missing:
            print(f"  [✗] {t} (not installed)")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="WRAITH — AI Security Swarm",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cipher.py --target example.com --mode recon
  cipher.py --target 192.168.1.1 --mode full --authorized
  cipher.py --target myapp.com --mode osint
  cipher.py --check-tools
  cipher.py --interactive
        """
    )
    parser.add_argument("--target", "-t", help="Target domain or IP (must be authorized)")
    parser.add_argument("--mode", "-m",
        choices=["recon", "osint", "scan", "full", "ai-audit"],
        default="recon",
        help="Scan mode (default: recon)"
    )
    parser.add_argument("--authorized", "-a", action="store_true",
        help="Confirm you have authorization to test this target")
    parser.add_argument("--output", "-o", default="./wraith_output",
        help="Output directory for reports")
    parser.add_argument("--check-tools", action="store_true",
        help="Check which security tools are installed")
    parser.add_argument("--interactive", "-i", action="store_true",
        help="Launch interactive WRAITH shell")
    parser.add_argument("--install-deps", action="store_true",
        help="Show installation commands for missing tools")
    parser.add_argument("--api-key", help="Anthropic API key (or set ANTHROPIC_API_KEY env var)")

    args = parser.parse_args()

    # ── Tool check mode ──
    if args.check_tools:
        available, missing = check_dependencies()
        print_tool_status(available, missing)
        if missing and args.install_deps:
            print("\n[INSTALL MISSING TOOLS]")
            print("On Kali Linux / Debian / Ubuntu:")
            print(f"  sudo apt-get install {' '.join(missing.keys())}")
            print("\nFor nuclei:")
            print("  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            print("\nFor amass:")
            print("  go install -v github.com/owasp-amass/amass/v4/...@master")
        return

    # ── Interactive shell ──
    if args.interactive:
        launch_interactive_shell(args)
        return

    # ── Scan mode ──
    if not args.target:
        parser.print_help()
        return

    if not args.authorized:
        if RICH:
            console.print("\n[bold red]⚠ AUTHORIZATION REQUIRED[/bold red]")
            console.print(
                "You must confirm you have explicit authorization to test this target.\n"
                "Run with [bold]--authorized[/bold] flag to confirm.\n\n"
                "[dim]WRAITH is legal-by-design. Unauthorized scanning is illegal.[/dim]"
            )
        else:
            print("\n⚠ ERROR: You must confirm authorization with --authorized flag")
            print("Unauthorized scanning is illegal. WRAITH is legal-by-design.")
        sys.exit(1)

    # ── Get API key ──
    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY", "")

    # ── Launch the swarm ──
    run_mission(args.target, args.mode, args.output, api_key)


def launch_interactive_shell(args):
    """Interactive WRAITH shell — talk to the commander directly."""
    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY", "")

    if RICH:
        console.print(Panel(
            "[bold]WRAITH Interactive Shell[/bold]\n"
            "[dim]Talk to Commander in plain English.\n"
            "Type 'help' for commands. Type 'exit' to quit.[/dim]",
            style="blue"
        ))
    else:
        print("\n=== WRAITH Interactive Shell ===")
        print("Talk to Commander in plain English.")
        print("Type 'help' for commands. Type 'exit' to quit.\n")

    commander = Commander(api_key=api_key)
    bus = MessageBus()

    # Attach agents to bus
    agents = {
        "ghost": GhostAgent(bus),
        "scanner": ScannerAgent(bus),
        "specter": SpecterAgent(bus),
        "forge": ForgeAgent(bus, api_key=api_key),
        "neuron": NeuronAgent(bus),
        "ledger": LedgerAgent(bus),
    }

    print()
    while True:
        try:
            if RICH:
                user_input = console.input("[bold cyan]wraith>[/bold cyan] ").strip()
            else:
                user_input = input("wraith> ").strip()

            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit", "q"):
                print("\nStaying safe. Shutting down WRAITH.\n")
                break
            if user_input.lower() == "help":
                print_help()
                continue
            if user_input.lower() == "tools":
                available, missing = check_dependencies()
                print_tool_status(available, missing)
                continue
            if user_input.lower().startswith("load "):
                # Load a previous report
                path = user_input[5:].strip()
                load_report(path)
                continue

            # Send to Commander
            response = commander.process(user_input, agents, bus)
            if RICH:
                console.print(f"\n[bold green]Commander:[/bold green] {response}\n")
            else:
                print(f"\nCommander: {response}\n")

        except KeyboardInterrupt:
            print("\n\nInterrupted. Type 'exit' to quit.\n")
        except Exception as e:
            if RICH:
                console.print(f"[red]Error: {e}[/red]")
            else:
                print(f"Error: {e}")


def print_help():
    help_text = """
WRAITH Commands:
  scan <target>           — Run recon on a target (must be authorized)
  osint <target>          — Run OSINT sweep on a target
  full <target>           — Full swarm attack (recon + osint + vuln scan)
  forge <description>     — Generate a custom script for a task
  report                  — Generate report from last mission
  tools                   — Show available security tools
  load <file>             — Load a previous scan report
  exit                    — Exit WRAITH

Examples:
  scan mycompany.com
  osint target-domain.com
  forge "script to enumerate all subdomains and check which have open port 443"
  full 192.168.1.0/24

Legal reminder: Only scan systems you own or have written permission to test.
"""
    print(help_text)


def load_report(path):
    try:
        with open(path) as f:
            data = json.load(f)
        print(f"\nLoaded report: {data.get('target', 'unknown')}")
        print(f"Mission time: {data.get('timestamp', 'unknown')}")
        print(f"Findings: {len(data.get('findings', []))}")
    except Exception as e:
        print(f"Could not load report: {e}")


def run_mission(target, mode, output_dir, api_key):
    """Execute a full mission against an authorized target."""

    # Setup
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    mission_id = f"mission_{timestamp}_{target.replace('.', '_')}"

    if RICH:
        console.print(f"\n[bold]Mission ID:[/bold] {mission_id}")
        console.print(f"[bold]Target:[/bold]     {target}")
        console.print(f"[bold]Mode:[/bold]       {mode}")
        console.print(f"[bold]Output:[/bold]     {output_dir}\n")
    else:
        print(f"\nMission: {mission_id}")
        print(f"Target:  {target}")
        print(f"Mode:    {mode}\n")

    bus = MessageBus()
    scope = ScopeValidator(target)
    results = {}

    # ── PHASE 1: GHOST Recon ──
    if mode in ("recon", "full", "scan"):
        ghost = GhostAgent(bus)
        if RICH:
            with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as p:
                task = p.add_task("[cyan]GHOST: Mapping attack surface...", total=None)
                recon_results = ghost.run(target, scope)
                p.update(task, description="[green]GHOST: Recon complete")
        else:
            print("[GHOST] Mapping attack surface...")
            recon_results = ghost.run(target, scope)
            print("[GHOST] Done.")
        results["recon"] = recon_results

    # ── PHASE 1.5: MIRROR AI-Audit ──
    if mode in ("ai-audit", "full"):
        from agents.mirror import MirrorAgent
        mirror = MirrorAgent(bus, api_key=api_key)
        if RICH:
            with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as p:
                task = p.add_task("[yellow]MIRROR: Auditing AI perimeter...", total=None)
                # For CLI we pass empty config for now
                mirror_results = mirror.run(target, scope, {})
                p.update(task, description="[green]MIRROR: AI-Audit complete")
        else:
            print("[MIRROR] Auditing AI perimeter...")
            mirror_results = mirror.run(target, scope, {})
            print("[MIRROR] Done.")
        results["mirror"] = mirror_results

    # ── PHASE 2: SPECTER OSINT ──
    if mode in ("osint", "full"):
        specter = SpecterAgent(bus)
        if RICH:
            with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as p:
                task = p.add_task("[magenta]SPECTER: Running OSINT sweep...", total=None)
                osint_results = specter.run(target, scope)
                p.update(task, description="[green]SPECTER: OSINT complete")
        else:
            print("[SPECTER] Running OSINT sweep...")
            osint_results = specter.run(target, scope)
            print("[SPECTER] Done.")
        results["osint"] = osint_results

    # ── PHASE 3: SCANNER Vuln Scan ──
    if mode in ("scan", "full"):
        scanner = ScannerAgent(bus)
        if RICH:
            with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as p:
                task = p.add_task("[red]SCANNER: Hunting vulnerabilities...", total=None)
                scan_results = scanner.run(target, scope)
                p.update(task, description="[green]SCANNER: Scan complete")
        else:
            print("[SCANNER] Hunting vulnerabilities...")
            scan_results = scanner.run(target, scope)
            print("[SCANNER] Done.")
        results["scan"] = scan_results

    # ── PHASE 4: LEDGER Report ──
    ledger = LedgerAgent(bus)
    report = ledger.generate(target, results, mission_id, api_key)

    # Save report
    report_file = output_path / f"{mission_id}_report.json"
    md_file = output_path / f"{mission_id}_report.md"

    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)
    with open(md_file, "w") as f:
        f.write(report.get("markdown", ""))

    if RICH:
        console.print(f"\n[bold green]✓ Mission complete![/bold green]")
        console.print(f"  JSON report: [cyan]{report_file}[/cyan]")
        console.print(f"  MD report:   [cyan]{md_file}[/cyan]")

        # Summary table
        findings = report.get("findings", [])
        if findings:
            table = Table(title="Findings Summary")
            table.add_column("Severity", style="bold")
            table.add_column("Finding")
            table.add_column("Tool")
            for f in findings[:15]:  # show top 15
                sev = f.get("severity", "info")
                color = {"critical": "red", "high": "red", "medium": "yellow",
                         "low": "cyan", "info": "dim"}.get(sev, "white")
                table.add_row(
                    f"[{color}]{sev.upper()}[/{color}]",
                    f.get("title", ""),
                    f.get("tool", "")
                )
            console.print(table)
    else:
        print(f"\n✓ Mission complete!")
        print(f"  Report saved: {report_file}")

    return report


if __name__ == "__main__":
    main()
