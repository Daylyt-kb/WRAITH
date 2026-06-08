"""
WRAITH v2.0 — Kali Linux Tool Wrappers
Each Kali tool gets a Python wrapper with standardized interface.
Agents use these to execute real security tools in sandboxes.

Categories: recon, web, exploit, password, osint, wireless, forensics, sniffing, reverse_eng
Risk levels: low, medium, high, critical (require authorization escalation)
"""

import os
import re
import json
import shutil
import subprocess
from typing import Optional, Dict, List
from datetime import datetime


class KaliTool:
    """
    Base class for all Kali Linux tool wrappers.
    
    Each tool defines its metadata and execution logic.
    Tools can run in sandboxes (Docker) or locally.
    
    Usage:
        tool = NmapTool()
        result = tool.run(target="example.com", args="-sV -sC")
        print(result["stdout"])
    """

    name: str = "base_tool"
    category: str = "generic"
    description: str = "Base tool wrapper"
    risk_level: str = "low"  # low, medium, high, critical
    sandbox_required: bool = True
    install_cmd: str = ""
    parse_output: bool = False

    def run(self, target: str = "", args: str = "", sandbox=None) -> dict:
        """
        Execute the tool against a target.
        
        Args:
            target: Target domain, IP, or URL
            args: Tool-specific arguments
            sandbox: Optional Sandbox instance for isolated execution
            
        Returns:
            dict with stdout, stderr, return_code, parsed data
        """
        command = self._build_command(target, args)
        start_time = datetime.now()

        if sandbox and self.sandbox_required:
            result = sandbox.run(command, tool=self.name)
        else:
            result = self._run_local(command)

        duration = (datetime.now() - start_time).total_seconds()
        result["duration"] = round(duration, 2)
        result["tool"] = self.name
        result["target"] = target
        result["category"] = self.category
        result["risk_level"] = self.risk_level

        if self.parse_output and result.get("return_code") == 0:
            result["parsed"] = self._parse(result.get("stdout", ""))

        return result

    def _build_command(self, target: str, args: str) -> str:
        """Build the full command string."""
        parts = [self.name]
        if args:
            parts.append(args)
        if target:
            parts.append(target)
        return " ".join(parts)

    def _run_local(self, command: str) -> dict:
        """Run command locally (fallback when no sandbox)."""
        try:
            result = subprocess.run(
                command, shell=True,
                capture_output=True, text=True, timeout=300
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.return_code,
                "engine": "local"
            }
        except subprocess.TimeoutExpired:
            return {
                "stdout": "",
                "stderr": "Command timed out after 300s",
                "return_code": -1,
                "engine": "local"
            }

    def _parse(self, output: str) -> dict:
        """Parse tool-specific output. Override in subclasses."""
        return {"raw": output}

    def is_available(self) -> bool:
        """Check if this tool is installed on the system."""
        return shutil.which(self.name) is not None

    def install(self) -> str:
        """Return the installation command for this tool."""
        return self.install_cmd

    def to_dict(self) -> dict:
        """Serialize tool metadata."""
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "risk_level": self.risk_level,
            "sandbox_required": self.sandbox_required,
            "available": self.is_available(),
            "install_cmd": self.install_cmd
        }


# ═══════════════════════════════════════════════════════════════
# RECON TOOLS
# ═══════════════════════════════════════════════════════════════

class NmapTool(KaliTool):
    """nmap — Network mapper and port scanner."""
    name = "nmap"
    category = "recon"
    description = "Network discovery and security auditing"
    risk_level = "low"
    sandbox_required = True
    install_cmd = "sudo apt-get install -y nmap"
    parse_output = True

    def _build_command(self, target: str, args: str) -> str:
        default_args = "-sV -sC -T4 --open"
        return f"nmap {args or default_args} -oA /output/nmap_scan {target}"

    def _parse(self, output: str) -> dict:
        """Parse nmap output into structured data."""
        ports = []
        current_host = None

        for line in output.split("\n"):
            # Host line
            host_match = re.search(r"Nmap scan report for (.+)", line)
            if host_match:
                current_host = host_match.group(1)

            # Port line
            port_match = re.match(r"(\d+)/(tcp|udp)\s+(\S+)\s+(.+)", line)
            if port_match:
                ports.append({
                    "port": int(port_match.group(1)),
                    "protocol": port_match.group(2),
                    "state": port_match.group(3),
                    "service": port_match.group(4).strip()
                })

        return {
            "host": current_host,
            "open_ports": ports,
            "total_ports": len(ports)
        }


class MasscanTool(KaliTool):
    """masscan — Fast port scanner for large networks."""
    name = "masscan"
    category = "recon"
    description = "Fast mass port scanner"
    risk_level = "medium"
    sandbox_required = True
    install_cmd = "sudo apt-get install -y masscan"

    def _build_command(self, target: str, args: str) -> str:
        default_args = "-p1-65535 --rate=1000"
        return f"masscan {args or default_args} {target} -oJ /output/masscan.json"


class AmassTool(KaliTool):
    """amass — Subdomain enumeration."""
    name = "amass"
    category = "recon"
    description = "In-depth subdomain enumeration and network mapping"
    risk_level = "low"
    sandbox_required = True
    install_cmd = "go install -v github.com/owasp-amass/amass/v4/...@master"
    parse_output = True

    def _build_command(self, target: str, args: str) -> str:
        return f"amass enum -d {target} -o /output/subdomains.txt"

    def _parse(self, output: str) -> dict:
        subdomains = [line.strip() for line in output.split("\n") if line.strip()]
        return {"subdomains": subdomains, "count": len(subdomains)}


class SubfinderTool(KaliTool):
    """subfinder — Fast subdomain discovery."""
    name = "subfinder"
    category = "recon"
    description = "Fast passive subdomain enumeration"
    risk_level = "low"
    sandbox_required = True
    install_cmd = "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    parse_output = True

    def _build_command(self, target: str, args: str) -> str:
        return f"subfinder -d {target} -o /output/subfinder_results.txt"

    def _parse(self, output: str) -> dict:
        subdomains = [line.strip() for line in output.split("\n") if line.strip()]
        return {"subdomains": subdomains, "count": len(subdomains)}


class HttpxTool(KaliTool):
    """httpx — HTTP toolkit for multiple hosts."""
    name = "httpx"
    category = "recon"
    description = "HTTP toolkit — status codes, titles, tech detection"
    risk_level = "low"
    sandbox_required = True
    install_cmd = "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    parse_output = True

    def _build_command(self, target: str, args: str) -> str:
        return f"httpx -u {target} -status-code -title -tech-detect -o /output/httpx_results.txt"

    def _parse(self, output: str) -> dict:
        results = []
        for line in output.split("\n"):
            if line.strip():
                results.append(line.strip())
        return {"endpoints": results, "count": len(results)}


class DnsenumTool(KaliTool):
    """dnsenum — DNS enumeration."""
    name = "dnsenum"
    category = "recon"
    description = "DNS enumeration and zone transfer testing"
    risk_level = "low"
    sandbox_required = True
    install_cmd = "sudo apt-get install -y dnsenum"


class FierceTool(KaliTool):
    """fierce — DNS reconnaissance."""
    name = "fierce"
    category = "recon"
    description = "DNS reconnaissance and zone transfer testing"
    risk_level = "low"
    sandbox_required = True
    install_cmd = "sudo apt-get install -y fierce"


# ═══════════════════════════════════════════════════════════════
# WEB HACKING TOOLS
# ═══════════════════════════════════════════════════════════════

class SqlmapTool(KaliTool):
    """sqlmap — SQL injection testing."""
    name = "sqlmap"
    category = "web"
    description = "Automatic SQL injection and database takeover"
    risk_level = "high"
    sandbox_required = True
    install_cmd = "sudo apt-get install -y sqlmap"

    def _build_command(self, target: str, args: str) -> str:
        return f"sqlmap -u {target} --batch --output-dir=/output/sqlmap {args}"


class NiktoTool(KaliTool):
    """nikto — Web server scanner."""
    name = "nikto"
    category = "web"
    description = "Web server vulnerability scanner"
    risk_level = "medium"
    sandbox_required = True
    install_cmd = "sudo apt-get install -y nikto"

    def _build_command(self, target: str, args: str) -> str:
        return f"nikto -h {target} -o /output/nikto_results.html {args}"


class GobusterTool(KaliTool):
    """gobuster — Directory/DNS brute forcer."""
    name = "gobuster"
    category = "web"
    description = "Directory and DNS brute forcing"
    risk_level = "medium"
    sandbox_required = True
    install_cmd = "sudo apt-get install -y gobuster"

    def _build_command(self, target: str, args: str) -> str:
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        return f"gobuster dir -u {target} -w {wordlist} -o /output/gobuster_results.txt {args}"


class FfufTool(KaliTool):
    """ffuf — Web fuzzer."""
    name = "ffuf"
    category = "web"
    description = "Fast web fuzzer"
    risk_level = "medium"
    sandbox_required = True
    install_cmd = "go install github.com/ffuf/ffuf/v2@latest"
    parse_output = True

    def _build_command(self, target: str, args: str) -> str:
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        return f"ffuf -u {target}/FUZZ -w {wordlist} -o /output/ffuf_results.json {args}"

    def _parse(self, output: str) -> dict:
        try:
            # ffuf JSON output
            with open("/output/ffuf_results.json") as f:
                data = json.load(f)
            return {"results": data.get("results", []), "count": len(data.get("results", []))}
        except Exception:
            return {"raw": output}


class WpscanTool(KaliTool):
    """wpscan — WordPress scanner."""
    name = "wpscan"
    category = "web"
    description = "WordPress vulnerability scanner"
    risk_level = "medium"
    sandbox_required = True
    install_cmd = "sudo apt-get install -y wpscan"


class XsserTool(KaliTool):
    """xsser — XSS vulnerability scanner."""
    name = "xsser"
    category = "web"
    description = "Automatic XSS vulnerability detection"
    risk_level = "high"
    sandbox_required = True
    install_cmd = "sudo apt-get install -y xsser"


# ═══════════════════════════════════════════════════════════════
# EXPLOITATION TOOLS
# ═══════════════════════════════════════════════════════════════

class MetasploitTool(KaliTool):
    """msfconsole — Metasploit Framework."""
    name = "msfconsole"
    category = "exploit"
    description = "Penetration testing framework"
    risk_level = "critical"
    sandbox_required = True
    install_cmd = "sudo apt-get install -y metasploit-framework"

    def _build_command(self, target: str, args: str) -> str:
        return f"msfconsole -q -x 'set RHOSTS {target}; {args}; exit'"


class SearchsploitTool(KaliTool):
    """searchsploit — Exploit database search."""
    name = "searchsploit"
    category = "exploit"
    description = "Search Exploit-DB for known exploits"
    risk_level = "low"
    sandbox_required = True
    install_cmd = "sudo apt-get install -y exploitdb"
    parse_output = True

    def _build_command(self, target: str, args: str) -> str:
        return f"searchsploit {args or target}"

    def _parse(self, output: str) -> dict:
        exploits = []
        for line in output.split("\n"):
            if "|" in line and not line.startswith("Exploit"):
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 2:
                    exploits.append({
                        "title": parts[0],
                        "path": parts[1] if len(parts) > 1 else ""
                    })
        return {"exploits": exploits, "count": len(exploits)}


# ═══════════════════════════════════════════════════════════════
# OSINT TOOLS
# ═══════════════════════════════════════════════════════════════

class TheHarvesterTool(KaliTool):
    """theHarvester — Email/subdomain OSINT."""
    name = "theHarvester"
    category = "osint"
    description = "Email, subdomain, and name OSINT gathering"
    risk_level = "low"
    sandbox_required = True
    install_cmd = "sudo apt-get install -y theharvester"
    parse_output = True

    def _build_command(self, target: str, args: str) -> str:
        return f"theHarvester -d {target} -b all -f /output/harvester_results {args}"

    def _parse(self, output: str) -> dict:
        emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', output)
        hosts = re.findall(r'[\w.-]+\.' + re.escape(target), output) if hasattr(self, 'target') else []
        return {"emails": list(set(emails)), "hosts": list(set(hosts))}


class SherlockTool(KaliTool):
    """sherlock — Social media username search."""
    name = "sherlock"
    category = "osint"
    description = "Search for usernames across social networks"
    risk_level = "low"
    sandbox_required = True
    install_cmd = "pip3 install sherlock-project"

    def _build_command(self, target: str, args: str) -> str:
        return f"sherlock {target} --folderoutput /output/sherlock {args}"


class ReconNgTool(KaliTool):
    """recon-ng — Reconnaissance framework."""
    name = "recon-ng"
    category = "osint"
    description = "Web reconnaissance framework"
    risk_level = "low"
    sandbox_required = True
    install_cmd = "sudo apt-get install -y recon-ng"


class MaltegoTool(KaliTool):
    """maltego — Link analysis and OSINT."""
    name = "maltego"
    category = "osint"
    description = "Visual link analysis and data mining"
    risk_level = "low"
    sandbox_required = True
    install_cmd = "Download from https://www.maltego.com"


class SpiderfootTool(KaliTool):
    """spiderfoot — Automated OSINT collection."""
    name = "spiderfoot"
    category = "osint"
    description = "Automated OSINT and threat intelligence"
    risk_level = "low"
    sandbox_required = True
    install_cmd = "pip3 install spiderfoot"

    def _build_command(self, target: str, args: str) -> str:
        return f"spiderfoot -s {target} -o /output/spiderfoot {args}"


# ═══════════════════════════════════════════════════════════════
# PASSWORD ATTACK TOOLS
# ═══════════════════════════════════════════════════════════════

class HashcatTool(KaliTool):
    """hashcat — Password hash cracker."""
    name = "hashcat"
    category = "password"
    description = "Advanced password recovery and hash cracking"
    risk_level = "high"
    sandbox_required = True
    install_cmd = "sudo apt-get install -y hashcat"


class JohnTool(KaliTool):
    """john — John the Ripper password cracker."""
    name = "john"
    category = "password"
    description = "Password hash cracker"
    risk_level = "high"
    sandbox_required = True
    install_cmd = "sudo apt-get install -y john"


class HydraTool(KaliTool):
    """hydra — Network login brute forcer."""
    name = "hydra"
    category = "password"
    description = "Network protocol brute force tool"
    risk_level = "high"
    sandbox_required = True
    install_cmd = "sudo apt-get install -y hydra"


# ═══════════════════════════════════════════════════════════════
# TOOL REGISTRY — All tools in one place
# ═══════════════════════════════════════════════════════════════

ALL_TOOLS = {
    # Recon
    "nmap": NmapTool,
    "masscan": MasscanTool,
    "amass": AmassTool,
    "subfinder": SubfinderTool,
    "httpx": HttpxTool,
    "dnsenum": DnsenumTool,
    "fierce": FierceTool,
    # Web
    "sqlmap": SqlmapTool,
    "nikto": NiktoTool,
    "gobuster": GobusterTool,
    "ffuf": FfufTool,
    "wpscan": WpscanTool,
    "xsser": XsserTool,
    # Exploit
    "msfconsole": MetasploitTool,
    "searchsploit": SearchsploitTool,
    # OSINT
    "theHarvester": TheHarvesterTool,
    "sherlock": SherlockTool,
    "recon-ng": ReconNgTool,
    "maltego": MaltegoTool,
    "spiderfoot": SpiderfootTool,
    # Password
    "hashcat": HashcatTool,
    "john": JohnTool,
    "hydra": HydraTool,
}


def get_tool(name: str) -> Optional[KaliTool]:
    """Get a tool instance by name."""
    tool_class = ALL_TOOLS.get(name)
    return tool_class() if tool_class else None


def list_tools(category: str = None) -> List[dict]:
    """List all available tools, optionally filtered by category."""
    tools = []
    for name, tool_class in ALL_TOOLS.items():
        tool = tool_class()
        if category and tool.category != category:
            continue
        tools.append(tool.to_dict())
    return tools


def check_tools() -> dict:
    """Check which tools are available on the current system."""
    available = {}
    missing = {}
    for name, tool_class in ALL_TOOLS.items():
        tool = tool_class()
        if tool.is_available():
            available[name] = tool.description
        else:
            missing[name] = tool.description
    return {"available": available, "missing": missing}


def get_install_commands(missing_tools: list = None) -> str:
    """Generate installation commands for missing tools."""
    if missing_tools is None:
        missing_tools = [name for name, cls in ALL_TOOLS.items() if not cls().is_available()]

    apt_tools = []
    go_tools = []
    pip_tools = []
    manual_tools = []

    for name in missing_tools:
        tool = get_tool(name)
        if not tool:
            continue
        cmd = tool.install_cmd
        if cmd.startswith("sudo apt-get"):
            apt_tools.append(name)
        elif cmd.startswith("go install"):
            go_tools.append(name)
        elif cmd.startswith("pip3"):
            pip_tools.append(name)
        else:
            manual_tools.append((name, cmd))

    output = []
    if apt_tools:
        output.append(f"# Install via apt:\nsudo apt-get install -y {' '.join(apt_tools)}")
    if go_tools:
        output.append(f"# Install via go:\n" + "\n".join([get_tool(t).install_cmd for t in go_tools]))
    if pip_tools:
        output.append(f"# Install via pip:\n" + "\n".join([get_tool(t).install_cmd for t in pip_tools]))
    if manual_tools:
        output.append("# Manual installation:\n" + "\n".join([f"# {n}: {c}" for n, c in manual_tools]))

    return "\n\n".join(output)
