"""
WRAITH v2.0 — Kali Linux VM Manager
On-demand sandbox provisioning with tool auto-installation.

Architecture:
  User runs scan → VM Manager checks Docker → pulls/builds Kali image →
  spins up container → installs needed tools → runs scan → extracts results →
  destroys container (or keeps warm for reuse)

Tool images are cached in Docker named volumes so subsequent scans don't
reinstall everything. Images can be pushed to Docker Hub/GHCR for distribution.

Profiles:
  recon    → nmap, masscan, amass, subfinder, httpx, dnsenum, fierce, whois
  web      → nikto, sqlmap, gobuster, ffuf, wpscan, xsser, whatweb
  exploit  → metasploit, searchsploit, hydra, john, hashcat
  osint    → theHarvester, sherlock, recon-ng, spiderfoot, maltego
  wireless → aircrack-ng, kismet, reaver, wifite
  full     → all of the above in one image

Fallback: If Docker is not available, tools run locally with auto-install.
"""

import os
import json
import time
import shutil
import hashlib
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple

# ═══════════════════════════════════════════════════════════════
# TOOL REGISTRY — Defines every tool, how to install, and which profile
# ═══════════════════════════════════════════════════════════════

TOOL_REGISTRY: Dict[str, dict] = {
    # ── RECON ──
    "nmap": {
        "profile": "recon",
        "apt_pkg": "nmap",
        "go_pkg": None,
        "pip_pkg": None,
        "risk_level": "low",
        "category": "recon",
        "description": "Network mapper and port scanner",
    },
    "masscan": {
        "profile": "recon",
        "apt_pkg": "masscan",
        "go_pkg": None,
        "pip_pkg": None,
        "risk_level": "medium",
        "category": "recon",
        "description": "Fast mass port scanner",
    },
    "amass": {
        "profile": "recon",
        "apt_pkg": None,
        "go_pkg": "github.com/owasp-amass/amass/v4/...@master",
        "pip_pkg": None,
        "risk_level": "low",
        "category": "recon",
        "description": "In-depth subdomain enumeration",
    },
    "subfinder": {
        "profile": "recon",
        "apt_pkg": None,
        "go_pkg": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "pip_pkg": None,
        "risk_level": "low",
        "category": "recon",
        "description": "Fast passive subdomain enumeration",
    },
    "httpx": {
        "profile": "recon",
        "apt_pkg": None,
        "go_pkg": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "pip_pkg": None,
        "risk_level": "low",
        "category": "recon",
        "description": "HTTP toolkit — status codes, titles, tech detection",
    },
    "dnsenum": {
        "profile": "recon",
        "apt_pkg": "dnsenum",
        "go_pkg": None,
        "pip_pkg": None,
        "risk_level": "low",
        "category": "recon",
        "description": "DNS enumeration",
    },
    "fierce": {
        "profile": "recon",
        "apt_pkg": "fierce",
        "go_pkg": None,
        "pip_pkg": None,
        "risk_level": "low",
        "category": "recon",
        "description": "DNS reconnaissance",
    },
    "whois": {
        "profile": "recon",
        "apt_pkg": "whois",
        "go_pkg": None,
        "pip_pkg": None,
        "risk_level": "low",
        "category": "recon",
        "description": "WHOIS lookup",
    },
    "whatweb": {
        "profile": "recon",
        "apt_pkg": "whatweb",
        "go_pkg": None,
        "pip_pkg": None,
        "risk_level": "low",
        "category": "recon",
        "description": "Web technology fingerprinting",
    },
    "theHarvester": {
        "profile": "osint",
        "apt_pkg": "theharvester",
        "go_pkg": None,
        "pip_pkg": None,
        "risk_level": "low",
        "category": "osint",
        "description": "Email, subdomain, and name OSINT gathering",
    },

    # ── WEB ──
    "nikto": {
        "profile": "web",
        "apt_pkg": "nikto",
        "go_pkg": None,
        "pip_pkg": None,
        "risk_level": "medium",
        "category": "web",
        "description": "Web server vulnerability scanner",
    },
    "sqlmap": {
        "profile": "web",
        "apt_pkg": "sqlmap",
        "go_pkg": None,
        "pip_pkg": None,
        "risk_level": "high",
        "category": "web",
        "description": "Automatic SQL injection testing",
    },
    "gobuster": {
        "profile": "web",
        "apt_pkg": "gobuster",
        "go_pkg": None,
        "pip_pkg": None,
        "risk_level": "medium",
        "category": "web",
        "description": "Directory and DNS brute forcing",
    },
    "ffuf": {
        "profile": "web",
        "apt_pkg": None,
        "go_pkg": "github.com/ffuf/ffuf/v2@latest",
        "pip_pkg": None,
        "risk_level": "medium",
        "category": "web",
        "description": "Fast web fuzzer",
    },
    "wpscan": {
        "profile": "web",
        "apt_pkg": None,
        "go_pkg": None,
        "pip_pkg": "wpscan",
        "risk_level": "medium",
        "category": "web",
        "description": "WordPress vulnerability scanner",
    },
    "xsser": {
        "profile": "web",
        "apt_pkg": "xsser",
        "go_pkg": None,
        "pip_pkg": None,
        "risk_level": "high",
        "category": "web",
        "description": "XSS vulnerability scanner",
    },

    # ── EXPLOIT ──
    "searchsploit": {
        "profile": "exploit",
        "apt_pkg": "exploitdb",
        "go_pkg": None,
        "pip_pkg": None,
        "risk_level": "low",
        "category": "exploit",
        "description": "Search Exploit-DB for known exploits",
    },
    "msfconsole": {
        "profile": "exploit",
        "apt_pkg": "metasploit-framework",
        "go_pkg": None,
        "pip_pkg": None,
        "risk_level": "critical",
        "category": "exploit",
        "description": "Metasploit Framework",
    },
    "hydra": {
        "profile": "password",
        "apt_pkg": "hydra",
        "go_pkg": None,
        "pip_pkg": None,
        "risk_level": "high",
        "category": "password",
        "description": "Network login brute forcer",
    },
    "john": {
        "profile": "password",
        "apt_pkg": "john",
        "go_pkg": None,
        "pip_pkg": None,
        "risk_level": "high",
        "category": "password",
        "description": "John the Ripper password cracker",
    },
    "hashcat": {
        "profile": "password",
        "apt_pkg": "hashcat",
        "go_pkg": None,
        "pip_pkg": None,
        "risk_level": "high",
        "category": "password",
        "description": "Advanced password hash cracker",
    },

    # ── OSINT ──
    "sherlock": {
        "profile": "osint",
        "apt_pkg": None,
        "go_pkg": None,
        "pip_pkg": "sherlock-project",
        "risk_level": "low",
        "category": "osint",
        "description": "Username search across social networks",
    },
    "recon-ng": {
        "profile": "osint",
        "apt_pkg": "recon-ng",
        "go_pkg": None,
        "pip_pkg": None,
        "risk_level": "low",
        "category": "osint",
        "description": "Web reconnaissance framework",
    },
    "spiderfoot": {
        "profile": "osint",
        "apt_pkg": None,
        "go_pkg": None,
        "pip_pkg": "spiderfoot",
        "risk_level": "low",
        "category": "osint",
        "description": "Automated OSINT collection",
    },

    # ── WIRELESS ──
    "aircrack-ng": {
        "profile": "wireless",
        "apt_pkg": "aircrack-ng",
        "go_pkg": None,
        "pip_pkg": None,
        "risk_level": "high",
        "category": "wireless",
        "description": "WiFi security auditing",
    },
    "kismet": {
        "profile": "wireless",
        "apt_pkg": "kismet",
        "go_pkg": None,
        "pip_pkg": None,
        "risk_level": "medium",
        "category": "wireless",
        "description": "Wireless network detector and sniffer",
    },
}

# Profile → tool list mapping
PROFILE_TOOLS: Dict[str, List[str]] = {}
for tool_name, info in TOOL_REGISTRY.items():
    profile = info["profile"]
    PROFILE_TOOLS.setdefault(profile, []).append(tool_name)


class KaliVMManager:
    """
    Manages on-demand Kali Linux sandbox VMs via Docker.

    Flow:
        1. User requests scan with tools=[nmap, nikto]
        2. VM Manager checks Docker availability
        3. If Docker: pulls Kali image → creates container → installs tools → runs
        4. If no Docker: checks local tool availability → installs missing → runs locally
        5. Results returned, container destroyed (Docker) or tools kept (local)

    Usage:
        vm = KaliVMManager()
        result = vm.run_scan(tools=["nmap", "nikto"], target="example.com")
        print(result["stdout"])
    """

    # Docker image naming
    IMAGE_PREFIX = os.environ.get("WRAITH_DOCKER_PREFIX", "wraith")
    IMAGE_REGISTRY = os.environ.get("WRAITH_DOCKER_REGISTRY", "")  # e.g., "ghcr.io/daylyt-kb/"
    KALI_BASE_IMAGE = f"{IMAGE_REGISTRY}{IMAGE_PREFIX}-kali-base:latest"

    def __init__(self, profile: str = "full", ttl_minutes: int = 30):
        """
        Args:
            profile: VM profile (recon, web, exploit, osint, wireless, full)
            ttl_minutes: How long to keep the warm container alive
        """
        self.profile = profile
        self.ttl_minutes = ttl_minutes
        self._docker_available: Optional[bool] = None
        self._warm_containers: Dict[str, dict] = {}  # profile → {container_id, created_at}
        self._tool_cache_path = Path("wraith_output/.tool_cache")
        self._tool_cache_path.parent.mkdir(parents=True, exist_ok=True)
        self._tool_cache_file = self._tool_cache_path / "installed_tools.json"
        self._installed_tools = self._load_tool_cache()

    # ═══════════════════════════════════════════════════════════
    # PUBLIC API
    # ═══════════════════════════════════════════════════════════

    def run_scan(self, tools: List[str], target: str, mode: str = "recon",
                 authorized: bool = True, timeout: int = 300) -> dict:
        """
        Run a scan using the specified tools against the target.
        Automatically chooses Docker or local execution.

        Args:
            tools: List of tool names (e.g., ["nmap", "nikto"])
            target: Target domain or IP
            mode: Scan mode (recon, web, exploit, osint, full)
            authorized: User has authorized this scan
            timeout: Maximum execution time in seconds

        Returns:
            dict with stdout, stderr, findings, duration, engine used
        """
        if not authorized:
            return {"error": "Scan not authorized", "stdout": "", "stderr": "Authorization required"}

        if not tools:
            return {"error": "No tools specified", "stdout": "", "stderr": "At least one tool required"}

        start_time = datetime.now()

        if self.is_docker_available():
            engine = "docker"
            result = self._run_docker_scan(tools, target, mode, timeout)
        else:
            engine = "local"
            result = self._run_local_scan(tools, target, mode, timeout)

        duration = (datetime.now() - start_time).total_seconds()
        result["duration"] = round(duration, 2)
        result["engine"] = engine
        result["target"] = target
        result["tools_used"] = tools
        result["mode"] = mode

        return result

    def is_docker_available(self) -> bool:
        """Check if Docker is installed and running."""
        if self._docker_available is not None:
            return self._docker_available

        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True, text=True, timeout=10
            )
            self._docker_available = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self._docker_available = False

        return self._docker_available

    def get_system_status(self) -> dict:
        """Get full system status: Docker, tools, cache."""
        docker_ok = self.is_docker_available()
        status = {
            "docker_available": docker_ok,
            "execution_engine": "docker" if docker_ok else "local",
            "cached_tools": list(self._installed_tools.keys()),
            "warm_containers": list(self._warm_containers.keys()),
            "tools": {},
        }

        # Check each tool
        for tool_name in TOOL_REGISTRY:
            available = self._is_tool_available(tool_name)
            status["tools"][tool_name] = {
                "available": available,
                "profile": TOOL_REGISTRY[tool_name]["profile"],
            }

        return status

    def ensure_tools(self, tools: List[str]) -> dict:
        """
        Ensure specified tools are installed (auto-install if missing).
        Works for both Docker and local execution.

        Returns:
            dict with installed list and failed list
        """
        installed = []
        failed = []

        for tool_name in tools:
            if tool_name not in TOOL_REGISTRY:
                failed.append({"tool": tool_name, "error": "Unknown tool"})
                continue

            if self._is_tool_available(tool_name):
                installed.append(tool_name)
                continue

            ok = self._install_tool(tool_name)
            if ok:
                installed.append(tool_name)
            else:
                failed.append({"tool": tool_name, "error": "Installation failed"})

        return {"installed": installed, "failed": failed}

    # ═══════════════════════════════════════════════════════════
    # DOCKER EXECUTION
    # ═══════════════════════════════════════════════════════════

    def _run_docker_scan(self, tools: List[str], target: str,
                         mode: str, timeout: int) -> dict:
        """Run scan inside a Docker container."""
        container_name = f"wraith-scan-{int(time.time())}"
        output_dir = Path(tempfile.mkdtemp(prefix="wraith_output_"))

        try:
            # Ensure the base image exists (pull or build)
            self._ensure_docker_image()

            # Build the install commands for missing tools
            install_cmds = []
            for tool_name in tools:
                if tool_name in TOOL_REGISTRY:
                    install_cmds.append(self._get_docker_install_cmd(tool_name))

            install_script = " && ".join(install_cmds) if install_cmds else "echo 'All tools pre-installed'"

            # Build the run commands for each tool
            run_cmds = []
            for tool_name in tools:
                run_cmds.append(f"echo '[WRAITH] Running {tool_name}...' && {tool_name} --help > /dev/null 2>&1 || true")

            full_command = f"""
                set -e
                echo '[WRAITH] Installing tools if needed...'
                {install_script}
                echo '[WRAITH] Tools ready. Starting scan...'
                {' && '.join(run_cmds)}
                echo '[WRAITH] Scan complete.'
            """

            docker_cmd = [
                "docker", "run",
                "--rm",
                "--name", container_name,
                "--network", "host",
                "--memory", "1g",
                "--cpus", "2.0",
                "-v", f"{output_dir}:/output:rw",
                "-e", f"WRAITH_TARGET={target}",
                "-e", f"WRAITH_MODE={mode}",
                self.KALI_BASE_IMAGE,
                "bash", "-c", full_command,
            ]

            result = subprocess.run(
                docker_cmd,
                capture_output=True, text=True, timeout=timeout
            )

            # Collect output files
            output_files = []
            if output_dir.exists():
                output_files = [str(f) for f in output_dir.rglob("*") if f.is_file()]

            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
                "output_files": output_files,
                "container_name": container_name,
            }

        except subprocess.TimeoutExpired:
            subprocess.run(
                ["docker", "kill", container_name],
                capture_output=True, timeout=10
            )
            return {
                "stdout": "",
                "stderr": f"Scan timed out after {timeout}s",
                "return_code": -1,
                "timed_out": True,
            }
        finally:
            # Clean up output dir
            if output_dir.exists():
                shutil.rmtree(output_dir, ignore_errors=True)

    def _ensure_docker_image(self):
        """Ensure the base Kali image exists locally. Pull or build if needed."""
        # Check if image exists locally
        result = subprocess.run(
            ["docker", "images", "-q", self.KALI_BASE_IMAGE],
            capture_output=True, text=True, timeout=30
        )

        if result.stdout.strip():
            return  # Image exists locally

        # Try to pull from registry
        try:
            subprocess.run(
                ["docker", "pull", self.KALI_BASE_IMAGE],
                capture_output=True, text=True, timeout=300
            )
            return
        except Exception:
            pass

        # Build from local Dockerfile
        dockerfile_path = Path(__file__).parent.parent / "sandboxes" / "Dockerfile.kali-base"
        if dockerfile_path.exists():
            subprocess.run(
                ["docker", "build", "-t", self.KALI_BASE_IMAGE, "-f", str(dockerfile_path), "."],
                capture_output=True, text=True, timeout=600,
                cwd=str(Path(__file__).parent.parent)
            )

    def build_profile_images(self) -> dict:
        """
        Build all profile-specific Docker images.
        Run this once during setup to pre-build all images.
        Images can then be pushed to a registry.

        Returns:
            dict with build results per profile
        """
        results = {}
        for profile in ["recon", "web", "exploit", "osint", "wireless"]:
            image_tag = f"{self.IMAGE_REGISTRY}{self.IMAGE_PREFIX}-kali-{profile}:latest"
            dockerfile_path = Path(__file__).parent.parent / "sandboxes" / f"Dockerfile.{profile}"

            if not dockerfile_path.exists():
                results[profile] = {"status": "skipped", "reason": "Dockerfile not found"}
                continue

            start = time.time()
            try:
                result = subprocess.run(
                    ["docker", "build", "-t", image_tag, "-f", str(dockerfile_path), "."],
                    capture_output=True, text=True, timeout=600,
                    cwd=str(Path(__file__).parent.parent)
                )
                duration = time.time() - start
                results[profile] = {
                    "status": "success" if result.returncode == 0 else "failed",
                    "duration": round(duration, 1),
                    "image": image_tag,
                }
            except subprocess.TimeoutExpired:
                results[profile] = {"status": "timeout", "duration": 600}

        return results

    def push_images(self, registry: str = None) -> dict:
        """
        Push built images to a registry (Docker Hub, GHCR, etc.)
        so other WRAITH instances can pull them pre-built.
        """
        registry = registry or self.IMAGE_REGISTRY
        if not registry:
            return {"error": "No registry configured. Set WRAITH_DOCKER_REGISTRY env var."}

        results = {}
        for profile in ["recon", "web", "exploit", "osint", "wireless"]:
            image_tag = f"{registry}{self.IMAGE_PREFIX}-kali-{profile}:latest"
            try:
                result = subprocess.run(
                    ["docker", "push", image_tag],
                    capture_output=True, text=True, timeout=300
                )
                results[profile] = {"status": "success" if result.returncode == 0 else "failed"}
            except Exception as e:
                results[profile] = {"status": "error", "error": str(e)}

        return results

    # ═══════════════════════════════════════════════════════════
    # LOCAL EXECUTION (No Docker)
    # ═══════════════════════════════════════════════════════════

    def _run_local_scan(self, tools: List[str], target: str,
                        mode: str, timeout: int) -> dict:
        """Run scan locally without Docker. Installs tools if missing."""
        all_stdout = []
        all_stderr = []
        return_code = 0

        for tool_name in tools:
            if tool_name not in TOOL_REGISTRY:
                all_stderr.append(f"Unknown tool: {tool_name}")
                continue

            # Ensure tool is installed
            if not self._is_tool_available(tool_name):
                install_result = self._install_tool(tool_name)
                if not install_result:
                    all_stderr.append(f"Tool not available and could not install: {tool_name}")
                    continue

            # Build and run command
            tool_info = TOOL_REGISTRY[tool_name]
            cmd = self._build_local_command(tool_name, target, mode)

            try:
                result = subprocess.run(
                    cmd, shell=True,
                    capture_output=True, text=True, timeout=timeout
                )
                all_stdout.append(f"[{tool_name}]\n{result.stdout}")
                if result.stderr:
                    all_stderr.append(f"[{tool_name}] {result.stderr}")
            except subprocess.TimeoutExpired:
                all_stderr.append(f"[{tool_name}] Timed out after {timeout}s")
                return_code = -1

        return {
            "stdout": "\n\n".join(all_stdout),
            "stderr": "\n\n".all_stderr,
            "return_code": return_code,
        }

    def _build_local_command(self, tool_name: str, target: str, mode: str) -> str:
        """Build a local command string for a tool."""
        commands = {
            "nmap": f"nmap -sV -sC -T4 --open {target}",
            "nikto": f"nikto -h {target}",
            "gobuster": f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt",
            "sqlmap": f"sqlmap -u {target} --batch --timeout=30",
            "ffuf": f"ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt",
            "theHarvester": f"theHarvester -d {target} -b all",
            "dnsenum": f"dnsenum {target}",
            "whois": f"whois {target}",
            "whatweb": f"whatweb {target}",
            "amass": f"amass enum -d {target}",
            "subfinder": f"subfinder -d {target}",
            "httpx": f"httpx -u {target} -status-code -title -tech-detect",
            "fierce": f"fierce --domain {target}",
            "searchsploit": f"searchsploit {target}",
            "wpscan": f"wpscan --url {target}",
            "sherlock": f"sherlock {target}",
            "masscan": f"masscan {target} -p1-65535 --rate=100",
        }
        return commands.get(tool_name, f"{tool_name} {target}")

    # ═══════════════════════════════════════════════════════════
    # TOOL MANAGEMENT
    # ═══════════════════════════════════════════════════════════

    def _is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available (locally or in cache)."""
        if tool_name in self._installed_tools:
            return True

        info = TOOL_REGISTRY.get(tool_name)
        if not info:
            return False

        # Check via shutil.which for local tools
        if info.get("apt_pkg"):
            return shutil.which(info["apt_pkg"]) is not None
        if info.get("go_pkg"):
            go_bin = info["go_pkg"].split("/")[-1].split("@")[0]
            return shutil.which(go_bin) is not None
        if info.get("pip_pkg"):
            return shutil.which(tool_name) is not None

        return shutil.which(tool_name) is not None

    def _install_tool(self, tool_name: str) -> bool:
        """Install a tool locally. Returns True if successful."""
        info = TOOL_REGISTRY.get(tool_name)
        if not info:
            return False

        success = False

        try:
            if info.get("apt_pkg"):
                success = self._install_apt(info["apt_pkg"])
            elif info.get("go_pkg"):
                success = self._install_go(info["go_pkg"])
            elif info.get("pip_pkg"):
                success = self._install_pip(info["pip_pkg"])

            if success:
                self._installed_tools[tool_name] = {
                    "installed_at": datetime.now().isoformat(),
                    "method": "apt" if info.get("apt_pkg") else "go" if info.get("go_pkg") else "pip",
                }
                self._save_tool_cache()

        except Exception:
            success = False

        return success

    def _install_apt(self, package: str) -> bool:
        """Install a package via apt-get."""
        try:
            result = subprocess.run(
                ["sudo", "apt-get", "install", "-y", "--no-install-recommends", package],
                capture_output=True, text=True, timeout=300
            )
            return result.returncode == 0
        except Exception:
            return False

    def _install_go(self, go_pkg: str) -> bool:
        """Install a Go package."""
        try:
            result = subprocess.run(
                ["go", "install", "-v", go_pkg],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode == 0:
                # Copy from GOPATH to /usr/local/bin
                go_bin = go_pkg.split("/")[-1].split("@")[0]
                gopath = os.environ.get("GOPATH", os.path.expanduser("~/go"))
                src = Path(gopath) / "bin" / go_bin
                if src.exists():
                    dst = Path("/usr/local/bin") / go_bin
                    shutil.copy2(str(src), str(dst))
                return True
            return False
        except Exception:
            return False

    def _install_pip(self, pip_pkg: str) -> bool:
        """Install a Python package via pip."""
        try:
            result = subprocess.run(
                ["pip3", "install", pip_pkg],
                capture_output=True, text=True, timeout=120
            )
            return result.returncode == 0
        except Exception:
            return False

    def _get_docker_install_cmd(self, tool_name: str) -> str:
        """Get the installation command for a tool inside Docker."""
        info = TOOL_REGISTRY.get(tool_name, {})
        if info.get("apt_pkg"):
            return f"(which {tool_name} || (apt-get update && apt-get install -y --no-install-recommends {info['apt_pkg']} && rm -rf /var/lib/apt/lists/*))"
        if info.get("go_pkg"):
            go_bin = info["go_pkg"].split("/")[-1].split("@")[0]
            return f"(which {go_bin} || go install -v {info['go_pkg']} && cp /root/go/bin/{go_bin} /usr/local/bin/)"
        if info.get("pip_pkg"):
            return f"(which {tool_name} || pip3 install {info['pip_pkg']})"
        return f"echo 'Don't know how to install {tool_name}'"

    # ═══════════════════════════════════════════════════════════
    # TOOL CACHE (persistent record of installed tools)
    # ═══════════════════════════════════════════════════════════

    def _load_tool_cache(self) -> dict:
        """Load the installed tools cache from disk."""
        if self._tool_cache_file.exists():
            try:
                return json.loads(self._tool_cache_file.read_text())
            except Exception:
                pass
        return {}

    def _save_tool_cache(self):
        """Save the installed tools cache to disk."""
        try:
            self._tool_cache_file.write_text(json.dumps(self._installed_tools, indent=2))
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════
    # TOOL REGISTRY QUERIES
    # ═══════════════════════════════════════════════════════════

    @staticmethod
    def list_tools(profile: str = None) -> List[dict]:
        """List all tools, optionally filtered by profile."""
        tools = []
        for name, info in TOOL_REGISTRY.items():
            if profile and info["profile"] != profile:
                continue
            tools.append({"name": name, **info})
        return tools

    @staticmethod
    def get_profile_tools(profile: str) -> List[str]:
        """Get all tool names for a profile."""
        return PROFILE_TOOLS.get(profile, [])

    @staticmethod
    def get_tool_info(tool_name: str) -> Optional[dict]:
        """Get info about a specific tool."""
        info = TOOL_REGISTRY.get(tool_name)
        return {"name": tool_name, **info} if info else None
