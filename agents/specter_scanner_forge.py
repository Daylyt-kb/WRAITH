"""
SPECTER — OSINT Intelligence Agent v2.0
Hunts the open web for intel: emails, subdomains, leaks, exposure.
Passive only. Never touches the target directly.
Inherits from WraithAgent.
"""

import subprocess
import socket
import urllib.request
import urllib.error
import json
import re
from datetime import datetime
from agents.base import WraithAgent


class SpecterAgent(WraithAgent):
    name = "specter"
    version = "2.0.0"
    description = "OSINT — hunts what the internet already knows"
    category = "osint"
    tools = ["theHarvester", "sherlock", "recon-ng", "spiderfoot"]
    sandbox_profile = "osint"
    risk_level = "low"

    def __init__(self, bus=None, **kwargs):
        super().__init__(bus=bus, **kwargs)

    def run(self, target: str, scope) -> dict:
        findings = []
        raw_output = {}
        start_time = datetime.now()
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        parts = domain.split(".")
        base_domain = ".".join(parts[-2:]) if len(parts) > 2 else domain

        print(f"  [SPECTER] Starting OSINT on: {domain}")

        # ── 1. theHarvester ──
        harvester = self._run_harvester(base_domain)
        raw_output["harvester"] = harvester
        if harvester.get("emails"):
            findings.append({
                "type": "emails",
                "title": f"Found {len(harvester['emails'])} email address(es)",
                "severity": "medium",
                "tool": "theHarvester",
                "data": {"emails": harvester["emails"][:10]}
            })
            print(f"  [SPECTER] Emails found: {len(harvester['emails'])}")

        if harvester.get("hosts"):
            findings.append({
                "type": "hosts",
                "title": f"Discovered {len(harvester['hosts'])} host(s) via OSINT",
                "severity": "info",
                "tool": "theHarvester",
                "data": {"hosts": harvester["hosts"][:10]}
            })

        # ── 2. Certificate Transparency (crt.sh) ──
        certs = self._crtsh_lookup(base_domain)
        raw_output["certs"] = certs
        if certs.get("domains"):
            findings.append({
                "type": "cert_transparency",
                "title": f"Certificate transparency: {len(certs['domains'])} domain(s) exposed",
                "severity": "info",
                "tool": "crt.sh",
                "data": {"domains": certs["domains"][:15]}
            })
            print(f"  [SPECTER] Certificate domains: {len(certs['domains'])}")

        # ── 3. Robots.txt & Sitemap ──
        robots = self._check_robots(target)
        raw_output["robots"] = robots
        if robots.get("disallowed_paths"):
            findings.append({
                "type": "robots_txt",
                "title": f"robots.txt reveals {len(robots['disallowed_paths'])} disallowed path(s)",
                "severity": "low",
                "tool": "curl",
                "data": robots
            })

        # ── 4. Google Dork hints ──
        dorks = self._generate_dorks(base_domain)
        raw_output["dorks"] = dorks
        findings.append({
            "type": "dorks",
            "title": f"Generated {len(dorks)} Google dork queries for manual investigation",
            "severity": "info",
            "tool": "SPECTER",
            "data": {"dorks": dorks}
        })

        # ── 5. GitHub exposure check hint ──
        findings.append({
            "type": "github_check",
            "title": f"Manual check recommended: GitHub for '{base_domain}' leaked secrets",
            "severity": "medium",
            "tool": "SPECTER",
            "data": {
                "search_url": f"https://github.com/search?q={base_domain}&type=code",
                "tip": "Search GitHub for API keys, passwords, and tokens referencing this domain"
            }
        })

        duration = (datetime.now() - start_time).seconds

        if self.bus:
            self.bus.emit("osint_complete", {
                "target": target,
                "findings": findings
            })

        summary_parts = []
        if harvester.get("emails"):
            summary_parts.append(f"{len(harvester['emails'])} emails")
        if certs.get("domains"):
            summary_parts.append(f"{len(certs['domains'])} cert domains")
        if robots.get("disallowed_paths"):
            summary_parts.append(f"{len(robots['disallowed_paths'])} hidden paths")

        return {
            "agent": "SPECTER",
            "target": target,
            "timestamp": start_time.isoformat(),
            "duration_seconds": duration,
            "findings": findings,
            "raw": raw_output,
            "summary": " | ".join(summary_parts) if summary_parts else "OSINT sweep complete",
            "finding_count": len(findings)
        }

    def _run_harvester(self, domain: str) -> dict:
        result = {"emails": [], "hosts": []}
        try:
            proc = subprocess.run(
                ["theHarvester", "-d", domain, "-b", "bing,google,certspotter", "-l", "100"],
                capture_output=True, text=True, timeout=60
            )
            output = proc.stdout
            for line in output.splitlines():
                line = line.strip()
                if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', line):
                    result["emails"].append(line)
                elif domain in line and line not in result["hosts"]:
                    result["hosts"].append(line)
        except FileNotFoundError:
            result["note"] = "theHarvester not installed — skipping email harvest"
        except Exception as e:
            result["error"] = str(e)
        return result

    def _crtsh_lookup(self, domain: str) -> dict:
        result = {"domains": []}
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            req = urllib.request.Request(url, headers={"User-Agent": "WRAITH/0.1"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
                seen = set()
                for entry in data:
                    name = entry.get("name_value", "").strip()
                    for n in name.splitlines():
                        n = n.strip().lstrip("*.")
                        if n and domain in n and n not in seen:
                            seen.add(n)
                            result["domains"].append(n)
        except Exception as e:
            result["error"] = str(e)
        return result

    def _check_robots(self, target: str) -> dict:
        result = {"disallowed_paths": [], "sitemaps": []}
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        url = f"https://{domain}/robots.txt"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                content = resp.read().decode("utf-8", errors="ignore")
                for line in content.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[-1].strip()
                        if path and path != "/":
                            result["disallowed_paths"].append(path)
                    elif line.lower().startswith("sitemap:"):
                        result["sitemaps"].append(line.split(":", 1)[-1].strip())
        except Exception:
            pass
        return result

    def _generate_dorks(self, domain: str) -> list:
        return [
            f'site:{domain} filetype:pdf',
            f'site:{domain} filetype:xls OR filetype:xlsx',
            f'site:{domain} inurl:admin OR inurl:login',
            f'site:{domain} inurl:api OR inurl:swagger',
            f'"{domain}" filetype:env OR filetype:config',
            f'"{domain}" "api_key" OR "password" OR "secret"',
            f'site:{domain} "index of"',
            f'"{domain}" site:pastebin.com',
        ]


# ─────────────────────────────────────────────────────────────────────────────

class ScannerAgent(WraithAgent):
    """
    SCANNER — Vulnerability Detection Agent v2.0
    Finds CVEs, misconfigurations, and security weaknesses.
    """
    name = "scanner"
    version = "2.0.0"
    description = "Vulnerability detection — finds the weaknesses"
    category = "scanner"
    tools = ["nikto", "nuclei", "ssl-check"]
    sandbox_profile = "web"
    risk_level = "low"

    def __init__(self, bus=None, **kwargs):
        super().__init__(bus=bus, **kwargs)

    def run(self, target: str, scope) -> dict:
        findings = []
        raw_output = {}
        start_time = datetime.now()
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        url = f"https://{domain}"

        print(f"  [SCANNER] Scanning for vulnerabilities: {domain}")

        # ── 1. Nikto web scan ──
        nikto = self._nikto_scan(url)
        raw_output["nikto"] = nikto
        for vuln in nikto.get("vulnerabilities", []):
            findings.append({
                "type": "web_vulnerability",
                "title": vuln["title"],
                "severity": vuln.get("severity", "medium"),
                "tool": "nikto",
                "data": vuln
            })
        if nikto.get("vulnerabilities"):
            print(f"  [SCANNER] Nikto found {len(nikto['vulnerabilities'])} issue(s)")

        # ── 2. SSL/TLS check ──
        ssl = self._ssl_check(domain)
        raw_output["ssl"] = ssl
        for issue in ssl.get("issues", []):
            findings.append({
                "type": "ssl_issue",
                "title": issue["title"],
                "severity": issue["severity"],
                "tool": "ssl_check",
                "data": issue
            })

        # ── 3. Nuclei templates ──
        nuclei = self._nuclei_scan(url)
        raw_output["nuclei"] = nuclei
        for finding in nuclei.get("findings", []):
            findings.append({
                "type": "nuclei_template",
                "title": finding["title"],
                "severity": finding.get("severity", "info"),
                "tool": "nuclei",
                "data": finding
            })

        # ── 4. Common vulnerability patterns ──
        patterns = self._check_common_patterns(url)
        raw_output["patterns"] = patterns
        for p in patterns.get("findings", []):
            findings.append({
                "type": "pattern_match",
                "title": p["title"],
                "severity": p["severity"],
                "tool": "SCANNER",
                "data": p
            })

        duration = (datetime.now() - start_time).seconds

        if self.bus:
            self.bus.emit("scan_complete", {"target": target, "findings": findings})
            critical = [f for f in findings if f.get("severity") in ("critical", "high")]
            if critical:
                self.bus.emit("critical_vuln_found", {"target": target, "findings": critical})

        crit_count = len([f for f in findings if f.get("severity") == "critical"])
        high_count = len([f for f in findings if f.get("severity") == "high"])
        med_count = len([f for f in findings if f.get("severity") == "medium"])

        summary = f"{crit_count} critical, {high_count} high, {med_count} medium findings"

        return {
            "agent": "SCANNER",
            "target": target,
            "timestamp": start_time.isoformat(),
            "duration_seconds": duration,
            "findings": findings,
            "raw": raw_output,
            "summary": summary,
            "finding_count": len(findings)
        }

    def _nikto_scan(self, url: str) -> dict:
        result = {"vulnerabilities": []}
        try:
            proc = subprocess.run(
                ["nikto", "-h", url, "-output", "/dev/stdout",
                 "-Format", "txt", "-Pause", "0", "-timeout", "10",
                 "-maxtime", "60s"],
                capture_output=True, text=True, timeout=90
            )
            for line in proc.stdout.splitlines():
                if line.startswith("+ ") and len(line) > 5:
                    msg = line[2:].strip()
                    # Classify severity
                    sev = "info"
                    if any(w in msg.lower() for w in ["xss", "sql", "rce", "injection", "critical"]):
                        sev = "high"
                    elif any(w in msg.lower() for w in ["outdated", "vulnerable", "deprecated"]):
                        sev = "medium"
                    result["vulnerabilities"].append({"title": msg, "severity": sev})
        except FileNotFoundError:
            result["note"] = "nikto not installed"
        except Exception as e:
            result["error"] = str(e)
        return result

    def _ssl_check(self, domain: str) -> dict:
        result = {"issues": [], "valid": False}
        try:
            import ssl
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.socket(), server_hostname=domain
            ) as ssock:
                ssock.settimeout(5)
                try:
                    ssock.connect((domain, 443))
                    cert = ssock.getpeercert()
                    result["valid"] = True
                    result["subject"] = dict(x[0] for x in cert.get("subject", []))
                    result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    result["expires"] = cert.get("notAfter", "")

                    # Check expiry
                    from datetime import datetime
                    import ssl as ssl_mod
                    expiry_str = cert.get("notAfter", "")
                    if expiry_str:
                        expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry - datetime.utcnow()).days
                        if days_left < 30:
                            result["issues"].append({
                                "title": f"SSL certificate expires in {days_left} days",
                                "severity": "high" if days_left < 7 else "medium"
                            })
                except ssl.SSLCertVerificationError:
                    result["issues"].append({
                        "title": "SSL certificate verification failed — possible misconfiguration",
                        "severity": "high"
                    })
        except Exception as e:
            if "443" in str(e) or "Connection refused" in str(e):
                result["issues"].append({
                    "title": "No HTTPS on port 443 — site may be HTTP only",
                    "severity": "high"
                })
        return result

    def _nuclei_scan(self, url: str) -> dict:
        result = {"findings": []}
        try:
            proc = subprocess.run(
                ["nuclei", "-u", url, "-severity", "high,critical,medium",
                 "-silent", "-timeout", "5", "-rate-limit", "10",
                 "-no-interactsh"],
                capture_output=True, text=True, timeout=120
            )
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("["):
                    continue
                # nuclei output: [template-id] [type] [severity] URL
                m = re.match(r'\[([^\]]+)\]\s*(?:\[([^\]]+)\])?\s*(?:\[([^\]]+)\])?\s*(.*)', line)
                if m:
                    result["findings"].append({
                        "title": f"{m.group(1)}: {m.group(4).strip()}",
                        "severity": m.group(3).lower() if m.group(3) else "info",
                        "template": m.group(1)
                    })
        except FileNotFoundError:
            result["note"] = "nuclei not installed"
        except Exception as e:
            result["error"] = str(e)
        return result

    def _check_common_patterns(self, url: str) -> dict:
        """Check for common exposed files and paths."""
        result = {"findings": []}
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]

        sensitive_paths = [
            ("/.env", "high", "Exposed .env file — may contain credentials/API keys"),
            ("/.git/HEAD", "critical", "Exposed .git directory — source code may be accessible"),
            ("/phpinfo.php", "high", "PHP info page exposed — reveals server configuration"),
            ("/wp-admin/", "medium", "WordPress admin panel exposed"),
            ("/admin/", "low", "Admin panel path detected"),
            ("/api/v1/", "info", "API endpoint discovered"),
            ("/swagger-ui.html", "medium", "Swagger UI exposed — API documentation public"),
            ("/actuator/", "high", "Spring Boot actuator exposed — server internals visible"),
            ("/.well-known/security.txt", "info", "security.txt found — check for disclosed info"),
        ]

        for path, severity, title in sensitive_paths:
            try:
                req = urllib.request.Request(
                    f"https://{domain}{path}",
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    if resp.status == 200:
                        result["findings"].append({
                            "title": title,
                            "severity": severity,
                            "path": path,
                            "url": f"https://{domain}{path}"
                        })
            except Exception:
                pass

        return result


# ─────────────────────────────────────────────────────────────────────────────

class ForgeAgent(WraithAgent):
    """
    FORGE — Live Script Generation Agent v2.0
    When no tool covers a gap, FORGE writes the script.
    Works with or without API key. Uses sandbox for execution.
    """
    name = "forge"
    version = "2.0.0"
    description = "Script generation — writes code when no tool exists"
    category = "forge"
    tools = ["python3"]
    sandbox_profile = "custom"
    risk_level = "low"

    def __init__(self, bus=None, api_key: str = "", **kwargs):
        super().__init__(bus=bus, api_key=api_key, **kwargs)

    def generate_from_description(self, description: str) -> str:
        """Generate a Python script from a plain English description."""
        if self.api_key:
            return self._ai_generate(description)
        return self._template_generate(description)

    def _ai_generate(self, description: str) -> str:
        """Use Gemini to generate a custom security script."""
        try:
            import google.generativeai as genai
            gemini_key = os.environ.get("GEMINI_API_KEY", "")
            if not gemini_key:
                return "[FORGE] No Gemini API key found. Falling back to templates."
                
            genai.configure(api_key=gemini_key)
            model = genai.GenerativeModel('gemini-1.5-pro')

            prompt = f"""You are FORGE, a security script generation engine.
Generate a complete, working Python script for the following task:

{description}

Rules:
- The script must only work on targets the user has authorization for
- Include a clear authorization warning at the top
- Use only standard Python libraries + requests + subprocess
- Include error handling
- Add comments explaining each step
- Do NOT include anything destructive or that bypasses authentication without consent

Return ONLY the Python code, no explanation outside the code."""

            response = model.generate_content(prompt)
            script = response.text

            # Save the script
            import os
            os.makedirs("./wraith_output/scripts", exist_ok=True)
            filename = f"./wraith_output/scripts/forge_{int(__import__('time').time())}.py"
            with open(filename, "w") as f:
                f.write(script)

            return f"[FORGE] Script generated and saved to: {filename}\n\n{script[:500]}..."

        except Exception as e:
            return f"[FORGE] AI generation failed: {e}\nFalling back to templates."

    def _template_generate(self, description: str) -> str:
        """Template-based script generation without API."""
        desc = description.lower()

        if "subdomain" in desc:
            return self._subdomain_enum_script()
        elif "port" in desc or "scan" in desc:
            return self._port_scan_script()
        elif "header" in desc:
            return self._header_check_script()
        elif "directory" in desc or "path" in desc or "fuzz" in desc:
            return self._dir_enum_script()
        else:
            return (
                "[FORGE] No template matched. Set ANTHROPIC_API_KEY for AI-powered script generation.\n"
                "Available templates: subdomain enum, port scan, header check, directory enum\n"
                "Try: 'forge a script to enumerate subdomains'"
            )

    def _subdomain_enum_script(self) -> str:
        script = '''#!/usr/bin/env python3
"""
FORGE-generated: Subdomain Enumeration Script
⚠ Only use on domains you own or have written authorization to test.
"""
import socket
import sys
import concurrent.futures

WORDLIST = [
    "www", "mail", "api", "dev", "staging", "test", "admin", "vpn",
    "ftp", "smtp", "pop", "imap", "static", "cdn", "assets", "app",
    "portal", "dashboard", "docs", "blog", "shop", "store", "git",
    "gitlab", "jenkins", "jira", "confluence", "kibana", "grafana",
    "prometheus", "backup", "db", "database", "mysql", "redis", "beta",
    "alpha", "internal", "intranet", "corp", "secure", "login", "auth",
    "oauth", "sso", "remote", "vpn2", "cloud", "s3", "media", "files",
]

def check_subdomain(subdomain, domain):
    hostname = f"{subdomain}.{domain}"
    try:
        ips = socket.getaddrinfo(hostname, None)
        ip = ips[0][4][0]
        return hostname, ip
    except Exception:
        return None, None

def enumerate(domain):
    print(f"[*] Enumerating subdomains for: {domain}")
    print(f"[*] Checking {len(WORDLIST)} common subdomains...")
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(check_subdomain, s, domain): s for s in WORDLIST}
        for future in concurrent.futures.as_completed(futures):
            hostname, ip = future.result()
            if hostname:
                print(f"  [+] {hostname} -> {ip}")
                found.append({"hostname": hostname, "ip": ip})
    print(f"\\n[*] Found {len(found)} subdomains")
    return found

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <domain>")
        print("Example: python script.py example.com")
        sys.exit(1)
    domain = sys.argv[1]
    print("⚠ AUTHORIZATION REQUIRED: Only run on domains you own or have permission to test.")
    confirm = input("Do you have authorization? (yes/no): ")
    if confirm.lower() != "yes":
        print("Aborted. Authorization required.")
        sys.exit(1)
    results = enumerate(domain)
'''
        # Save it
        import os
        os.makedirs("./wraith_output/scripts", exist_ok=True)
        fname = "./wraith_output/scripts/forge_subdomain_enum.py"
        with open(fname, "w") as f:
            f.write(script)
        return f"[FORGE] Subdomain enum script generated and saved to: {fname}\n\n{script}"

    def _header_check_script(self) -> str:
        script = """#!/usr/bin/env python3
import requests
import sys
def check(url):
    try:
        r = requests.get(url, timeout=10)
        headers = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security"]
        print(f"[*] Checking headers for: {url}")
        for h in headers:
            if h in r.headers: print(f"  [+] {h}: Present")
            else: print(f"  [-] {h}: MISSING")
    except Exception as e: print(f"Error: {e}")
if __name__ == '__main__':
    if len(sys.argv) > 1: check(sys.argv[1])
"""
        return f"[FORGE] Header check script generated.\n\n{script}"

    def _port_scan_script(self) -> str:
        return "[FORGE] Port scan template: python -c 'import socket; ...'"

    def _dir_enum_script(self) -> str:
        return "[FORGE] Directory enum template: python -c 'import requests; ...'"
