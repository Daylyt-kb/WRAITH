"""
WRAITH v3.0 — Scanner Agent
TCP port scanner with banner grabbing, SSL analysis, and vulnerability-to-port mapping.
Uses stdlib socket + ssl + threading. No external dependencies.
"""

import socket
import ssl
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from agents.base import WraithAgent

logger = logging.getLogger("wraith.agent.scanner")

PORT_VULN_MAP = {
    21: {"name": "FTP", "risks": ["anonymous_login", "cleartext_auth"]},
    22: {"name": "SSH", "risks": ["weak_kex", "password_auth", "old_version"]},
    23: {"name": "Telnet", "risks": ["cleartext_auth", "no_encryption"]},
    25: {"name": "SMTP", "risks": ["open_relay", "user_enum"]},
    53: {"name": "DNS", "risks": ["zone_transfer"]},
    80: {"name": "HTTP", "risks": ["no_https", "info_disclosure", "dir_listing"]},
    110: {"name": "POP3", "risks": ["cleartext_auth"]},
    135: {"name": "MSRPC", "risks": ["windows_exposure"]},
    139: {"name": "NetBIOS", "risks": ["smb_leak", "null_session"]},
    143: {"name": "IMAP", "risks": ["cleartext_auth"]},
    443: {"name": "HTTPS", "risks": ["weak_tls", "cert_issues", "old_protocol"]},
    445: {"name": "SMB", "risks": ["eternalblue", "smbghost", "null_session"]},
    993: {"name": "IMAPS", "risks": ["weak_tls"]},
    995: {"name": "POP3S", "risks": ["weak_tls"]},
    3306: {"name": "MySQL", "risks": ["no_auth", "weak_auth", "exposed"]},
    3389: {"name": "RDP", "risks": ["bluekeep", "exposed"]},
    5432: {"name": "PostgreSQL", "risks": ["trust_auth", "exposed"]},
    6379: {"name": "Redis", "risks": ["no_auth", "exposed", "rce_risk"]},
    8080: {"name": "HTTP-Alt", "risks": ["proxy_open", "debug_panel"]},
    8443: {"name": "HTTPS-Alt", "risks": ["weak_tls", "self_signed"]},
    27017: {"name": "MongoDB", "risks": ["no_auth", "exposed"]},
    9200: {"name": "Elasticsearch", "risks": ["no_auth", "exposed", "data_leak"]},
    11211: {"name": "Memcached", "risks": ["no_auth", "amplification"]},
}

COMMON_WEB_PATHS = [".env", ".git/config", ".git/HEAD", "wp-config.php",
                     "phpinfo.php", "server-status", "admin", "debug"]


class ScannerAgent(WraithAgent):
    """WRAITH Scanner — Port scanning, service detection, vulnerability mapping."""

    name = "scanner"
    version = "3.0.0"
    description = "Port scanning and service detection with vulnerability mapping"
    category = "recon"
    tools = ["nmap"]
    sandbox_profile = "recon"
    risk_level = "medium"

    def run(self, target: str, scope, **kwargs) -> dict:
        from datetime import datetime
        start = datetime.now()
        findings = []
        logger.info(f"Scanner starting: {target}")

        ip, dns_findings = self._dns_check(target)
        findings.extend(dns_findings)
        scan_target = ip if ip else target

        open_ports = self._scan_ports(scan_target)

        for port in open_ports:
            service_info = self._analyze_port(scan_target, port)
            port_vulns = PORT_VULN_MAP.get(port, {})
            risks = port_vulns.get("risks", [])
            severity = "high" if port in (445, 6379, 27017, 9200) else "medium" if port in (21, 23, 3306, 3389) else "info"
            findings.append({
                "type": "open_port",
                "title": f"Port {port} ({port_vulns.get('name', 'unknown')}) open: {service_info.get('banner', '')[:80]}",
                "severity": severity,
                "tool": "SCANNER",
                "data": {"port": port, "service": port_vulns.get("name", "unknown"),
                         "banner": service_info.get("banner", ""), "risks": risks,
                         "tls_version": service_info.get("tls_version"),
                         "cipher": service_info.get("cipher")},
            })

        web_ports = [p for p in open_ports if p in (80, 443, 8080, 8443)]
        for wp in web_ports:
            web_findings = self._check_web_paths(target, wp)
            findings.extend(web_findings)

        summary = f"Found {len(open_ports)} open ports on {target}. {len(findings)} findings."
        return self._make_result(target, findings, summary, start)

    def _dns_check(self, target: str) -> tuple:
        findings = []
        ip = None
        try:
            ip = socket.gethostbyname(target)
            findings.append({"type": "dns_resolution", "title": f"{target} → {ip}",
                             "severity": "info", "tool": "SCANNER", "data": {"ip": ip}})
        except socket.gaierror:
            findings.append({"type": "dns_failure", "title": f"DNS resolution failed for {target}",
                             "severity": "medium", "tool": "SCANNER", "data": {}})
        return ip, findings

    def _scan_ports(self, target: str, ports: list = None, max_threads: int = 20, timeout: float = 1.0) -> list:
        ports = ports or list(PORT_VULN_MAP.keys())
        open_ports = []

        def _check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                sock.close()
                return port if result == 0 else None
            except (socket.error, OSError):
                return None

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(_check_port, p): p for p in ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        return sorted(open_ports)

    def _analyze_port(self, target: str, port: int) -> dict:
        info = {"banner": "", "tls_version": None, "cipher": None}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            if port in (80, 8080, 8000, 3000):
                sock.send(f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode())
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            info["banner"] = banner[:200]
            sock.close()
        except Exception:
            pass
        if port in (443, 993, 995, 8443):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(socket.socket(), server_hostname=target) as ssock:
                    ssock.settimeout(5)
                    ssock.connect((target, port))
                    info["tls_version"] = ssock.version()
                    info["cipher"] = ssock.cipher()[0]
            except Exception:
                pass
        return info

    def _check_web_paths(self, target: str, port: int) -> list:
        findings = []
        import urllib.request
        scheme = "https" if port in (443, 8443) else "http"
        for path in COMMON_WEB_PATHS:
            try:
                url = f"{scheme}://{target}:{port}/{path}"
                req = urllib.request.Request(url, headers={"User-Agent": "WRAITH-Scanner/3.0"})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    findings.append({
                        "type": "sensitive_path",
                        "title": f"Sensitive path exposed: {url} ({resp.status})",
                        "severity": "high" if path in (".env", ".git/config") else "medium",
                        "tool": "SCANNER", "data": {"url": url, "path": path, "status": resp.status},
                    })
            except Exception:
                pass
        return findings
