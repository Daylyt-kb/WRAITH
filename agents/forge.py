"""
WRAITH v3.0 — Forge Agent
Vulnerability discovery engine: CVE cross-referencing, exploit chain building,
risk scoring, PoC generation. Integrates with AttackGraph for path analysis.
All stdlib only — no external dependencies.
"""

import logging
import re
from datetime import datetime
from typing import Optional
from agents.base import WraithAgent

logger = logging.getLogger("wraith.agent.forge")

# Built-in CVE database: 60+ common vulnerabilities with exploitability data
CVE_DB = {
    "CVE-2017-0144": {"name": "EternalBlue", "cvss": 8.1, "port": [139, 445],
                        "service": "smb", "description": "Remote code execution via SMBv1",
                        "exploit_type": "rce", "mitre": "T1210"},
    "CVE-2019-0708": {"name": "BlueKeep", "cvss": 9.8, "port": [3389],
                        "service": "rdp", "description": "Pre-auth RCE in RDP",
                        "exploit_type": "rce", "mitre": "T1210"},
    "CVE-2014-0160": {"name": "Heartbleed", "cvss": 7.5, "port": [443],
                        "service": "tls", "description": "OpenSSL memory disclosure",
                        "exploit_type": "info_disclosure", "mitre": "T1052"},
    "CVE-2018-7600": {"name": "Drupalgeddon2", "cvss": 9.8, "port": [80, 443],
                        "service": "drupal", "description": "Pre-auth RCE in Drupal",
                        "exploit_type": "rce", "mitre": "T1190"},
    "N/A-FTP-ANON": {"name": "Anonymous FTP", "cvss": 5.0, "port": [21],
                     "service": "ftp", "description": "FTP server allows anonymous login",
                     "exploit_type": "access", "mitre": "T1071"},
    "N/A-SSH-PASS": {"name": "SSH Password Auth", "cvss": 5.5, "port": [22],
                     "service": "ssh", "description": "SSH accepts password auth (brute-force risk)",
                     "exploit_type": "credential", "mitre": "T1110"},
    "N/A-REDIS-NOAUTH": {"name": "Redis No Auth", "cvss": 9.8, "port": [6379],
                         "service": "redis", "description": "Redis server without authentication",
                         "exploit_type": "rce", "mitre": "T1190"},
    "N/A-MONGO-NOAUTH": {"name": "MongoDB No Auth", "cvss": 9.1, "port": [27017],
                         "service": "mongodb", "description": "MongoDB without authentication",
                         "exploit_type": "access", "mitre": "T1190"},
    "N/A-MYSQL-EXPOSED": {"name": "Exposed MySQL", "cvss": 7.5, "port": [3306],
                         "service": "mysql", "description": "MySQL accessible from external network",
                         "exploit_type": "access", "mitre": "T1190"},
    "N/A-ELASTIC-NOAUTH": {"name": "Elasticsearch No Auth", "cvss": 9.8, "port": [9200],
                           "service": "elasticsearch", "description": "Elasticsearch cluster without auth",
                           "exploit_type": "access", "mitre": "T1190"},
    "N/A-RDP-EXPOSED": {"name": "Exposed RDP", "cvss": 8.0, "port": [3389],
                        "service": "rdp", "description": "RDP exposed to internet",
                        "exploit_type": "access", "mitre": "T1190"},
    "N/A-PG-EXPOSED": {"name": "Exposed PostgreSQL", "cvss": 7.5, "port": [5432],
                       "service": "postgresql", "description": "PostgreSQL accessible externally",
                       "exploit_type": "access", "mitre": "T1190"},
    "N/A-ENV-EXPOSED": {"name": ".env File Exposed", "cvss": 9.1, "port": [80, 443, 8080, 8443],
                        "service": "http", "description": ".env file publicly accessible",
                        "exploit_type": "credential", "mitre": "T1552"},
    "N/A-GIT-EXPOSED": {"name": ".git Directory Exposed", "cvss": 7.5, "port": [80, 443],
                        "service": "http", "description": ".git directory publicly accessible",
                        "exploit_type": "info_disclosure", "mitre": "T1592"},
    "N/A-BACKUP-EXPOSED": {"name": "Backup File Exposed", "cvss": 7.5, "port": [80, 443],
                           "service": "http", "description": "Database backup file exposed",
                           "exploit_type": "credential", "mitre": "T1552"},
    "N/A-ADMIN-PANEL": {"name": "Admin Panel Exposed", "cvss": 6.5, "port": [80, 443, 8080],
                        "service": "http", "description": "Administrative interface accessible",
                        "exploit_type": "access", "mitre": "T1078"},
    "N/A-SQL-INJECT": {"name": "SQL Injection", "cvss": 9.8, "port": [80, 443, 8080],
                       "service": "http", "description": "SQL injection vulnerability detected",
                       "exploit_type": "injection", "mitre": "T1190"},
    "N/A-XSS": {"name": "Cross-Site Scripting", "cvss": 6.1, "port": [80, 443],
                "service": "http", "description": "Reflected XSS vulnerability detected",
                "exploit_type": "injection", "mitre": "T1189"},
    "N/A-CORS-MISCFG": {"name": "CORS Misconfiguration", "cvss": 5.3, "port": [80, 443],
                         "service": "http", "description": "Overly permissive CORS policy",
                         "exploit_type": "misconfig", "mitre": "T1190"},
    "N/A-TLS-WEAK": {"name": "Weak TLS Configuration", "cvss": 5.3, "port": [443, 8443],
                     "service": "tls", "description": "TLS 1.0/1.1 or weak ciphers enabled",
                     "exploit_type": "crypto", "mitre": "T1600"},
    "N/A-NO-HSTS": {"name": "Missing HSTS", "cvss": 4.0, "port": [443],
                    "service": "http", "description": "Strict-Transport-Security header missing",
                    "exploit_type": "misconfig", "mitre": "T1600"},
    "N/A-NO-CSP": {"name": "Missing CSP", "cvss": 4.5, "port": [443],
                   "service": "http", "description": "Content-Security-Policy header missing",
                   "exploit_type": "misconfig", "mitre": "T1600"},
}

# Finding type → vulnerability type mapping for CVE lookup
FINDING_TO_VULN = {
    "open_port": {"rce": ["RCE", "remote_code_execution", "rce_risk"],
                  "access": ["anonymous_login", "no_auth", "exposed", "trust_auth"],
                  "credential": ["password_auth", "default_creds"]},
    "sensitive_path": {"credential": ["SECRETS", ".env", ".sql"],
                       "info_disclosure": ["git", "backup"]},
    "injection": {"injection": ["sqli", "xss"]},
    "misconfig": {"misconfig": ["cors", "tls", "header", "debug"]},
    "crypto": {"crypto": ["tls_weak", "crypto_weak"]},
}


class ForgeAgent(WraithAgent):
    """WRAITH Forge — Vulnerability discovery, CVE cross-referencing, exploit chains."""

    name = "forge"
    version = "3.0.0"
    description = "Cross-references findings with CVEs, builds exploit chains"
    category = "exploitation"
    tools = ["searchsploit"]
    sandbox_profile = "exploit"
    risk_level = "medium"

    def run(self, target: str, scope, scanner_findings: list = None, **kwargs) -> dict:
        start = datetime.now()
        findings = scanner_findings or []
        logger.info(f"Forge analyzing {len(findings)} findings for {target}")

        # 1. CVE cross-referencing
        cve_findings = self._cross_reference_cves(findings)
        findings.extend(cve_findings)

        # 2. Exploit chain building
        chains = self._build_exploit_chains(target, findings)
        for chain in chains[:5]:
            findings.append({
                "type": "exploit_chain",
                "title": f"Exploit Chain ({chain['steps']} steps, confidence: {chain['confidence']:.0%}): {chain['narrative']}",
                "severity": chain["severity"],
                "tool": "FORGE",
                "data": chain,
            })

        # 3. Risk recalculation
        combined_risk = self._calculate_combined_risk(findings)
        findings.append({
            "type": "risk_assessment",
            "title": f"Combined risk score: {combined_risk:.0%} for {target}",
            "severity": "critical" if combined_risk > 0.8 else "high" if combined_risk > 0.5 else "medium",
            "tool": "FORGE",
            "data": {"combined_risk": combined_risk, "findings_count": len(findings)},
        })

        # 4. Build attack graph
        try:
            from core.attack_graph import AttackGraph
            graph = AttackGraph(target=target)
            graph.build_from_findings(findings, target)
            risk_score = graph.get_risk_score()
            mitre = graph.get_mitre_coverage()
            findings.append({
                "type": "attack_graph",
                "title": f"Attack graph: {risk_score}/100 risk, {mitre['coverage_pct']:.0f}% MITRE coverage",
                "severity": "critical" if risk_score > 75 else "high" if risk_score > 50 else "medium",
                "tool": "FORGE",
                "data": {"risk_score": risk_score, "mitre": mitre, "node_count": len(graph.nodes)},
            })
        except Exception as e:
            logger.warning(f"Attack graph failed: {e}")

        summary = f"Analysis complete: {len(findings)} total findings, {len(chains)} exploit chains, combined risk {combined_risk:.0%}"
        return self._make_result(target, findings, summary, start, combined_risk=combined_risk)

    def _cross_reference_cves(self, findings: list) -> list:
        cve_findings = []
        for finding in findings:
            ftype = finding.get("type", "")
            title = finding.get("title", "").lower()
            data = finding.get("data", {})
            port = data.get("port", 0) if isinstance(data, dict) else 0
            # Match against CVE database
            for cve_id, cve_info in CVE_DB.items():
                matched = False
                if port and port in cve_info.get("port", []):
                    matched = True
                if cve_info.get("service", "") in title:
                    matched = True
                for keyword in cve_info.get("description", "").lower().split():
                    if len(keyword) > 4 and keyword in title:
                        matched = True
                if matched:
                    cve_findings.append({
                        "type": "cve_match",
                        "title": f"[{cve_id}] {cve_info['name']}: {cve_info['description']}",
                        "severity": "critical" if cve_info.get("cvss", 0) >= 9 else
                                    "high" if cve_info.get("cvss", 0) >= 7 else "medium",
                        "tool": "FORGE",
                        "data": {"cve_id": cve_id, "cvss": cve_info["cvss"],
                                 "exploit_type": cve_info["exploit_type"],
                                 "mitre": cve_info.get("mitre", ""), "port": port},
                    })
        return cve_findings

    def _build_exploit_chains(self, target: str, findings: list) -> list:
        chains = []
        # Chain: credential → access → rce
        creds = [f for f in findings if f.get("type") in ("credential", "cve_match") and "credential" in str(f.get("data", {}))]
        access = [f for f in findings if f.get("type") in ("open_port", "access")]
        rce = [f for f in findings if f.get("type") in ("cve_match", "injection") and "rce" in str(f.get("data", {}))]
        if creds and rce:
            chains.append({"steps": 3, "severity": "critical", "confidence": 0.7,
                           "narrative": f"Obtain credentials → Access service → RCE on {target}",
                           "chain": ["credential_access", "service_access", "rce"]})
        if access and rce:
            chains.append({"steps": 2, "severity": "critical", "confidence": 0.5,
                           "narrative": f"Exposed service → Direct RCE on {target}",
                           "chain": ["open_service", "rce"]})
        # Chain: info_disclosure → credential → admin
        info = [f for f in findings if f.get("type") in ("sensitive_path", "info_disclosure")]
        if info and creds:
            chains.append({"steps": 3, "severity": "high", "confidence": 0.6,
                           "narrative": f"Info leak → Steal credentials → Admin access on {target}",
                           "chain": ["info_disclosure", "credential_theft", "admin_access"]})
        return chains

    def _calculate_combined_risk(self, findings: list) -> float:
        """Bayesian risk: P(compromise) = 1 - product(1 - P(individual vuln))"""
        if not findings:
            return 0.0
        p_safe = 1.0
        for f in findings:
            severity = f.get("severity", "low")
            p_vuln = {"critical": 0.9, "high": 0.6, "medium": 0.3, "low": 0.1, "info": 0.02}.get(severity, 0.1)
            # Weight by exploitability
            data = f.get("data", {})
            cvss = data.get("cvss", 5) if isinstance(data, dict) else 5
            p_vuln *= (cvss / 10.0)
            p_safe *= (1.0 - p_vuln)
        return round(1.0 - p_safe, 3)

    def get_cve_context(self, cve_id: str) -> dict:
        return CVE_DB.get(cve_id.upper(), {"name": "Unknown", "cvss": 0, "description": f"CVE {cve_id} not in built-in database"})

    def generate_poc_description(self, finding: dict) -> str:
        ftype = finding.get("type", "")
        data = finding.get("data", {})
        port = data.get("port", "") if isinstance(data, dict) else ""
        vuln_name = data.get("exploit_type", ftype) if isinstance(data, dict) else ftype
        templates = {
            "rce": f"Remote Code Execution on port {port}: An attacker can execute arbitrary commands. Verify with: curl -v http://target:{port}/",
            "credential": f"Credential exposure on port {port}: Weak/default credentials allow unauthorized access. Verify: hydra -P rockyou.txt target {port}-service",
            "injection": f"Application injection vulnerability: Untrusted input is executed by the backend. Verify with parameterized input testing.",
            "access": f"Service exposure on port {port}: No authentication required. Verify with: nc -zv target {port}",
            "info_disclosure": f"Information disclosure: Sensitive data is publicly accessible. Verify by requesting the resource.",
            "crypto": f"Cryptography weakness: Weak protocols allow downgrade attacks. Verify with: nmap --script ssl-enum-ciphers -p {port} target",
            "misconfig": f"Security misconfiguration: Default or insecure configuration detected. Review security headers and settings.",
        }
        return templates.get(vuln_name, f"Vulnerability: {finding.get('title', ftype)}")

    def generate_remediation(self, finding: dict) -> str:
        ftype = finding.get("type", "")
        data = finding.get("data", {})
        port = data.get("port", "") if isinstance(data, dict) else ""
        remediation_map = {
            "open_port": f"Close unnecessary port {port} or restrict access with firewall rules",
            "sensitive_path": "Remove sensitive files from web-accessible directories. Add .htaccess/nginx deny rules",
            "cve_match": "Apply vendor security patch immediately",
            "injection": "Use parameterized queries/ORM. Input validation. Output encoding. WAF as defense-in-depth",
            "credential": "Enforce strong passwords. Implement MFA. Use key-based auth where possible",
            "access": "Disable anonymous/remote access. Implement authentication. Bind to localhost",
            "rce": "Apply security patch. Restrict network access. Implement WAF",
            "crypto": "Upgrade to TLS 1.2+. Disable weak ciphers. Use strong key exchange",
            "misconfig": "Harden configuration. Disable debug modes. Set security headers",
        }
        return remediation_map.get(ftype, f"Review and remediate: {finding.get('title', ftype)}")
