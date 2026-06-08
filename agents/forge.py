"""
WRAITH v3.0 — Forge Agent
Vulnerability discovery engine: CVE cross-referencing, exploit chain building,
risk scoring, PoC generation. Integrates with AttackGraph for path analysis.
All stdlib only — no external dependencies.
"""

import logging
from datetime import datetime
from typing import Optional
from agents.base import WraithAgent

logger = logging.getLogger("wraith.agent.forge")

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
    "N/A-REDIS-NOAUTH": {"name": "Redis No Auth", "cvss": 9.8, "port": [6379],
                         "service": "redis", "description": "Redis without authentication",
                         "exploit_type": "rce", "mitre": "T1190"},
    "N/A-MONGO-NOAUTH": {"name": "MongoDB No Auth", "cvss": 9.1, "port": [27017],
                         "service": "mongodb", "description": "MongoDB without authentication",
                         "exploit_type": "access", "mitre": "T1190"},
    "N/A-ELASTIC-NOAUTH": {"name": "Elasticsearch No Auth", "cvss": 9.8, "port": [9200],
                           "service": "elasticsearch", "description": "Elasticsearch without auth",
                           "exploit_type": "access", "mitre": "T1190"},
    "N/A-ENV-EXPOSED": {"name": ".env File Exposed", "cvss": 9.1, "port": [80, 443, 8080],
                        "service": "http", "description": ".env file publicly accessible",
                        "exploit_type": "credential", "mitre": "T1552"},
    "N/A-SQL-INJECT": {"name": "SQL Injection", "cvss": 9.8, "port": [80, 443],
                       "service": "http", "description": "SQL injection vulnerability",
                       "exploit_type": "injection", "mitre": "T1190"},
    "N/A-XSS": {"name": "Cross-Site Scripting", "cvss": 6.1, "port": [80, 443],
                "service": "http", "description": "Reflected XSS vulnerability",
                "exploit_type": "injection", "mitre": "T1189"},
    "N/A-TLS-WEAK": {"name": "Weak TLS", "cvss": 5.3, "port": [443, 8443],
                     "service": "tls", "description": "Weak TLS configuration",
                     "exploit_type": "crypto", "mitre": "T1600"},
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
        findings = list(scanner_findings) if scanner_findings else []
        logger.info(f"Forge analyzing {len(findings)} findings for {target}")

        cve_findings = self._cross_reference_cves(findings)
        findings.extend(cve_findings)

        chains = self._build_exploit_chains(target, findings)
        for chain in chains[:5]:
            findings.append({
                "type": "exploit_chain",
                "title": f"Exploit Chain ({chain['steps']} steps, confidence: {chain['confidence']:.0%}): {chain['narrative']}",
                "severity": chain["severity"], "tool": "FORGE", "data": chain,
            })

        combined_risk = self._calculate_combined_risk(findings)
        findings.append({
            "type": "risk_assessment",
            "title": f"Combined risk: {combined_risk:.0%} for {target}",
            "severity": "critical" if combined_risk > 0.8 else "high" if combined_risk > 0.5 else "medium",
            "tool": "FORGE", "data": {"combined_risk": combined_risk},
        })

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
                "tool": "FORGE", "data": {"risk_score": risk_score, "mitre": mitre},
            })
        except Exception as e:
            logger.warning(f"Attack graph failed: {e}")

        summary = f"Analysis: {len(findings)} findings, {len(chains)} chains, risk {combined_risk:.0%}"
        return self._make_result(target, findings, summary, start, combined_risk=combined_risk)

    def _cross_reference_cves(self, findings: list) -> list:
        cve_findings = []
        for finding in findings:
            ftype = finding.get("type", "")
            title = finding.get("title", "").lower()
            data = finding.get("data", {})
            port = data.get("port", 0) if isinstance(data, dict) else 0
            for cve_id, cve_info in CVE_DB.items():
                matched = False
                if port and port in cve_info.get("port", []):
                    matched = True
                if cve_info.get("service", "") in title:
                    matched = True
                if matched:
                    cve_findings.append({
                        "type": "cve_match",
                        "title": f"[{cve_id}] {cve_info['name']}: {cve_info['description']}",
                        "severity": "critical" if cve_info.get("cvss", 0) >= 9 else
                                    "high" if cve_info.get("cvss", 0) >= 7 else "medium",
                        "tool": "FORGE",
                        "data": {"cve_id": cve_id, "cvss": cve_info["cvss"],
                                 "exploit_type": cve_info["exploit_type"]},
                    })
        return cve_findings

    def _build_exploit_chains(self, target: str, findings: list) -> list:
        chains = []
        creds = [f for f in findings if f.get("type") in ("credential", "cve_match") and "credential" in str(f.get("data", {}))]
        rce = [f for f in findings if f.get("type") in ("cve_match", "injection") and "rce" in str(f.get("data", {}))]
        if creds and rce:
            chains.append({"steps": 3, "severity": "critical", "confidence": 0.7,
                           "narrative": f"Credentials → Access → RCE on {target}",
                           "chain": ["credential", "access", "rce"]})
        return chains

    def _calculate_combined_risk(self, findings: list) -> float:
        if not findings:
            return 0.0
        p_safe = 1.0
        for f in findings:
            severity = f.get("severity", "low")
            p_vuln = {"critical": 0.9, "high": 0.6, "medium": 0.3, "low": 0.1, "info": 0.02}.get(severity, 0.1)
            data = f.get("data", {})
            cvss = data.get("cvss", 5) if isinstance(data, dict) else 5
            p_vuln *= (cvss / 10.0)
            p_safe *= (1.0 - p_vuln)
        return round(1.0 - p_safe, 3)

    def get_cve_context(self, cve_id: str) -> dict:
        return CVE_DB.get(cve_id.upper(), {"name": "Unknown", "cvss": 0,
                                            "description": f"CVE {cve_id} not in database"})

    def generate_poc_description(self, finding: dict) -> str:
        vuln = finding.get("data", {}).get("exploit_type", finding.get("type", "")) if isinstance(finding.get("data"), dict) else ""
        port = finding.get("data", {}).get("port", "") if isinstance(finding.get("data"), dict) else ""
        templates = {
            "rce": f"Remote Code Execution on port {port}: Verify with safe payload testing",
            "credential": f"Credential exposure on port {port}: Check for weak/default credentials",
            "injection": f"Application injection: Test with parameterized input validation",
            "access": f"Service exposure on port {port}: Verify access controls",
        }
        return templates.get(vuln, f"Vulnerability: {finding.get('title', vuln)}")

    def generate_remediation(self, finding: dict) -> str:
        ftype = finding.get("type", "")
        data = finding.get("data", {})
        port = data.get("port", "") if isinstance(data, dict) else ""
        return {
            "open_port": f"Close unnecessary port {port} or restrict with firewall",
            "sensitive_path": "Remove sensitive files from web-accessible directories",
            "cve_match": "Apply vendor security patch immediately",
            "injection": "Use parameterized queries/ORM. Input validation. Output encoding.",
            "credential": "Enforce strong passwords. Implement MFA.",
            "access": "Disable anonymous/remote access. Implement authentication.",
            "rce": "Apply security patch. Restrict network access.",
            "crypto": "Upgrade to TLS 1.2+. Disable weak ciphers.",
        }.get(ftype, f"Review and remediate: {finding.get('title', ftype)}")
