"""
WRAITH v2.0 — Compliance Mapper
Maps security findings to compliance frameworks automatically.
Supports: OWASP Top 10 (2025), NIST CSF 2.0, ISO 27001:2022, SOC 2 Type II,
PCI DSS 4.0, HIPAA Security Rule, GDPR Article 32, CIS Controls v8
"""

import json
from typing import Optional


# ── Comprehensive finding → control mapping ──
FINDING_TO_CONTROLS = {
    "sql_injection": {
        "owasp_top10_2025": ["A03:2021-Injection"],
        "nist_csf": ["PR.DS-2", "PR.DS-10"],
        "iso_27001": ["A.8.25-Secure development", "A.8.28-Secure coding"],
        "soc2": ["CC6.1", "CC6.6"],
        "pci_dss_4": ["6.2.4", "6.3.1"],
        "hipaa": ["164.312(a)(1)", "164.312(e)(1)"],
        "gdpr_art32": ["data_protection_by_design"],
        "cis_v8": ["13.4", "16.11"],
    },
    "xss": {
        "owasp_top10_2025": ["A03:2021-Injection"],
        "nist_csf": ["PR.DS-2"],
        "iso_27001": ["A.8.28-Secure coding"],
        "soc2": ["CC6.1"],
        "pci_dss_4": ["6.2.4"],
        "hipaa": ["164.312(e)(1)"],
        "gdpr_art32": ["data_protection_by_design"],
        "cis_v8": ["13.4"],
    },
    "ssrf": {
        "owasp_top10_2025": ["A10:2021-Server-Side Request Forgery"],
        "nist_csf": ["PR.AC-5", "PR.DS-2"],
        "iso_27001": ["A.8.2-Security of network services"],
        "soc2": ["CC6.1", "CC6.6"],
        "pci_dss_4": ["6.2.4"],
        "hipaa": ["164.312(a)(1)"],
        "gdpr_art32": ["integrity"],
        "cis_v8": ["13.4"],
    },
    "broken_access_control": {
        "owasp_top10_2025": ["A01:2021-Broken Access Control"],
        "nist_csf": ["PR.AC-1", "PR.AC-4", "PR.AC-5"],
        "iso_27001": ["A.8.3-Information access restriction", "A.8.2-User access management"],
        "soc2": ["CC6.1", "CC6.2", "CC6.3"],
        "pci_dss_4": ["7.1.1", "7.2.1"],
        "hipaa": ["164.312(a)(1)", "164.308(a)(4)"],
        "gdpr_art32": ["access_control"],
        "cis_v8": ["6.1", "6.2", "6.3"],
    },
    "auth_bypass": {
        "owasp_top10_2025": ["A01:2021-Broken Access Control", "A07:2021-Identification and Auth Failures"],
        "nist_csf": ["PR.AC-1", "PR.AC-7"],
        "iso_27001": ["A.8.2-User access management", "A.8.5-Secure authentication"],
        "soc2": ["CC6.1"],
        "pci_dss_4": ["8.2.1", "8.3.1"],
        "hipaa": ["164.312(d)"],
        "gdpr_art32": ["access_control"],
        "cis_v8": ["6.1", "6.2"],
    },
    "security_misconfiguration": {
        "owasp_top10_2025": ["A05:2021-Security Misconfiguration"],
        "nist_csf": ["PR.IP-3", "PR.IP-12"],
        "iso_27001": ["A.8.9-Configuration management"],
        "soc2": ["CC6.1", "CC8.1"],
        "pci_dss_4": ["2.1.1", "2.2.1"],
        "hipaa": ["164.312(a)(1)", "164.312(c)(1)"],
        "gdpr_art32": ["resilience"],
        "cis_v8": ["4.1", "4.2"],
    },
    "missing_hsts": {
        "owasp_top10_2025": ["A05:2021-Security Misconfiguration"],
        "nist_csf": ["PR.DS-2"],
        "iso_27001": ["A.8.24-Use of cryptography"],
        "soc2": ["CC6.1"],
        "pci_dss_4": ["4.1.1"],
        "hipaa": ["164.312(e)(1)"],
        "gdpr_art32": ["encryption"],
        "cis_v8": ["13.4"],
    },
    "missing_csp": {
        "owasp_top10_2025": ["A05:2021-Security Misconfiguration"],
        "nist_csf": ["PR.DS-2"],
        "iso_27001": ["A.8.24-Use of cryptography"],
        "soc2": ["CC6.1"],
        "pci_dss_4": ["6.2.4"],
        "hipaa": ["164.312(e)(1)"],
        "gdpr_art32": ["data_protection_by_design"],
        "cis_v8": ["13.4"],
    },
    "missing_x_frame_options": {
        "owasp_top10_2025": ["A05:2021-Security Misconfiguration"],
        "nist_csf": ["PR.DS-2"],
        "iso_27001": ["A.8.9-Configuration management"],
        "soc2": ["CC6.1"],
        "pci_dss_4": ["6.2.4"],
        "hipaa": ["164.312(e)(1)"],
        "gdpr_art32": ["data_protection_by_design"],
        "cis_v8": ["13.4"],
    },
    "tls_weak": {
        "owasp_top10_2025": ["A02:2021-Cryptographic Failures"],
        "nist_csf": ["PR.DS-2"],
        "iso_27001": ["A.8.24-Use of cryptography"],
        "soc2": ["CC6.7"],
        "pci_dss_4": ["4.1.1", "4.2.1"],
        "hipaa": ["164.312(e)(1)", "164.312(e)(2)(ii)"],
        "gdpr_art32": ["encryption", "integrity"],
        "cis_v8": ["13.10"],
    },
    "outdated_software": {
        "owasp_top10_2025": ["A06:2021-Vulnerable and Outdated Components"],
        "nist_csf": ["ID.RA-1", "PR.IP-12"],
        "iso_27001": ["A.8.8-Management of technical vulnerabilities"],
        "soc2": ["CC7.1", "CC8.1"],
        "pci_dss_4": ["6.2.1", "6.2.2"],
        "hipaa": ["164.308(a)(5)(ii)(B)"],
        "gdpr_art32": ["resilience"],
        "cis_v8": ["7.1", "7.2"],
    },
    "admin_panel_exposed": {
        "owasp_top10_2025": ["A01:2021-Broken Access Control"],
        "nist_csf": ["PR.AC-4", "PR.AC-5"],
        "iso_27001": ["A.8.2-User access management"],
        "soc2": ["CC6.1"],
        "pci_dss_4": ["7.1.1"],
        "hipaa": ["164.312(a)(1)"],
        "gdpr_art32": ["access_control"],
        "cis_v8": ["6.1"],
    },
    "info_disclosure": {
        "owasp_top10_2025": ["A05:2021-Security Misconfiguration"],
        "nist_csf": ["PR.DS-2", "PR.IP-12"],
        "iso_27001": ["A.8.11-Data masking", "A.8.12-Data leakage prevention"],
        "soc2": ["CC6.7"],
        "pci_dss_4": ["3.1.1"],
        "hipaa": ["164.312(e)(1)", "164.502"],
        "gdpr_art32": ["confidentiality", "integrity"],
        "cis_v8": ["3.4"],
    },
    "secrets_exposed": {
        "owasp_top10_2025": ["A07:2021-Identification and Auth Failures"],
        "nist_csf": ["PR.AC-1", "PR.DS-2"],
        "iso_27001": ["A.8.24-Use of cryptography", "A.8.9-Configuration management"],
        "soc2": ["CC6.1", "CC6.7"],
        "pci_dss_4": ["3.1.1", "3.6.1"],
        "hipaa": ["164.312(a)(2)(iv)", "164.312(e)(1)"],
        "gdpr_art32": ["encryption", "confidentiality"],
        "cis_v8": ["3.4", "13.4"],
    },
    "default_credentials": {
        "owasp_top10_2025": ["A07:2021-Identification and Auth Failures"],
        "nist_csf": ["PR.AC-1", "PR.AC-6"],
        "iso_27001": ["A.8.5-Secure authentication", "A.8.2-User access management"],
        "soc2": ["CC6.1"],
        "pci_dss_4": ["8.2.1", "8.2.3"],
        "hipaa": ["164.312(d)", "164.308(a)(5)(ii)(D)"],
        "gdpr_art32": ["access_control"],
        "cis_v8": ["5.1", "5.2"],
    },
    "cors_misconfig": {
        "owasp_top10_2025": ["A01:2021-Broken Access Control"],
        "nist_csf": ["PR.AC-4"],
        "iso_27001": ["A.8.9-Configuration management"],
        "soc2": ["CC6.1"],
        "pci_dss_4": ["6.2.4"],
        "hipaa": ["164.312(e)(1)"],
        "gdpr_art32": ["access_control", "data_protection_by_design"],
        "cis_v8": ["13.4"],
    },
    "cookie_secure_missing": {
        "owasp_top10_2025": ["A05:2021-Security Misconfiguration"],
        "nist_csf": ["PR.DS-2"],
        "iso_27001": ["A.8.24-Use of cryptography"],
        "soc2": ["CC6.1"],
        "pci_dss_4": ["4.1.1"],
        "hipaa": ["164.312(e)(1)"],
        "gdpr_art32": ["encryption"],
        "cis_v8": ["13.4"],
    },
    "command_injection": {
        "owasp_top10_2025": ["A03:2021-Injection"],
        "nist_csf": ["PR.DS-2", "PR.DS-10"],
        "iso_27001": ["A.8.25-Secure development", "A.8.28-Secure coding"],
        "soc2": ["CC6.1", "CC6.6"],
        "pci_dss_4": ["6.2.4", "6.3.1"],
        "hipaa": ["164.312(a)(1)"],
        "gdpr_art32": ["data_protection_by_design"],
        "cis_v8": ["13.4", "16.11"],
    },
    "path_traversal": {
        "owasp_top10_2025": ["A01:2021-Broken Access Control"],
        "nist_csf": ["PR.AC-4", "PR.DS-2"],
        "iso_27001": ["A.8.25-Secure development"],
        "soc2": ["CC6.1"],
        "pci_dss_4": ["6.2.4"],
        "hipaa": ["164.312(a)(1)"],
        "gdpr_art32": ["data_protection_by_design"],
        "cis_v8": ["13.4"],
    },
    "file_upload_risk": {
        "owasp_top10_2025": ["A01:2021-Broken Access Control"],
        "nist_csf": ["PR.AC-4"],
        "iso_27001": ["A.8.25-Secure development"],
        "soc2": ["CC6.1"],
        "pci_dss_4": ["6.2.4"],
        "hipaa": ["164.312(a)(1)"],
        "gdpr_art32": ["data_protection_by_design"],
        "cis_v8": ["13.4"],
    },
    "debug_enabled": {
        "owasp_top10_2025": ["A05:2021-Security Misconfiguration"],
        "nist_csf": ["PR.IP-3", "PR.DS-2"],
        "iso_27001": ["A.8.9-Configuration management"],
        "soc2": ["CC8.1"],
        "pci_dss_4": ["6.2.4"],
        "hipaa": ["164.312(a)(1)"],
        "gdpr_art32": ["confidentiality"],
        "cis_v8": ["4.1"],
    },
}

# Framework display names
FRAMEWORK_NAMES = {
    "owasp_top10_2025": "OWASP Top 10 (2025)",
    "nist_csf": "NIST CSF 2.0",
    "iso_27001": "ISO/IEC 27001:2022",
    "soc2": "SOC 2 Type II",
    "pci_dss_4": "PCI DSS 4.0",
    "hipaa": "HIPAA Security Rule",
    "gdpr_art32": "GDPR Article 32",
    "cis_v8": "CIS Controls v8",
}

# Framework descriptions for reports
FRAMEWORK_DESCRIPTIONS = {
    "owasp_top10_2025": "The Open Worldwide Application Security Project Top 10 most critical security risks to web applications.",
    "nist_csf": "National Institute of Standards and Technology Cybersecurity Framework 2.0 — industry-standard security controls.",
    "iso_27001": "International standard for information security management systems (ISMS).",
    "soc2": "System and Organization Controls 2 — trust service criteria for service organizations.",
    "pci_dss_4": "Payment Card Industry Data Security Standard 4.0 — requirements for entities handling cardholder data.",
    "hipaa": "Health Insurance Portability and Accountability Act — Security Rule for electronic protected health information.",
    "gdpr_art32": "General Data Protection Regulation Article 32 — Security of processing personal data.",
    "cis_v8": "Center for Internet Security Critical Security Controls v8 — prioritized cybersecurity best practices.",
}


class ComplianceMapper:
    """Maps security findings to compliance framework controls."""

    def __init__(self, frameworks: list = None):
        self.frameworks = frameworks or list(FRAMEWORK_NAMES.keys())

    def map_finding(self, finding: dict) -> dict:
        """Map a single finding to all framework controls."""
        ftype = finding.get("type", "").lower().replace(" ", "_")
        severity = finding.get("severity", "info")
        result = {"finding_type": ftype, "title": finding.get("title", ""), "severity": severity, "mappings": {}}
        for fw in self.frameworks:
            controls = FINDING_TO_CONTROLS.get(ftype, {}).get(fw, [])
            if controls:
                result["mappings"][fw] = {"framework": FRAMEWORK_NAMES[fw], "controls": controls}
        return result

    def generate_compliance_report(self, findings: list, frameworks: list = None) -> dict:
        """Generate a complete compliance report for all findings."""
        fws = frameworks or self.frameworks
        report = {
            "generated_at": None,  # filled below
            "frameworks": {},
            "overall_scores": {},
            "findings_count": len(findings),
            "critical_findings": sum(1 for f in findings if f.get("severity") == "critical"),
            "high_findings": sum(1 for f in findings if f.get("severity") == "high"),
        }
        from datetime import datetime
        report["generated_at"] = datetime.utcnow().isoformat()
        for fw in fws:
            fw_findings = []
            controls_failed = set()
            controls_passed = set()
            all_controls = set()
            # Gather which controls are touched
            for finding in findings:
                mapped = self.map_finding(finding)
                if fw in mapped.get("mappings", {}):
                    fw_findings.append({"finding": finding, "controls": mapped["mappings"][fw]["controls"]})
                    for c in mapped["mappings"][fw]["controls"]:
                        controls_failed.add(c)
            # Build score: if no findings map to a control, assume pass (simplified)
            total_controls = max(len(controls_failed) * 3, 10)  # estimate
            passed = total_controls - len(controls_failed)
            score = round(passed / total_controls * 100, 1)
            report["frameworks"][fw] = {
                "name": FRAMEWORK_NAMES[fw],
                "description": FRAMEWORK_DESCRIPTIONS.get(fw, ""),
                "findings": fw_findings,
                "controls_failed": sorted(controls_failed),
                "compliance_score": score,
            }
            report["overall_scores"][fw] = score
        return report

    def get_compliance_score(self, findings: list, framework: str) -> float:
        """Get compliance score 0-100 for a specific framework."""
        controls_failed = set()
        for finding in findings:
            ftype = finding.get("type", "").lower().replace(" ", "_")
            controls = FINDING_TO_CONTROLS.get(ftype, {}).get(framework, [])
            for c in controls:
                controls_failed.add(c)
        total = max(len(controls_failed) * 3, 10)
        return round((total - len(controls_failed)) / total * 100, 1)

    def get_gaps(self, findings: list, framework: str) -> list:
        """List controls not addressed by the scan."""
        covered = set()
        for finding in findings:
            ftype = finding.get("type", "").lower().replace(" ", "_")
            for c in FINDING_TO_CONTROLS.get(ftype, {}).get(framework, []):
                covered.add(c)
        # Known controls per framework
        all_controls = set()
        for ftype_controls in FINDING_TO_CONTROLS.values():
            for c in ftype_controls.get(framework, []):
                all_controls.add(c)
        return sorted(all_controls - covered)

    def get_remediation_for_control(self, control_id: str, framework: str) -> str:
        """Get specific remediation guidance for a control."""
        remediation_db = {
            "A01:2021-Broken Access Control": "Implement proper authentication and authorization checks. Use RBAC. Validate permissions server-side.",
            "A02:2021-Cryptographic Failures": "Use TLS 1.2+. Encrypt data at rest and in transit. Use strong key management. Never hardcode secrets.",
            "A03:2021-Injection": "Use parameterized queries/ORM. Input validation. Output encoding. WAF as defense-in-depth.",
            "A05:2021-Security Misconfiguration": "Harden configurations. Disable unnecessary features. Automated security scanning. Minimal platform.",
            "A06:2021-Vulnerable and Outdated Components": "Regular patching. Software composition analysis. Remove unused dependencies.",
            "A07:2021-Identification and Auth Failures": "Multi-factor authentication. Strong password policies. Session management. Account lockout.",
            "A10:2021-SSRF": "Validate and sanitize user-supplied URLs. Allowlist destinations. Disable unused URL schemes.",
            "PR.AC-1": "Identify and authenticate all users. Enforce least privilege. Use MFA.",
            "PR.DS-2": "Protect data at rest and in transit. Use encryption.",
            "CC6.1": "Implement logical access controls. Enforce least privilege.",
            "CC6.6": "Restrict access to system components based on need-to-know.",
            "6.2.4": "Address vulnerabilities through coding best practices. OWASP guidelines.",
        }
        return remediation_db.get(control_id, f"Review control {control_id} requirements and implement necessary security measures.")

    def export_compliance_markdown(self, findings: list, frameworks: list = None) -> str:
        """Export compliance report as Markdown."""
        report = self.generate_compliance_report(findings, frameworks)
        lines = [
            "# WRAITH Compliance Report",
            f"**Generated:** {report['generated_at']}",
            f"**Findings:** {report['findings_count']} (Critical: {report['critical_findings']}, High: {report['high_findings']})",
            "",
        ]
        for fw_key, fw_data in report["frameworks"].items():
            lines.append(f"## {fw_data['name']} — Score: {fw_data['compliance_score']:.0f}%")
            lines.append(f"*{fw_data['description']}*")
            lines.append("")
            if fw_data["controls_failed"]:
                lines.append("### Failed Controls")
                for c in fw_data["controls_failed"]:
                    remediation = self.get_remediation_for_control(c, fw_key)
                    lines.append(f"- **{c}**: {remediation}")
            else:
                lines.append("*No failed controls identified in scan scope.*")
            lines.append("")
        return "\n".join(lines)
