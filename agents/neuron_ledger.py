"""
NEURON — Self-Upgrade Intelligence Agent
Ingests live CVE feeds, ExploitDB, MITRE ATT&CK.
Stores knowledge locally. No cloud needed.

LEDGER — Report Generation Agent
Turns raw findings into human-readable reports.
"""

import json
import os
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from agents.base import WraithAgent


class _NeuronAgentLegacy(WraithAgent):
    """
    NEURON legacy — file-based knowledge storage.
    DEPRECATED: Use agents.neuron.NeuronAgent instead.
    Kept for backward compatibility.
    """
    name = "neuron_legacy"
    version = "1.0.0"
    description = "Legacy file-based knowledge storage"
    category = "intelligence"
    tools = []
    sandbox_profile = None
    risk_level = "low"

    def __init__(self, bus=None, **kwargs):
        super().__init__(bus=bus, **kwargs)
        self.name = "NEURON_LEGACY"
        self.knowledge_dir = Path("./wraith_output/knowledge")
        self.knowledge_dir.mkdir(parents=True, exist_ok=True)

    def fetch_latest_cves(self, limit: int = 20) -> list:
        """Fetch latest CVEs from NVD (free, no API key needed for basic use)."""
        cves = []
        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20&startIndex=0"
            req = urllib.request.Request(url, headers={"User-Agent": "WRAITH/0.1"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
                for item in data.get("vulnerabilities", [])[:limit]:
                    cve = item.get("cve", {})
                    desc_list = cve.get("descriptions", [])
                    desc = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")
                    metrics = cve.get("metrics", {})
                    cvss_data = (
                        metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                        if metrics.get("cvssMetricV31")
                        else metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})
                        if metrics.get("cvssMetricV2")
                        else {}
                    )
                    cves.append({
                        "id": cve.get("id", ""),
                        "description": desc[:300],
                        "severity": cvss_data.get("baseSeverity", "UNKNOWN"),
                        "score": cvss_data.get("baseScore", 0),
                        "published": cve.get("published", "")
                    })
            # Cache locally
            cache_file = self.knowledge_dir / "latest_cves.json"
            with open(cache_file, "w") as f:
                json.dump({"fetched": datetime.now().isoformat(), "cves": cves}, f, indent=2)
            print(f"  [NEURON] Cached {len(cves)} latest CVEs to {cache_file}")
        except Exception as e:
            print(f"  [NEURON] CVE fetch error: {e}")
            # Try to load cache
            cache_file = self.knowledge_dir / "latest_cves.json"
            if cache_file.exists():
                with open(cache_file) as f:
                    data = json.load(f)
                    cves = data.get("cves", [])
                print(f"  [NEURON] Loaded {len(cves)} CVEs from cache")
        return cves

    def search_cves(self, keyword: str) -> list:
        """Search cached CVEs for a keyword."""
        cache_file = self.knowledge_dir / "latest_cves.json"
        if not cache_file.exists():
            self.fetch_latest_cves()
        try:
            with open(cache_file) as f:
                data = json.load(f)
            cves = data.get("cves", [])
            keyword = keyword.lower()
            return [
                c for c in cves
                if keyword in c.get("description", "").lower()
                or keyword in c.get("id", "").lower()
            ]
        except Exception:
            return []

    def store_mission_knowledge(self, mission_id: str, findings: list):
        """Store findings from a mission to build the knowledge base."""
        kb_file = self.knowledge_dir / f"{mission_id}_knowledge.json"
        with open(kb_file, "w") as f:
            json.dump({
                "mission_id": mission_id,
                "timestamp": datetime.now().isoformat(),
                "finding_count": len(findings),
                "findings": findings
            }, f, indent=2)


# ─────────────────────────────────────────────────────────────────────────────


class LedgerAgent(WraithAgent):
    """
    LEDGER — Intelligence Report Generator v2.0
    Converts raw findings into clear, actionable reports.
    Works without API key. With API key: richer analysis.
    """
    name = "ledger"
    version = "2.0.0"
    description = "Reports — translates findings to plain English"
    category = "reporting"
    tools = []
    sandbox_profile = None
    risk_level = "low"

    def __init__(self, bus=None, **kwargs):
        super().__init__(bus=bus, **kwargs)
        self.name = "LEDGER"

    def generate(self, target: str, results: dict, mission_id: str, api_key: str = "") -> dict:
        """Generate a full report from mission results."""
        all_findings = []
        for phase, data in results.items():
            if isinstance(data, dict):
                all_findings.extend(data.get("findings", []))

        # Sort by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        all_findings.sort(key=lambda f: sev_order.get(f.get("severity", "info"), 5))

        # Count by severity
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            sev = f.get("severity", "info")
            if sev in counts:
                counts[sev] += 1

        # Risk score
        risk_score = (
            counts["critical"] * 10 +
            counts["high"] * 5 +
            counts["medium"] * 2 +
            counts["low"] * 1
        )
        risk_level = (
            "CRITICAL" if risk_score >= 20 else
            "HIGH" if risk_score >= 10 else
            "MEDIUM" if risk_score >= 5 else
            "LOW" if risk_score >= 1 else
            "MINIMAL"
        )

        # AI-enhanced analysis if available
        executive_summary = ""
        remediation_plan = ""
        if api_key:
            executive_summary, remediation_plan = self._ai_analysis(
                target, all_findings, counts, api_key
            )

        if not executive_summary:
            executive_summary = self._basic_summary(target, counts, risk_level)
        if not remediation_plan:
            remediation_plan = self._basic_remediation(all_findings)

        # Build report
        report = {
            "mission_id": mission_id,
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "risk_level": risk_level,
            "risk_score": risk_score,
            "finding_counts": counts,
            "total_findings": len(all_findings),
            "executive_summary": executive_summary,
            "remediation_plan": remediation_plan,
            "findings": all_findings,
            "phases": list(results.keys()),
            "generated_by": "WRAITH LEDGER Agent",
            "legal_note": "This report is for authorized security testing only."
        }

        # Generate Markdown
        report["markdown"] = self._to_markdown(report)

        return report

    def _ai_analysis(self, target: str, findings: list, counts: dict, api_key: str):
        """Use Claude for intelligent analysis."""
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)

            findings_summary = json.dumps(
                [{"title": f["title"], "severity": f["severity"]} for f in findings[:20]],
                indent=2
            )

            prompt = f"""You are WRAITH LEDGER, a security analysis AI.

Target: {target}
Findings: {counts['critical']} critical, {counts['high']} high, {counts['medium']} medium, {counts['low']} low

Top findings:
{findings_summary}

Write:
1. EXECUTIVE SUMMARY (3-4 sentences, plain English for a business owner)
2. TOP 3 REMEDIATION STEPS (actionable, specific, prioritized)

Keep it concise and actionable. No jargon."""

            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=600,
                messages=[{"role": "user", "content": prompt}]
            )
            text = response.content[0].text

            # Split into summary and remediation
            parts = text.split("2.")
            summary = parts[0].replace("1.", "").replace("EXECUTIVE SUMMARY", "").strip()
            remediation = ("2." + parts[1]).strip() if len(parts) > 1 else ""
            return summary, remediation

        except Exception as e:
            return "", ""

    def _basic_summary(self, target: str, counts: dict, risk_level: str) -> str:
        total = sum(counts.values())
        if total == 0:
            return f"Security assessment of {target} completed. No significant findings detected."
        return (
            f"Security assessment of {target} identified {total} findings "
            f"({counts['critical']} critical, {counts['high']} high, "
            f"{counts['medium']} medium, {counts['low']} low). "
            f"Overall risk level: {risk_level}. "
            f"Immediate attention required for all critical and high severity findings."
        )

    def _basic_remediation(self, findings: list) -> str:
        steps = []
        critical_high = [f for f in findings if f.get("severity") in ("critical", "high")]
        for i, f in enumerate(critical_high[:3], 1):
            steps.append(f"{i}. [{f['severity'].upper()}] {f['title']}")
        if not steps:
            steps = ["No immediate critical actions required."]
        return "\n".join(steps)

    def _to_markdown(self, report: dict) -> str:
        lines = [
            f"# WRAITH Security Report",
            f"",
            f"**Target:** `{report['target']}`  ",
            f"**Mission ID:** `{report['mission_id']}`  ",
            f"**Date:** {report['timestamp'][:10]}  ",
            f"**Risk Level:** {report['risk_level']}  ",
            f"**Risk Score:** {report['risk_score']}  ",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            report['executive_summary'],
            f"",
            f"## Finding Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]
        for sev, count in report['finding_counts'].items():
            if count > 0:
                lines.append(f"| {sev.upper()} | {count} |")

        lines += [
            f"",
            f"## Remediation Plan",
            f"",
            report['remediation_plan'],
            f"",
            f"## Detailed Findings",
            f"",
        ]

        for i, f in enumerate(report['findings'], 1):
            sev = f.get("severity", "info").upper()
            lines.append(f"### {i}. [{sev}] {f.get('title', '')}")
            lines.append(f"**Tool:** {f.get('tool', 'unknown')}  ")
            lines.append(f"**Type:** {f.get('type', 'unknown')}  ")
            if f.get("data"):
                data = f["data"]
                if isinstance(data, dict) and data.get("recommendation"):
                    lines.append(f"**Fix:** {data['recommendation']}")
            lines.append("")

        lines += [
            f"---",
            f"",
            f"*Generated by WRAITH — The World's First Civilian AI Security Swarm*  ",
            f"*Legal notice: This report is for authorized security testing only.*"
        ]
        return "\n".join(lines)
