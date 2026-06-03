"""
WRAITH v2.0 — Autonomous Learning Engine
Analyzes scan results to identify patterns, learn from findings,
and generate new detection rules. Stores everything in Supabase.
"""

import json
import re
from datetime import datetime
from collections import Counter
from typing import Optional


class WraithLearner:
    """
    Autonomous learning engine for WRAITH.
    Analyzes scan results, identifies patterns, finds knowledge gaps,
    and generates new detection rules.
    """

    def __init__(self):
        self.findings_history = []
        self.patterns = {}
        self.gaps = []

    def analyze_findings(self, findings: list) -> dict:
        """
        Analyze scan results for patterns.

        Args:
            findings: List of finding dicts from agents

        Returns:
            dict with identified patterns and statistics
        """
        if not findings:
            return {"patterns": [], "stats": {}}

        # Count by type
        type_counts = Counter(f.get("type", "unknown") for f in findings)
        severity_counts = Counter(f.get("severity", "info") for f in findings)
        tool_counts = Counter(f.get("tool", "unknown") for f in findings)

        # Identify recurring patterns
        patterns = []
        for ftype, count in type_counts.most_common(5):
            if count > 1:
                patterns.append({
                    "type": "recurring_finding",
                    "finding_type": ftype,
                    "count": count,
                    "description": f"Found {count} instances of {ftype} findings",
                })

        # Identify high-severity clusters
        critical_high = [f for f in findings if f.get("severity") in ("critical", "high")]
        if len(critical_high) >= 3:
            patterns.append({
                "type": "severity_cluster",
                "count": len(critical_high),
                "description": f"High concentration of critical/high findings ({len(critical_high)})",
            })

        # Store in history
        self.findings_history.extend(findings)
        self.patterns[datetime.now().isoformat()] = patterns

        return {
            "patterns": patterns,
            "stats": {
                "total_findings": len(findings),
                "by_type": dict(type_counts),
                "by_severity": dict(severity_counts),
                "by_tool": dict(tool_counts),
                "critical_count": severity_counts.get("critical", 0),
                "high_count": severity_counts.get("high", 0),
            },
        }

    def identify_gaps(self, findings: list, knowledge_base: list = None) -> list:
        """
        Identify knowledge gaps — what WRAITH missed or couldn't detect.

        Args:
            findings: Current scan findings
            knowledge_base: Existing knowledge base entries

        Returns:
            list of identified gaps
        """
        gaps = []
        knowledge_base = knowledge_base or []

        # Check for common vulnerability types that weren't found
        common_checks = [
            ("sql_injection", "SQL injection testing was not performed"),
            ("xss", "Cross-site scripting testing was not performed"),
            ("csrf", "CSRF protection was not verified"),
            ("ssrf", "Server-side request forgery was not tested"),
            ("open_redirect", "Open redirect was not tested"),
            ("xxe", "XML external entity was not tested"),
            ("command_injection", "Command injection was not tested"),
            ("path_traversal", "Path traversal was not tested"),
        ]

        finding_types = {f.get("type", "") for f in findings}
        kb_keywords = {k.get("keyword", "").lower() for k in knowledge_base}

        for check_type, description in common_checks:
            if check_type not in finding_types and check_type not in kb_keywords:
                gaps.append({
                    "type": "missing_check",
                    "check_type": check_type,
                    "description": description,
                    "severity": "medium",
                })

        # Check for missing security headers
        header_findings = [f for f in findings if f.get("type") == "missing_header"]
        common_headers = ["strict-transport-security", "content-security-policy",
                          "x-frame-options", "x-content-type-options", "permissions-policy"]
        found_headers = set()
        for f in header_findings:
            data = f.get("data", {})
            if isinstance(data, dict):
                found_headers.add(data.get("missing_header", ""))

        for header in common_headers:
            if header not in found_headers:
                # Check if it was found as present (not just missing)
                present = any(
                    header in str(f.get("data", {}))
                    for f in findings
                    if f.get("type") == "header_present"
                )
                if not present:
                    gaps.append({
                        "type": "unverified_header",
                        "header": header,
                        "description": f"Security header '{header}' was not verified",
                        "severity": "low",
                    })

        self.gaps.extend(gaps)
        return gaps

    def generate_learning(self, gap: dict) -> dict:
        """
        Generate a new detection rule/learning from an identified gap.

        Args:
            gap: Gap dict from identify_gaps()

        Returns:
            dict with generated learning
        """
        learning_templates = {
            "missing_check": {
                "finding_type": "detection_rule",
                "title": f"Add {gap.get('check_type', 'unknown')} detection",
                "severity": "medium",
                "data": {
                    "rule_type": gap.get("check_type"),
                    "description": gap.get("description"),
                    "source": "gap_analysis",
                    "auto_generated": True,
                },
            },
            "unverified_header": {
                "finding_type": "header_check",
                "title": f"Verify {gap.get('header', 'unknown')} header",
                "severity": "low",
                "data": {
                    "header": gap.get("header"),
                    "description": gap.get("description"),
                    "source": "gap_analysis",
                    "auto_generated": True,
                },
            },
        }

        template = learning_templates.get(gap.get("type"), {
            "finding_type": "general_learning",
            "title": gap.get("description", "Unknown learning"),
            "severity": gap.get("severity", "info"),
            "data": {"source": "gap_analysis", "auto_generated": True},
        })

        template["generated_at"] = datetime.utcnow().isoformat()
        return template

    def update_knowledge(self, learning: dict) -> bool:
        """Store a learning in Supabase knowledge base."""
        try:
            from core.supabase_store import get_store
            store = get_store()
            store.store_learning(
                finding_type=learning.get("finding_type", "general"),
                title=learning.get("title", ""),
                severity=learning.get("severity", "info"),
                data=learning.get("data", {}),
            )
            return True
        except Exception as e:
            print(f"[Learner] Failed to store learning: {e}")
            return False

    def get_learning_summary(self) -> dict:
        """Get summary of all learnings."""
        return {
            "total_findings_analyzed": len(self.findings_history),
            "patterns_identified": sum(len(p) for p in self.patterns.values()),
            "gaps_identified": len(self.gaps),
            "recent_gaps": self.gaps[-10:],
        }


# Module-level singleton
_learner = None

def get_learner() -> WraithLearner:
    """Get the singleton learner instance."""
    global _learner
    if _learner is None:
        _learner = WraithLearner()
    return _learner
