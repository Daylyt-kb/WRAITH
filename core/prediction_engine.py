"""
WRAITH v2.0 — Zero-Day Prediction Engine
Analyzes tech stacks, config patterns, and historical data to predict
unknown vulnerabilities before they're discovered.

Bayesian reasoning: P(vulnerability | tech_stack, config, historical_data)
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional


class PredictionEngine:
    """Predicts unknown vulnerabilities based on patterns across all scans."""

    # Tech stack → common weakness probability matrix
    # Format: tech → [{"vulnerability_type": str, "probability": float, "severity": str, "reason": str}]
    TECH_VULN_MATRIX = {
        "nginx": [
            {"type": "missing_hsts", "probability": 0.65, "severity": "medium", "reason": "Nginx doesn't add HSTS by default"},
            {"type": "missing_csp", "probability": 0.70, "severity": "medium", "reason": "CSP headers rarely configured manually"},
            {"type": "ip_leak", "probability": 0.25, "severity": "low", "reason": "X-Real-IP/X-Forwarded-For headers can leak internal IPs"},
            {"type": "path_traversal", "probability": 0.15, "severity": "high", "reason": "alias/location misconfigurations"},
        ],
        "apache": [
            {"type": "trace_enabled", "probability": 0.40, "severity": "medium", "reason": "TRACE method often left enabled"},
            {"type": "info_disclosure", "probability": 0.55, "severity": "low", "reason": "ServerTokens reveals version info"},
            {"type": "dir_listing", "probability": 0.35, "severity": "medium", "reason": "Indexes option often left on"},
        ],
        "wordpress": [
            {"type": "xmlrpc_bruteforce", "probability": 0.80, "severity": "high", "reason": "XML-RPC enabled by default, no rate limiting"},
            {"type": "plugin_vuln", "probability": 0.70, "severity": "high", "reason": "WordPress plugins frequently have CVEs"},
            {"type": "user_enum", "probability": 0.60, "severity": "low", "reason": "Author ID enumeration via /?author=N"},
            {"type": "backup_exposed", "probability": 0.25, "severity": "high", "reason": "wp-config.php.bak often left behind"},
        ],
        "django": [
            {"type": "debug_mode", "probability": 0.20, "severity": "critical", "reason": "DEBUG=True exposes stack traces"},
            {"type": "secret_key_exposed", "probability": 0.15, "severity": "critical", "reason": "SECRET_KEY in version control"},
            {"type": "sql_injection_raw", "probability": 0.10, "severity": "high", "reason": "raw() SQL usage bypasses ORM protection"},
        ],
        "flask": [
            {"type": "debug_mode", "probability": 0.25, "severity": "critical", "reason": "debug=True in production"},
            {"type": "weak_secret", "probability": 0.30, "severity": "high", "reason": "SECRET_KEY often uses weak values"},
        ],
        "mysql": [
            {"type": "no_password", "probability": 0.10, "severity": "critical", "reason": "Root account without password"},
            {"type": "remote_root", "probability": 0.15, "severity": "critical", "reason": "root@% grants remote access"},
            {"type": "weak_auth", "probability": 0.20, "severity": "high", "reason": "Old auth plugin usage"},
        ],
        "redis": [
            {"type": "no_auth", "probability": 0.40, "severity": "critical", "reason": "Redis default: no authentication"},
            {"type": "exposed", "probability": 0.30, "severity": "critical", "reason": "Bound to 0.0.0.0 without firewall"},
            {"type": "rce_risk", "probability": 0.20, "severity": "critical", "reason": "EVAL + exposed = RCE"},
        ],
        "mongodb": [
            {"type": "no_auth", "probability": 0.35, "severity": "critical", "reason": "MongoDB default: no authentication"},
            {"type": "exposed", "probability": 0.30, "severity": "critical", "reason": "Bound to 0.0.0.0"},
        ],
        "php": [
            {"type": "expose_php", "probability": 0.45, "severity": "low", "reason": "expose_php=On reveals version"},
            {"type": "allow_url_include", "probability": 0.15, "severity": "critical", "reason": "Enables RFI attacks"},
            {"type": "file_upload", "probability": 0.30, "severity": "high", "reason": "Unrestricted file uploads"},
        ],
        "docker": [
            {"type": "socket_exposed", "probability": 0.20, "severity": "critical", "reason": "Docker socket mounted into containers"},
            {"type": "root_container", "probability": 0.50, "severity": "high", "reason": "Containers running as root"},
            {"type": "privileged", "probability": 0.10, "severity": "critical", "reason": "Privileged containers"},
        ],
        "elasticsearch": [
            {"type": "no_auth", "probability": 0.50, "severity": "critical", "reason": "Pre-7.x default: no auth"},
            {"type": "exposed", "probability": 0.40, "severity": "critical", "reason": "Port 9200 exposed to internet"},
        ],
    }

    # Security baseline for config deviation analysis
    SECURITY_BASELINES = {
        "http_headers": {
            "strict-transports-security": {"required": True, "severity": "medium"},
            "content-security-policy": {"required": True, "severity": "high"},
            "x-frame-options": {"required": True, "severity": "medium"},
            "x-content-type-options": {"required": True, "severity": "medium"},
            "referrer-policy": {"required": False, "severity": "low"},
            "permissions-policy": {"required": False, "severity": "low"},
        },
        "tls_minimum_version": "1.2",
        "cookie_flags": {
            "secure": True,
            "httponly": True,
            "samesite": "Lax",
        },
    }

    def __init__(self, db_path: str = None):
        self.db_path = Path(db_path or "wraith_output/predictions.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS predictions (
                    id TEXT PRIMARY KEY,
                    target_type TEXT,
                    tech_stack TEXT,
                    prediction_type TEXT,
                    description TEXT,
                    probability NUMERIC,
                    severity TEXT,
                    confidence NUMERIC,
                    created_at TEXT,
                    validated_at TEXT,
                    was_correct INTEGER
                );
                CREATE TABLE IF NOT EXISTS scan_validations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    prediction_id TEXT,
                    scan_id TEXT,
                    was_confirmed INTEGER,
                    notes TEXT,
                    validated_at TEXT
                );
            """)

    def analyze_tech_stack(self, fingerprints: list) -> list:
        """Analyze detected tech stack → predict likely weaknesses."""
        predictions = []
        for tech in fingerprints:
            tech_lower = tech.lower().strip()
            for known_tech, vulns in self.TECH_VULN_MATRIX.items():
                if known_tech in tech_lower or tech_lower in known_tech:
                    for vuln in vulns:
                        predictions.append({
                            "tech": known_tech,
                            "type": vuln["type"],
                            "description": vuln["reason"],
                            "probability": vuln["probability"],
                            "severity": vuln["severity"],
                            "confidence": 0.7,
                            "source": "tech_matrix",
                        })
        return sorted(predictions, key=lambda x: x["probability"], reverse=True)

    def check_config_deviation(self, observed_headers: dict) -> list:
        """Compare observed HTTP headers against security baseline."""
        deviations = []
        if not observed_headers:
            return deviations
        observed_lower = {k.lower(): v for k, v in observed_headers.items()}
        for header, config in self.SECURITY_BASELINES["http_headers"].items():
            if config["required"] and header not in observed_lower:
                deviations.append({
                    "type": "missing_header",
                    "header": header,
                    "severity": config["severity"],
                    "description": f"Required security header '{header}' is missing",
                    "remediation": f"Add '{header}' header to all HTTP responses",
                })
        # Check for dangerous headers
        dangerous = ["server", "x-powered-by", "x-aspnet-version"]
        for d in dangerous:
            if d in observed_lower:
                deviations.append({
                    "type": "info_disclosure",
                    "header": d,
                    "value": observed_lower[d],
                    "severity": "low",
                    "description": f"Header '{d}' reveals implementation details",
                    "remediation": f"Remove or obscure the '{d}' header",
                })
        return deviations

    def predict_vulnerabilities(self, target_profile: dict, historical_data: list = None) -> list:
        """Main prediction method. Returns ranked vulnerability hypotheses."""
        predictions = []
        tech_stack = target_profile.get("tech_stack", [])
        headers = target_profile.get("headers", {})
        # Tech-based predictions
        for p in self.analyze_tech_stack(tech_stack):
            p["source"] = "tech_stack_analysis"
            predictions.append(p)
        # Config deviation
        for d in self.check_config_deviation(headers):
            d["probability"] = 0.9  # Config deviations are high-confidence
            d["confidence"] = 0.85
            d["source"] = "config_analysis"
            predictions.append(d)
        # Historical pattern matching
        if historical_data:
            for hist in historical_data:
                if hist.get("target_type") == target_profile.get("target_type"):
                    for pattern in hist.get("common_vulns", []):
                        predictions.append({
                            "type": pattern,
                            "description": f"Historically found in {hist.get('target_type', 'similar')} targets",
                            "probability": 0.5,
                            "severity": "medium",
                            "confidence": min(hist.get("scan_count", 0) / 100.0, 0.8),
                            "source": "historical_pattern",
                        })
        # Deduplicate and rank
        seen = set()
        unique = []
        for p in predictions:
            key = (p.get("type", ""), p.get("tech", p.get("header", "")))
            if key not in seen:
                seen.add(key)
                unique.append(p)
        return sorted(unique, key=lambda x: x.get("probability", 0) * x.get("confidence", 0.5), reverse=True)

    def validate_prediction(self, prediction_id: str, scan_results: dict) -> dict:
        """Validate a prediction against actual scan results."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM predictions WHERE id = ?", (prediction_id,)).fetchone()
            if not row:
                return {"error": "Prediction not found"}
            prediction = dict(row)
        # Check if any scan finding matches the prediction
        findings = scan_results.get("findings", [])
        confirmed = any(
            prediction.get("prediction_type", "").lower() in f.get("type", "").lower()
            for f in findings
        )
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                "UPDATE predictions SET validated_at=?, was_correct=? WHERE id=?",
                (datetime.now().isoformat(), 1 if confirmed else 0, prediction_id)
            )
            conn.execute(
                "INSERT INTO scan_validations (prediction_id, scan_id, was_confirmed, validated_at) VALUES (?, ?, ?, ?)",
                (prediction_id, scan_results.get("id", ""), 1 if confirmed else 0, datetime.now().isoformat())
            )
        return {"prediction": prediction, "confirmed": confirmed}

    def get_prediction_accuracy(self) -> dict:
        """Get prediction accuracy statistics."""
        with sqlite3.connect(str(self.db_path)) as conn:
            total = conn.execute("SELECT COUNT(*) FROM predictions WHERE validated_at IS NOT NULL").fetchone()[0]
            correct = conn.execute("SELECT COUNT(*) FROM predictions WHERE was_correct = 1").fetchone()[0]
        return {
            "total_validated": total,
            "correct": correct,
            "accuracy": round(correct / max(total, 1) * 100, 1),
        }

    def generate_hypotheses_report(self, target_profile: dict) -> str:
        """Generate a human-readable hypotheses report."""
        predictions = self.predict_vulnerabilities(target_profile)
        lines = [
            f"# WRAITH Prediction Report",
            f"**Target:** {target_profile.get('target', 'Unknown')}",
            f"**Tech Stack:** {', '.join(target_profile.get('tech_stack', []))}",
            f"**Predictions:** {len(predictions)} hypotheses generated",
            "",
        ]
        for i, p in enumerate(predictions[:20]):
            prob = p.get("probability", 0)
            sev = p.get("severity", "unknown").upper()
            lines.append(f"## {i+1}. [{sev}] {p.get('description', p.get('type', 'Unknown'))}")
            lines.append(f"   - Probability: {prob:.0%} | Confidence: {p.get('confidence', 0):.0%}")
            lines.append(f"   - Source: {p.get('source', 'unknown')}")
            if p.get("remediation"):
                lines.append(f"   - Remediation: {p['remediation']}")
            lines.append("")
        return "\n".join(lines)
