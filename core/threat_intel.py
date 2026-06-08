"""
WRAITH v2.0 — Threat Intelligence Aggregator
Multi-source threat intelligence with SQLite caching.
Sources: NVD/CVE, HaveIBeenPwned, Certificate Transparency, Shodan, GitHub dorking.
All via stdlib urllib — no external dependencies.
"""

import os
import json
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


class ThreatIntel:
    """Multi-source threat intelligence aggregator with local caching."""

    def __init__(self, cache_dir: str = None):
        self.cache_dir = Path(cache_dir or "wraith_output/threat_intel")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_db = self.cache_dir / "cache.db"
        self._init_cache()

    def _init_cache(self):
        with sqlite3.connect(str(self.cache_db)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS intel_cache (
                    source TEXT NOT NULL,
                    key TEXT NOT NULL,
                    data TEXT NOT NULL,
                    cached_at TEXT NOT NULL,
                    ttl_seconds INTEGER DEFAULT 3600,
                    PRIMARY KEY (source, key)
                )
            """)

    def _get_cached(self, source: str, key: str) -> Optional[dict]:
        with sqlite3.connect(str(self.cache_db)) as conn:
            row = conn.execute(
                "SELECT data, cached_at, ttl_seconds FROM intel_cache WHERE source=? AND key=?",
                (source, key)
            ).fetchone()
            if row:
                cached_at = datetime.fromisoformat(row[1])
                if datetime.now() < cached_at + timedelta(seconds=row[2]):
                    return json.loads(row[0])
        return None

    def _set_cache(self, source: str, key: str, data: dict, ttl: int = 3600):
        with sqlite3.connect(str(self.cache_db)) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO intel_cache (source, key, data, cached_at, ttl_seconds) VALUES (?, ?, ?, ?, ?)",
                (source, key, json.dumps(data, default=str), datetime.now().isoformat(), ttl)
            )

    def get_cve_feed(self, hours: int = 24) -> list:
        """Get recent CVEs from NVD API."""
        cache_key = f"recent_{hours}h"
        cached = self._get_cached("nvd", cache_key)
        if cached:
            return cached.get("cves", [])
        try:
            import urllib.request
            pub_start = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.000")
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={pub_start}&resultsPerPage=20"
            req = urllib.request.Request(url, headers={"User-Agent": "WRAITH-Intel/2.0"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read())
            cves = []
            for item in data.get("vulnerabilities", [])[:20]:
                cve = item.get("cve", {})
                cves.append({
                    "id": cve.get("id", ""),
                    "description": next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""),
                    "severity": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN"),
                    "score": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", 0),
                    "published": cve.get("published", ""),
                })
            self._set_cache("nvd", cache_key, {"cves": cves}, ttl=3600)
            return cves
        except Exception:
            return []

    def check_hibp_breaches(self, domain: str) -> list:
        """Check HaveIBeenPwned for domain breaches."""
        cached = self._get_cached("hibp", domain)
        if cached:
            return cached.get("breaches", [])
        api_key = os.environ.get("HIBP_API_KEY", "")
        if not api_key:
            return [{"info": "HIBP_API_KEY not set — get one at https://haveibeenpwned.com/API/Key"}]
        try:
            import urllib.request
            url = f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}"
            req = urllib.request.Request(url, headers={"User-Agent": "WRAITH/2.0", "hibp-api-key": api_key})
            with urllib.request.urlopen(req, timeout=15) as resp:
                breaches = json.loads(resp.read())
            result = [{"name": b.get("Name", ""), "date": b.get("BreachDate", ""),
                       "description": b.get("Description", "")[:200]} for b in breaches[:10]]
            self._set_cache("hibp", domain, {"breaches": result}, ttl=86400)
            return result
        except Exception as e:
            return [{"error": str(e)[:100]}]

    def get_ct_logs(self, domain: str) -> list:
        """Certificate Transparency subdomain enumeration via crt.sh."""
        cached = self._get_cached("ct", domain)
        if cached:
            return cached.get("subdomains", [])
        try:
            import urllib.request
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            req = urllib.request.Request(url, headers={"User-Agent": "WRAITH/2.0"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read())
            subdomains = list(set(entry.get("name_value", "").strip() for entry in data if entry.get("name_value")))
            subdomains = [s for s in subdomains if s and "*" not in s][:200]
            self._set_cache("ct", domain, {"subdomains": subdomains}, ttl=86400)
            return subdomains
        except Exception:
            return []

    def get_shodan_context(self, ip: str) -> dict:
        """Get Shodan context for an IP."""
        cached = self._get_cached("shodan", ip)
        if cached:
            return cached
        api_key = os.environ.get("SHODAN_API_KEY", "")
        if not api_key:
            return {"info": "SHODAN_API_KEY not set"}
        try:
            import urllib.request
            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
            result = {
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "os": data.get("os", "unknown"),
                "vulns": data.get("vulns", [])[:10],
                "tags": data.get("tags", []),
            }
            self._set_cache("shodan", ip, result, ttl=86400)
            return result
        except Exception as e:
            return {"error": str(e)[:100]}

    def get_github_dorks(self, domain: str) -> list:
        """Generate GitHub search URLs for secret dorking."""
        return [
            {"title": f"API keys for {domain}", "url": f"https://github.com/search?q=%22{domain}%22+api_key&type=code"},
            {"title": f"Passwords for {domain}", "url": f"https://github.com/search?q=%22{domain}%22+password&type=code"},
            {"title": f"Secrets for {domain}", "url": f"https://github.com/search?q=%22{domain}%22+secret&type=code"},
            {"title": f"Config files for {domain}", "url": f"https://github.com/search?q=%22{domain}%22+filename:.env&type=code"},
        ]

    def get_tech_stack_weaknesses(self, tech: str) -> list:
        """Get known weaknesses for a technology from local knowledge base."""
        cached = self._get_cached("tech", tech)
        if cached:
            return cached.get("weaknesses", [])
        tech_db = {
            "nginx": [{"type": "misconfiguration", "title": "Missing security headers", "severity": "medium"},
                       {"type": "cve", "title": "CVE-2021-23017 DNS resolver vulnerability", "severity": "high"}],
            "apache": [{"type": "misconfiguration", "title": "ServerTokens Prod not set", "severity": "low"},
                        {"type": "misconfiguration", "title": "TRACE method enabled", "severity": "medium"}],
            "wordpress": [{"type": "vulnerability", "title": "XML-RPC brute force", "severity": "high"},
                           {"type": "vulnerability", "title": "Plugin vulnerabilities", "severity": "high"}],
            "mysql": [{"type": "misconfiguration", "title": "Root without password", "severity": "critical"},
                       {"type": "misconfiguration", "title": "Remote root login enabled", "severity": "high"}],
            "postgresql": [{"type": "misconfiguration", "title": "trust auth enabled", "severity": "high"}],
            "redis": [{"type": "misconfiguration", "title": "No authentication required", "severity": "critical"},
                      {"type": "misconfiguration", "title": "Exposed to internet", "severity": "critical"}],
            "mongodb": [{"type": "misconfiguration", "title": "No authentication enabled", "severity": "critical"}],
            "docker": [{"type": "misconfiguration", "title": "Docker socket exposed", "severity": "critical"}],
            "kubernetes": [{"type": "misconfiguration", "title": "Dashboard exposed", "severity": "high"},
                            {"type": "misconfiguration", "title": "Anonymous access enabled", "severity": "critical"}],
            "django": [{"type": "misconfiguration", "title": "DEBUG=True in production", "severity": "high"},
                        {"type": "misconfiguration", "title": "SECRET_KEY exposed", "severity": "critical"}],
            "flask": [{"type": "misconfiguration", "title": "DEBUG=True in production", "severity": "high"}],
            "php": [{"type": "cve", "title": "PHP vulnerabilities (version-dependent)", "severity": "medium"}],
        }
        weaknesses = tech_db.get(tech.lower(), [])
        self._set_cache("tech", tech, {"weaknesses": weaknesses}, ttl=604800)
        return weaknesses
