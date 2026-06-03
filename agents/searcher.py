"""
SEARCHER — Web Search Intelligence Agent
Searches the web for security intelligence: CVEs, exploits, advisories, threat intel.
Uses DuckDuckGo (free, no API key) as primary search engine.
Stores findings in Supabase knowledge base for WRAITH's learning system.
"""

import json
import re
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from agents.base import WraithAgent


class SearcherAgent(WraithAgent):
    """
    SEARCHER — Web Search Intelligence Agent
    Searches the web for security intelligence and stores findings
    in Supabase knowledge base for WRAITH's learning system.
    """
    name = "searcher"
    version = "2.0.0"
    description = "Web search — hunts security intelligence from the web"
    category = "osint"
    tools = ["duckduckgo", "web_search"]
    sandbox_profile = None
    risk_level = "low"

    # Search categories and their query templates
    SEARCH_TEMPLATES = {
        "cve": "site:cve.mitre.org OR site:nvd.nist.gov {query} 2025 2026",
        "exploit": "site:exploit-db.com OR site:github.com/exploit {query}",
        "advisory": "security advisory {query} 2025 2026",
        "threat_intel": "threat intelligence {query} 2025",
        "technique": "MITRE ATT&CK {query} technique",
        "vulnerability": "{query} vulnerability CVE exploit",
        "default": "security {query} 2025",
    }

    def run(self, query: str, category: str = "default") -> dict:
        """
        Search the web for security intelligence.

        Args:
            query: Search query (e.g., "Apache RCE", "WordPress XSS")
            category: Search category (cve, exploit, advisory, threat_intel, technique)

        Returns:
            dict with search results and stored knowledge entries
        """
        start = datetime.now()
        findings = []

        self.logger.info(f"SEARCHER: Searching for '{query}' in category '{category}'")

        # Build search query
        template = self.SEARCH_TEMPLATES.get(category, self.SEARCH_TEMPLATES["default"])
        search_query = template.format(query=query)

        # Try DuckDuckGo first (free, no API key)
        results = self._search_duckduckgo(search_query)

        if not results:
            # Fallback: try alternative search
            results = self._search_fallback(search_query)

        for r in results:
            findings.append({
                "type": "web_intel",
                "title": r.get("title", ""),
                "severity": "info",
                "tool": "SEARCHER",
                "data": {
                    "url": r.get("url", ""),
                    "snippet": r.get("snippet", "")[:300],
                    "query": query,
                    "category": category,
                }
            })

        # Store findings in Supabase knowledge base
        stored = 0
        if findings:
            try:
                from core.supabase_store import get_store
                store = get_store()
                for f in findings:
                    store.store_knowledge(
                        keyword=query,
                        content=f["data"]["snippet"],
                        source_url=f["data"]["url"],
                    )
                    stored += 1
            except Exception as e:
                self.logger.warning(f"Failed to store knowledge: {self.name}")

        self.emit("search_complete", {"query": query, "findings": findings})

        summary = f"Found {len(findings)} results for '{query}' ({stored} stored)"
        return self._make_result(query, findings, summary, start,
                                  category=category, stored=stored)

    def _search_duckduckgo(self, query: str) -> list:
        """Search using DuckDuckGo (free, no API key needed)."""
        try:
            from duckduckgo_search import DDGS
            with DDGS() as ddgs:
                results = list(ddgs.text(query, max_results=10))
                return [
                    {"title": r.get("title", ""), "url": r.get("href", ""),
                     "snippet": r.get("body", "")}
                    for r in results
                ]
        except ImportError:
            self.logger.info("duckduckgo_search not installed, using fallback")
            return self._search_fallback(query)
        except Exception as e:
            self.logger.warning(f"DuckDuckGo search failed: {e}")
            return self._search_fallback(query)

    def _search_fallback(self, query: str) -> list:
        """Fallback search using urllib (no external dependencies)."""
        try:
            # Use DuckDuckGo HTML interface
            encoded = urllib.parse.quote(query)
            url = f"https://html.duckduckgo.com/html/?q={encoded}"
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (compatible; WRAITH-SEARCHER/2.0)"
            })
            with urllib.request.urlopen(req, timeout=10) as resp:
                html = resp.read().decode("utf-8", errors="ignore")

            results = []
            # Parse result links and snippets
            result_blocks = re.findall(
                r'<a rel="nofollow" class="result__a" href="([^"]+)">(.*?)</a>',
                html
            )
            snippets = re.findall(
                r'<a class="result__snippet"[^>]*>(.*?)</a>',
                html
            )

            for i, (link, title) in enumerate(result_blocks[:10]):
                title = re.sub(r'<[^>]+>', '', title).strip()
                snippet = re.sub(r'<[^>]+>', '', snippets[i] if i < len(snippets) else "").strip()
                if title and link:
                    # Decode DuckDuckGo redirect URLs
                    if link.startswith("//duckduckgo.com/l/?"):
                        parsed = urllib.parse.parse_qs(urllib.parse.urlparse(link).query)
                        link = parsed.get("uddg", [link])[0]
                    results.append({"title": title, "url": link, "snippet": snippet})

            return results
        except Exception as e:
            self.logger.warning(f"Fallback search failed: {e}")
            return []
