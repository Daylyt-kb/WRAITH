"""
NEURON — Self-Upgrade Intelligence Agent
Local SQLite knowledge base. Hourly CVE + ATT&CK + ExploitDB feeds.
"""

import json, time, sqlite3, urllib.request, urllib.error, threading, re
from datetime import datetime, timedelta
from pathlib import Path
from agents.base import WraithAgent

KNOWLEDGE_DIR = Path(__file__).parent.parent / "wraith_output" / "knowledge"
DB_PATH = KNOWLEDGE_DIR / "neuron.db"


class NeuronAgent(WraithAgent):
    name = "neuron"
    version = "2.0.0"
    description = "Self-upgrade — learns new CVEs and techniques 24/7"
    category = "intelligence"
    tools = []
    sandbox_profile = None
    risk_level = "low"

    def __init__(self, bus=None, **kwargs):
        super().__init__(bus=bus, **kwargs)
        self.name = "NEURON"
        self.running = False
        self._lock = threading.Lock()
        KNOWLEDGE_DIR.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS cves (
                    id TEXT PRIMARY KEY,
                    description TEXT,
                    severity TEXT,
                    score REAL,
                    published TEXT,
                    modified TEXT,
                    fetched_at TEXT,
                    keywords TEXT
                );
                CREATE TABLE IF NOT EXISTS techniques (
                    id TEXT PRIMARY KEY,
                    name TEXT,
                    tactic TEXT,
                    description TEXT,
                    platforms TEXT,
                    fetched_at TEXT
                );
                CREATE TABLE IF NOT EXISTS exploits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT,
                    url TEXT,
                    published TEXT,
                    fetched_at TEXT
                );
                CREATE TABLE IF NOT EXISTS mission_learnings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mission_id TEXT,
                    target TEXT,
                    finding_type TEXT,
                    finding_title TEXT,
                    severity TEXT,
                    tool TEXT,
                    timestamp TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_cve_sev ON cves(severity);
                CREATE INDEX IF NOT EXISTS idx_cve_pub ON cves(published);
            """)

    def _conn(self):
        return sqlite3.connect(str(DB_PATH), timeout=10)

    def run(self, target: str, scope) -> dict:
        start = datetime.now()
        fetched = self.fetch_latest(limit_cves=30)
        summary = f"CVEs: {fetched['cves']} | ATT&CK: {fetched['techniques']} | Exploits: {fetched['exploits']}"
        if self.bus:
            self.bus.emit("neuron_updated", fetched)
        return {
            "agent": "NEURON", "target": target,
            "timestamp": start.isoformat(),
            "duration_seconds": (datetime.now() - start).seconds,
            "findings": [], "summary": summary, "finding_count": 0, "stats": fetched
        }

    def fetch_latest(self, limit_cves: int = 50) -> dict:
        stats = {"cves": 0, "techniques": 0, "exploits": 0, "errors": []}
        for name, fn in [
            ("NVD CVEs", lambda: self._fetch_nvd(limit_cves)),
            ("MITRE ATT&CK", lambda: self._fetch_mitre()),
            ("ExploitDB", lambda: self._fetch_exploitdb()),
        ]:
            try:
                n = fn()
                key = "cves" if "CVE" in name else "techniques" if "MITRE" in name else "exploits"
                stats[key] = n
                print(f"  [NEURON] {name}: {n}")
            except Exception as e:
                stats["errors"].append(f"{name}: {str(e)[:80]}")
                print(f"  [NEURON] {name} error: {str(e)[:80]}")
        return stats

    def search(self, keyword: str, limit: int = 10) -> dict:
        kw = keyword.lower().strip()
        results = {"cves": [], "techniques": [], "keyword": keyword}
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, description, severity, score, published FROM cves "
                "WHERE lower(description) LIKE ? OR lower(keywords) LIKE ? "
                "ORDER BY score DESC, published DESC LIMIT ?",
                (f"%{kw}%", f"%{kw}%", limit)
            ).fetchall()
            results["cves"] = [
                {"id": r[0], "description": r[1][:200], "severity": r[2],
                 "score": r[3], "published": r[4]} for r in rows
            ]
            rows = conn.execute(
                "SELECT id, name, tactic, description FROM techniques "
                "WHERE lower(name) LIKE ? OR lower(description) LIKE ? LIMIT 5",
                (f"%{kw}%", f"%{kw}%")
            ).fetchall()
            results["techniques"] = [
                {"id": r[0], "name": r[1], "tactic": r[2],
                 "description": (r[3] or "")[:150]} for r in rows
            ]
        return results

    def get_critical_cves(self, days_back: int = 30, limit: int = 20) -> list:
        since = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%d")
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, description, severity, score, published FROM cves "
                "WHERE severity IN ('CRITICAL','HIGH') AND published >= ? "
                "ORDER BY score DESC LIMIT ?",
                (since, limit)
            ).fetchall()
        return [{"id": r[0], "description": r[1][:200], "severity": r[2],
                 "score": r[3], "published": r[4]} for r in rows]

    def store_mission_learning(self, mission_id: str, target: str, findings: list):
        with self._conn() as conn:
            for f in findings:
                conn.execute(
                    "INSERT OR IGNORE INTO mission_learnings "
                    "(mission_id,target,finding_type,finding_title,severity,tool,timestamp) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (mission_id, target, f.get("type",""), f.get("title","")[:200],
                     f.get("severity","info"), f.get("tool",""), datetime.utcnow().isoformat())
                )

    def stats(self) -> dict:
        with self._conn() as conn:
            def q(sql): return conn.execute(sql).fetchone()[0]
            return {
                "cves": q("SELECT COUNT(*) FROM cves"),
                "critical_cves": q("SELECT COUNT(*) FROM cves WHERE severity='CRITICAL'"),
                "techniques": q("SELECT COUNT(*) FROM techniques"),
                "exploits": q("SELECT COUNT(*) FROM exploits"),
                "mission_learnings": q("SELECT COUNT(*) FROM mission_learnings"),
                "db_path": str(DB_PATH)
            }

    def start_loop(self, interval_seconds: int = 3600):
        if self.running:
            return
        self.running = True
        def _loop():
            while self.running:
                try:
                    self.fetch_latest()
                except Exception as e:
                    print(f"  [NEURON] Loop error: {e}")
                time.sleep(interval_seconds)
        threading.Thread(target=_loop, daemon=True, name="NEURON-loop").start()
        print(f"  [NEURON] Self-upgrade loop started (every {interval_seconds//60}m)")

    def stop_loop(self):
        self.running = False

    def _fetch_nvd(self, limit: int = 50) -> int:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage={min(limit,2000)}&startIndex=0"
        req = urllib.request.Request(url, headers={"User-Agent": "WRAITH-NEURON/1.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
        count = 0
        with self._conn() as conn:
            for item in data.get("vulnerabilities", [])[:limit]:
                cve = item.get("cve", {})
                cid = cve.get("id", "")
                if not cid:
                    continue
                desc = next((d["value"] for d in cve.get("descriptions",[]) if d.get("lang")=="en"), "")
                m = cve.get("metrics", {})
                v3 = m.get("cvssMetricV31",[]) or m.get("cvssMetricV30",[])
                v2 = m.get("cvssMetricV2",[])
                cd = (v3[0].get("cvssData",{}) if v3 else v2[0].get("cvssData",{}) if v2 else {})
                sev = cd.get("baseSeverity","UNKNOWN")
                score = cd.get("baseScore", 0.0)
                kw = f"{cid} {desc[:400]} {sev}".lower()
                conn.execute(
                    "INSERT OR REPLACE INTO cves (id,description,severity,score,published,modified,fetched_at,keywords) VALUES (?,?,?,?,?,?,?,?)",
                    (cid, desc[:500], sev, score, cve.get("published","")[:10],
                     cve.get("lastModified","")[:10], datetime.utcnow().isoformat(), kw[:1000])
                )
                count += 1
        return count

    def _fetch_mitre(self, limit: int = 100) -> int:
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        req = urllib.request.Request(url, headers={"User-Agent": "WRAITH-NEURON/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        count = 0
        with self._conn() as conn:
            for obj in data.get("objects", []):
                if obj.get("type") != "attack-pattern": continue
                if obj.get("revoked") or obj.get("x_mitre_deprecated"): continue
                tid = next((r.get("external_id","") for r in obj.get("external_references",[])
                           if r.get("source_name")=="mitre-attack"), "")
                if not tid: continue
                tactics = [p.get("phase_name","") for p in obj.get("kill_chain_phases",[])]
                conn.execute(
                    "INSERT OR REPLACE INTO techniques (id,name,tactic,description,platforms,fetched_at) VALUES (?,?,?,?,?,?)",
                    (tid, obj.get("name",""), ", ".join(tactics),
                     obj.get("description","")[:500],
                     json.dumps(obj.get("x_mitre_platforms",[])),
                     datetime.utcnow().isoformat())
                )
                count += 1
                if count >= limit: break
        return count

    def _fetch_exploitdb(self) -> int:
        req = urllib.request.Request(
            "https://www.exploit-db.com/rss.xml",
            headers={"User-Agent": "WRAITH-NEURON/1.0", "Accept": "application/rss+xml"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
        items = re.findall(r'<item>(.*?)</item>', content, re.DOTALL)
        count = 0
        with self._conn() as conn:
            for item in items[:50]:
                tm = re.search(r'<title>(.*?)</title>', item)
                lm = re.search(r'<link>(.*?)</link>', item)
                dm = re.search(r'<pubDate>(.*?)</pubDate>', item)
                if not tm: continue
                title = tm.group(1).replace("<![CDATA[","").replace("]]>","").strip()
                conn.execute(
                    "INSERT OR IGNORE INTO exploits (title,url,published,fetched_at) VALUES (?,?,?,?)",
                    (title[:200], (lm.group(1).strip() if lm else "")[:200],
                     (dm.group(1).strip()[:30] if dm else ""),
                     datetime.utcnow().isoformat())
                )
                count += 1
        return count
