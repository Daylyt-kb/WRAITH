"""
WRAITH Self-Evolving Memory System

This is what makes WRAITH impossible to replicate or catch up with.
Every scan, every user interaction, every task solved makes WRAITH smarter.

Architecture:
- Per-user memory: learns how each user works, what they test, how they remediate
- Cross-user intelligence (anonymized): patterns from all users improve everyone
- Task-solving chains: remembers HOW each task was solved, reuses successful patterns
- Adaptive tool selection: learns which tools work best for which targets
- Open source → Private flow: free users contribute to paid version intelligence
- Persistent: survives restarts, updates, migrations
"""

import os
import json
import hashlib
import sqlite3
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from pathlib import Path


class WraithMemory:
    """
    Self-evolving memory system for WRAITH.
    Stores task-solving patterns, user preferences, and cross-user intelligence.
    """

    def __init__(self, db_path: str = None, user_id: str = "local"):
        self.user_id = user_id
        self.db_path = db_path or os.path.join(
            os.environ.get("WRAITH_DATA_DIR", "./wraith_output"),
            "memory.db"
        )
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initialize the SQLite database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS task_memory (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    task_type TEXT NOT NULL,
                    target TEXT,
                    target_type TEXT,
                    tools_used TEXT,  -- JSON array
                    agent_sequence TEXT,  -- JSON array
                    outcome TEXT,  -- success/partial/failure
                    findings_count INTEGER DEFAULT 0,
                    duration_seconds REAL,
                    techniques TEXT,  -- JSON array of techniques used
                    patterns_found TEXT,  -- JSON array of vulnerability patterns
                    remediation_suggestions TEXT,  -- JSON array
                    raw_summary TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS user_preferences (
                    user_id TEXT PRIMARY KEY,
                    preferred_tools TEXT,  -- JSON object {tool: frequency}
                    preferred_agents TEXT,  -- JSON object {agent: frequency}
                    common_targets TEXT,  -- JSON array
                    scan_frequency TEXT,  -- daily/weekly/monthly
                    report_format TEXT,  -- markdown/pdf/both
                    ai_provider TEXT,
                    ai_model TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS tool_effectiveness (
                    tool TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    success_count INTEGER DEFAULT 0,
                    fail_count INTEGER DEFAULT 0,
                    avg_duration REAL,
                    common_findings TEXT,  -- JSON array
                    last_used TEXT,
                    PRIMARY KEY (tool, target_type)
                );

                CREATE TABLE IF NOT EXISTS vulnerability_patterns (
                    id TEXT PRIMARY KEY,
                    pattern_type TEXT NOT NULL,
                    target_type TEXT,
                    description TEXT,
                    severity TEXT,
                    detection_method TEXT,
                    remediation TEXT,
                    discovered_by TEXT,  -- user_id or 'global'
                    confirmed_count INTEGER DEFAULT 1,
                    false_positive_count INTEGER DEFAULT 0,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS agent_knowledge (
                    agent_name TEXT NOT NULL,
                    knowledge_type TEXT NOT NULL,
                    content TEXT NOT NULL,
                    confidence REAL DEFAULT 0.5,
                    source TEXT,  -- 'user', 'global', 'cve', 'attack_db'
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (agent_name, knowledge_type, source)
                );

                CREATE INDEX IF NOT EXISTS idx_task_user ON task_memory(user_id);
                CREATE INDEX IF NOT EXISTS idx_task_type ON task_memory(task_type);
                CREATE INDEX IF NOT EXISTS idx_task_target ON task_memory(target_type);
                CREATE INDEX IF NOT EXISTS idx_vuln_type ON vulnerability_patterns(pattern_type);
                CREATE INDEX IF NOT EXISTS idx_tool_target ON tool_effectiveness(tool, target_type);
            """)

    # ── Task Memory ──

    def record_task(self, task_data: Dict[str, Any]) -> str:
        """Record a completed task for future learning."""
        task_id = hashlib.sha256(
            f"{self.user_id}{task_data.get('target', '')}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]

        now = datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO task_memory
                (id, user_id, task_type, target, target_type, tools_used,
                 agent_sequence, outcome, findings_count, duration_seconds,
                 techniques, patterns_found, remediation_suggestions,
                 raw_summary, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                task_id, self.user_id,
                task_data.get("task_type", "scan"),
                task_data.get("target", ""),
                task_data.get("target_type", "unknown"),
                json.dumps(task_data.get("tools_used", [])),
                json.dumps(task_data.get("agent_sequence", [])),
                task_data.get("outcome", "success"),
                task_data.get("findings_count", 0),
                task_data.get("duration_seconds", 0),
                json.dumps(task_data.get("techniques", [])),
                json.dumps(task_data.get("patterns_found", [])),
                json.dumps(task_data.get("remediation_suggestions", [])),
                task_data.get("raw_summary", ""),
                now, now,
            ))

        # Update tool effectiveness
        for tool in task_data.get("tools_used", []):
            self._update_tool_effectiveness(
                tool,
                task_data.get("target_type", "unknown"),
                task_data.get("outcome") == "success",
                task_data.get("duration_seconds", 0),
                task_data.get("patterns_found", [])
            )

        # Update user preferences
        self._update_user_preferences(task_data)

        return task_id

    def get_similar_tasks(self, target_type: str, task_type: str = "scan",
                          limit: int = 5) -> List[Dict]:
        """Find similar past tasks to inform current approach."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT * FROM task_memory
                WHERE target_type = ? AND task_type = ? AND outcome = 'success'
                ORDER BY findings_count DESC, created_at DESC
                LIMIT ?
            """, (target_type, task_type, limit)).fetchall()

        return [dict(row) for row in rows]

    def get_recommended_tools(self, target_type: str) -> List[Dict]:
        """Get the most effective tools for a target type, based on history."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT tool, target_type, success_count, fail_count, avg_duration
                FROM tool_effectiveness
                WHERE target_type = ?
                ORDER BY success_count DESC, avg_duration ASC
            """, (target_type,)).fetchall()

        return [dict(row) for row in rows]

    def get_recommended_approach(self, target: str, target_type: str) -> Dict[str, Any]:
        """
        Based on past experience, recommend the best approach for a target.
        This is the core of self-evolution: WRAITH learns what works.
        """
        similar = self.get_similar_tasks(target_type)
        if not similar:
            return {"confidence": 0, "recommendation": "default"}

        # Find the most successful approach
        best = max(similar, key=lambda x: x.get("findings_count", 0))

        return {
            "confidence": min(len(similar) / 10.0, 1.0),  # More data = more confidence
            "recommended_agents": json.loads(best.get("agent_sequence", "[]")),
            "recommended_tools": json.loads(best.get("tools_used", "[]")),
            "expected_findings": best.get("findings_count", 0),
            "common_techniques": json.loads(best.get("techniques", "[]")),
            "common_patterns": json.loads(best.get("patterns_found", "[]")),
            "based_on_scans": len(similar),
        }

    # ── Tool Effectiveness ──

    def _update_tool_effectiveness(self, tool: str, target_type: str,
                                    success: bool, duration: float,
                                    findings: List[str]):
        """Update tool effectiveness tracking."""
        with sqlite3.connect(self.db_path) as conn:
            existing = conn.execute(
                "SELECT * FROM tool_effectiveness WHERE tool = ? AND target_type = ?",
                (tool, target_type)
            ).fetchone()

            if existing:
                success_count = existing[2] + (1 if success else 0)
                fail_count = existing[3] + (0 if success else 1)
                avg_dur = ((existing[4] or 0) + duration) / 2
                common = json.loads(existing[5] or "[]")
                common.extend(findings)
                common = list(set(common))[:50]  # Keep last 50 unique

                conn.execute("""
                    UPDATE tool_effectiveness
                    SET success_count = ?, fail_count = ?, avg_duration = ?,
                        common_findings = ?, last_used = ?
                    WHERE tool = ? AND target_type = ?
                """, (success_count, fail_count, avg_dur, json.dumps(common),
                      datetime.now().isoformat(), tool, target_type))
            else:
                conn.execute("""
                    INSERT INTO tool_effectiveness
                    (tool, target_type, success_count, fail_count, avg_duration,
                     common_findings, last_used)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (tool, target_type,
                      1 if success else 0, 0 if success else 1,
                      duration, json.dumps(findings[:20]),
                      datetime.now().isoformat()))

    # ── User Preferences ──

    def _update_user_preferences(self, task_data: Dict):
        """Learn user preferences from their behavior."""
        with sqlite3.connect(self.db_path) as conn:
            existing = conn.execute(
                "SELECT * FROM user_preferences WHERE user_id = ?",
                (self.user_id,)
            ).fetchone()

            now = datetime.now().isoformat()

            if existing:
                # Update preferences based on frequency
                tools = json.loads(existing[1] or "{}")
                agents = json.loads(existing[2] or "{}")
                targets = json.loads(existing[3] or "[]")

                for tool in task_data.get("tools_used", []):
                    tools[tool] = tools.get(tool, 0) + 1
                for agent in task_data.get("agent_sequence", []):
                    agents[agent] = agents.get(agent, 0) + 1

                target = task_data.get("target", "")
                if target and target not in targets:
                    targets.append(target)
                targets = targets[-50:]  # Keep last 50

                conn.execute("""
                    UPDATE user_preferences
                    SET preferred_tools = ?, preferred_agents = ?,
                        common_targets = ?, updated_at = ?
                    WHERE user_id = ?
                """, (json.dumps(tools), json.dumps(agents),
                      json.dumps(targets), now, self.user_id))
            else:
                conn.execute("""
                    INSERT INTO user_preferences
                    (user_id, preferred_tools, preferred_agents, common_targets,
                     scan_frequency, report_format, ai_provider, ai_model,
                     created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    self.user_id,
                    json.dumps({t: 1 for t in task_data.get("tools_used", [])}),
                    json.dumps({a: 1 for a in task_data.get("agent_sequence", [])}),
                    json.dumps([task_data.get("target", "")]),
                    "weekly", "markdown",
                    os.environ.get("WRAITH_AI_PROVIDER", "ollama"),
                    os.environ.get("WRAITH_AI_MODEL", "llama3.1"),
                    now, now,
                ))

    def get_user_profile(self) -> Dict[str, Any]:
        """Get the learned profile for the current user."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM user_preferences WHERE user_id = ?",
                (self.user_id,)
            ).fetchone()

        if not row:
            return {"user_id": self.user_id, "scans": 0}

        return {
            "user_id": self.user_id,
            "preferred_tools": json.loads(row["preferred_tools"] or "{}"),
            "preferred_agents": json.loads(row["preferred_agents"] or "{}"),
            "common_targets": json.loads(row["common_targets"] or "[]"),
            "scan_frequency": row["scan_frequency"],
            "report_format": row["report_format"],
            "ai_provider": row["ai_provider"],
            "ai_model": row["ai_model"],
        }

    # ── Vulnerability Patterns ──

    def record_pattern(self, pattern: Dict[str, Any]) -> str:
        """Record a discovered vulnerability pattern."""
        pid = hashlib.sha256(
            f"{pattern.get('pattern_type', '')}{pattern.get('target_type', '')}{pattern.get('description', '')}".encode()
        ).hexdigest()[:12]

        now = datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            existing = conn.execute(
                "SELECT * FROM vulnerability_patterns WHERE id = ?", (pid,)
            ).fetchone()

            if existing:
                conn.execute("""
                    UPDATE vulnerability_patterns
                    SET confirmed_count = confirmed_count + 1,
                        last_seen = ?
                    WHERE id = ?
                """, (now, pid))
            else:
                conn.execute("""
                    INSERT INTO vulnerability_patterns
                    (id, pattern_type, target_type, description, severity,
                     detection_method, remediation, discovered_by,
                     first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    pid, pattern.get("pattern_type", ""),
                    pattern.get("target_type", ""),
                    pattern.get("description", ""),
                    pattern.get("severity", "medium"),
                    pattern.get("detection_method", ""),
                    pattern.get("remediation", ""),
                    self.user_id, now, now,
                ))

        return pid

    def get_patterns(self, target_type: str = None, severity: str = None) -> List[Dict]:
        """Get known vulnerability patterns, optionally filtered."""
        query = "SELECT * FROM vulnerability_patterns WHERE 1=1"
        params = []
        if target_type:
            query += " AND target_type = ?"
            params.append(target_type)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY confirmed_count DESC, last_seen DESC"

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()

        return [dict(row) for row in rows]

    # ── Agent Knowledge ──

    def teach_agent(self, agent_name: str, knowledge_type: str,
                    content: str, confidence: float = 0.8, source: str = "user"):
        """Teach an agent new knowledge."""
        now = datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO agent_knowledge
                (agent_name, knowledge_type, content, confidence, source,
                 created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (agent_name, knowledge_type, content, confidence, source, now, now))

    def get_agent_knowledge(self, agent_name: str,
                            knowledge_type: str = None) -> List[Dict]:
        """Get knowledge for an agent."""
        query = "SELECT * FROM agent_knowledge WHERE agent_name = ?"
        params = [agent_name]
        if knowledge_type:
            query += " AND knowledge_type = ?"
            params.append(knowledge_type)
        query += " ORDER BY confidence DESC, updated_at DESC"

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()

        return [dict(row) for row in rows]

    # ── Statistics ──

    def get_stats(self) -> Dict[str, Any]:
        """Get memory system statistics."""
        with sqlite3.connect(self.db_path) as conn:
            tasks = conn.execute("SELECT COUNT(*) FROM task_memory").fetchone()[0]
            patterns = conn.execute("SELECT COUNT(*) FROM vulnerability_patterns").fetchone()[0]
            tools = conn.execute("SELECT COUNT(*) FROM tool_effectiveness").fetchone()[0]
            knowledge = conn.execute("SELECT COUNT(*) FROM agent_knowledge").fetchone()[0]
            success_rate = conn.execute(
                "SELECT AVG(CASE WHEN outcome='success' THEN 1.0 ELSE 0.0 END) FROM task_memory"
            ).fetchone()[0]

        return {
            "total_tasks_recorded": tasks,
            "vulnerability_patterns_known": patterns,
            "tools_tracked": tools,
            "knowledge_entries": knowledge,
            "overall_success_rate": round(success_rate or 0, 2),
            "user_id": self.user_id,
        }

    # ── Export for Private Repo (Anonymized) ──

    def export_anonymized_patterns(self) -> Dict[str, Any]:
        """
        Export anonymized patterns for the private repo.
        Strips user IDs and target specifics, keeps only patterns and techniques.
        This is how the open source version makes the paid version smarter.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            # Get tool effectiveness (already anonymized)
            tools = conn.execute(
                "SELECT * FROM tool_effectiveness ORDER BY success_count DESC LIMIT 100"
            ).fetchall()

            # Get vulnerability patterns (strip user IDs)
            patterns = conn.execute(
                "SELECT pattern_type, target_type, severity, detection_method, "
                "remediation, confirmed_count FROM vulnerability_patterns "
                "ORDER BY confirmed_count DESC LIMIT 200"
            ).fetchall()

            # Get common techniques from successful scans
            techniques = conn.execute(
                "SELECT techniques, patterns_found FROM task_memory "
                "WHERE outcome = 'success' ORDER BY created_at DESC LIMIT 100"
            ).fetchall()

        return {
            "exported_at": datetime.now().isoformat(),
            "tool_effectiveness": [dict(t) for t in tools],
            "vulnerability_patterns": [dict(p) for p in patterns],
            "common_techniques": [
                {
                    "techniques": json.loads(t["techniques"] or "[]"),
                    "patterns": json.loads(t["patterns_found"] or "[]"),
                }
                for t in techniques
            ],
        }
