"""
WRAITH v2.0 — Attack Graph Engine
Graph-based attack path reasoning. Takes findings from all agents and builds
a directed graph of the attack surface: targets → services → vulnerabilities → attack paths.

Uses adjacency list representation (stdlib only). Supports:
- Building attack graphs from agent findings
- Finding attack paths (initial access → full compromise)
- MITRE ATT&CK mapping for each node/edge
- Criticality scoring
- Export to JSON for D3.js visualization
- Export to Mermaid for reports
"""

import json
from collections import defaultdict, deque
from typing import Optional


# ── MITRE ATT&CK mapping: finding keywords → technique IDs ──
MITRE_MAP = {
    "open_port": "T1046",
    "service_discovery": "T1046",
    "port_scan": "T1046",
    "sql_injection": "T1190",
    "sqli": "T1190",
    "xss": "T1190",
    "cross_site_scripting": "T1190",
    "ssrf": "T1190",
    "rce": "T1190",
    "remote_code_execution": "T1190",
    "default_credentials": "T1078",
    "weak_password": "T1078",
    "credential": "T1078",
    "command_injection": "T1059",
    "code_execution": "T1059",
    "file_inclusion": "T1059",
    "secrets_exposed": "T1081",
    "credentials_in_files": "T1081",
    "api_key_exposed": "T1081",
    "directory_listing": "T1083",
    "information_disclosure": "T1083",
    "network_sniffing": "T1040",
    "credential_dump": "T1003",
    "c2": "T1071",
    "command_and_control": "T1071",
    "proxy": "T1090",
    "remote_desktop": "T1021",
    "lateral_movement": "T1021",
    "scheduled_task": "T1053",
    "system_info": "T1082",
    "user_discovery": "T1033",
    "privilege_escalation": "T1069",
    "process_injection": "T1055",
    "indicator_removal": "T1070",
    "account_manipulation": "T1098",
    "data_exfiltration": "T1048",
    "exfiltration": "T1048",
    "missing_header": "A05",
    "security_misconfiguration": "A05",
    "broken_access_control": "A01",
    "auth_bypass": "A01",
    "tls_weak": "A02",
    "crypto_weak": "A02",
    "outdated_software": "A06",
    "vulnerable_component": "A06",
    "admin_panel_exposed": "A01",
    "backup_exposed": "A01",
    "debug_enabled": "A05",
    "cors_misconfig": "A05",
    "cookie_secure_missing": "A05",
    "cookie_httponly_missing": "A05",
}

SEVERITY_SCORES = {
    "critical": 10, "high": 8, "medium": 5, "low": 2, "info": 0
}


class AttackPath:
    """A single attack path through the graph."""

    def __init__(self, nodes=None, edges=None, confidence=1.0, cumulative_risk=0.0):
        self.nodes = nodes or []
        self.edges = edges or []
        self.confidence = confidence
        self.cumulative_risk = cumulative_risk
        self.mitre_chain = []

    @property
    def effectiveness(self) -> float:
        if not self.nodes:
            return 0.0
        return round((self.cumulative_risk * self.confidence) / max(len(self.nodes), 1), 2)

    def to_report(self) -> str:
        lines = [f"**Attack Path** (Risk: {self.cumulative_risk:.0f}/10, Confidence: {self.confidence:.0%})"]
        for i, node in enumerate(self.nodes):
            severity = node.get("severity", "info").upper()
            lines.append(f"  {i+1}. [{severity}] {node.get('label', node.get('id', 'unknown'))} ({node.get('type', 'unknown')})")
            if i < len(self.edges):
                lines.append(f"      ↓ {self.edges[i].get('label', 'leads to')} ({self.edges[i].get('confidence', 1):.0%} confidence)")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "nodes": self.nodes,
            "edges": self.edges,
            "confidence": self.confidence,
            "cumulative_risk": self.cumulative_risk,
            "effectiveness": self.effectiveness,
            "mitre_chain": self.mitre_chain,
        }


class AttackGraph:
    """
    Attack graph for reasoning about multi-stage attack paths.
    Supports 8 node types: target, service, vulnerability, credential,
    technique, finding, config, exfiltration.
    """

    def __init__(self, target: str = ""):
        self.target = target
        self.nodes: dict = {}
        self.edges: dict = defaultdict(list)  # from_id → [{to, label, confidence}]
        self._reverse_edges: dict = defaultdict(list)

    def add_node(self, node_id: str, node_type: str, label: str,
                 data: dict = None, mitre_technique: str = None,
                 severity: str = "info") -> dict:
        self.nodes[node_id] = {
            "id": node_id, "type": node_type, "label": label,
            "data": data or {}, "mitre_technique": mitre_technique,
            "severity": severity, "severity_score": SEVERITY_SCORES.get(severity, 0),
        }
        return self.nodes[node_id]

    def add_edge(self, from_id: str, to_id: str, label: str = "", confidence: float = 1.0):
        if from_id not in self.nodes:
            self.add_node(from_id, "unknown", from_id)
        if to_id not in self.nodes:
            self.add_node(to_id, "unknown", to_id)
        edge = {"to": to_id, "label": label, "confidence": confidence}
        self.edges[from_id].append(edge)
        self._reverse_edges[to_id].append({"from": from_id, "label": label, "confidence": confidence})

    def build_from_findings(self, findings: list, target: str = ""):
        """Bulk-load from agent finding dicts. Auto-maps to MITRE ATT&CK."""
        self.target = target or self.target
        target_id = "target:" + (self.target or "unknown")
        self.add_node(target_id, "target", self.target or "Unknown Target")

        for i, finding in enumerate(findings):
            ftype = finding.get("type", "unknown").lower().replace(" ", "_")
            severity = finding.get("severity", "info")
            finding_id = f"finding_{i}"
            mitre = None
            for keyword, technique in MITRE_MAP.items():
                if keyword in ftype:
                    mitre = technique
                    break
            self.add_node(finding_id, "finding", finding.get("title", ftype),
                          data=finding, mitre_technique=mitre, severity=severity)
            self.add_edge(target_id, finding_id, "has finding", confidence=1.0)
            # Cross-link findings by shared mitre technique
            for j in range(i):
                prev = f"finding_{j}"
                prev_node = self.nodes.get(prev, {})
                if prev_node.get("mitre_technique") and prev_node["mitre_technique"] == mitre:
                    self.add_edge(prev, finding_id, f"same technique: {mitre}", confidence=0.8)

    def get_attack_paths(self, source_type: str = "target",
                         target_type: str = "finding", max_depth: int = 10) -> list:
        """Find all attack paths from source to target type. Returns ranked AttackPath list."""
        sources = [nid for nid, n in self.nodes.items() if n["type"] == source_type]
        targets = {nid for nid, n in self.nodes.items() if n["type"] == target_type}
        if not sources or not targets:
            return []

        paths = []
        for src in sources:
            # BFS with path tracking
            queue = deque([(src, [src], [], 1.0, 0.0)])
            visited_global = set()
            while queue:
                current, path, edge_list, conf, risk = queue.popleft()
                if current in targets and len(path) > 1:
                    node_objs = [self.nodes[n] for n in path]
                    path_obj = AttackPath(nodes=node_objs, edges=edge_list,
                                          confidence=conf, cumulative_risk=risk)
                    path_obj.mitre_chain = list({n.get("mitre_technique") for n in node_objs if n.get("mitre_technique")})
                    paths.append(path_obj)
                if len(path) >= max_depth:
                    continue
                for edge in self.edges.get(current, []):
                    nxt = edge["to"]
                    if nxt not in path:
                        nxt_node = self.nodes.get(nxt, {})
                        queue.append((nxt, path + [nxt], edge_list + [edge],
                                      conf * edge.get("confidence", 1.0),
                                      risk + nxt_node.get("severity_score", 0)))
        paths.sort(key=lambda p: p.effectiveness, reverse=True)
        return paths[:50]  # return top 50

    def get_critical_nodes(self, top_n: int = 5) -> list:
        """Find nodes that appear in the most attack paths (bottlenecks)."""
        paths = self.get_attack_paths()
        node_counts = defaultdict(int)
        for path in paths:
            for node in path.nodes:
                node_counts[node["id"]] += 1
        sorted_nodes = sorted(node_counts.items(), key=lambda x: x[1], reverse=True)
        return [{"node": self.nodes[nid], "path_count": count} for nid, count in sorted_nodes[:top_n] if nid in self.nodes]

    def get_mitre_coverage(self) -> dict:
        """Report MITRE ATT&CK technique coverage."""
        techniques = set()
        for node in self.nodes.values():
            mitre = node.get("mitre_technique")
            if mitre:
                techniques.add(mitre)
        all_mittech = set(MITRE_MAP.values())
        return {
            "covered": sorted(techniques),
            "coverage_pct": round(len(techniques) / max(len(all_mittech), 1) * 100, 1),
            "total_known": len(all_mittech),
            "gaps": sorted(all_mittech - techniques),
        }

    def get_risk_score(self) -> int:
        """Overall risk score: 0-100 based on severity, connectivity, paths."""
        if not self.nodes:
            return 0
        severity_score = max((n.get("severity_score", 0) for n in self.nodes.values()), default=0)
        connectivity = min(len(self.edges) * 2, 20)
        paths = self.get_attack_paths()
        path_diversity = min(len(paths) * 4, 20)
        mitre = self.get_mitre_coverage()
        kill_chain = min(mitre["coverage_pct"] / 5, 20)
        total = min(severity_score * 4 + connectivity + path_diversity + kill_chain, 100)
        return int(total)

    def shortest_path(self, src: str, tgt: str) -> Optional[list]:
        """Dijkstra's shortest path using inverse confidence as weight."""
        import heapq
        dist = {src: 0}
        prev = {}
        pq = [(0, src)]
        while pq:
            d, u = heapq.heappop(pq)
            if u == tgt:
                path = []
                while u in prev:
                    path.append(u)
                    u = prev[u]
                path.append(src)
                return list(reversed(path))
            if d > dist.get(u, float('inf')):
                continue
            for edge in self.edges.get(u, []):
                w = 1.0 / max(edge.get("confidence", 0.01), 0.01)
                nd = d + w
                v = edge["to"]
                if nd < dist.get(v, float('inf')):
                    dist[v] = nd
                    prev[v] = u
                    heapq.heappush(pq, (nd, v))
        return None

    def to_d3_json(self) -> dict:
        """Export for D3.js force-directed graph."""
        nodes = []
        id_to_idx = {}
        for i, (nid, node) in enumerate(self.nodes.items()):
            id_to_idx[nid] = i
            severity = node.get("severity", "info")
            color = {"critical": "#ff2d55", "high": "#ff6b35", "medium": "#ffaa00",
                     "low": "#00ff9d", "info": "#66667a"}.get(severity, "#66667a")
            nodes.append({"id": nid, "label": node.get("label", nid),
                          "type": node["type"], "severity": severity, "color": color,
                          "risk": node.get("severity_score", 0)})
        links = []
        for from_id, edge_list in self.edges.items():
            if from_id not in id_to_idx:
                continue
            for edge in edge_list:
                if edge["to"] in id_to_idx:
                    links.append({"source": id_to_idx[from_id], "target": id_to_idx[edge["to"]],
                                  "label": edge.get("label", ""), "confidence": edge.get("confidence", 1.0)})
        return {"nodes": nodes, "links": links, "target": self.target,
                "risk_score": self.get_risk_score(), "mitre_coverage": self.get_mitre_coverage()}

    def to_mermaid(self) -> str:
        """Export as Mermaid flowchart."""
        lines = ["graph TD"]
        for nid, node in self.nodes.items():
            label = node.get("label", nid).replace(" ", "_")[:30]
            severity = node.get("severity", "info")
            shape = {"critical": f'["{label}"]', "high": f'("{label}")', "medium": f'[{label}]',
                     "low": f'({label})', "info": f'{label}'}.get(severity, f'{label}')
            lines.append(f'    {nid}{shape}')
        for from_id, edge_list in self.edges.items():
            for edge in edge_list:
                label = edge.get("label", "")[:20]
                conf = edge.get("confidence", 1.0)
                style = "==>" if conf > 0.8 else "-->"
                lines.append(f'    {from_id} {style}|{label}| {edge["to"]}')
        return "\n".join(lines)

    def generate_report(self) -> str:
        """Generate Markdown report."""
        risk = self.get_risk_score()
        mitre = self.get_mitre_coverage()
        critical = self.get_critical_nodes()
        paths = self.get_attack_paths()
        lines = [
            f"# WRAITH Attack Graph Report: {self.target}",
            f"",
            f"**Risk Score:** {risk}/100",
            f"**Nodes:** {len(self.nodes)} | **Edges:** {sum(len(e) for e in self.edges.values())}",
            f"**MITRE ATT&CK Coverage:** {mitre['coverage_pct']}% ({len(mitre['covered'])}/{mitre['total_known']} techniques)",
            f"",
            f"## Top Attack Paths",
        ]
        for i, path in enumerate(paths[:10]):
            lines.append(f"\n### Path {i+1} (Effectiveness: {path.effectiveness})")
            lines.append(path.to_report())
        if critical:
            lines.append("\n## Critical Nodes (Bottlenecks)")
            for cn in critical:
                n = cn["node"]
                lines.append(f"- [{n['severity'].upper()}] {n['label']} — appears in {cn['path_count']} attack paths")
        lines.append(f"\n## MITRE ATT&CK Techniques Covered")
        for t in mitre["covered"]:
            lines.append(f"- {t}")
        return "\n".join(lines)

    def __repr__(self):
        return f"AttackGraph(target={self.target}, nodes={len(self.nodes)}, edges={sum(len(e) for e in self.edges.values())})"


def build_attack_graph_from_orchestrator(results: dict, target: str) -> AttackGraph:
    """Build an attack graph from orchestrator results (multi-agent output)."""
    graph = AttackGraph(target=target)
    all_findings = []
    for agent_name, result in results.items():
        if isinstance(result, dict):
            findings = result.get("findings", [])
            all_findings.extend(findings)
    graph.build_from_findings(all_findings, target)
    return graph
