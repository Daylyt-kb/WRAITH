"""
WRAITH v3.0 — Upgraded Agent Tests
Tests for ScannerAgent, ForgeAgent, AttackGraph, ComplianceMapper,
RiskCalculator, and PredictionEngine.

Uses unittest.mock for all network calls. Uses pytest fixtures.
"""

import sys
import os
import json
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, r"C:\Users\Kebro\Documents\wraith\private")

import pytest


# ═══════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp(prefix="wraith_test_")
    yield d
    import shutil
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def mock_scope():
    from core.scope import ScopeValidator
    return ScopeValidator("example.com")


@pytest.fixture
def mock_bus():
    from core.bus import MessageBus
    return MessageBus()


@pytest.fixture
def sample_findings():
    return [
        {
            "type": "open_port",
            "title": "Port 443 (HTTPS) open: nginx/1.24",
            "severity": "info",
            "tool": "SCANNER",
            "data": {"port": 443, "service": "HTTPS", "banner": "nginx/1.24",
                     "risks": ["weak_tls", "cert_issues"], "tls_version": "TLSv1.3"},
        },
        {
            "type": "open_port",
            "title": "Port 6379 (Redis) open: redis 6.2",
            "severity": "high",
            "tool": "SCANNER",
            "data": {"port": 6379, "service": "Redis", "banner": "redis 6.2",
                     "risks": ["no_auth", "exposed", "rce_risk"]},
        },
        {
            "type": "sensitive_path",
            "title": "Sensitive path exposed: http://example.com/.env (200)",
            "severity": "critical",
            "tool": "SCANNER",
            "data": {"url": "http://example.com/.env", "path": ".env", "status": 200},
        },
        {
            "type": "cve_match",
            "title": "[CVE-2017-0144] EternalBlue: Remote code execution via SMBv1",
            "severity": "critical",
            "tool": "FORGE",
            "data": {"cve_id": "CVE-2017-0144", "cvss": 8.1, "exploit_type": "rce",
                     "mitre": "T1210", "port": 445},
        },
    ]


# ═══════════════════════════════════════════════════════════════
# TEST SCANNER AGENT
# ═══════════════════════════════════════════════════════════════

class TestScannerAgent:
    """Tests for ScannerAgent: init, port scanning, banner grabbing, SSL, result format, PORT_VULN_MAP."""

    def test_scanner_init(self, mock_bus):
        from agents.scanner import ScannerAgent
        agent = ScannerAgent(bus=mock_bus)
        assert agent.name == "scanner"
        assert agent.version == "3.0.0"
        assert agent.category == "recon"
        assert agent.risk_level == "medium"
        assert agent.pro_only is False

    def test_scanner_metadata(self, mock_bus):
        from agents.scanner import ScannerAgent
        agent = ScannerAgent(bus=mock_bus)
        meta = agent.to_dict()
        assert meta["name"] == "scanner"
        assert "nmap" in meta["tools"]
        assert meta["sandbox_profile"] == "recon"

    def test_port_vuln_map_populated(self):
        from agents.scanner import PORT_VULN_MAP
        assert len(PORT_VULN_MAP) >= 20
        assert 443 in PORT_VULN_MAP
        assert 6379 in PORT_VULN_MAP
        assert "risks" in PORT_VULN_MAP[443]
        assert "weak_tls" in PORT_VULN_MAP[443]["risks"]

    def test_port_vuln_map_redis(self):
        from agents.scanner import PORT_VULN_MAP
        redis = PORT_VULN_MAP[6379]
        assert redis["name"] == "Redis"
        assert "no_auth" in redis["risks"]
        assert "rce_risk" in redis["risks"]

    @patch("agents.scanner.socket.socket")
    def test_port_scan_open_port(self, mock_socket_cls, mock_bus):
        from agents.scanner import ScannerAgent
        agent = ScannerAgent(bus=mock_bus)
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock
        open_ports = agent._scan_ports("127.0.0.1", ports=[80, 443], max_threads=2, timeout=0.1)
        assert 80 in open_ports
        assert 443 in open_ports

    @patch("agents.scanner.socket.socket")
    def test_port_scan_closed_port(self, mock_socket_cls, mock_bus):
        from agents.scanner import ScannerAgent
        agent = ScannerAgent(bus=mock_bus)
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111
        mock_socket_cls.return_value = mock_sock
        open_ports = agent._scan_ports("127.0.0.1", ports=[9999], max_threads=1, timeout=0.1)
        assert 9999 not in open_ports

    @patch("agents.scanner.socket.socket")
    def test_port_scan_handles_oserror(self, mock_socket_cls, mock_bus):
        from agents.scanner import ScannerAgent
        agent = ScannerAgent(bus=mock_bus)
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = OSError("mock error")
        mock_socket_cls.return_value = mock_sock
        open_ports = agent._scan_ports("127.0.0.1", ports=[80], max_threads=1, timeout=0.1)
        assert open_ports == []

    @patch("agents.scanner.socket.socket")
    def test_banner_grabbing(self, mock_socket_cls, mock_bus):
        from agents.scanner import ScannerAgent
        agent = ScannerAgent(bus=mock_bus)
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
        mock_socket_cls.return_value = mock_sock
        info = agent._analyze_port("127.0.0.1", 22)
        assert "SSH" in info["banner"]
        assert info["tls_version"] is None

    @patch("agents.scanner.socket.socket")
    @patch("agents.scanner.ssl.create_default_context")
    def test_ssl_analysis(self, mock_ssl_ctx, mock_socket_cls, mock_bus):
        from agents.scanner import ScannerAgent
        agent = ScannerAgent(bus=mock_bus)
        mock_ssock = MagicMock()
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.getpeercert.return_value = {"subject": "example.com", "issuer": "Let's Encrypt"}
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
        mock_ssl_ctx.return_value = mock_ctx
        info = agent._analyze_port("127.0.0.1", 443)
        assert info["tls_version"] == "TLSv1.3"
        assert info["cipher"] == "TLS_AES_256_GCM_SHA384"

    def test_result_format(self, mock_bus, mock_scope):
        from agents.scanner import ScannerAgent
        agent = ScannerAgent(bus=mock_bus)
        with patch.object(agent, "_dns_check", return_value=(None, [])), \
             patch.object(agent, "_scan_ports", return_value=[]), \
             patch.object(agent, "_check_web_paths", return_value=[]), \
             patch.object(agent, "_enumerate_subdomains", return_value=[]):
            result = agent.run("example.com", mock_scope)
        assert "agent" in result
        assert result["agent"] == "scanner"
        assert "target" in result
        assert "findings" in result
        assert "summary" in result
        assert "finding_count" in result
        assert isinstance(result["findings"], list)

    def test_scanner_run_with_open_ports(self, mock_bus, mock_scope):
        from agents.scanner import ScannerAgent
        agent = ScannerAgent(bus=mock_bus)
        with patch.object(agent, "_dns_check", return_value=("93.184.216.34", [])), \
             patch.object(agent, "_scan_ports", return_value=[80, 443]), \
             patch.object(agent, "_analyze_port", return_value={"banner": "nginx", "tls_version": None, "cipher": None}), \
             patch.object(agent, "_check_web_paths", return_value=[]), \
             patch.object(agent, "_enumerate_subdomains", return_value=[]):
            result = agent.run("example.com", mock_scope)
        assert result["finding_count"] >= 2
        ports_found = [f["data"]["port"] for f in result["findings"] if f["type"] == "open_port"]
        assert 80 in ports_found
        assert 443 in ports_found

    def test_scanner_high_severity_for_dangerous_ports(self, mock_bus, mock_scope):
        from agents.scanner import ScannerAgent
        agent = ScannerAgent(bus=mock_bus)
        with patch.object(agent, "_dns_check", return_value=("1.2.3.4", [])), \
             patch.object(agent, "_scan_ports", return_value=[6379]), \
             patch.object(agent, "_analyze_port", return_value={"banner": "redis", "tls_version": None, "cipher": None}), \
             patch.object(agent, "_check_web_paths", return_value=[]), \
             patch.object(agent, "_enumerate_subdomains", return_value=[]):
            result = agent.run("example.com", mock_scope)
        redis_findings = [f for f in result["findings"] if f["data"].get("port") == 6379]
        assert len(redis_findings) > 0
        assert redis_findings[0]["severity"] == "high"


# ═══════════════════════════════════════════════════════════════
# TEST FORGE AGENT
# ═══════════════════════════════════════════════════════════════

class TestForgeAgent:
    """Tests for ForgeAgent: init, CVE cross-reference, exploit chains, risk, PoC, remediation."""

    def test_forge_init(self, mock_bus):
        from agents.forge import ForgeAgent
        agent = ForgeAgent(bus=mock_bus)
        assert agent.name == "forge"
        assert agent.version == "3.0.0"
        assert agent.category == "exploitation"
        assert agent.risk_level == "medium"

    def test_forge_metadata(self, mock_bus):
        from agents.forge import ForgeAgent
        agent = ForgeAgent(bus=mock_bus)
        meta = agent.to_dict()
        assert meta["name"] == "forge"
        assert "searchsploit" in meta["tools"]

    def test_cve_db_populated(self):
        from agents.forge import CVE_DB
        assert len(CVE_DB) >= 10
        assert "CVE-2017-0144" in CVE_DB
        assert "CVE-2019-0708" in CVE_DB
        assert CVE_DB["CVE-2017-0144"]["cvss"] == 8.1

    def test_cve_cross_reference(self, mock_bus, sample_findings):
        from agents.forge import ForgeAgent
        agent = ForgeAgent(bus=mock_bus)
        cve_findings = agent._cross_reference_cves(sample_findings)
        assert isinstance(cve_findings, list)
        assert len(cve_findings) > 0
        for cf in cve_findings:
            assert "cve_id" in cf["data"]
            assert "cvss" in cf["data"]

    def test_cve_cross_reference_matches_port(self, mock_bus):
        from agents.forge import ForgeAgent
        agent = ForgeAgent(bus=mock_bus)
        findings = [{"type": "open_port", "title": "Port 445 open", "severity": "high",
                     "tool": "SCANNER", "data": {"port": 445, "service": "SMB", "banner": ""}}]
        cve_findings = agent._cross_reference_cves(findings)
        cve_ids = [cf["data"]["cve_id"] for cf in cve_findings]
        assert "CVE-2017-0144" in cve_ids

    def test_exploit_chain_building(self, mock_bus, sample_findings):
        from agents.forge import ForgeAgent
        agent = ForgeAgent(bus=mock_bus)
        chains = agent._build_exploit_chains("example.com", sample_findings)
        assert isinstance(chains, list)
        assert len(chains) > 0
        for chain in chains:
            assert "steps" in chain
            assert "severity" in chain
            assert "confidence" in chain
            assert "narrative" in chain
            assert "chain" in chain

    def test_combined_risk_calculation(self, mock_bus, sample_findings):
        from agents.forge import ForgeAgent
        agent = ForgeAgent(bus=mock_bus)
        risk = agent._calculate_combined_risk(sample_findings)
        assert 0.0 <= risk <= 1.0
        assert risk > 0.0

    def test_combined_risk_empty(self, mock_bus):
        from agents.forge import ForgeAgent
        agent = ForgeAgent(bus=mock_bus)
        assert agent._calculate_combined_risk([]) == 0.0

    def test_poc_generation(self, mock_bus):
        from agents.forge import ForgeAgent
        agent = ForgeAgent(bus=mock_bus)
        finding = {"type": "cve_match", "title": "RCE on port 80", "severity": "critical",
                   "data": {"port": 80, "exploit_type": "rce"}}
        poc = agent.generate_poc_description(finding)
        assert "Remote Code Execution" in poc
        assert "80" in poc

    def test_poc_generation_credential(self, mock_bus):
        from agents.forge import ForgeAgent
        agent = ForgeAgent(bus=mock_bus)
        finding = {"type": "credential", "title": "Weak creds", "severity": "high",
                   "data": {"port": 22, "exploit_type": "credential"}}
        poc = agent.generate_poc_description(finding)
        assert "Credential" in poc

    def test_remediation_generation(self, mock_bus):
        from agents.forge import ForgeAgent
        agent = ForgeAgent(bus=mock_bus)
        finding = {"type": "open_port", "title": "Port 6379 open", "severity": "high",
                   "data": {"port": 6379}}
        rem = agent.generate_remediation(finding)
        assert "6379" in rem
        assert len(rem) > 20

    def test_remediation_sqli(self, mock_bus):
        from agents.forge import ForgeAgent
        agent = ForgeAgent(bus=mock_bus)
        finding = {"type": "injection", "title": "SQL injection", "severity": "critical",
                   "data": {"port": 443}}
        rem = agent.generate_remediation(finding)
        assert "parameterized" in rem.lower() or "ORM" in rem

    def test_forge_run_integration(self, mock_bus, mock_scope, sample_findings):
        from agents.forge import ForgeAgent
        agent = ForgeAgent(bus=mock_bus)
        with patch("core.attack_graph.AttackGraph") as MockGraph:
            mock_graph = MagicMock()
            mock_graph.get_risk_score.return_value = 65
            mock_graph.get_mitre_coverage.return_value = {"coverage_pct": 30.0}
            mock_graph.nodes = {}
            MockGraph.return_value = mock_graph
            input_findings = [dict(f) for f in sample_findings]
            input_len = len(input_findings)
            result = agent.run("example.com", mock_scope, scanner_findings=input_findings)
        assert result["agent"] == "forge"
        assert "findings" in result
        assert result["finding_count"] >= input_len

    def test_get_cve_context(self, mock_bus):
        from agents.forge import ForgeAgent
        agent = ForgeAgent(bus=mock_bus)
        ctx = agent.get_cve_context("CVE-2017-0144")
        assert ctx["name"] == "EternalBlue"
        assert ctx["cvss"] == 8.1

    def test_get_cve_context_unknown(self, mock_bus):
        from agents.forge import ForgeAgent
        agent = ForgeAgent(bus=mock_bus)
        ctx = agent.get_cve_context("CVE-9999-9999")
        assert ctx["name"] == "Unknown"


# ═══════════════════════════════════════════════════════════════
# TEST ATTACK GRAPH
# ═══════════════════════════════════════════════════════════════

class TestAttackGraph:
    """Tests for AttackGraph: node/edge creation, build_from_findings, paths, risk, D3, Mermaid."""

    def test_graph_init(self):
        from core.attack_graph import AttackGraph
        g = AttackGraph(target="example.com")
        assert g.target == "example.com"
        assert len(g.nodes) == 0

    def test_add_node(self):
        from core.attack_graph import AttackGraph
        g = AttackGraph(target="example.com")
        node = g.add_node("n1", "target", "Example", severity="high")
        assert "n1" in g.nodes
        assert node["type"] == "target"
        assert node["severity"] == "high"
        assert node["severity_score"] == 8

    def test_add_edge(self):
        from core.attack_graph import AttackGraph
        g = AttackGraph(target="example.com")
        g.add_node("a", "target", "A")
        g.add_node("b", "finding", "B")
        g.add_edge("a", "b", "leads to", confidence=0.9)
        assert "a" in g.edges
        assert len(g.edges["a"]) == 1
        assert g.edges["a"][0]["to"] == "b"

    def test_add_edge_auto_creates_nodes(self):
        from core.attack_graph import AttackGraph
        g = AttackGraph(target="example.com")
        g.add_edge("x", "y", "test")
        assert "x" in g.nodes
        assert "y" in g.nodes

    def test_build_from_findings(self, sample_findings):
        from core.attack_graph import AttackGraph
        g = AttackGraph(target="example.com")
        g.build_from_findings(sample_findings, "example.com")
        assert len(g.nodes) > 0
        assert "target:example.com" in g.nodes
        assert any(n["type"] == "finding" for n in g.nodes.values())

    def test_build_from_findings_mitre_mapping(self):
        from core.attack_graph import AttackGraph
        g = AttackGraph(target="example.com")
        findings = [{"type": "sql_injection", "title": "SQLi", "severity": "critical",
                     "tool": "test", "data": {}}]
        g.build_from_findings(findings, "example.com")
        finding_nodes = [n for n in g.nodes.values() if n["type"] == "finding"]
        assert len(finding_nodes) > 0
        assert finding_nodes[0]["mitre_technique"] == "T1190"

    def test_get_attack_paths(self, sample_findings):
        from core.attack_graph import AttackGraph
        g = AttackGraph(target="example.com")
        g.build_from_findings(sample_findings, "example.com")
        paths = g.get_attack_paths()
        assert isinstance(paths, list)
        assert len(paths) > 0
        for p in paths:
            assert len(p.nodes) > 0
            assert p.confidence > 0

    def test_get_attack_paths_empty(self):
        from core.attack_graph import AttackGraph
        g = AttackGraph(target="example.com")
        paths = g.get_attack_paths()
        assert paths == []

    def test_risk_score(self, sample_findings):
        from core.attack_graph import AttackGraph
        g = AttackGraph(target="example.com")
        g.build_from_findings(sample_findings, "example.com")
        score = g.get_risk_score()
        assert 0 <= score <= 100
        assert score > 0

    def test_risk_score_empty(self):
        from core.attack_graph import AttackGraph
        g = AttackGraph(target="example.com")
        assert g.get_risk_score() == 0

    def test_to_d3_json(self, sample_findings):
        from core.attack_graph import AttackGraph
        g = AttackGraph(target="example.com")
        g.build_from_findings(sample_findings, "example.com")
        d3 = g.to_d3_json()
        assert "nodes" in d3
        assert "links" in d3
        assert "target" in d3
        assert "risk_score" in d3
        assert "mitre_coverage" in d3
        assert len(d3["nodes"]) > 0
        for node in d3["nodes"]:
            assert "id" in node
            assert "color" in node

    def test_to_mermaid(self, sample_findings):
        from core.attack_graph import AttackGraph
        g = AttackGraph(target="example.com")
        g.build_from_findings(sample_findings, "example.com")
        mermaid = g.to_mermaid()
        assert mermaid.startswith("graph TD")
        assert "example.com" in mermaid

    def test_mitre_coverage(self, sample_findings):
        from core.attack_graph import AttackGraph
        g = AttackGraph(target="example.com")
        g.build_from_findings(sample_findings, "example.com")
        coverage = g.get_mitre_coverage()
        assert "covered" in coverage
        assert "coverage_pct" in coverage
        assert "total_known" in coverage
        assert "gaps" in coverage
        assert isinstance(coverage["covered"], list)

    def test_critical_nodes(self, sample_findings):
        from core.attack_graph import AttackGraph
        g = AttackGraph(target="example.com")
        g.build_from_findings(sample_findings, "example.com")
        critical = g.get_critical_nodes(top_n=3)
        assert isinstance(critical, list)
        for cn in critical:
            assert "node" in cn
            assert "path_count" in cn

    def test_shortest_path(self):
        from core.attack_graph import AttackGraph
        g = AttackGraph(target="example.com")
        g.add_node("a", "target", "A")
        g.add_node("b", "finding", "B")
        g.add_node("c", "finding", "C")
        g.add_edge("a", "b", confidence=0.9)
        g.add_edge("b", "c", confidence=0.8)
        path = g.shortest_path("a", "c")
        assert path is not None
        assert path[0] == "a"
        assert path[-1] == "c"

    def test_generate_report(self, sample_findings):
        from core.attack_graph import AttackGraph
        g = AttackGraph(target="example.com")
        g.build_from_findings(sample_findings, "example.com")
        report = g.generate_report()
        assert "Attack Graph Report" in report
        assert "example.com" in report
        assert "Risk Score" in report

    def test_build_from_orchestrator(self, sample_findings):
        from core.attack_graph import build_attack_graph_from_orchestrator
        results = {"scanner": {"findings": sample_findings}}
        g = build_attack_graph_from_orchestrator(results, "example.com")
        assert g.target == "example.com"
        assert len(g.nodes) > 0


# ═══════════════════════════════════════════════════════════════
# TEST COMPLIANCE MAPPER
# ═══════════════════════════════════════════════════════════════

class TestComplianceMapper:
    """Tests for ComplianceMapper: map_finding, generate_compliance_report, get_compliance_score."""

    def test_mapper_init(self):
        from core.compliance_mapper import ComplianceMapper
        m = ComplianceMapper()
        assert len(m.frameworks) >= 5

    def test_mapper_init_custom_frameworks(self):
        from core.compliance_mapper import ComplianceMapper
        m = ComplianceMapper(frameworks=["owasp_top10_2025", "nist_csf"])
        assert len(m.frameworks) == 2

    def test_map_finding_sqli(self):
        from core.compliance_mapper import ComplianceMapper
        m = ComplianceMapper()
        finding = {"type": "sql_injection", "title": "SQLi in login", "severity": "critical"}
        result = m.map_finding(finding)
        assert result["finding_type"] == "sql_injection"
        assert "owasp_top10_2025" in result["mappings"]
        assert "nist_csf" in result["mappings"]

    def test_map_finding_xss(self):
        from core.compliance_mapper import ComplianceMapper
        m = ComplianceMapper()
        finding = {"type": "xss", "title": "Reflected XSS", "severity": "high"}
        result = m.map_finding(finding)
        assert "owasp_top10_2025" in result["mappings"]

    def test_map_finding_unknown_type(self):
        from core.compliance_mapper import ComplianceMapper
        m = ComplianceMapper()
        finding = {"type": "unknown_type_xyz", "title": "Unknown", "severity": "info"}
        result = m.map_finding(finding)
        assert result["mappings"] == {}

    def test_generate_compliance_report(self, sample_findings):
        from core.compliance_mapper import ComplianceMapper
        m = ComplianceMapper()
        report = m.generate_compliance_report(sample_findings)
        assert "frameworks" in report
        assert "overall_scores" in report
        assert "findings_count" in report
        assert report["findings_count"] == len(sample_findings)
        assert "generated_at" in report

    def test_compliance_report_has_frameworks(self, sample_findings):
        from core.compliance_mapper import ComplianceMapper
        m = ComplianceMapper()
        report = m.generate_compliance_report(sample_findings)
        assert len(report["frameworks"]) > 0
        for fw_key, fw_data in report["frameworks"].items():
            assert "name" in fw_data
            assert "compliance_score" in fw_data
            assert "controls_failed" in fw_data

    def test_get_compliance_score(self, sample_findings):
        from core.compliance_mapper import ComplianceMapper
        m = ComplianceMapper()
        score = m.get_compliance_score(sample_findings, "owasp_top10_2025")
        assert 0.0 <= score <= 100.0

    def test_get_compliance_score_empty(self):
        from core.compliance_mapper import ComplianceMapper
        m = ComplianceMapper()
        score = m.get_compliance_score([], "nist_csf")
        assert score == 100.0

    def test_get_gaps(self, sample_findings):
        from core.compliance_mapper import ComplianceMapper
        m = ComplianceMapper()
        gaps = m.get_gaps(sample_findings, "owasp_top10_2025")
        assert isinstance(gaps, list)

    def test_get_remediation_for_control(self):
        from core.compliance_mapper import ComplianceMapper
        m = ComplianceMapper()
        rem = m.get_remediation_for_control("A03:2021-Injection", "owasp_top10_2025")
        assert len(rem) > 20
        assert "parameterized" in rem.lower() or "ORM" in rem

    def test_export_compliance_markdown(self, sample_findings):
        from core.compliance_mapper import ComplianceMapper
        m = ComplianceMapper()
        md = m.export_compliance_markdown(sample_findings)
        assert "# WRAITH Compliance Report" in md
        assert "Findings:" in md


# ═══════════════════════════════════════════════════════════════
# TEST RISK CALCULATOR
# ═══════════════════════════════════════════════════════════════

class TestRiskCalculator:
    """Tests for RiskCalculator: risk scores, breach cost, annualized loss."""

    def test_calculator_init(self):
        from core.risk_calculator import RiskCalculator
        rc = RiskCalculator()
        assert rc.industry == "default"
        assert rc.company_size == "medium"

    def test_calculator_init_custom(self):
        from core.risk_calculator import RiskCalculator
        rc = RiskCalculator(industry="healthcare", company_size="enterprise")
        assert rc.industry == "healthcare"
        assert rc.company_size == "enterprise"

    def test_risk_score(self, sample_findings):
        from core.risk_calculator import RiskCalculator
        rc = RiskCalculator()
        result = rc.calculate_risk_score(sample_findings)
        assert "score" in result
        assert "level" in result
        assert "breakdown" in result
        assert 0 <= result["score"] <= 100
        assert result["level"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_risk_score_empty(self):
        from core.risk_calculator import RiskCalculator
        rc = RiskCalculator()
        result = rc.calculate_risk_score([])
        assert result["score"] == 0
        assert result["level"] == "LOW"

    def test_risk_score_critical_level(self):
        from core.risk_calculator import RiskCalculator
        rc = RiskCalculator()
        findings = [{"type": "rce", "severity": "critical"} for _ in range(5)]
        result = rc.calculate_risk_score(findings)
        assert result["level"] == "CRITICAL"

    def test_loss_event_frequency(self, sample_findings):
        from core.risk_calculator import RiskCalculator
        rc = RiskCalculator()
        freq = rc.calculate_loss_event_frequency(sample_findings)
        assert freq > 0.0
        assert freq <= 20.0

    def test_loss_event_frequency_empty(self):
        from core.risk_calculator import RiskCalculator
        rc = RiskCalculator()
        assert rc.calculate_loss_event_frequency([]) == 0.0

    def test_loss_magnitude(self, sample_findings):
        from core.risk_calculator import RiskCalculator
        rc = RiskCalculator()
        mag = rc.calculate_loss_magnitude(sample_findings)
        assert mag > 0.0

    def test_annualized_loss(self, sample_findings):
        from core.risk_calculator import RiskCalculator
        rc = RiskCalculator()
        ale = rc.calculate_annualized_loss(sample_findings)
        assert "loss_event_frequency_per_year" in ale
        assert "loss_magnitude_per_event_usd" in ale
        assert "annualized_loss_expectancy_usd" in ale
        assert ale["annualized_loss_expectancy_usd"] >= 0

    def test_estimate_breach_cost(self, sample_findings):
        from core.risk_calculator import RiskCalculator
        rc = RiskCalculator()
        cost = rc.estimate_breach_cost(sample_findings)
        assert "estimated_breach_cost_usd" in cost
        assert "estimated_breach_cost_formatted" in cost
        assert "cost_per_record_usd" in cost
        assert "risk_score" in cost
        assert cost["estimated_breach_cost_usd"] > 0

    def test_industry_benchmark(self):
        from core.risk_calculator import RiskCalculator
        rc = RiskCalculator()
        bench = rc.get_industry_benchmark(60, "healthcare")
        assert "your_score" in bench
        assert "industry_average" in bench
        assert "comparison" in bench
        assert bench["comparison"] in ("above", "below", "at")

    def test_prioritize_by_risk(self, sample_findings):
        from core.risk_calculator import RiskCalculator
        rc = RiskCalculator()
        prioritized = rc.prioritize_by_risk(sample_findings)
        assert len(prioritized) == len(sample_findings)
        for f in prioritized:
            assert "_risk_score" in f

    def test_executive_summary(self, sample_findings):
        from core.risk_calculator import RiskCalculator
        rc = RiskCalculator()
        summary = rc.generate_executive_summary(sample_findings)
        assert "Executive Security Summary" in summary
        assert "Risk Level" in summary
        assert "Business Impact" in summary


# ═══════════════════════════════════════════════════════════════
# TEST PREDICTION ENGINE
# ═══════════════════════════════════════════════════════════════

class TestPredictionEngine:
    """Tests for PredictionEngine: tech stack analysis, config deviation, predict_vulnerabilities."""

    def test_engine_init(self, temp_dir):
        from core.prediction_engine import PredictionEngine
        db_path = os.path.join(temp_dir, "predictions.db")
        engine = PredictionEngine(db_path=db_path)
        assert os.path.exists(db_path)

    def test_tech_vuln_matrix_populated(self):
        from core.prediction_engine import PredictionEngine
        assert "nginx" in PredictionEngine.TECH_VULN_MATRIX
        assert "redis" in PredictionEngine.TECH_VULN_MATRIX
        assert "wordpress" in PredictionEngine.TECH_VULN_MATRIX

    def test_analyze_tech_stack_nginx(self, temp_dir):
        from core.prediction_engine import PredictionEngine
        engine = PredictionEngine(db_path=os.path.join(temp_dir, "pred.db"))
        predictions = engine.analyze_tech_stack(["nginx/1.24", "php 8.1"])
        assert len(predictions) > 0
        for p in predictions:
            assert "type" in p
            assert "probability" in p
            assert "severity" in p
            assert 0.0 <= p["probability"] <= 1.0

    def test_analyze_tech_stack_redis(self, temp_dir):
        from core.prediction_engine import PredictionEngine
        engine = PredictionEngine(db_path=os.path.join(temp_dir, "pred.db"))
        predictions = engine.analyze_tech_stack(["redis 6.2"])
        types = [p["type"] for p in predictions]
        assert "no_auth" in types

    def test_analyze_tech_stack_empty(self, temp_dir):
        from core.prediction_engine import PredictionEngine
        engine = PredictionEngine(db_path=os.path.join(temp_dir, "pred.db"))
        predictions = engine.analyze_tech_stack([])
        assert predictions == []

    def test_config_deviation_missing_headers(self, temp_dir):
        from core.prediction_engine import PredictionEngine
        engine = PredictionEngine(db_path=os.path.join(temp_dir, "pred.db"))
        observed = {"content-type": "text/html", "server": "nginx"}
        deviations = engine.check_config_deviation(observed)
        assert len(deviations) > 0
        missing_headers = [d["header"] for d in deviations if d["type"] == "missing_header"]
        assert "strict-transports-security" in missing_headers

    def test_config_deviation_dangerous_headers(self, temp_dir):
        from core.prediction_engine import PredictionEngine
        engine = PredictionEngine(db_path=os.path.join(temp_dir, "pred.db"))
        observed = {"server": "nginx/1.24", "x-powered-by": "PHP/8.1"}
        deviations = engine.check_config_deviation(observed)
        info_disclosures = [d for d in deviations if d["type"] == "info_disclosure"]
        assert len(info_disclosures) > 0

    def test_config_deviation_empty(self, temp_dir):
        from core.prediction_engine import PredictionEngine
        engine = PredictionEngine(db_path=os.path.join(temp_dir, "pred.db"))
        assert engine.check_config_deviation({}) == []
        assert engine.check_config_deviation(None) == []

    def test_predict_vulnerabilities(self, temp_dir):
        from core.prediction_engine import PredictionEngine
        engine = PredictionEngine(db_path=os.path.join(temp_dir, "pred.db"))
        profile = {
            "target": "example.com",
            "tech_stack": ["nginx", "php"],
            "headers": {"server": "nginx"},
        }
        predictions = engine.predict_vulnerabilities(profile)
        assert len(predictions) > 0
        for p in predictions:
            assert "type" in p
            assert "probability" in p
            assert "source" in p

    def test_predict_vulnerabilities_with_history(self, temp_dir):
        from core.prediction_engine import PredictionEngine
        engine = PredictionEngine(db_path=os.path.join(temp_dir, "pred.db"))
        profile = {"target": "example.com", "tech_stack": [], "headers": {}, "target_type": "web_app"}
        history = [{"target_type": "web_app", "common_vulns": ["xss", "sqli"], "scan_count": 50}]
        predictions = engine.predict_vulnerabilities(profile, historical_data=history)
        sources = [p["source"] for p in predictions]
        assert "historical_pattern" in sources

    def test_generate_hypotheses_report(self, temp_dir):
        from core.prediction_engine import PredictionEngine
        engine = PredictionEngine(db_path=os.path.join(temp_dir, "pred.db"))
        profile = {"target": "example.com", "tech_stack": ["nginx", "redis"]}
        report = engine.generate_hypotheses_report(profile)
        assert "Prediction Report" in report
        assert "example.com" in report
        assert "nginx" in report

    def test_security_baselines_defined(self):
        from core.prediction_engine import PredictionEngine
        assert "http_headers" in PredictionEngine.SECURITY_BASELINES
        assert "strict-transports-security" in PredictionEngine.SECURITY_BASELINES["http_headers"]
