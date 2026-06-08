"""Tests for WRAITH v3.0 new core modules."""

import sys
sys.path.insert(0, r'C:\Users\Kebro\Documents\wraith\private')

import pytest
from unittest.mock import patch, MagicMock
from core.attack_graph import AttackGraph, MITRE_MAP, SEVERITY_SCORES
from core.compliance_mapper import ComplianceMapper, FINDING_TO_CONTROLS
from core.risk_calculator import RiskCalculator
from core.prediction_engine import PredictionEngine
from core.threat_intel import ThreatIntel


class TestAttackGraph:
    def test_create_graph(self):
        g = AttackGraph("example.com")
        assert g.target == "example.com"
        assert len(g.nodes) == 0

    def test_add_node(self):
        g = AttackGraph("test.com")
        node = g.add_node("n1", "target", "test.com", {"ip": "1.2.3.4"})
        assert "n1" in g.nodes
        assert g.nodes["n1"]["type"] == "target"

    def test_add_edge(self):
        g = AttackGraph("test.com")
        g.add_node("a", "target", "a.com")
        g.add_node("b", "vulnerability", "SQLi")
        g.add_edge("a", "b", "has_vuln", 0.9)
        assert len(g.edges["a"]) == 1
        assert g.edges["a"][0]["confidence"] == 0.9

    def test_build_from_findings(self):
        g = AttackGraph("test.com")
        findings = [
            {"type": "sql_injection", "title": "SQLi", "severity": "critical"},
            {"type": "missing_header", "title": "No HSTS", "severity": "medium"},
        ]
        g.build_from_findings(findings, "test.com")
        assert len(g.nodes) == 3  # target + 2 findings

    def test_risk_score(self):
        g = AttackGraph("test.com")
        g.build_from_findings([
            {"type": "sql_injection", "title": "SQLi", "severity": "critical"},
        ], "test.com")
        score = g.get_risk_score()
        assert 0 <= score <= 100

    def test_mitre_coverage(self):
        g = AttackGraph("test.com")
        g.build_from_findings([
            {"type": "sql_injection", "title": "SQLi", "severity": "critical"},
        ], "test.com")
        coverage = g.get_mitre_coverage()
        assert "covered" in coverage
        assert "coverage_pct" in coverage

    def test_to_d3_json(self):
        g = AttackGraph("test.com")
        g.build_from_findings([{"type": "sql_injection", "title": "SQLi", "severity": "high"}], "test.com")
        d3 = g.to_d3_json()
        assert "nodes" in d3
        assert "links" in d3
        assert len(d3["nodes"]) > 0

    def test_to_mermaid(self):
        g = AttackGraph("test.com")
        g.build_from_findings([{"type": "sql_injection", "title": "SQLi", "severity": "high"}], "test.com")
        mermaid = g.to_mermaid()
        assert "graph TD" in mermaid

    def test_attack_paths(self):
        g = AttackGraph("test.com")
        g.build_from_findings([
            {"type": "sql_injection", "title": "SQLi", "severity": "critical"},
            {"type": "xss", "title": "XSS", "severity": "high"},
        ], "test.com")
        paths = g.get_attack_paths()
        assert isinstance(paths, list)

    def test_critical_nodes(self):
        g = AttackGraph("test.com")
        g.build_from_findings([{"type": "sql_injection", "title": "SQLi", "severity": "critical"}], "test.com")
        critical = g.get_critical_nodes()
        assert isinstance(critical, list)

    def test_shortest_path(self):
        g = AttackGraph("test.com")
        g.add_node("a", "target", "a")
        g.add_node("b", "vulnerability", "v")
        g.add_node("c", "credential", "c")
        g.add_edge("a", "b", confidence=1.0)
        g.add_edge("b", "c", confidence=0.8)
        path = g.shortest_path("a", "c")
        assert path is not None
        assert len(path) == 3

    def test_mitre_map_not_empty(self):
        assert len(MITRE_MAP) > 20

    def test_severity_scores(self):
        assert SEVERITY_SCORES["critical"] == 10
        assert SEVERITY_SCORES["info"] == 0


class TestComplianceMapper:
    def test_init(self):
        cm = ComplianceMapper()
        assert len(cm.frameworks) == 8

    def test_map_finding(self):
        cm = ComplianceMapper()
        result = cm.map_finding({"type": "sql_injection", "title": "SQLi", "severity": "critical"})
        assert "mappings" in result
        assert len(result["mappings"]) > 0

    def test_generate_compliance_report(self):
        cm = ComplianceMapper()
        findings = [{"type": "sql_injection", "severity": "critical"}]
        report = cm.generate_compliance_report(findings)
        assert "frameworks" in report
        assert len(report["frameworks"]) > 0

    def test_compliance_score(self):
        cm = ComplianceMapper()
        score = cm.get_compliance_score([{"type": "sql_injection", "severity": "critical"}], "owasp_top10_2025")
        assert 0 <= score <= 100

    def test_gaps(self):
        cm = ComplianceMapper()
        gaps = cm.get_gaps([], "owasp_top10_2025")
        assert isinstance(gaps, list)
        assert len(gaps) > 0

    def test_remediation(self):
        cm = ComplianceMapper()
        rem = cm.get_remediation_for_control("A03:2021-Injection", "owasp_top10_2025")
        assert len(rem) > 10

    def test_finding_to_controls_not_empty(self):
        assert len(FINDING_TO_CONTROLS) > 15


class TestRiskCalculator:
    def test_init(self):
        rc = RiskCalculator()
        assert rc.industry == "default"

    def test_loss_event_frequency(self):
        rc = RiskCalculator()
        freq = rc.calculate_loss_event_frequency([{"severity": "critical"}, {"severity": "high"}])
        assert freq > 0

    def test_loss_magnitude(self):
        rc = RiskCalculator()
        mag = rc.calculate_loss_magnitude([{"severity": "critical"}], 10000)
        assert mag > 0

    def test_annualized_loss(self):
        rc = RiskCalculator()
        result = rc.calculate_annualized_loss([{"severity": "critical"}])
        assert "annualized_loss_expectancy_usd" in result

    def test_risk_score(self):
        rc = RiskCalculator()
        risk = rc.calculate_risk_score([{"severity": "critical"}])
        assert "score" in risk
        assert "level" in risk

    def test_empty_findings(self):
        rc = RiskCalculator()
        risk = rc.calculate_risk_score([])
        assert risk["score"] == 0

    def test_breach_cost(self):
        rc = RiskCalculator(industry="healthcare")
        cost = rc.estimate_breach_cost([{"severity": "critical"}])
        assert "estimated_breach_cost_usd" in cost
        assert cost["estimated_breach_cost_usd"] > 0

    def test_industry_benchmark(self):
        rc = RiskCalculator()
        bench = rc.get_industry_benchmark(60, "healthcare")
        assert "your_score" in bench

    def test_prioritize_by_risk(self):
        rc = RiskCalculator()
        findings = [{"severity": "low", "type": "info"}, {"severity": "critical", "type": "sqli"}]
        prioritized = rc.prioritize_by_risk(findings)
        assert prioritized[0]["severity"] == "critical"


class TestPredictionEngine:
    def test_init(self):
        pe = PredictionEngine()
        assert pe is not None

    def test_analyze_tech_stack(self):
        pe = PredictionEngine()
        preds = pe.analyze_tech_stack(["nginx", "mysql", "php"])
        assert len(preds) > 0
        assert preds[0]["tech"] in ("nginx", "mysql", "php")

    def test_config_deviation(self):
        pe = PredictionEngine()
        deviations = pe.check_config_deviation({"server": "nginx/1.18"})
        assert isinstance(deviations, list)

    def test_predict_vulnerabilities(self):
        pe = PredictionEngine()
        preds = pe.predict_vulnerabilities({"target": "test.com", "tech_stack": ["nginx", "mysql"]})
        assert isinstance(preds, list)

    def test_hypotheses_report(self):
        pe = PredictionEngine()
        report = pe.generate_hypotheses_report({"target": "test.com", "tech_stack": ["nginx"]})
        assert "Prediction Report" in report


class TestThreatIntel:
    def test_init(self):
        ti = ThreatIntel()
        assert ti is not None

    def test_tech_stack_weaknesses(self):
        ti = ThreatIntel()
        weaknesses = ti.get_tech_stack_weaknesses("nginx")
        assert isinstance(weaknesses, list)
        assert len(weaknesses) > 0

    def test_github_dorks(self):
        ti = ThreatIntel()
        dorks = ti.get_github_dorks("example.com")
        assert len(dorks) > 0
        assert "url" in dorks[0]

    def test_cve_feed_cached(self):
        ti = ThreatIntel()
        # Test cache mechanism directly
        ti._set_cache("nvd", "test_key", {"cves": [{"id": "CVE-2024-0001"}]}, ttl=3600)
        cached = ti._get_cached("nvd", "test_key")
        assert cached is not None
        assert cached["cves"][0]["id"] == "CVE-2024-0001"
        # Test cache miss
        miss = ti._get_cached("nvd", "nonexistent")
        assert miss is None
