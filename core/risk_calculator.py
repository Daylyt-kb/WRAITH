"""
WRAITH v2.0 — Risk Calculator
Quantitative security risk analysis using FAIR (Factor Analysis of Information Risk).
Translates technical findings into business risk (dollars).
"""

from typing import Optional


# IBM Cost of a Data Breach Report 2024 averages
BREACH_COST_BY_INDUSTRY = {
    "healthcare": 9_770_000,
    "financial": 5_900_000,
    "industrial": 5_560_000,
    "technology": 5_450_000,
    "energy": 5_290_000,
    "retail": 4_670_000,
    "hospitality": 4_510_000,
    "public_sector": 4_350_000,
    "transportation": 4_260_000,
    "education": 4_100_000,
    "media": 3_890_000,
    "research": 3_720_000,
    "nonprofit": 3_500_000,
    "default": 4_880_000,  # Overall average
}

# Cost per record by industry
COST_PER_RECORD = {
    "healthcare": 165,
    "financial": 158,
    "industrial": 149,
    "technology": 148,
    "default": 165,
}

BREACH_COST_BY_COMPANY_SIZE = {
    "small": 3_200_000,      # < 500 employees
    "medium": 4_500_000,     # 500-25,000 employees
    "enterprise": 6_200_000,  # > 25,000 employees
}

SEVERITY_TO_PROBABILITY = {
    "critical": 0.9,
    "high": 0.6,
    "medium": 0.3,
    "low": 0.1,
    "info": 0.02,
}

CVSS_TO_ANNUAL_RATE = {
    "critical": 5.0,  # ~5 successful attacks per year expected
    "high": 2.0,
    "medium": 0.5,
    "low": 0.1,
    "info": 0.01,
}


class RiskCalculator:
    """Quantitative risk analysis using FAIR methodology."""

    def __init__(self, industry: str = "default", company_size: str = "medium",
                 asset_value_usd: float = None):
        self.industry = industry.lower()
        self.company_size = company_size.lower()
        self.asset_value = asset_value_usd or BREACH_COST_BY_INDUSTRY.get(self.industry, 4_880_000)

    def calculate_loss_event_frequency(self, findings: list) -> float:
        """Estimate number of successful attacks per year based on findings."""
        if not findings:
            return 0.0
        rate = 0.0
        for finding in findings:
            sev = finding.get("severity", "low")
            rate += CVSS_TO_ANNUAL_RATE.get(sev, 0.1)
        # Cap at reasonable max (multiple vulns don't stack linearly)
        return min(rate, 20.0)

    def calculate_loss_magnitude(self, findings: list, affected_records: int = 10000) -> float:
        """Estimate financial loss per breach event."""
        base_cost = BREACH_COST_BY_INDUSTRY.get(self.industry, 4_880_000)
        size_cost = BREACH_COST_BY_COMPANY_SIZE.get(self.company_size, 4_500_000)
        avg_base = (base_cost + size_cost) / 2
        # Adjust for severity of findings
        severity_multiplier = 1.0
        for finding in findings:
            sev = finding.get("severity", "low")
            if sev == "critical":
                severity_multiplier += 0.5
            elif sev == "high":
                severity_multiplier += 0.3
            elif sev == "medium":
                severity_multiplier += 0.1
        per_record = COST_PER_RECORD.get(self.industry, 165)
        data_cost = affected_records * per_record
        return min(avg_base * severity_multiplier + data_cost * 0.1, avg_base * 3)

    def calculate_annualized_loss(self, findings: list, affected_records: int = 10000) -> dict:
        """Calculate Annualized Loss Expectancy (ALE)."""
        lemf = self.calculate_loss_event_frequency(findings)
        lmm = self.calculate_loss_magnitude(findings, affected_records)
        ale = lemf * lmm
        return {
            "loss_event_frequency_per_year": round(lemf, 2),
            "loss_magnitude_per_event_usd": round(lmm),
            "annualized_loss_expectancy_usd": round(ale),
            "industry": self.industry,
            "company_size": self.company_size,
        }

    def calculate_risk_score(self, findings: list) -> dict:
        """Calculate overall risk score (0-100) with breakdown."""
        if not findings:
            return {"score": 0, "level": "LOW", "details": "No findings"}
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        medium = sum(1 for f in findings if f.get("severity") == "medium")
        low = sum(1 for f in findings if f.get("severity") == "low")
        score = min(critical * 25 + high * 10 + medium * 3 + low * 1, 100)
        level = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
        return {"score": score, "level": level,
                "breakdown": {"critical": critical, "high": high, "medium": medium, "low": low,
                              "total": len(findings)}}

    def get_industry_benchmark(self, risk_score: int, industry: str = None) -> dict:
        """Compare risk score against industry average."""
        ind = industry or self.industry
        benchmarks = {
            "healthcare": 55, "financial": 45, "technology": 50, "retail": 60,
            "default": 50,
        }
        avg = benchmarks.get(ind, 50)
        return {
            "your_score": risk_score,
            "industry_average": avg,
            "comparison": "above" if risk_score > avg else "below" if risk_score < avg else "at",
            "percentile": round(max(0, min(100, 50 + (avg - risk_score))), 1),
        }

    def estimate_breach_cost(self, findings: list, company_size: str = None) -> dict:
        """Estimate potential breach cost based on findings."""
        size = company_size or self.company_size
        base = BREACH_COST_BY_COMPANY_SIZE.get(size, 4_500_000)
        risk = self.calculate_risk_score(findings)
        score_factor = risk["score"] / 100.0
        estimated_cost = base * (0.5 + score_factor)
        cost_per_record = COST_PER_RECORD.get(self.industry, 165)
        records_at_risk = int(10000 * (1 + score_factor))
        return {
            "estimated_breach_cost_usd": round(estimated_cost),
            "estimated_breach_cost_formatted": f"${estimated_cost:,.0f}",
            "cost_per_record_usd": cost_per_record,
            "estimated_records_at_risk": records_at_risk,
            "risk_score": risk["score"],
            "risk_level": risk["level"],
            "company_size": size,
            "industry": self.industry,
        }

    def prioritize_by_risk(self, findings: list) -> list:
        """Sort findings by business impact (risk × exploitability)."""
        scored = []
        for f in findings:
            sev = f.get("severity", "low")
            prob = SEVERITY_TO_PROBABILITY.get(sev, 0.1)
            impact = {"critical": 10, "high": 8, "medium": 5, "low": 2, "info": 0}.get(sev, 0)
            scored.append({**f, "_risk_score": prob * impact * 10})
        scored.sort(key=lambda x: x["_risk_score"], reverse=True)
        return scored

    def generate_executive_summary(self, findings: list) -> str:
        """Generate a board-ready executive summary."""
        risk = self.calculate_risk_score(findings)
        breach = self.estimate_breach_cost(findings)
        annual = self.calculate_annualized_loss(findings)
        benchmark = self.get_industry_benchmark(risk["score"])
        return f"""## Executive Security Summary

**Risk Level: {risk['level']} ({risk['score']}/100)**

WRAITH identified {len(findings)} security findings:
- 🔴 **{risk['breakdown']['critical']} Critical** — Immediate action required
- 🟠 **{risk['breakdown']['high']} High** — Remediate within 48 hours
- 🟡 **{risk['breakdown']['medium']} Medium** — Remediate within 30 days
- 🟢 **{risk['breakdown']['low']} Low** — Address in next sprint

**Business Impact:**
- Estimated cost of a data breach: {breach['estimated_breach_cost_formatted']}
- Expected frequency: {annual['loss_event_frequency_per_year']} incidents/year
- Projected annual loss: ${annual['annualized_loss_expectancy_usd']:,.0f}

**Industry Comparison:** Your security posture is {benchmark['comparison']} the {self.industry} industry average (50th percentile).

**Key Recommendations:**
1. Prioritize remediation of {risk['breakdown']['critical']} critical findings
2. Address all high-severity items within 48 hours
3. Implement continuous monitoring with WRAITH Sentinel
4. Schedule next scan within 7 days to verify remediation
"""
