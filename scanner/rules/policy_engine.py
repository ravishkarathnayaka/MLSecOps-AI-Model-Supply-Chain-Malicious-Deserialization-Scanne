"""
Policy Evaluation Engine.
Evaluates static scan findings against security thresholds, strictness policies,
and determines deployment admission verdicts (PASS, WARN, FAIL).
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from scanner.rules.dangerous_symbols import RiskLevel


class AdmissionVerdict(str, Enum):
    PASSED = "PASSED"
    WARNING = "WARNING"
    FAILED = "FAILED"


SEVERITY_ORDER: Dict[RiskLevel, int] = {
    RiskLevel.INFO: 1,
    RiskLevel.LOW: 2,
    RiskLevel.MEDIUM: 3,
    RiskLevel.HIGH: 4,
    RiskLevel.CRITICAL: 5,
}

SEVERITY_WEIGHTS: Dict[RiskLevel, float] = {
    RiskLevel.INFO: 1.0,
    RiskLevel.LOW: 5.0,
    RiskLevel.MEDIUM: 15.0,
    RiskLevel.HIGH: 40.0,
    RiskLevel.CRITICAL: 100.0,
}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: RiskLevel
    description: str
    location: str
    category: str = "general"
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "location": self.location,
            "details": self.details,
        }


@dataclass
class PolicyViolation:
    finding: Finding
    threshold: RiskLevel
    message: str


@dataclass
class EvaluationResult:
    verdict: AdmissionVerdict
    passed: bool
    fail_threshold: RiskLevel
    violations: List[PolicyViolation]
    findings: List[Finding]
    highest_severity: Optional[RiskLevel]
    risk_score: float
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "passed": self.passed,
            "fail_threshold": self.fail_threshold.value,
            "violations_count": len(self.violations),
            "findings_count": len(self.findings),
            "highest_severity": self.highest_severity.value if self.highest_severity else None,
            "risk_score": round(self.risk_score, 2),
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }


class PolicyEngine:
    """
    Evaluates scan findings against configurable thresholds.
    Enforces security baselines for CI/CD gates and inference deployment admission controllers.
    """

    def __init__(
        self,
        fail_on_threshold: RiskLevel = RiskLevel.HIGH,
        strict_mode: bool = False,
        custom_allowed_globals: Optional[Set[str]] = None,
    ):
        self.fail_on_threshold = fail_on_threshold
        self.strict_mode = strict_mode
        self.custom_allowed_globals = custom_allowed_globals or set()

    def evaluate(self, findings: List[Finding]) -> EvaluationResult:
        violations: List[PolicyViolation] = []
        highest_severity: Optional[RiskLevel] = None
        threshold_rank = SEVERITY_ORDER[self.fail_on_threshold]

        total_weight = 0.0

        for finding in findings:
            finding_rank = SEVERITY_ORDER[finding.severity]
            total_weight += SEVERITY_WEIGHTS[finding.severity]

            if highest_severity is None or finding_rank > SEVERITY_ORDER[highest_severity]:
                highest_severity = finding.severity

            # If severity meets or exceeds the failure threshold
            if finding_rank >= threshold_rank:
                violations.append(
                    PolicyViolation(
                        finding=finding,
                        threshold=self.fail_on_threshold,
                        message=(
                            f"Finding '{finding.rule_id}' with severity {finding.severity.value} "
                            f"meets or exceeds failure threshold {self.fail_on_threshold.value}"
                        ),
                    )
                )

        # Risk score normalized (capped at 100.0)
        risk_score = min(100.0, total_weight)

        if violations:
            verdict = AdmissionVerdict.FAILED
            passed = False
            summary = (
                f"Policy evaluation FAILED: {len(violations)} violation(s) exceeded "
                f"the threshold '{self.fail_on_threshold.value}'. Blocked model deployment."
            )
        elif findings:
            verdict = AdmissionVerdict.WARNING
            passed = True
            summary = (
                f"Policy evaluation PASSED with WARNINGS: {len(findings)} non-blocking finding(s) detected. "
                f"Highest severity is {highest_severity.value if highest_severity else 'None'}."
            )
        else:
            verdict = AdmissionVerdict.PASSED
            passed = True
            summary = "Policy evaluation PASSED: No security findings detected."

        return EvaluationResult(
            verdict=verdict,
            passed=passed,
            fail_threshold=self.fail_on_threshold,
            violations=violations,
            findings=findings,
            highest_severity=highest_severity,
            risk_score=risk_score,
            summary=summary,
        )
