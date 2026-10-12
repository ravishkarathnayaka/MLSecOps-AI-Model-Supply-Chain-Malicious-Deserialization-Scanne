"""
CVSS v3.1 and ML-CVSS Risk Scoring Engine.
Computes Common Vulnerability Scoring System (CVSS v3.1) vectors and numerical base scores
for AI/ML model supply chain vulnerabilities.
"""

from dataclasses import dataclass
from typing import Dict, List, Tuple

from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import Finding


@dataclass
class CVSSScoreResult:
    base_score: float
    severity_label: str
    vector_string: str


class CVSSScoringEngine:
    """Calculates CVSS v3.1 vectors and scores for ML findings."""

    CATEGORY_METRICS: Dict[str, Tuple[float, str]] = {
        "code_execution": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        "process_spawning": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        "arbitrary_code_execution": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        "network_exfiltration": (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        "filesystem_tampering": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"),
        "file_traversal": (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"),
        "steganography": (6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),
        "untrusted_domain": (7.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"),
    }

    @classmethod
    def score_finding(cls, finding: Finding) -> CVSSScoreResult:
        """Returns CVSS v3.1 score and vector string for an individual finding."""
        if finding.category in cls.CATEGORY_METRICS:
            score, vector = cls.CATEGORY_METRICS[finding.category]
        else:
            default_scores = {
                RiskLevel.CRITICAL: (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
                RiskLevel.HIGH: (8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
                RiskLevel.MEDIUM: (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
                RiskLevel.LOW: (3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
                RiskLevel.INFO: (0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
            }
            score, vector = default_scores.get(finding.severity, (5.0, ""))

        label = "CRITICAL" if score >= 9.0 else "HIGH" if score >= 7.0 else "MEDIUM" if score >= 4.0 else "LOW"
        return CVSSScoreResult(base_score=score, severity_label=label, vector_string=vector)

    @classmethod
    def aggregate_model_score(cls, findings: List[Finding]) -> float:
        """Computes composite risk score across all findings (0.0 to 10.0 scale)."""
        if not findings:
            return 0.0
        scores = [cls.score_finding(f).base_score for f in findings]
        return round(max(scores), 1)
