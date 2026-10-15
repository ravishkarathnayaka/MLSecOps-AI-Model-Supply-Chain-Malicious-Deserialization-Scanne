"""
Markdown Executive Summary Report Generator for CI/CD Pipeline Comments and Audit Dossiers.
Builds GitHub-Flavored Markdown tables, badges, and threat metrics from EvaluationResults.
"""

from typing import List
from scanner.rules.policy_engine import EvaluationResult


class MarkdownReporter:
    """Generates structured Markdown security reports."""

    @classmethod
    def generate_report(cls, evaluation: EvaluationResult, scanned_files: List[str]) -> str:
        verdict_badge = "🟩 **PASSED**" if evaluation.passed else "🟥 **FAILED - QUARANTINED**"
        lines = [
            "# 🛡️ MLSecOps Model Supply Chain Security Report",
            "",
            f"**Audit Verdict:** {verdict_badge}  ",
            f"**Total Scanned Files:** {len(scanned_files)}  ",
            f"**Overall Risk Score:** {evaluation.risk_score:.1f} / 100.0  ",
            f"**Highest Severity:** {evaluation.highest_severity.value if evaluation.highest_severity else 'NONE'}",
            "",
            "---",
            "",
            "## 📊 Findings Summary",
            "",
        ]

        if not evaluation.findings:
            lines.append("🎉 *Zero security vulnerabilities or policy violations detected in model artifacts.*")
            return "\n".join(lines)

        lines.extend([
            "| Rule ID | Severity | Category | Description | Location |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])

        for f in evaluation.findings:
            sev_emoji = {
                "CRITICAL": "🔴 CRITICAL",
                "HIGH": "🟠 HIGH",
                "MEDIUM": "🟡 MEDIUM",
                "LOW": "🔵 LOW",
                "INFO": "⚪ INFO",
            }.get(f.severity.value, f.severity.value)

            lines.append(
                f"| `{f.rule_id}` | {sev_emoji} | {f.category} | {f.description[:80]} | `{f.location}` |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 🛠️ Remediation Guidance",
            "",
            "1. **Isolate Compromised Artifacts:** Block models with `CRITICAL` or `HIGH` findings from reaching GPU memory.",
            "2. **Use Zero-Executable Formats:** Migrate legacy PyTorch (`.pt`, `.bin`) weights to `.safetensors`.",
            "3. **Enforce Cryptographic Provenance:** Validate detached Sigstore/Cosign signatures and in-toto attestations before inference load.",
            "",
            "*Report generated automatically by MLSecOps Scanner.*",
        ])

        return "\n".join(lines)
