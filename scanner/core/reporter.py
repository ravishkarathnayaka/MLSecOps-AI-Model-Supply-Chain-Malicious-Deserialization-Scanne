"""
Report Generation Engine for MLSecOps Scanner.
Produces OASIS SARIF v2.1.0 (for GitHub Code Scanning), structured JSON audit logs,
and high-readability terminal reports.
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import AdmissionVerdict, EvaluationResult, Finding

SARIF_SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
TOOL_NAME = "MLSecOps-Scanner"
TOOL_VERSION = "1.0.0"
TOOL_INFO_URI = "https://github.com/ravishkarathnayaka/MLSecOps-AI-Model-Supply-Chain-Malicious-Deserialization-Scanne"


# Severity to SARIF level mapping
SARIF_LEVEL_MAP: Dict[RiskLevel, str] = {
    RiskLevel.CRITICAL: "error",
    RiskLevel.HIGH: "error",
    RiskLevel.MEDIUM: "warning",
    RiskLevel.LOW: "note",
    RiskLevel.INFO: "note",
}

# ANSI Terminal Colors
COLOR_RESET = "\033[0m"
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"
COLOR_BOLD = "\033[1m"
COLOR_GRAY = "\033[90m"


class Reporter:
    """Generates SARIF v2.1.0, JSON, and terminal audit reports."""

    @classmethod
    def to_sarif(
        cls,
        evaluation: EvaluationResult,
        scanned_paths: List[str],
    ) -> Dict[str, Any]:
        """Builds a SARIF v2.1.0 document compatible with GitHub Code Scanning."""
        rules_map: Dict[str, Dict[str, Any]] = {}
        sarif_results: List[Dict[str, Any]] = []

        for f in evaluation.findings:
            if f.rule_id not in rules_map:
                rules_map[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.title.replace(" ", ""),
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "defaultConfiguration": {
                        "level": SARIF_LEVEL_MAP.get(f.severity, "warning")
                    },
                    "properties": {
                        "tags": ["security", "mlsecops", f.category],
                        "precision": "high",
                    },
                }

            # Normalize URI location
            file_loc = f.location.split(" ")[0].split("::")[0]
            norm_uri = os.path.abspath(file_loc).replace("\\", "/") if os.path.exists(file_loc) else file_loc

            sarif_results.append({
                "ruleId": f.rule_id,
                "level": SARIF_LEVEL_MAP.get(f.severity, "warning"),
                "message": {"text": f.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": norm_uri,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": 1,
                                "startColumn": 1,
                            },
                        }
                    }
                ],
                "properties": {
                    "severity": f.severity.value,
                    "category": f.category,
                    "details": f.details,
                },
            })

        sarif_doc: Dict[str, Any] = {
            "$schema": SARIF_SCHEMA_URI,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": TOOL_NAME,
                            "semanticVersion": TOOL_VERSION,
                            "informationUri": TOOL_INFO_URI,
                            "rules": list(rules_map.values()),
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                        }
                    ],
                    "artifacts": [
                        {"location": {"uri": p.replace("\\", "/")}} for p in scanned_paths
                    ],
                    "results": sarif_results,
                }
            ],
        }

        return sarif_doc

    @classmethod
    def to_json(
        cls,
        evaluation: EvaluationResult,
        scanned_paths: List[str],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Builds a structured JSON audit report."""
        report = {
            "scanner": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "scan_time_utc": datetime.now(timezone.utc).isoformat(),
            },
            "scanned_targets": scanned_paths,
            "target_count": len(scanned_paths),
            "evaluation": evaluation.to_dict(),
            "metadata": metadata or {},
        }
        return report

    @classmethod
    def to_terminal_text(
        cls,
        evaluation: EvaluationResult,
        scanned_paths: List[str],
        use_color: bool = True,
    ) -> str:
        """Renders an enterprise-grade terminal audit output."""
        c_reset = COLOR_RESET if use_color else ""
        c_bold = COLOR_BOLD if use_color else ""
        c_red = COLOR_RED if use_color else ""
        c_green = COLOR_GREEN if use_color else ""
        c_yellow = COLOR_YELLOW if use_color else ""
        c_blue = COLOR_BLUE if use_color else ""
        c_cyan = COLOR_CYAN if use_color else ""
        c_gray = COLOR_GRAY if use_color else ""

        def color_sev(sev: RiskLevel) -> str:
            if not use_color:
                return f"[{sev.value}]"
            if sev == RiskLevel.CRITICAL:
                return f"{c_red}{c_bold}[CRITICAL]{c_reset}"
            elif sev == RiskLevel.HIGH:
                return f"{c_red}[HIGH]{c_reset}"
            elif sev == RiskLevel.MEDIUM:
                return f"{c_yellow}[MEDIUM]{c_reset}"
            elif sev == RiskLevel.LOW:
                return f"{c_blue}[LOW]{c_reset}"
            return f"{c_gray}[INFO]{c_reset}"

        lines = [
            f"{c_cyan}{c_bold}=================================================================================={c_reset}",
            f"{c_cyan}{c_bold}   MLSecOps: AI Model Supply Chain & Malicious Deserialization Scanner v{TOOL_VERSION}{c_reset}",
            f"{c_cyan}{c_bold}=================================================================================={c_reset}",
            f"{c_gray}Target(s) Scanned : {len(scanned_paths)} model artifact(s){c_reset}",
            f"{c_gray}Fail Threshold    : {evaluation.fail_threshold.value}{c_reset}",
            f"{c_gray}Risk Score        : {evaluation.risk_score}/100.0{c_reset}",
            "",
        ]

        if not evaluation.findings:
            lines.append(
                f"{c_green}{c_bold}[+] All model artifacts clean. Zero dangerous opcodes or anomalies detected.{c_reset}"
            )
        else:
            lines.append(f"{c_bold}SECURITY FINDINGS ({len(evaluation.findings)} detected):{c_reset}")
            lines.append("----------------------------------------------------------------------------------")

            for idx, finding in enumerate(evaluation.findings, 1):
                sev_badge = color_sev(finding.severity)
                lines.append(f"{idx}. {sev_badge} {c_bold}{finding.title}{c_reset}")
                lines.append(f"   {c_gray}Rule ID  :{c_reset} {finding.rule_id}")
                lines.append(f"   {c_gray}Category :{c_reset} {finding.category}")
                lines.append(f"   {c_gray}Location :{c_reset} {finding.location}")
                lines.append(f"   {c_gray}Detail   :{c_reset} {finding.description}")
                if finding.details:
                    details_str = ", ".join(f"{k}={v}" for k, v in finding.details.items())
                    lines.append(f"   {c_gray}Context  :{c_reset} {details_str}")
                lines.append("")

        # Summary box
        lines.append("----------------------------------------------------------------------------------")
        lines.append(f"{c_bold}ADMISSION GATE VERDICT:{c_reset}")

        if evaluation.verdict == AdmissionVerdict.PASSED:
            lines.append(
                f"{c_green}{c_bold}   [ APPROVED ] ADMISSION PASSED - Model artifact approved for inference loading.{c_reset}"
            )
        elif evaluation.verdict == AdmissionVerdict.WARNING:
            lines.append(
                f"{c_yellow}{c_bold}   [ APPROVED WITH WARNINGS ] ADMISSION PASSED - Non-blocking findings recorded.{c_reset}"
            )
        else:
            lines.append(
                f"{c_red}{c_bold}   [ REJECTED / BLOCKED ] DEPLOYMENT FORBIDDEN - Critical/High security violations!{c_reset}"
            )

        lines.append(f"   {evaluation.summary}")
        lines.append(
            f"{c_cyan}{c_bold}=================================================================================={c_reset}\n"
        )

        return "\n".join(lines)
