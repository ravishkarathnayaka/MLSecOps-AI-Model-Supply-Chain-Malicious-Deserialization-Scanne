"""
Standalone Interactive HTML Security Report Generator.
Renders responsive security audit dashboards containing risk gauges, findings tables,
and remediation guidance without external CDN dependencies.
"""

from datetime import datetime, timezone
import html
from typing import Any, Dict, List, Optional

from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import AdmissionVerdict, EvaluationResult


class HTMLReporter:
    """Generates self-contained HTML audit reports."""

    @classmethod
    def generate_html(
        cls,
        evaluation: EvaluationResult,
        scanned_paths: List[str],
        title: str = "MLSecOps Model Supply Chain Security Audit",
    ) -> str:
        verdict_color = {
            AdmissionVerdict.PASSED: "#10b981",
            AdmissionVerdict.WARNING: "#f59e0b",
            AdmissionVerdict.FAILED: "#ef4444",
        }.get(evaluation.verdict, "#6b7280")

        findings_rows = []
        for idx, f in enumerate(evaluation.findings, 1):
            sev_badge_color = {
                RiskLevel.CRITICAL: "#ef4444",
                RiskLevel.HIGH: "#f97316",
                RiskLevel.MEDIUM: "#f59e0b",
                RiskLevel.LOW: "#3b82f6",
                RiskLevel.INFO: "#6b7280",
            }.get(f.severity, "#6b7280")

            findings_rows.append(f"""
            <tr>
                <td style="padding: 12px; border-bottom: 1px solid #374151;">{idx}</td>
                <td style="padding: 12px; border-bottom: 1px solid #374151;">
                    <span style="background: {sev_badge_color}; color: #fff; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold;">
                        {f.severity.value}
                    </span>
                </td>
                <td style="padding: 12px; border-bottom: 1px solid #374151; font-weight: 600; color: #f3f4f6;">
                    {html.escape(f.title)}
                    <div style="font-size: 12px; color: #9ca3af; font-family: monospace; margin-top: 4px;">{html.escape(f.rule_id)}</div>
                </td>
                <td style="padding: 12px; border-bottom: 1px solid #374151; color: #d1d5db; font-size: 13px;">
                    {html.escape(f.description)}
                </td>
                <td style="padding: 12px; border-bottom: 1px solid #374151; font-family: monospace; font-size: 12px; color: #60a5fa;">
                    {html.escape(f.location)}
                </td>
            </tr>
            """)

        table_content = "".join(findings_rows) if findings_rows else """
            <tr>
                <td colspan="5" style="text-align: center; padding: 24px; color: #10b981; font-size: 15px; font-weight: bold;">
                    ✔ No security findings detected. All models meet deployment baseline criteria.
                </td>
            </tr>
        """

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)}</title>
    <style>
        body {{
            background-color: #0f172a;
            color: #e2e8f0;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 32px 24px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 24px; margin-bottom: 28px; }}
        .badge-verdict {{ background: {verdict_color}; color: #fff; padding: 8px 16px; border-radius: 6px; font-weight: bold; font-size: 14px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 32px; }}
        .card {{ background: #1e293b; padding: 20px; border-radius: 8px; border: 1px solid #334155; }}
        .card-num {{ font-size: 28px; font-weight: 800; color: #f8fafc; margin-top: 6px; }}
        .table-wrap {{ background: #1e293b; border-radius: 8px; border: 1px solid #334155; overflow-x: auto; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; }}
        th {{ background: #0f172a; padding: 14px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8; border-bottom: 2px solid #334155; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 style="margin: 0 0 6px 0; font-size: 24px; color: #f8fafc;">{html.escape(title)}</h1>
                <div style="font-size: 13px; color: #94a3b8;">Generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | MLSecOps Engine v1.0.0</div>
            </div>
            <div class="badge-verdict">{evaluation.verdict.value}</div>
        </div>

        <div class="grid">
            <div class="card">
                <div style="font-size: 12px; color: #94a3b8; text-transform: uppercase;">Scanned Targets</div>
                <div class="card-num">{len(scanned_paths)}</div>
            </div>
            <div class="card">
                <div style="font-size: 12px; color: #94a3b8; text-transform: uppercase;">Security Findings</div>
                <div class="card-num">{len(evaluation.findings)}</div>
            </div>
            <div class="card">
                <div style="font-size: 12px; color: #94a3b8; text-transform: uppercase;">Violations Count</div>
                <div class="card-num" style="color: {'#ef4444' if evaluation.violations else '#10b981'};">{len(evaluation.violations)}</div>
            </div>
            <div class="card">
                <div style="font-size: 12px; color: #94a3b8; text-transform: uppercase;">Risk Score</div>
                <div class="card-num">{evaluation.risk_score}/100.0</div>
            </div>
        </div>

        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th style="width: 50px;">#</th>
                        <th style="width: 100px;">Severity</th>
                        <th>Finding & Rule ID</th>
                        <th>Description</th>
                        <th>Location</th>
                    </tr>
                </thead>
                <tbody>
                    {table_content}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""
        return html_template
