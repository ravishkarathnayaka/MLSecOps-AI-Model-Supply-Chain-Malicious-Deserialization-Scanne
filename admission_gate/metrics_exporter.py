"""
Prometheus Metrics Exporter for MLSecOps Admission Controller.
Generates standard Prometheus text formatting for scraping by Prometheus Operator.
"""

from typing import Dict


class PrometheusMetricsExporter:
    """Formats in-memory metrics into Prometheus text representation."""

    @classmethod
    def render_metrics(cls, metrics: Dict[str, int]) -> str:
        lines = [
            "# HELP mlsecops_scans_total Total number of model security scans conducted.",
            "# TYPE mlsecops_scans_total counter",
            f"mlsecops_scans_total {metrics.get('total_scans', 0)}",
            "",
            "# HELP mlsecops_models_allowed_total Number of models approved for inference admission.",
            "# TYPE mlsecops_models_allowed_total counter",
            f"mlsecops_models_allowed_total {metrics.get('allowed_models', 0)}",
            "",
            "# HELP mlsecops_models_blocked_total Number of models blocked due to critical/high violations.",
            "# TYPE mlsecops_models_blocked_total counter",
            f"mlsecops_models_blocked_total {metrics.get('blocked_models', 0)}",
            "",
            "# HELP mlsecops_violations_total Cumulative security violations flagged across all scans.",
            "# TYPE mlsecops_violations_total counter",
            f"mlsecops_violations_total {metrics.get('total_violations', 0)}",
            "",
        ]
        return "\n".join(lines)
