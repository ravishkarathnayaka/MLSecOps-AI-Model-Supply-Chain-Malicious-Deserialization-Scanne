"""
Interactive CLI Security Dashboard.
Renders colored terminal progress meters, active findings breakdown,
and scan telemetry for large multi-shard model directory scans.
"""

import sys
import time
from typing import Dict, List

from scanner.rules.dangerous_symbols import RiskLevel


class TerminalDashboard:
    """Live ASCII progress display for batch model scans."""

    @staticmethod
    def render_progress_bar(current: int, total: int, width: int = 30) -> str:
        ratio = current / max(1, total)
        filled = int(width * ratio)
        bar = "=" * filled + "-" * (width - filled)
        percent = int(ratio * 100)
        return f"[{bar}] {percent}% ({current}/{total})"

    @classmethod
    def render_summary_panel(cls, stats: Dict[str, int], elapsed_sec: float) -> str:
        crit = stats.get("CRITICAL", 0)
        high = stats.get("HIGH", 0)
        med = stats.get("MEDIUM", 0)
        low = stats.get("LOW", 0)

        lines = [
            "+--------------------------------------------------------------+",
            "|                 MLSecOps Live Audit Summary                  |",
            "+--------------------------------------------------------------+",
            f"| Time Elapsed : {elapsed_sec:.2f}s                                       |",
            f"| Critical : {crit:<4} | High : {high:<4} | Medium : {med:<4} | Low : {low:<4}    |",
            "+--------------------------------------------------------------+",
        ]
        return "\n".join(lines)
