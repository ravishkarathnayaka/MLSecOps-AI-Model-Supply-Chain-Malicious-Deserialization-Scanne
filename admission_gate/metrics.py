"""
Prometheus metrics and telemetry instrumentation for MLSecOps admission gate.
Provides thread-safe counters, gauges, and Prometheus exposition formatting (/metrics).
"""

from collections import defaultdict
import threading
import time
from typing import Dict, Tuple


class AdmissionMetrics:
    """Thread-safe Prometheus metrics collector for admission gatekeeper."""

    def __init__(self):
        self._lock = threading.Lock()
        self.admission_requests = defaultdict(int)  # (status, reason) -> count
        self.threat_findings = defaultdict(int)     # (severity, rule_id) -> count
        self.cache_hits = 0
        self.cache_misses = 0
        self.total_scanned_bytes = 0

    def record_admission(self, status: str, reason: str = "ok") -> None:
        with self._lock:
            self.admission_requests[(status, reason)] += 1

    def record_finding(self, severity: str, rule_id: str) -> None:
        with self._lock:
            self.threat_findings[(severity, rule_id)] += 1

    def record_cache_hit(self) -> None:
        with self._lock:
            self.cache_hits += 1

    def record_cache_miss(self) -> None:
        with self._lock:
            self.cache_misses += 1

    def record_bytes(self, num_bytes: int) -> None:
        with self._lock:
            self.total_scanned_bytes += num_bytes

    def generate_prometheus_text(self) -> str:
        """Renders standard Prometheus exposition format."""
        with self._lock:
            lines = [
                "# HELP mlsecops_admission_requests_total Total number of model admission evaluations.",
                "# TYPE mlsecops_admission_requests_total counter",
            ]
            for (status, reason), count in self.admission_requests.items():
                lines.append(f'mlsecops_admission_requests_total{{status="{status}",reason="{reason}"}} {count}')

            lines.extend([
                "# HELP mlsecops_threat_findings_total Total threat findings detected by rule and severity.",
                "# TYPE mlsecops_threat_findings_total counter",
            ])
            for (sev, rule_id), count in self.threat_findings.items():
                lines.append(f'mlsecops_threat_findings_total{{severity="{sev}",rule_id="{rule_id}"}} {count}')

            lines.extend([
                "# HELP mlsecops_cache_hits_total Total admission hash cache hits.",
                "# TYPE mlsecops_cache_hits_total counter",
                f"mlsecops_cache_hits_total {self.cache_hits}",
                "# HELP mlsecops_cache_misses_total Total admission hash cache misses.",
                "# TYPE mlsecops_cache_misses_total counter",
                f"mlsecops_cache_misses_total {self.cache_misses}",
                "# HELP mlsecops_scanned_bytes_total Total raw bytes processed.",
                "# TYPE mlsecops_scanned_bytes_total counter",
                f"mlsecops_scanned_bytes_total {self.total_scanned_bytes}",
                "",
            ])
            return "\n".join(lines)


# Singleton instance
GLOBAL_METRICS = AdmissionMetrics()
