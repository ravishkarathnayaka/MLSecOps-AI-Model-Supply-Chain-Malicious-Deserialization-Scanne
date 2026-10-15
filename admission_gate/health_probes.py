"""
Kubernetes Liveness, Readiness, and Startup Probes for MLSecOps Admission Controller.
Provides /healthz, /livez, and /readyz endpoint status handlers and dependency checks.
"""

from dataclasses import dataclass
import time
from typing import Any, Dict, Optional, Tuple


@dataclass
class ProbeStatus:
    healthy: bool
    status_code: int
    details: Dict[str, Any]


class HealthProbeManager:
    """Manages Kubernetes container lifecycle probe evaluations."""

    def __init__(self, check_redis_callable: Optional[Any] = None):
        self.start_time = time.time()
        self.check_redis = check_redis_callable
        self.ready_override = True

    def check_livez(self) -> ProbeStatus:
        """Liveness probe: verifies container process is responsive."""
        uptime_seconds = time.time() - self.start_time
        return ProbeStatus(
            healthy=True,
            status_code=200,
            details={"status": "alive", "uptime_seconds": round(uptime_seconds, 2)},
        )

    def check_readyz(self) -> ProbeStatus:
        """Readiness probe: verifies scanner engine and dependencies are ready for traffic."""
        if not self.ready_override:
            return ProbeStatus(
                healthy=False,
                status_code=503,
                details={"status": "not_ready", "reason": "Manually marked unready"},
            )

        details = {"status": "ready"}
        if self.check_redis:
            try:
                redis_ok = self.check_redis()
                details["redis"] = "connected" if redis_ok else "disconnected"
                if not redis_ok:
                    return ProbeStatus(healthy=False, status_code=503, details=details)
            except Exception as e:
                details["redis_error"] = str(e)
                return ProbeStatus(healthy=False, status_code=503, details=details)

        return ProbeStatus(healthy=True, status_code=200, details=details)

    def check_healthz(self) -> ProbeStatus:
        """Composite health check."""
        return self.check_readyz()
