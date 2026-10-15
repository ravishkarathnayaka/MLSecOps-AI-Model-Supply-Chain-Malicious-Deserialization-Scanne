"""
Envoy External Authorization (ext_authz) HTTP Filter Adapter for MLSecOps.
Enables Istio / Envoy service mesh sidecars to intercept model load calls before reaching backend pods.
"""

from dataclasses import dataclass, field
import json
from typing import Any, Dict, Optional, Tuple


@dataclass
class EnvoyCheckResponse:
    allowed: bool
    http_status: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""


class EnvoyExtAuthzAdapter:
    """Processes Envoy HTTP CheckRequest payloads for model admission."""

    def __init__(self, admission_evaluator_callable: Any):
        self.evaluator = admission_evaluator_callable

    def handle_check(
        self,
        request_path: str,
        request_headers: Dict[str, str],
        request_body: Optional[bytes] = None,
    ) -> EnvoyCheckResponse:
        """Evaluates whether Envoy should permit the inbound request."""
        # Extract model path from header or body
        model_path = request_headers.get("x-model-path")

        if not model_path and request_body:
            try:
                body_json = json.loads(request_body.decode("utf-8"))
                model_path = body_json.get("model_path") or body_json.get("model")
            except Exception:
                pass

        if not model_path:
            # If no model reference in request, permit pass-through
            return EnvoyCheckResponse(
                allowed=True,
                http_status=200,
                headers={"x-mlsecops-status": "pass-through"},
            )

        # Call underlying admission evaluator
        is_admitted, reason = self.evaluator(model_path)
        if is_admitted:
            return EnvoyCheckResponse(
                allowed=True,
                http_status=200,
                headers={"x-mlsecops-verdict": "admitted"},
            )
        else:
            return EnvoyCheckResponse(
                allowed=False,
                http_status=403,
                headers={"x-mlsecops-verdict": "rejected"},
                body=json.dumps({"error": "Forbidden", "message": f"MLSecOps admission gate blocked model: {reason}"}),
            )
