"""
Hugging Face Hub Integration Module.
Inspects remote Hugging Face repositories, fetches model cards and weight metadata,
and enables pre-download supply chain scanning via Hugging Face REST APIs.
"""

import json
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from scanner.provenance.modelcard_auditor import ModelCardAuditor
from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import Finding

HF_API_BASE = "https://huggingface.co/api/models"


class HuggingFaceHubScanner:
    """
    Statically audits remote Hugging Face Hub repositories prior to downloading weights.
    """

    def __init__(self, api_token: Optional[str] = None):
        self.api_token = api_token

    def audit_repo_metadata(self, repo_id: str) -> Tuple[List[Finding], Dict[str, Any]]:
        """
        Queries Hugging Face model API for repository metadata, siblings, and model card.
        """
        findings: List[Finding] = []
        url = f"{HF_API_BASE}/{repo_id}"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "MLSecOps-Scanner/1.0.0")
        if self.api_token:
            req.add_header("Authorization", f"Bearer {self.api_token}")

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            findings.append(
                Finding(
                    rule_id="HF-API-FETCH-ERROR",
                    title="Failed to Query Hugging Face Hub API",
                    severity=RiskLevel.HIGH,
                    category="remote_fetch",
                    description=f"Error accessing HF repo '{repo_id}': {str(e)}",
                    location=f"hf://{repo_id}",
                )
            )
            return findings, {}

        # 1. Audit sibling file formats
        siblings = data.get("siblings", [])
        pickle_weights = []
        safetensors_present = False

        for s in siblings:
            rfilename = s.get("rfilename", "")
            if rfilename.endswith((".safetensors",)):
                safetensors_present = True
            elif rfilename.endswith((".bin", ".pt", ".pth", ".pkl")):
                pickle_weights.append(rfilename)

        if pickle_weights and not safetensors_present:
            findings.append(
                Finding(
                    rule_id="HF-LEGACY-PICKLE-ONLY-REPOSITORY",
                    title="Hugging Face Repository Only Ships Pickle Weights",
                    severity=RiskLevel.MEDIUM,
                    category="supply_chain_warning",
                    description=(
                        f"Repository '{repo_id}' provides serialized pickle weights ({', '.join(pickle_weights[:3])}) "
                        "without safe alternative Safetensors format."
                    ),
                    location=f"hf://{repo_id}",
                )
            )

        # 2. Audit Model Card if present
        card_data = data.get("cardData")
        if card_data and isinstance(card_data, dict):
            if card_data.get("trust_remote_code") is True or card_data.get("custom_code") is True:
                findings.append(
                    Finding(
                        rule_id="HF-TRUST-REMOTE-CODE-FLAGGED",
                        title="Repository Flags 'trust_remote_code: true'",
                        severity=RiskLevel.HIGH,
                        category="remote_code_execution",
                        description=f"Hugging Face model card for '{repo_id}' indicates remote Python code execution.",
                        location=f"hf://{repo_id}::README.md",
                    )
                )

        return findings, data
