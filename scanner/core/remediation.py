"""
Automated Security Remediation Recommendation Engine.
Produces actionable engineering remediation guidance and safe code snippets
for identified model supply chain vulnerabilities and policy violations.
"""

from typing import Dict, List, Optional
from scanner.core.reporter import Finding


REMEDIATION_GUIDANCE: Dict[str, Dict[str, str]] = {
    "ARBITRARY-CODE-EXECUTION": {
        "title": "Migrate to Zero-Executable Safetensors",
        "action": (
            "Do not call torch.load() or pickle.load() on this file. "
            "Convert weights in a sandboxed offline environment using safetensors:\n"
            "  from safetensors.torch import save_file\n"
            "  save_file(state_dict, 'model.safetensors')"
        ),
        "docs": "https://huggingface.co/docs/safetensors",
    },
    "ONNX-CUSTOM-OPERATOR": {
        "title": "Replace Custom Operator with Standard ONNX Domain",
        "action": (
            "Export the graph using standard ONNX operator set (ai.onnx opset >= 17). "
            "Avoid registering arbitrary C++ runtime operator plugins in production inference."
        ),
        "docs": "https://onnx.ai/onnx/intro/operators.html",
    },
    "NETWORK-EXFILTRATION": {
        "title": "Air-Gap Inference Container Egress",
        "action": (
            "Enforce Kubernetes Cilium or Calico NetworkPolicy denying outbound egress "
            "from model-serving pods to prevent data leakage."
        ),
        "docs": "https://kubernetes.io/docs/concepts/services-networking/network-policies/",
    },
    "MISSING-SIGNATURE": {
        "title": "Sign Model Checkpoint with Sigstore / Cosign",
        "action": (
            "Generate cryptographic provenance proof using keyless Cosign signing:\n"
            "  cosign sign-blob model.safetensors --bundle model.sigstore.json"
        ),
        "docs": "https://docs.sigstore.dev/cosign/signing_with_blobs/",
    },
}


class RemediationAdvisor:
    """Generates remediation advice for findings."""

    @classmethod
    def get_remediation_for_finding(cls, finding: Finding) -> Dict[str, str]:
        rule_id = finding.rule_id
        for key, guide in REMEDIATION_GUIDANCE.items():
            if key in rule_id:
                return guide

        # Default fallback guidance
        return {
            "title": "Isolate Artifact and Review Provenance",
            "action": (
                "Quarantine the flagged model artifact. Verify its cryptographic hash against "
                "the author's published model card before allowing production deployment."
            ),
            "docs": "https://github.com/ravishkarathnayaka/MLSecOps",
        }

    @classmethod
    def attach_remediations(cls, findings: List[Finding]) -> List[Finding]:
        for f in findings:
            f.details["remediation"] = cls.get_remediation_for_finding(f)
        return findings
