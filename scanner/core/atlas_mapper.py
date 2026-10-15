"""
MITRE ATLAS (Adversarial Threat Landscape for AI Systems) Threat Matrix Mapper.
Correlates MLSecOps findings and static disassembly rules to official MITRE ATLAS technique IDs.
"""

from typing import Any, Dict, List, Optional
from scanner.core.reporter import Finding


ATLAS_TECHNIQUE_MAP: Dict[str, Dict[str, str]] = {
    # Supply Chain Compromise
    "deserialization_injection": {
        "id": "AML.T0010",
        "name": "ML Supply Chain Compromise",
        "tactic": "Initial Access",
        "url": "https://atlas.mitre.org/techniques/AML.T0010/",
    },
    "arbitrary_code_execution": {
        "id": "AML.T0010.001",
        "name": "Publish Poisoned Model / Arbitrary Execution",
        "tactic": "Execution",
        "url": "https://atlas.mitre.org/techniques/AML.T0010/",
    },
    "remote_code_execution": {
        "id": "AML.T0010.001",
        "name": "Remote Code Execution via ML Payload",
        "tactic": "Execution",
        "url": "https://atlas.mitre.org/techniques/AML.T0010/",
    },
    # Backdoors & Model Poisoning
    "prompt_injection_backdoor": {
        "id": "AML.T0043",
        "name": "Craft Adversarial Data / Prompt Injection",
        "tactic": "Execution",
        "url": "https://atlas.mitre.org/techniques/AML.T0043/",
    },
    "steganography_payload": {
        "id": "AML.T0018",
        "name": "Backdoor ML Model",
        "tactic": "Persistence",
        "url": "https://atlas.mitre.org/techniques/AML.T0018/",
    },
    # Exfiltration
    "network_exfiltration": {
        "id": "AML.T0024",
        "name": "Exfiltration via ML Artifacts",
        "tactic": "Exfiltration",
        "url": "https://atlas.mitre.org/techniques/AML.T0024/",
    },
    "remote_payload_download": {
        "id": "AML.T0010.002",
        "name": "Staged Payload Ingestion",
        "tactic": "Defense Evasion",
        "url": "https://atlas.mitre.org/techniques/AML.T0010/",
    },
    "compute_hijacking": {
        "id": "AML.T0034",
        "name": "Compute Resource Hijacking",
        "tactic": "Impact",
        "url": "https://atlas.mitre.org/techniques/AML.T0034/",
    },
}


class MITREATLASMapper:
    """Enriches security findings with standard MITRE ATLAS technique classifications."""

    @classmethod
    def enrich_finding(cls, finding: Finding) -> Finding:
        cat = getattr(finding, "category", "general")
        if cat in ATLAS_TECHNIQUE_MAP:
            technique = ATLAS_TECHNIQUE_MAP[cat]
            finding.details["mitre_atlas"] = technique
        else:
            finding.details["mitre_atlas"] = {
                "id": "AML.T0010",
                "name": "ML Supply Chain Compromise",
                "tactic": "Supply Chain",
                "url": "https://atlas.mitre.org/techniques/AML.T0010/",
            }
        return finding

    @classmethod
    def enrich_findings(cls, findings: List[Finding]) -> List[Finding]:
        for f in findings:
            cls.enrich_finding(f)
        return findings
