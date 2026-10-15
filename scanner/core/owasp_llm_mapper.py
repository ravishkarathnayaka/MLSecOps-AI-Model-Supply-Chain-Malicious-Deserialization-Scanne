"""
OWASP Top 10 for Large Language Model Applications (LLM01-LLM10) Classification Mapper.
Categorizes MLSecOps inspection findings into the industry-standard OWASP LLM framework.
"""

from typing import Dict, List
from scanner.core.reporter import Finding


OWASP_LLM_MAP: Dict[str, Dict[str, str]] = {
    "prompt_injection_backdoor": {
        "id": "LLM01",
        "title": "Prompt Injection",
        "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    },
    "deserialization_injection": {
        "id": "LLM05",
        "title": "Supply Chain Vulnerabilities",
        "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    },
    "arbitrary_code_execution": {
        "id": "LLM05",
        "title": "Supply Chain Vulnerabilities",
        "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    },
    "network_exfiltration": {
        "id": "LLM06",
        "title": "Sensitive Information Disclosure",
        "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    },
    "compute_hijacking": {
        "id": "LLM04",
        "title": "Model Denial of Service",
        "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    },
    "steganography_payload": {
        "id": "LLM03",
        "title": "Training Data Poisoning / Model Backdoors",
        "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    },
    "gpu_memory_manipulation": {
        "id": "LLM05",
        "title": "Supply Chain Vulnerabilities",
        "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    },
}


class OWASPLLMMapper:
    """Enriches finding metadata with OWASP Top 10 for LLM tags."""

    @classmethod
    def enrich_finding(cls, finding: Finding) -> Finding:
        cat = getattr(finding, "category", "general")
        if cat in OWASP_LLM_MAP:
            finding.details["owasp_llm"] = OWASP_LLM_MAP[cat]
        else:
            finding.details["owasp_llm"] = {
                "id": "LLM05",
                "title": "Supply Chain Vulnerabilities",
                "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            }
        return finding

    @classmethod
    def enrich_findings(cls, findings: List[Finding]) -> List[Finding]:
        for f in findings:
            cls.enrich_finding(f)
        return findings
