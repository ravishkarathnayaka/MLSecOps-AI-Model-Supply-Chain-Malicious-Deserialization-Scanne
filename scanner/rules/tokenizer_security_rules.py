"""
Security rules validating tokenizer configuration files (tokenizer_config.json, tokenizer.json)
for unpinned dynamic external resource URLs, remote code execution flags, and SSRF hooks.
"""

import json
from typing import Any, Dict, List
from scanner.core.reporter import Finding
from scanner.rules.dangerous_symbols import RiskLevel


class TokenizerSecurityValidator:
    """Validates tokenizer JSON manifests against supply chain and SSRF threats."""

    UNTRUSTED_DOMAINS = ["pastebin.com", "raw.githubusercontent.com", "bit.ly", "ngrok.io", "webhook.site"]

    def __init__(self, allow_http: bool = False):
        self.allow_http = allow_http

    def validate_tokenizer_json(self, content_str: str, source_name: str = "tokenizer_config.json") -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = json.loads(content_str)
        except Exception as e:
            findings.append(
                Finding(
                    rule_id="TOKENIZER-CONFIG-MALFORMED",
                    title="Malformed Tokenizer Configuration JSON",
                    severity=RiskLevel.MEDIUM,
                    description=f"JSON decoding error: {e}",
                    location=source_name,
                    category="format_anomaly",
                )
            )
            return findings

        # Check for auto_map or remote code execution flags
        auto_map = data.get("auto_map", {})
        if auto_map:
            findings.append(
                Finding(
                    rule_id="TOKENIZER-AUTO-MAP-REMOTE-CODE",
                    title="Dynamic Auto-Map Code Execution in Tokenizer",
                    severity=RiskLevel.CRITICAL,
                    description=f"Tokenizer configuration requests dynamic Python class loading via auto_map: {auto_map}",
                    location=source_name,
                    category="remote_code_execution",
                )
            )

        # Recursively search for URLs and file paths in JSON
        self._check_dict_urls(data, source_name, findings)
        return findings

    def _check_dict_urls(self, obj: Any, path: str, findings: List[Finding]) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                self._check_dict_urls(v, f"{path}:{k}", findings)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                self._check_dict_urls(v, f"{path}[{i}]", findings)
        elif isinstance(obj, str):
            if obj.startswith("file://"):
                findings.append(
                    Finding(
                        rule_id="TOKENIZER-LOCAL-FILE-SCHEME",
                        title="Local File URI Scheme in Tokenizer Config",
                        severity=RiskLevel.HIGH,
                        description=f"Prohibited file:// URI detected: {obj}",
                        location=path,
                        category="ssrf_file_inclusion",
                    )
                )
            elif obj.startswith("http://") and not self.allow_http:
                findings.append(
                    Finding(
                        rule_id="TOKENIZER-INSECURE-HTTP-URL",
                        title="Unencrypted Insecure HTTP URL in Tokenizer Config",
                        severity=RiskLevel.HIGH,
                        description=f"Insecure plaintext HTTP resource URL detected: {obj}",
                        location=path,
                        category="supply_chain_integrity",
                    )
                )
            elif any(domain in obj for domain in self.UNTRUSTED_DOMAINS):
                findings.append(
                    Finding(
                        rule_id="TOKENIZER-UNTRUSTED-DOMAIN-URL",
                        title="Untrusted Domain URL in Tokenizer Config",
                        severity=RiskLevel.HIGH,
                        description=f"External resource points to untrusted hosting domain: {obj}",
                        location=path,
                        category="supply_chain_integrity",
                    )
                )
