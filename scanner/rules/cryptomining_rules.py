"""
Rules identifying cryptomining pool endpoints and compute hijacking payloads
embedded within model weights, tokenizer configs, or deserialization scripts.
"""

import re
from typing import List
from scanner.core.reporter import Finding
from scanner.rules.dangerous_symbols import RiskLevel


MINING_SIGNATURES = [
    (r"stratum\+tcp://[a-zA-Z0-9\.\-_]+:\d+", "CRYPTOMINING-STRATUM-POOL", "Stratum mining pool connection protocol URL"),
    (r"(moneroocean|supportxmr|minexmr|nanopool|f2pool)\.(com|stream|org)", "CRYPTOMINING-POOL-DOMAIN", "Known cryptocurrency mining pool domain"),
    (r"\b(xmrig|minerd|ethminer|cpuminer|cryptonight)\b", "CRYPTOMINING-BINARY-REFERENCE", "Cryptocurrency mining binary executable name"),
    (r"nohup\s+.*&\s*$", "COMPUTE-HIJACK-BACKGROUND-PROCESS", "Background process spawn pattern (compute hijacking)"),
]


def scan_for_cryptomining(text_or_bytes: str | bytes, location_hint: str = "model_artifact") -> List[Finding]:
    """Inspects text or raw binary string for cryptomining and compute hijacking markers."""
    findings: List[Finding] = []
    text = text_or_bytes.decode("ascii", errors="ignore") if isinstance(text_or_bytes, bytes) else text_or_bytes

    for pattern, rule_id, desc in MINING_SIGNATURES:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            findings.append(
                Finding(
                    rule_id=f"HIJACK-{rule_id}",
                    title=f"Cryptomining / Compute Hijacking Signature ({rule_id})",
                    severity=RiskLevel.CRITICAL,
                    description=f"{desc} (matched: {match.group(0)})",
                    location=location_hint,
                    category="compute_hijacking",
                )
            )
    return findings
