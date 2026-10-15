"""
Heuristic detection rules for steganographic payload smuggling and executable embedding
within machine learning weight tensors and bias arrays.
"""

from typing import List
from scanner.core.reporter import Finding
from scanner.rules.dangerous_symbols import RiskLevel


EMBEDDED_FILE_SIGNATURES = [
    (b"PK\x03\x04", "STEG-EMBEDDED-ZIP", "Embedded ZIP archive header inside tensor data"),
    (b"\x7fELF", "STEG-EMBEDDED-ELF", "Embedded Linux ELF binary header inside tensor data"),
    (b"MZ\x90\x00", "STEG-EMBEDDED-PE", "Embedded Windows Portable Executable (PE) header inside tensor data"),
    (b"\xca\xfe\xba\xbe", "STEG-EMBEDDED-MACHO", "Embedded Mach-O binary header inside tensor data"),
    (b"#!/bin/", "STEG-EMBEDDED-SHELLSCRIPT", "Embedded shell script shebang inside tensor data"),
]


def scan_tensor_bytes_for_steganography(data: bytes, tensor_name: str = "tensor") -> List[Finding]:
    """Inspects raw tensor byte buffer for hidden executable signatures or steganographic markers."""
    findings: List[Finding] = []
    if len(data) < 4:
        return findings

    for sig, rule_id, desc in EMBEDDED_FILE_SIGNATURES:
        idx = data.find(sig)
        if idx != -1:
            findings.append(
                Finding(
                    rule_id=f"STEG-{rule_id}",
                    title=f"Steganographic Executable Signature in Tensor ({rule_id})",
                    severity=RiskLevel.CRITICAL,
                    description=f"{desc} detected at byte offset {idx} in tensor '{tensor_name}'.",
                    location=f"{tensor_name}:offset_{idx}",
                    category="steganography_payload",
                )
            )

    return findings
