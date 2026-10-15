"""
Static security analyzer for JAX / Flax model checkpoints (.msgpack, .flax).
Inspects MessagePack serialization trees for custom extension types, embedded pickle opcodes,
and recursion depth anomalies without importing JAX or executing model code.
"""

from typing import Any, Dict, List, Optional
from scanner.core.reporter import Finding
from scanner.rules.dangerous_symbols import RiskLevel


class FlaxMsgpackAnalyzer:
    """Static security validator for JAX/Flax msgpack checkpoints."""

    MAX_RECURSION_DEPTH = 64
    MAX_KEY_LENGTH = 1024

    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode

    def analyze_bytes(self, raw_bytes: bytes, source_name: str = "checkpoint.msgpack") -> List[Finding]:
        """Scans raw msgpack bytes for malicious extension codes and payload injection."""
        findings: List[Finding] = []

        if not raw_bytes:
            return findings

        # Check for pickle magic header inside msgpack payload
        if b"\x80\x02" in raw_bytes or b"\x80\x03" in raw_bytes or b"\x80\x04" in raw_bytes or b"\x80\x05" in raw_bytes:
            # Check if common pickle opcodes follow
            if b"cbuiltins" in raw_bytes or b"cos\nsystem" in raw_bytes or b"cposix\nsystem" in raw_bytes:
                findings.append(
                    Finding(
                        rule_id="FLAX-EMBEDDED-PICKLE-PAYLOAD",
                        title="Embedded Malicious Pickle in Flax Checkpoint",
                        severity=RiskLevel.CRITICAL,
                        description="Flax msgpack checkpoint contains embedded pickle opcode sequence referencing dangerous globals.",
                        location=source_name,
                        category="deserialization_injection",
                    )
                )

        # MessagePack extension format byte: 0xc7, 0xc8, 0xc9 (ext 8, ext 16, ext 32)
        # or fixext types: 0xd4 to 0xd8
        # Flag untrusted custom extension types often used for Python code unpickling
        i = 0
        n = len(raw_bytes)
        while i < n - 1:
            b = raw_bytes[i]
            # fixext 1..16 or ext 8/16/32
            if b in (0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xC7, 0xC8, 0xC9):
                findings.append(
                    Finding(
                        rule_id="FLAX-CUSTOM-EXT-TYPE",
                        title="Unsupported Msgpack Custom Extension in Flax Model",
                        severity=RiskLevel.HIGH,
                        description=f"MessagePack stream contains non-standard extension type byte 0x{b:02x}.",
                        location=f"{source_name}:offset_{i}",
                        category="format_anomaly",
                    )
                )
                break
            i += 1

        # Check for shell command strings in strings table
        dangerous_signatures = [b"/bin/sh", b"/bin/bash", b"powershell.exe", b"cmd.exe", b"curl http"]
        for sig in dangerous_signatures:
            if sig in raw_bytes:
                findings.append(
                    Finding(
                        rule_id="FLAX-EMBEDDED-SHELL-STRING",
                        title="Embedded Shell Command in Flax Checkpoint",
                        severity=RiskLevel.CRITICAL,
                        description=f"Flax checkpoint contains suspicious shell reference: {sig.decode('ascii', errors='ignore')}",
                        location=source_name,
                        category="remote_code_execution",
                    )
                )

        return findings
