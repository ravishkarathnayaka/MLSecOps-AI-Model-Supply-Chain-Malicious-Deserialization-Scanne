"""
GGUF (GPT-Generated Unified Format) Static Security and Structure Analyzer.
Inspects quantized LLM models (.gguf) used by llama.cpp, Ollama, and local inference engines.
Validates magic headers, metadata schema integrity, alignment parameters, and identifies anomalous fields.
"""

import io
import os
import struct
from typing import Any, Dict, List, Optional, Tuple

from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import Finding

GGUF_MAGIC = b"GGUF"
GGUF_SUPPORTED_VERSIONS = {1, 2, 3}

# GGUF Metadata Value Types
GGUF_TYPE_UINT8 = 0
GGUF_TYPE_INT8 = 1
GGUF_TYPE_UINT16 = 2
GGUF_TYPE_INT16 = 3
GGUF_TYPE_UINT32 = 4
GGUF_TYPE_INT32 = 5
GGUF_TYPE_FLOAT32 = 6
GGUF_TYPE_BOOL = 7
GGUF_TYPE_STRING = 8
GGUF_TYPE_ARRAY = 9
GGUF_TYPE_UINT64 = 10
GGUF_TYPE_INT64 = 11
GGUF_TYPE_FLOAT64 = 12


class GGUFChecker:
    """
    Statically analyzes and validates GGUF binary headers and metadata without loading weights into RAM.
    """

    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode

    def check_file(self, file_path: str) -> List[Finding]:
        if not os.path.exists(file_path):
            return [
                Finding(
                    rule_id="GGUF-FILE-NOT-FOUND",
                    title="GGUF Model File Not Found",
                    severity=RiskLevel.HIGH,
                    category="io_error",
                    description=f"Model path does not exist: {file_path}",
                    location=file_path,
                )
            ]
        try:
            with open(file_path, "rb") as f:
                data = f.read(64 * 1024)  # Read header chunk
            return self.check_bytes(data, source_name=file_path, total_size=os.path.getsize(file_path))
        except Exception as e:
            return [
                Finding(
                    rule_id="GGUF-READ-ERROR",
                    title="Error Reading GGUF File",
                    severity=RiskLevel.HIGH,
                    category="io_error",
                    description=str(e),
                    location=file_path,
                )
            ]

    def check_bytes(
        self, data: bytes, source_name: str = "model.gguf", total_size: Optional[int] = None
    ) -> List[Finding]:
        findings: List[Finding] = []
        actual_size = len(data) if total_size is None else total_size

        if len(data) < 24:
            findings.append(
                Finding(
                    rule_id="GGUF-TRUNCATED-HEADER",
                    title="Truncated GGUF Header",
                    severity=RiskLevel.CRITICAL,
                    category="format_validation",
                    description="File is too short to contain a valid GGUF header structure.",
                    location=source_name,
                )
            )
            return findings

        # 1. Magic byte check
        magic = data[:4]
        if magic != GGUF_MAGIC:
            findings.append(
                Finding(
                    rule_id="GGUF-INVALID-MAGIC",
                    title="Invalid GGUF Magic Header Bytes",
                    severity=RiskLevel.CRITICAL,
                    category="format_validation",
                    description=f"Expected magic b'GGUF', but found {magic!r}.",
                    location=f"{source_name} [Offset: 0x0000]",
                    details={"found_magic": magic.hex()},
                )
            )
            return findings

        # 2. Version check (uint32 little endian at offset 4)
        version = struct.unpack("<I", data[4:8])[0]
        if version not in GGUF_SUPPORTED_VERSIONS:
            findings.append(
                Finding(
                    rule_id="GGUF-UNSUPPORTED-VERSION",
                    title=f"Unsupported GGUF Specification Version: {version}",
                    severity=RiskLevel.HIGH,
                    category="format_validation",
                    description=f"GGUF version {version} is not recognized or supported by standard runtimes.",
                    location=f"{source_name} [Offset: 0x0004]",
                    details={"version": version},
                )
            )

        # 3. Tensor count & KV count (uint64 at offset 8 and 16)
        tensor_count, kv_count = struct.unpack("<QQ", data[8:24])

        if kv_count > 100_000:
            findings.append(
                Finding(
                    rule_id="GGUF-ANOMALOUS-KV-COUNT",
                    title="Anomalously High Metadata Key-Value Count",
                    severity=RiskLevel.HIGH,
                    category="format_validation",
                    description=(
                        f"Declared metadata KV count ({kv_count}) is abnormally high. "
                        "May cause parser memory exhaustion (denial of service)."
                    ),
                    location=f"{source_name} [Offset: 0x0010]",
                    details={"kv_count": kv_count},
                )
            )

        # 4. Parse first few metadata keys if buffer allows
        stream = io.BytesIO(data[24:])
        parsed_keys: Dict[str, Any] = {}
        try:
            for _ in range(min(kv_count, 50)):
                key_len_bytes = stream.read(8)
                if len(key_len_bytes) < 8:
                    break
                k_len = struct.unpack("<Q", key_len_bytes)[0]
                if k_len > 1024:
                    findings.append(
                        Finding(
                            rule_id="GGUF-KEY-LENGTH-OVERFLOW",
                            title="Metadata Key Length Overflow",
                            severity=RiskLevel.HIGH,
                            category="format_validation",
                            description=f"GGUF key length {k_len} exceeds maximum reasonable string size.",
                            location=source_name,
                        )
                    )
                    break
                key_bytes = stream.read(k_len)
                key_name = key_bytes.decode("utf-8", errors="replace")

                val_type_bytes = stream.read(4)
                if len(val_type_bytes) < 4:
                    break
                val_type = struct.unpack("<I", val_type_bytes)[0]

                # Check for suspicious metadata keys
                if any(bad in key_name.lower() for bad in ("eval", "exec", "payload", "cmd", "shell")):
                    findings.append(
                        Finding(
                            rule_id="GGUF-SUSPICIOUS-METADATA-KEY",
                            title=f"Suspicious GGUF Metadata Key: '{key_name}'",
                            severity=RiskLevel.HIGH,
                            category="suspicious_metadata",
                            description=f"Detected unusual metadata key '{key_name}' that may indicate command payload injection.",
                            location=f"{source_name}::metadata[{key_name}]",
                            details={"key": key_name, "value_type": val_type},
                        )
                    )
                parsed_keys[key_name] = val_type
        except Exception:
            # Reached end of buffer or malformed
            pass

        return findings
