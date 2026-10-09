"""
Safetensors Format and Zero-Executable Memory Validator.
Validates Safetensors 8-byte little-endian header length, UTF-8 JSON metadata schema,
tensor shape/dtype consistency, non-overlapping or valid data buffer offsets,
and asserts zero-executable guarantees.
"""

import json
import os
import struct
from typing import Any, Dict, List, Set

from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import Finding

# Standard Safetensors dtypes and their byte sizes per element
VALID_SAFETENSORS_DTYPES: Dict[str, int] = {
    "F64": 8,
    "F32": 4,
    "F16": 2,
    "BF16": 2,
    "I64": 8,
    "I32": 4,
    "I16": 2,
    "I8": 1,
    "U8": 1,
    "BOOL": 1,
    "F8_E4M3": 1,
    "F8_E5M2": 1,
}

MAX_HEADER_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB max header sanity limit


class SafetensorsChecker:
    """
    Validates Safetensors model files against official specification and security baselines.
    """

    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode

    def check_file(self, file_path: str) -> List[Finding]:
        if not os.path.exists(file_path):
            return [
                Finding(
                    rule_id="SAFETENSORS-FILE-NOT-FOUND",
                    title="File Not Found",
                    severity=RiskLevel.HIGH,
                    category="io_error",
                    description=f"Specified model path does not exist: {file_path}",
                    location=file_path,
                )
            ]

        try:
            file_size = os.path.getsize(file_path)
            with open(file_path, "rb") as f:
                return self.check_bytes(f.read(), source_name=file_path, total_file_size=file_size)
        except Exception as e:
            return [
                Finding(
                    rule_id="SAFETENSORS-READ-ERROR",
                    title="Error Reading Safetensors File",
                    severity=RiskLevel.HIGH,
                    category="io_error",
                    description=f"Error reading safetensors file {file_path}: {str(e)}",
                    location=file_path,
                    details={"error": str(e)},
                )
            ]

    def check_bytes(
        self, data: bytes, source_name: str = "model.safetensors", total_file_size: int = -1
    ) -> List[Finding]:
        findings: List[Finding] = []
        actual_size = len(data) if total_file_size < 0 else total_file_size

        # 1. Minimum size verification (8-byte header length + minimal json)
        if actual_size < 10:
            findings.append(
                Finding(
                    rule_id="SAFETENSORS-TRUNCATED-FILE",
                    title="Safetensors File Truncated or Under Minimum Size",
                    severity=RiskLevel.CRITICAL,
                    category="format_validation",
                    description=f"File size ({actual_size} bytes) is too small to contain a valid Safetensors header.",
                    location=source_name,
                    details={"file_size": actual_size},
                )
            )
            return findings

        # 2. Extract 8-byte unsigned little-endian header size
        header_size = struct.unpack("<Q", data[:8])[0]

        if header_size <= 0:
            findings.append(
                Finding(
                    rule_id="SAFETENSORS-INVALID-HEADER-SIZE",
                    title="Zero or Negative Header Size",
                    severity=RiskLevel.CRITICAL,
                    category="format_validation",
                    description=f"Safetensors header size is invalid: {header_size} bytes.",
                    location=f"{source_name} [Offset: 0x0000]",
                    details={"header_size": header_size},
                )
            )
            return findings

        if header_size > MAX_HEADER_SIZE_BYTES:
            findings.append(
                Finding(
                    rule_id="SAFETENSORS-EXCESSIVE-HEADER-SIZE",
                    title="Excessive Header Size (Potential Denial-of-Service / Overflow)",
                    severity=RiskLevel.HIGH,
                    category="format_validation",
                    description=(
                        f"Header size ({header_size} bytes) exceeds maximum allowable safety threshold "
                        f"({MAX_HEADER_SIZE_BYTES} bytes)."
                    ),
                    location=f"{source_name} [Offset: 0x0000]",
                    details={"header_size": header_size},
                )
            )
            return findings

        if (8 + header_size) > actual_size:
            findings.append(
                Finding(
                    rule_id="SAFETENSORS-HEADER-OUT-OF-BOUNDS",
                    title="Header Size Exceeds Total File Size",
                    severity=RiskLevel.CRITICAL,
                    category="format_validation",
                    description=(
                        f"Specified header size ({header_size} bytes) plus 8-byte prefix exceeds total file size "
                        f"({actual_size} bytes). File is corrupted or tampered."
                    ),
                    location=f"{source_name} [Offset: 0x0000]",
                    details={"header_size": header_size, "file_size": actual_size},
                )
            )
            return findings

        # 3. Decode UTF-8 JSON header
        header_raw = data[8 : 8 + header_size]
        try:
            header_str = header_raw.decode("utf-8")
        except UnicodeDecodeError as ue:
            findings.append(
                Finding(
                    rule_id="SAFETENSORS-HEADER-NOT-UTF8",
                    title="Safetensors Header Is Not Valid UTF-8",
                    severity=RiskLevel.CRITICAL,
                    category="format_validation",
                    description=f"Failed to decode header bytes as UTF-8: {str(ue)}",
                    location=f"{source_name} [Offset: 0x0008]",
                    details={"error": str(ue)},
                )
            )
            return findings

        # 4. Parse JSON
        try:
            header_json = json.loads(header_str)
        except json.JSONDecodeError as je:
            findings.append(
                Finding(
                    rule_id="SAFETENSORS-HEADER-INVALID-JSON",
                    title="Safetensors Header Is Not Valid JSON",
                    severity=RiskLevel.CRITICAL,
                    category="format_validation",
                    description=f"Header failed JSON syntax validation: {str(je)}",
                    location=f"{source_name} [Offset: 0x0008]",
                    details={"error": str(je)},
                )
            )
            return findings

        if not isinstance(header_json, dict):
            findings.append(
                Finding(
                    rule_id="SAFETENSORS-HEADER-ROOT-NOT-OBJECT",
                    title="Safetensors Header Root Must Be a JSON Object",
                    severity=RiskLevel.CRITICAL,
                    category="format_validation",
                    description=f"Expected JSON object at root of header, got {type(header_json).__name__}.",
                    location=f"{source_name} [Offset: 0x0008]",
                )
            )
            return findings

        # 5. Buffer bounds and tensor schema validation
        buffer_size = actual_size - (8 + header_size)
        self._validate_tensors(header_json, buffer_size, source_name, findings)

        # 6. Zero-executable memory inspection (check for embedded pickle or shellcode strings)
        self._check_zero_executable_guarantees(header_str, source_name, findings)

        return findings

    def _validate_tensors(
        self, header_json: Dict[str, Any], buffer_size: int, source_name: str, findings: List[Finding]
    ) -> None:
        tensor_count = 0

        for key, val in header_json.items():
            if key == "__metadata__":
                # Optional metadata dictionary
                if not isinstance(val, dict):
                    findings.append(
                        Finding(
                            rule_id="SAFETENSORS-INVALID-METADATA",
                            title="__metadata__ Must Be a JSON Object",
                            severity=RiskLevel.HIGH,
                            category="schema_validation",
                            description="Safetensors __metadata__ field must be a key-value dictionary.",
                            location=f"{source_name}::__metadata__",
                        )
                    )
                continue

            tensor_count += 1
            loc = f"{source_name}::tensor[{key}]"

            if not isinstance(val, dict):
                findings.append(
                    Finding(
                        rule_id="SAFETENSORS-TENSOR-DESCRIPTOR-INVALID",
                        title=f"Invalid Tensor Descriptor for '{key}'",
                        severity=RiskLevel.HIGH,
                        category="schema_validation",
                        description=f"Tensor descriptor for '{key}' must be an object.",
                        location=loc,
                    )
                )
                continue

            # Check required fields: dtype, shape, data_offsets
            dtype = val.get("dtype")
            shape = val.get("shape")
            offsets = val.get("data_offsets")

            if not dtype or not isinstance(dtype, str):
                findings.append(
                    Finding(
                        rule_id="SAFETENSORS-MISSING-DTYPE",
                        title=f"Missing or Invalid Dtype for Tensor '{key}'",
                        severity=RiskLevel.HIGH,
                        category="schema_validation",
                        description=f"Tensor '{key}' must declare a string 'dtype'.",
                        location=loc,
                    )
                )
            elif dtype not in VALID_SAFETENSORS_DTYPES:
                findings.append(
                    Finding(
                        rule_id="SAFETENSORS-UNRECOGNIZED-DTYPE",
                        title=f"Unrecognized Dtype '{dtype}' in Tensor '{key}'",
                        severity=RiskLevel.HIGH,
                        category="schema_validation",
                        description=f"Dtype '{dtype}' is not part of the standard Safetensors specification.",
                        location=loc,
                        details={"dtype": dtype},
                    )
                )

            if not isinstance(shape, list) or not all(isinstance(x, int) and x >= 0 for x in shape):
                findings.append(
                    Finding(
                        rule_id="SAFETENSORS-INVALID-SHAPE",
                        title=f"Invalid Shape Definition for Tensor '{key}'",
                        severity=RiskLevel.HIGH,
                        category="schema_validation",
                        description=f"Tensor '{key}' shape must be a list of non-negative integers. Got: {shape}",
                        location=loc,
                    )
                )

            if not isinstance(offsets, list) or len(offsets) != 2 or not all(isinstance(x, int) for x in offsets):
                findings.append(
                    Finding(
                        rule_id="SAFETENSORS-INVALID-OFFSETS",
                        title=f"Invalid data_offsets for Tensor '{key}'",
                        severity=RiskLevel.CRITICAL,
                        category="schema_validation",
                        description=f"Tensor '{key}' data_offsets must be a list of exactly two integers [start, end].",
                        location=loc,
                        details={"offsets": offsets},
                    )
                )
                continue

            start, end = offsets[0], offsets[1]
            if start < 0 or end < start or end > buffer_size:
                findings.append(
                    Finding(
                        rule_id="SAFETENSORS-BUFFER-OUT-OF-BOUNDS",
                        title=f"Tensor Buffer Offset Out of Bounds for '{key}'",
                        severity=RiskLevel.CRITICAL,
                        category="memory_bounds_violation",
                        description=(
                            f"Tensor '{key}' offsets [{start}, {end}] exceed buffer boundaries "
                            f"(total buffer size: {buffer_size} bytes)."
                        ),
                        location=loc,
                        details={"start": start, "end": end, "buffer_size": buffer_size},
                    )
                )
                continue

            # Verify byte count consistency with shape and dtype
            if dtype in VALID_SAFETENSORS_DTYPES and isinstance(shape, list):
                num_elements = 1
                for dim in shape:
                    num_elements *= dim
                expected_bytes = num_elements * VALID_SAFETENSORS_DTYPES[dtype]
                actual_bytes = end - start
                if actual_bytes != expected_bytes:
                    findings.append(
                        Finding(
                            rule_id="SAFETENSORS-TENSOR-SIZE-MISMATCH",
                            title=f"Tensor Byte Length Mismatch for '{key}'",
                            severity=RiskLevel.HIGH,
                            category="memory_integrity",
                            description=(
                                f"Tensor '{key}' offsets indicate {actual_bytes} bytes, but shape {shape} "
                                f"and dtype '{dtype}' require exactly {expected_bytes} bytes."
                            ),
                            location=loc,
                            details={
                                "expected_bytes": expected_bytes,
                                "actual_bytes": actual_bytes,
                                "shape": shape,
                                "dtype": dtype,
                            },
                        )
                    )

    def _check_zero_executable_guarantees(
        self, header_str: str, source_name: str, findings: List[Finding]
    ) -> None:
        """Verifies header does not contain embedded executable markers or injection strings."""
        suspicious_markers = [
            ("__reduce__", "Pickle magic method __reduce__ found in header text"),
            ("subprocess.Popen", "Subprocess execution command found in metadata string"),
            ("os.system", "OS system command found in metadata string"),
            ("<script", "Cross-site scripting / HTML payload detected in metadata string"),
            ("eval(", "JavaScript / Python eval statement found in metadata string"),
        ]

        for marker, desc in suspicious_markers:
            if marker in header_str:
                findings.append(
                    Finding(
                        rule_id="SAFETENSORS-SUSPICIOUS-METADATA-PAYLOAD",
                        title=f"Suspicious Content in Safetensors Header: '{marker}'",
                        severity=RiskLevel.HIGH,
                        category="suspicious_payload",
                        description=f"Safetensors header text contains suspicious marker: {desc}.",
                        location=f"{source_name}::header",
                        details={"marker": marker},
                    )
                )
