"""
NumPy Array File Static Security Analyzer (.npy, .npz).
Inspects NumPy binary headers and compressed ZIP archives.
Detects dangerous 'Object' arrays (|O) that invoke arbitrary pickle deserialization on np.load(),
and identifies Zip Slip directory traversal vulnerabilities in .npz packages.
"""

import ast
import io
import os
import struct
import zipfile
from typing import List, Optional

from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import Finding

NUMPY_MAGIC = b"\x93NUMPY"


class NumPyAnalyzer:
    """
    Statically analyzes NumPy .npy and .npz array files without executing np.load().
    """

    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode

    def analyze_file(self, file_path: str) -> List[Finding]:
        findings: List[Finding] = []
        if not os.path.exists(file_path):
            return findings

        # Check for .npz (ZIP archive containing .npy files)
        if zipfile.is_zipfile(file_path):
            return self._analyze_npz_archive(file_path)

        # Single .npy file
        try:
            with open(file_path, "rb") as f:
                data = f.read(4096)  # Read header chunk
            return self._analyze_npy_bytes(data, source_name=file_path)
        except Exception as e:
            findings.append(
                Finding(
                    rule_id="NUMPY-READ-ERROR",
                    title="Error Reading NumPy File",
                    severity=RiskLevel.LOW,
                    category="io_error",
                    description=str(e),
                    location=file_path,
                )
            )
        return findings

    def _analyze_npy_bytes(self, data: bytes, source_name: str) -> List[Finding]:
        findings: List[Finding] = []
        if len(data) < 10 or not data.startswith(NUMPY_MAGIC):
            return findings

        major_ver = data[6]
        minor_ver = data[7]

        # Extract header length (uint16 for v1.0, uint32 for v2.0+)
        if major_ver == 1:
            header_len = struct.unpack("<H", data[8:10])[0]
            header_bytes = data[10 : 10 + header_len]
        else:
            if len(data) < 12:
                return findings
            header_len = struct.unpack("<I", data[8:12])[0]
            header_bytes = data[12 : 12 + header_len]

        header_str = header_bytes.decode("latin1", errors="replace").strip()

        # Parse Python dict literal header safely
        try:
            parsed_header = ast.literal_eval(header_str)
            if isinstance(parsed_header, dict):
                descr = str(parsed_header.get("descr", ""))

                # Flag Object arrays (|O, O) which trigger pickle deserialization
                if descr in ("|O", "O", "object") or descr.startswith("|O"):
                    findings.append(
                        Finding(
                            rule_id="NUMPY-OBJECT-PICKLE-DESERIALIZATION",
                            title="NumPy Array Contains Serialized Object Data (|O)",
                            severity=RiskLevel.CRITICAL,
                            category="arbitrary_code_execution",
                            description=(
                                f"NumPy file '{source_name}' declares Object array dtype ('{descr}'). "
                                "Loading this file via np.load(allow_pickle=True) triggers unsafe pickle execution."
                            ),
                            location=source_name,
                            details={"descr": descr, "shape": parsed_header.get("shape")},
                        )
                    )
        except Exception:
            # Fallback string check
            if "'descr': '|O'" in header_str or "'descr': 'O'" in header_str:
                findings.append(
                    Finding(
                        rule_id="NUMPY-OBJECT-PICKLE-DESERIALIZATION",
                        title="NumPy Array Declares Dangerous Object Dtype",
                        severity=RiskLevel.CRITICAL,
                        category="arbitrary_code_execution",
                        description="Header contains '|O' object dtype marker indicating embedded pickle stream.",
                        location=source_name,
                    )
                )

        return findings

    def _analyze_npz_archive(self, file_path: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                for info in zf.infolist():
                    name = info.filename
                    loc = f"{file_path}::{name}"

                    # Zip Slip Traversal Check
                    if ".." in name or name.startswith("/") or name.startswith("\\"):
                        findings.append(
                            Finding(
                                rule_id="NUMPY-NPZ-ZIP-SLIP",
                                title="Directory Traversal Token in .npz Archive",
                                severity=RiskLevel.CRITICAL,
                                category="file_traversal",
                                description=f"NPZ archive entry '{name}' contains directory traversal sequences.",
                                location=loc,
                            )
                        )

                    # Inspect inner .npy stream
                    if name.endswith(".npy"):
                        inner_data = zf.read(name)[:4096]
                        findings.extend(self._analyze_npy_bytes(inner_data, source_name=loc))
        except Exception as e:
            findings.append(
                Finding(
                    rule_id="NUMPY-NPZ-PARSE-ERROR",
                    title="Failed to Parse .npz Archive",
                    severity=RiskLevel.HIGH,
                    category="parsing_error",
                    description=str(e),
                    location=file_path,
                )
            )
        return findings
