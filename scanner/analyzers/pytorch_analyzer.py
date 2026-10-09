"""
PyTorch Model Archive Static Analyzer.
Inspects PyTorch archive structure (ZIP format), archive manifests, directory traversal risks (Zip Slip),
suspicious embedded executable scripts, and inner pickle weight streams (data.pkl, constants.pkl).
"""

import io
import os
import zipfile
from typing import List, Optional, Set, Tuple

from scanner.analyzers.pickle_inspector import PickleInspector
from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import Finding


class PyTorchAnalyzer:
    """
    Analyzes PyTorch model files (.pt, .pth, .bin).
    Safely dissects ZIP-based PyTorch archives and inner pickle files without running torch.load().
    """

    def __init__(self, strict_mode: bool = False, custom_allowed: Optional[Set[Tuple[str, str]]] = None):
        self.strict_mode = strict_mode
        self.pickle_inspector = PickleInspector(strict_mode=strict_mode, custom_allowed=custom_allowed)

    def analyze(self, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        if not os.path.exists(file_path):
            return [
                Finding(
                    rule_id="PYTORCH-FILE-NOT-FOUND",
                    title="File Not Found",
                    severity=RiskLevel.HIGH,
                    category="io_error",
                    description=f"Specified model path does not exist: {file_path}",
                    location=file_path,
                )
            ]

        # Check if file is a ZIP archive (standard modern PyTorch format)
        if zipfile.is_zipfile(file_path):
            findings.extend(self._analyze_zip_archive(file_path))
        else:
            # Fallback to direct raw pickle inspection (legacy format)
            findings.extend(self.pickle_inspector.inspect_file(file_path))

        return findings

    def analyze_bytes(self, data: bytes, source_name: str = "pytorch_model.pt") -> List[Finding]:
        """Analyzes PyTorch archive from in-memory byte buffer."""
        findings: List[Finding] = []
        stream = io.BytesIO(data)

        if zipfile.is_zipfile(stream):
            findings.extend(self._analyze_zip_stream(stream, source_name))
        else:
            findings.extend(self.pickle_inspector.inspect_bytes(data, source_name=source_name))

        return findings

    def _analyze_zip_archive(self, file_path: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                findings.extend(self._inspect_zip_entries(zf, file_path))
        except zipfile.BadZipFile as e:
            findings.append(
                Finding(
                    rule_id="PYTORCH-CORRUPTED-ZIP",
                    title="Corrupted PyTorch ZIP Archive",
                    severity=RiskLevel.HIGH,
                    category="file_corruption",
                    description=f"PyTorch archive appears to be a damaged or malformed ZIP file: {str(e)}",
                    location=file_path,
                )
            )
        except Exception as e:
            findings.append(
                Finding(
                    rule_id="PYTORCH-ZIP-READ-ERROR",
                    title="Error Reading PyTorch Archive",
                    severity=RiskLevel.HIGH,
                    category="io_error",
                    description=f"Unexpected error analyzing PyTorch archive: {str(e)}",
                    location=file_path,
                )
            )

        return findings

    def _analyze_zip_stream(self, stream: io.BytesIO, source_name: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            with zipfile.ZipFile(stream, "r") as zf:
                findings.extend(self._inspect_zip_entries(zf, source_name))
        except Exception as e:
            findings.append(
                Finding(
                    rule_id="PYTORCH-ZIP-READ-ERROR",
                    title="Error Reading PyTorch Memory Stream",
                    severity=RiskLevel.HIGH,
                    category="io_error",
                    description=f"Error reading PyTorch ZIP stream: {str(e)}",
                    location=source_name,
                )
            )
        return findings

    def _inspect_zip_entries(self, zf: zipfile.ZipFile, root_source: str) -> List[Finding]:
        findings: List[Finding] = []
        has_pickle_weights = False

        suspicious_extensions = {".sh", ".exe", ".bat", ".cmd", ".vbs", ".ps1", ".dll", ".so", ".dylib"}

        for info in zf.infolist():
            filename = info.filename
            loc = f"{root_source}::{filename}"

            # 1. Zip Slip / Directory Traversal Check
            if ".." in filename or filename.startswith("/") or filename.startswith("\\"):
                findings.append(
                    Finding(
                        rule_id="PYTORCH-ZIP-SLIP-TRAVERSAL",
                        title="Directory Traversal / Zip Slip Payload Detected",
                        severity=RiskLevel.CRITICAL,
                        category="file_traversal",
                        description=(
                            f"Archive entry '{filename}' contains directory traversal sequences. "
                            "Extracting or loading this archive may overwrite critical system files."
                        ),
                        location=loc,
                        details={"entry_name": filename},
                    )
                )

            # 2. Suspicious executable / script file inside model archive
            _, ext = os.path.splitext(filename.lower())
            if ext in suspicious_extensions:
                findings.append(
                    Finding(
                        rule_id="PYTORCH-EMBEDDED-EXECUTABLE",
                        title=f"Suspicious Embedded Executable File: {filename}",
                        severity=RiskLevel.HIGH,
                        category="embedded_payload",
                        description=(
                            f"Model archive contains executable script or binary '{filename}'. "
                            "Legitimate model weight archives should not bundle standalone executables."
                        ),
                        location=loc,
                        details={"extension": ext, "entry_name": filename},
                    )
                )

            # 3. Compression ratio anomaly (Zip Bomb check)
            if info.compress_size > 0 and (info.file_size / info.compress_size) > 100 and info.file_size > 10_000_000:
                findings.append(
                    Finding(
                        rule_id="PYTORCH-ZIP-BOMB-ANOMALY",
                        title="Potential Decompression Bomb Anomaly",
                        severity=RiskLevel.HIGH,
                        category="resource_exhaustion",
                        description=(
                            f"Entry '{filename}' has an anomalous compression ratio of "
                            f"{info.file_size / info.compress_size:.1f}x (uncompressed: {info.file_size} bytes)."
                        ),
                        location=loc,
                        details={"compression_ratio": info.file_size / info.compress_size},
                    )
                )

            # 4. Check for inner pickle files: data.pkl, constants.pkl, *.pkl
            if filename.endswith(".pkl") or "data.pkl" in filename or "constants.pkl" in filename:
                has_pickle_weights = True
                try:
                    entry_bytes = zf.read(filename)
                    inner_findings = self.pickle_inspector.inspect_bytes(entry_bytes, source_name=loc)
                    findings.extend(inner_findings)
                except Exception as ex:
                    findings.append(
                        Finding(
                            rule_id="PYTORCH-INNER-PICKLE-ERROR",
                            title=f"Failed to Inspect Inner Pickle: {filename}",
                            severity=RiskLevel.HIGH,
                            category="parsing_error",
                            description=f"Error inspecting inner pickle archive stream '{filename}': {str(ex)}",
                            location=loc,
                        )
                    )

        # Informational check if archive had zero standard weight entries
        if not has_pickle_weights and not any(info.filename.endswith(".json") for info in zf.infolist()):
            findings.append(
                Finding(
                    rule_id="PYTORCH-EMPTY-WEIGHTS",
                    title="No Standard Weight Streams Found",
                    severity=RiskLevel.INFO,
                    category="structure_warning",
                    description="PyTorch archive does not contain standard 'data.pkl' or pickle weight streams.",
                    location=root_source,
                )
            )

        return findings
