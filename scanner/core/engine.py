"""
Master Orchestration Engine.
Routes model artifacts (.pkl, .pt, .bin, .onnx, .safetensors) to appropriate format analyzers,
orchestrates cryptographic provenance checks, and evaluates findings against policy gates.
"""

import os
from typing import Dict, List, Optional, Set, Tuple, Union

from scanner.analyzers.onnx_analyzer import ONNXAnalyzer
from scanner.analyzers.pickle_inspector import PickleInspector
from scanner.analyzers.pytorch_analyzer import PyTorchAnalyzer
from scanner.analyzers.safetensors_checker import SafetensorsChecker
from scanner.provenance.hash_verifier import HashVerifier
from scanner.provenance.signature_checker import SignatureChecker
from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import EvaluationResult, Finding, PolicyEngine

MODEL_EXTENSIONS = {
    ".pkl",
    ".pickle",
    ".pt",
    ".pth",
    ".bin",
    ".safetensors",
    ".onnx",
}


class ModelScanEngine:
    """
    Core static scanning engine orchestrating format analyzers,
    provenance verifiers, and policy admission decisions.
    """

    def __init__(
        self,
        fail_on_threshold: RiskLevel = RiskLevel.HIGH,
        strict_mode: bool = False,
        custom_allowed_globals: Optional[Set[Tuple[str, str]]] = None,
        allowed_onnx_domains: Optional[Set[str]] = None,
    ):
        self.fail_on_threshold = fail_on_threshold
        self.strict_mode = strict_mode
        self.policy_engine = PolicyEngine(
            fail_on_threshold=fail_on_threshold,
            strict_mode=strict_mode,
        )

        # Analyzers
        self.pickle_inspector = PickleInspector(
            strict_mode=strict_mode, custom_allowed=custom_allowed_globals
        )
        self.pytorch_analyzer = PyTorchAnalyzer(
            strict_mode=strict_mode, custom_allowed=custom_allowed_globals
        )
        self.safetensors_checker = SafetensorsChecker(strict_mode=strict_mode)
        self.onnx_analyzer = ONNXAnalyzer(
            allowed_domains=allowed_onnx_domains, strict_mode=strict_mode
        )

    def scan_path(
        self,
        path: str,
        expected_sha256: Optional[str] = None,
        expected_sha512: Optional[str] = None,
        signature_path: Optional[str] = None,
        public_key_pem: Optional[Union[str, bytes]] = None,
        attestation_path: Optional[str] = None,
    ) -> Tuple[EvaluationResult, List[str]]:
        """
        Scans a single file or traverses an entire directory for model files.
        Returns the policy EvaluationResult and list of scanned model file paths.
        """
        scanned_files: List[str] = []
        all_findings: List[Finding] = []

        if not os.path.exists(path):
            missing_finding = Finding(
                rule_id="TARGET-PATH-NOT-FOUND",
                title="Target Scan Path Does Not Exist",
                severity=RiskLevel.HIGH,
                category="io_error",
                description=f"Scan path '{path}' does not exist on disk.",
                location=path,
            )
            eval_res = self.policy_engine.evaluate([missing_finding])
            return eval_res, []

        if os.path.isfile(path):
            scanned_files.append(path)
            findings = self._scan_single_file(
                file_path=path,
                expected_sha256=expected_sha256,
                expected_sha512=expected_sha512,
                signature_path=signature_path,
                public_key_pem=public_key_pem,
                attestation_path=attestation_path,
            )
            all_findings.extend(findings)
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for f in sorted(files):
                    ext = os.path.splitext(f)[1].lower()
                    if ext in MODEL_EXTENSIONS:
                        f_path = os.path.join(root, f)
                        scanned_files.append(f_path)
                        findings = self._scan_single_file(file_path=f_path)
                        all_findings.extend(findings)

        evaluation = self.policy_engine.evaluate(all_findings)
        return evaluation, scanned_files

    def _scan_single_file(
        self,
        file_path: str,
        expected_sha256: Optional[str] = None,
        expected_sha512: Optional[str] = None,
        signature_path: Optional[str] = None,
        public_key_pem: Optional[Union[str, bytes]] = None,
        attestation_path: Optional[str] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []
        ext = os.path.splitext(file_path)[1].lower()

        # 1. Cryptographic Provenance Checks (if requested)
        if expected_sha256 or expected_sha512:
            findings.extend(
                HashVerifier.verify_against_expected(
                    file_path=file_path,
                    expected_sha256=expected_sha256,
                    expected_sha512=expected_sha512,
                )
            )

        if signature_path and public_key_pem:
            findings.extend(
                SignatureChecker.verify_detached_signature(
                    model_path=file_path,
                    signature_path=signature_path,
                    public_key_pem=public_key_pem,
                )
            )

        if attestation_path:
            findings.extend(
                SignatureChecker.verify_intoto_attestation(
                    model_path=file_path,
                    attestation_file_or_data=attestation_path,
                )
            )

        # 2. Format-Specific Static Analysis
        if ext in (".pkl", ".pickle"):
            findings.extend(self.pickle_inspector.inspect_file(file_path))
        elif ext in (".pt", ".pth", ".bin"):
            findings.extend(self.pytorch_analyzer.analyze(file_path))
        elif ext == ".safetensors":
            findings.extend(self.safetensors_checker.check_file(file_path))
        elif ext == ".onnx":
            findings.extend(self.onnx_analyzer.analyze(file_path))
        else:
            # Format sniffing fallback by inspecting first bytes
            findings.extend(self._sniff_and_analyze(file_path))

        return findings

    def _sniff_and_analyze(self, file_path: str) -> List[Finding]:
        """Sniffs magic bytes to determine analyzer when extension is unrecognized."""
        try:
            with open(file_path, "rb") as f:
                header = f.read(16)

            # ZIP magic bytes: PK\x03\x04
            if header.startswith(b"PK\x03\x04"):
                return self.pytorch_analyzer.analyze(file_path)

            # Pickle protocol header: \x80[\x02-\x05]
            if len(header) >= 2 and header[0] == 0x80 and 2 <= header[1] <= 5:
                return self.pickle_inspector.inspect_file(file_path)

            # Safetensors: 8-byte uint64 followed by '{"'
            if len(header) >= 10 and b'{"' in header[8:10]:
                return self.safetensors_checker.check_file(file_path)

            # Fallback
            return [
                Finding(
                    rule_id="UNKNOWN-MODEL-FORMAT",
                    title="Unrecognized Model File Format",
                    severity=RiskLevel.MEDIUM,
                    category="format_validation",
                    description=(
                        f"Unable to determine model format for file '{file_path}'. "
                        "Static inspection could not be performed."
                    ),
                    location=file_path,
                )
            ]
        except Exception as e:
            return [
                Finding(
                    rule_id="FILE-SNIFF-ERROR",
                    title="Error Sniffing File Format",
                    severity=RiskLevel.HIGH,
                    category="io_error",
                    description=f"Error inspecting file bytes: {str(e)}",
                    location=file_path,
                )
            ]

    def scan_bytes(
        self,
        data: bytes,
        format_hint: str = "pkl",
        source_name: str = "memory_buffer",
    ) -> EvaluationResult:
        """Directly scans an in-memory byte buffer without writing to disk."""
        format_norm = format_hint.lower().lstrip(".")
        findings: List[Finding] = []

        if format_norm in ("pkl", "pickle"):
            findings.extend(self.pickle_inspector.inspect_bytes(data, source_name=source_name))
        elif format_norm in ("pt", "pth", "bin"):
            findings.extend(self.pytorch_analyzer.analyze_bytes(data, source_name=source_name))
        elif format_norm == "safetensors":
            findings.extend(self.safetensors_checker.check_bytes(data, source_name=source_name))
        elif format_norm == "onnx":
            findings.extend(self.onnx_analyzer.analyze_bytes(data, source_name=source_name))
        else:
            findings.extend(self.pickle_inspector.inspect_bytes(data, source_name=source_name))

        return self.policy_engine.evaluate(findings)
