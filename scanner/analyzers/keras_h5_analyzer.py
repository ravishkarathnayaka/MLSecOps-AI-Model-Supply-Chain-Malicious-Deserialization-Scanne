"""
Keras and HDF5 Model Static Security Analyzer.
Inspects Keras archives (.keras) and HDF5 model containers (.h5).
Detects arbitrary code execution vulnerabilities in serialized Keras Lambda layers
and custom unmarshalled bytecode definitions without calling keras.models.load_model().
"""

import base64
import json
import marshal
import os
import zipfile
from typing import Any, Dict, List, Optional

from scanner.rules.dangerous_symbols import RiskLevel, lookup_symbol_rule
from scanner.rules.policy_engine import Finding


class KerasH5Analyzer:
    """
    Statically analyzes Keras v2/v3 model definitions for Lambda layer bytecode injection.
    """

    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode

    def analyze_file(self, file_path: str) -> List[Finding]:
        if not os.path.exists(file_path):
            return [
                Finding(
                    rule_id="KERAS-FILE-NOT-FOUND",
                    title="Keras Model File Not Found",
                    severity=RiskLevel.HIGH,
                    category="io_error",
                    description=f"Path does not exist: {file_path}",
                    location=file_path,
                )
            ]

        # Check if file is a ZIP archive (.keras modern format)
        if zipfile.is_zipfile(file_path):
            return self._analyze_keras_zip(file_path)

        # Fallback to inspecting raw HDF5 string blocks
        return self._analyze_h5_raw(file_path)

    def _analyze_keras_zip(self, file_path: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                for name in zf.namelist():
                    if name in ("config.json", "metadata.json") or name.endswith(".json"):
                        raw_json = zf.read(name).decode("utf-8", errors="replace")
                        findings.extend(self._scan_keras_config_json(raw_json, f"{file_path}::{name}"))
        except Exception as e:
            findings.append(
                Finding(
                    rule_id="KERAS-ZIP-PARSE-ERROR",
                    title="Failed to Parse Keras Archive",
                    severity=RiskLevel.HIGH,
                    category="parsing_error",
                    description=str(e),
                    location=file_path,
                )
            )
        return findings

    def _analyze_h5_raw(self, file_path: str) -> List[Finding]:
        """Scans raw HDF5 bytes searching for model_config JSON strings without requiring h5py."""
        findings: List[Finding] = []
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            # Check for HDF5 signature (\x89HDF\r\n\x1a\n)
            if not data.startswith(b"\x89HDF\r\n\x1a\n"):
                return findings

            # Search for model_config or Lambda strings
            if b'"class_name": "Lambda"' in data or b'"class_name":"Lambda"' in data:
                findings.append(
                    Finding(
                        rule_id="KERAS-HDF5-LAMBDA-LAYER",
                        title="Insecure Keras Lambda Layer Found in HDF5",
                        severity=RiskLevel.CRITICAL,
                        category="code_execution",
                        description=(
                            "HDF5 model contains a serialized Keras 'Lambda' layer. "
                            "Lambda layers deserialized via Keras load_model() can execute arbitrary bytecode."
                        ),
                        location=file_path,
                    )
                )
        except Exception as e:
            findings.append(
                Finding(
                    rule_id="HDF5-SCAN-ERROR",
                    title="Error Scanning HDF5 File",
                    severity=RiskLevel.LOW,
                    category="io_error",
                    description=str(e),
                    location=file_path,
                )
            )
        return findings

    def _scan_keras_config_json(self, json_str: str, location: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            config = json.loads(json_str)
            self._traverse_layer_nodes(config, location, findings)
        except Exception:
            # Fallback simple substring check
            if '"class_name": "Lambda"' in json_str:
                findings.append(
                    Finding(
                        rule_id="KERAS-LAMBDA-LAYER-DETECTED",
                        title="Unsafe Keras Lambda Layer Detected",
                        severity=RiskLevel.CRITICAL,
                        category="code_execution",
                        description="Keras model configuration declares an arbitrary executable Lambda layer.",
                        location=location,
                    )
                )
        return findings

    def _traverse_layer_nodes(self, obj: Any, location: str, findings: List[Finding]) -> None:
        if isinstance(obj, dict):
            if obj.get("class_name") == "Lambda":
                layer_config = obj.get("config", {})
                fn_str = layer_config.get("function")

                findings.append(
                    Finding(
                        rule_id="KERAS-LAMBDA-LAYER-DETECTED",
                        title="Arbitrary Code Execution: Keras Lambda Layer",
                        severity=RiskLevel.CRITICAL,
                        category="code_execution",
                        description=(
                            "Model configuration defines a 'Lambda' layer containing custom Python code. "
                            "Loading this model automatically executes embedded bytecode."
                        ),
                        location=location,
                        details={"layer_name": layer_config.get("name", "unnamed_lambda")},
                    )
                )

                # If bytecode is embedded in base64, check for suspicious strings
                if isinstance(fn_str, (list, tuple)) and len(fn_str) > 0 and isinstance(fn_str[0], str):
                    code_b64 = fn_str[0]
                    try:
                        raw_code = base64.b64decode(code_b64)
                        for bad_sym in (b"system", b"exec", b"eval", b"popen", b"subprocess", b"socket"):
                            if bad_sym in raw_code.lower():
                                findings.append(
                                    Finding(
                                        rule_id="KERAS-LAMBDA-DANGEROUS-BYTECODE",
                                        title=f"Malicious Primitive '{bad_sym.decode()}' in Lambda Bytecode",
                                        severity=RiskLevel.CRITICAL,
                                        category="code_execution",
                                        description="Embedded Keras Lambda bytecode contains dangerous OS or execution calls.",
                                        location=location,
                                    )
                                )
                    except Exception:
                        pass

            for val in obj.values():
                self._traverse_layer_nodes(val, location, findings)
        elif isinstance(obj, list):
            for item in obj:
                self._traverse_layer_nodes(item, location, findings)
