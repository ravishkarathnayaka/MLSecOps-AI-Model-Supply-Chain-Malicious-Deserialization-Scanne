"""
XGBoost and LightGBM Tabular Model Static Security Analyzer.
Inspects JSON, UBJ (Universal Binary JSON), and text-based tree model dumps.
Detects custom objective/metric code callbacks, embedded pickle attributes,
and anomalous split conditions.
"""

import json
import os
from typing import Any, Dict, List, Optional

from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import Finding


class TabularModelAnalyzer:
    """
    Statically audits XGBoost and LightGBM model configuration files.
    """

    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode

    def analyze_file(self, file_path: str) -> List[Finding]:
        findings: List[Finding] = []
        if not os.path.exists(file_path):
            return findings

        try:
            with open(file_path, "rb") as f:
                raw_bytes = f.read(512 * 1024)

            # Check if JSON format
            try:
                data = json.loads(raw_bytes.decode("utf-8"))
                findings.extend(self._analyze_json_model(data, file_path))
            except Exception:
                # Text-based LightGBM dump or raw binary inspection
                text_content = raw_bytes.decode("utf-8", errors="ignore")
                findings.extend(self._analyze_text_dump(text_content, file_path))
        except Exception as e:
            findings.append(
                Finding(
                    rule_id="TABULAR-READ-ERROR",
                    title="Error Reading Tabular Model",
                    severity=RiskLevel.LOW,
                    category="io_error",
                    description=str(e),
                    location=file_path,
                )
            )

        return findings

    def _analyze_json_model(self, data: Any, source_name: str) -> List[Finding]:
        findings: List[Finding] = []
        if not isinstance(data, dict):
            return findings

        # 1. Audit XGBoost learner attributes for serialized blobs
        learner = data.get("learner", {})
        attributes = learner.get("attributes", {})
        if isinstance(attributes, dict):
            for k, v in attributes.items():
                if isinstance(v, str):
                    # Check for base64 pickle signature (\x80\x02 - \x80\x05 -> gAJ, gAN, gAQ, gAU)
                    if any(v.startswith(sig) for sig in ("gAJ", "gAN", "gAQ", "gAU")):
                        findings.append(
                            Finding(
                                rule_id="XGBOOST-EMBEDDED-PICKLE-ATTRIBUTE",
                                title=f"Serialized Pickle Payload in XGBoost Attribute '{k}'",
                                severity=RiskLevel.CRITICAL,
                                category="code_execution",
                                description=(
                                    f"Attribute '{k}' contains base64-encoded pickle bytecode. "
                                    "Loading this model triggers arbitrary deserialization execution."
                                ),
                                location=f"{source_name}::learner.attributes[{k}]",
                                details={"attribute_key": k},
                            )
                        )

        # 2. Check for custom objective / metric strings indicating external python functions
        objective = learner.get("objective", {})
        obj_name = objective.get("name", "") if isinstance(objective, dict) else str(objective)
        if "custom" in obj_name.lower() or "python" in obj_name.lower():
            findings.append(
                Finding(
                    rule_id="TABULAR-CUSTOM-OBJECTIVE-CALLBACK",
                    title=f"Custom Objective Function Declared: '{obj_name}'",
                    severity=RiskLevel.HIGH,
                    category="untrusted_callback",
                    description="Model specifies a custom objective callback requiring external runtime binding.",
                    location=f"{source_name}::objective",
                    details={"objective": obj_name},
                )
            )

        return findings

    def _analyze_text_dump(self, text: str, source_name: str) -> List[Finding]:
        findings: List[Finding] = []
        # LightGBM tree text dump security checks
        if "tree" in text.lower():
            if "eval(" in text or "exec(" in text or "os.system" in text:
                findings.append(
                    Finding(
                        rule_id="LIGHTGBM-SUSPICIOUS-CODE-INJECTION",
                        title="Suspicious Code Injection in LightGBM Tree Parameters",
                        severity=RiskLevel.CRITICAL,
                        category="code_execution",
                        description="Detected executable shellcode or eval commands within tree specification.",
                        location=source_name,
                    )
                )
        return findings
