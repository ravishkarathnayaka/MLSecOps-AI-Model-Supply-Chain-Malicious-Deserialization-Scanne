"""
TorchScript Static IR and AST Security Analyzer.
Inspects PyTorch JIT and TorchScript compiled models for unsafe Python fallbacks,
custom un-allowlisted foreign operators, and embedded bytecode.
"""

import os
import zipfile
from typing import List, Optional

from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import Finding
from scanner.rules.torchscript_rules import DANGEROUS_TORCHSCRIPT_OPS


class TorchScriptAnalyzer:
    """
    Analyzes serialized TorchScript graph definitions within PyTorch archives.
    """

    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode

    def analyze_archive(self, file_path: str) -> List[Finding]:
        findings: List[Finding] = []
        if not os.path.exists(file_path):
            return findings

        if not zipfile.is_zipfile(file_path):
            return findings

        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                for name in zf.namelist():
                    # TorchScript stores code in code/ or code/__torch__/
                    if name.startswith("code/") or name.endswith(".py") or "model.json" in name:
                        content = zf.read(name).decode("utf-8", errors="replace")
                        self._scan_torchscript_code(content, f"{file_path}::{name}", findings)
        except Exception as e:
            findings.append(
                Finding(
                    rule_id="TORCHSCRIPT-READ-ERROR",
                    title="Error Reading TorchScript Archive",
                    severity=RiskLevel.LOW,
                    category="io_error",
                    description=str(e),
                    location=file_path,
                )
            )

        return findings

    def _scan_torchscript_code(self, code_str: str, location: str, findings: List[Finding]) -> None:
        # Check against dangerous TorchScript primitives
        for op_name, rule in DANGEROUS_TORCHSCRIPT_OPS.items():
            if op_name in code_str:
                findings.append(
                    Finding(
                        rule_id=f"TORCHSCRIPT-OP-{rule.severity.value}",
                        title=f"Suspicious TorchScript Operator: {op_name}",
                        severity=rule.severity,
                        category=rule.category,
                        description=rule.description,
                        location=location,
                        details={"operator": op_name},
                    )
                )

        # Check for direct suspicious python calls inside compiled code files
        suspicious_tokens = ("os.system", "subprocess.Popen", "builtins.eval", "__import__", "socket.socket")
        for token in suspicious_tokens:
            if token in code_str:
                findings.append(
                    Finding(
                        rule_id="TORCHSCRIPT-DANGEROUS-IMPORT",
                        title=f"Forbidden Execution Token '{token}' in TorchScript IR",
                        severity=RiskLevel.CRITICAL,
                        category="code_execution",
                        description=f"TorchScript compiled code contains dangerous call '{token}'.",
                        location=location,
                        details={"token": token},
                    )
                )
