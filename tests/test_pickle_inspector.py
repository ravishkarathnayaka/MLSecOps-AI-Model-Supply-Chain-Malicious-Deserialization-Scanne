"""
Unit tests validating static pickle disassembly, opcode inspection, and PyTorch archive analysis.
"""

import os
import pickle
import zipfile
import pytest

from scanner.analyzers.pickle_inspector import PickleInspector
from scanner.analyzers.pytorch_analyzer import PyTorchAnalyzer
from scanner.rules.dangerous_symbols import RiskLevel


class BenignPrintProbe:
    """Harmless test class using __reduce__ with builtins.print."""
    def __reduce__(self):
        return (print, ("Safe Test Payload",))


class BenignCustomState:
    """Safe class using __setstate__ with benign attributes."""
    def __init__(self, val=42):
        self.val = val

    def __getstate__(self):
        return {"val": self.val}

    def __setstate__(self, state):
        self.val = state.get("val", 0)


def test_pickle_inspector_safe_primitives():
    inspector = PickleInspector()
    safe_data = {
        "model_name": "bert-base-uncased",
        "weights": [0.1, 0.2, 0.3],
        "config": {"hidden_size": 768, "num_layers": 12},
    }
    raw_bytes = pickle.dumps(safe_data, protocol=4)
    findings = inspector.inspect_bytes(raw_bytes, source_name="safe_test.pkl")

    # Safe primitives should produce zero security findings
    assert len(findings) == 0


def test_pickle_inspector_flags_dangerous_reduce():
    inspector = PickleInspector()
    probe = BenignPrintProbe()
    raw_bytes = pickle.dumps(probe, protocol=4)

    findings = inspector.inspect_bytes(raw_bytes, source_name="trojan_test.pkl")
    assert len(findings) >= 1

    rule_ids = [f.rule_id for f in findings]
    assert any("ARBITRARY-CODE-EXECUTION-REDUCE" in r for r in rule_ids)
    assert any("DANGEROUS-GLOBAL" in r for r in rule_ids)

    # Check finding severity
    critical_findings = [f for f in findings if f.severity in (RiskLevel.CRITICAL, RiskLevel.HIGH)]
    assert len(critical_findings) >= 1


def test_pickle_inspector_flags_os_system_global():
    inspector = PickleInspector()
    # Manually constructed pickle opcode stream that imports os.system
    # c: GLOBAL opcode, 'os\nsystem\n'
    malicious_stream = b"cos\nsystem\n."
    findings = inspector.inspect_bytes(malicious_stream, source_name="os_system.pkl")

    assert len(findings) >= 1
    assert any("DANGEROUS-GLOBAL-CRITICAL" in f.rule_id for f in findings)
    assert findings[0].details.get("module") == "os"
    assert findings[0].details.get("symbol") == "system"


def test_pickle_inspector_flags_subprocess_popen():
    inspector = PickleInspector()
    malicious_stream = b"csubprocess\nPopen\n."
    findings = inspector.inspect_bytes(malicious_stream, source_name="subprocess_popen.pkl")

    assert len(findings) >= 1
    rule_ids = [f.rule_id for f in findings]
    assert any("DANGEROUS-GLOBAL-CRITICAL" in r for r in rule_ids)
    assert findings[0].details.get("module") == "subprocess"


def test_pickle_inspector_strict_mode():
    strict_inspector = PickleInspector(strict_mode=True)
    # Using collections.Counter which is not in default allowlist
    stream = b"ccollections\nCounter\n."
    findings = strict_inspector.inspect_bytes(stream, source_name="strict_test.pkl")

    assert len(findings) >= 1
    assert any(f.rule_id == "UNKNOWN-GLOBAL-STRICT" for f in findings)


def test_pytorch_analyzer_safe_archive(tmp_path):
    analyzer = PyTorchAnalyzer()
    model_path = str(tmp_path / "safe_pytorch.pt")

    safe_pickle = pickle.dumps({"weights": [1.0, 2.0, 3.0]}, protocol=4)
    with zipfile.ZipFile(model_path, "w") as zf:
        zf.writestr("archive/version", "3\n")
        zf.writestr("archive/data.pkl", safe_pickle)

    findings = analyzer.analyze(model_path)
    # Should be clean
    critical_or_high = [f for f in findings if f.severity in (RiskLevel.CRITICAL, RiskLevel.HIGH)]
    assert len(critical_or_high) == 0


def test_pytorch_analyzer_detects_trojan_in_zip(tmp_path):
    analyzer = PyTorchAnalyzer()
    model_path = str(tmp_path / "trojan_pytorch.pt")

    trojan_pickle = pickle.dumps(BenignPrintProbe(), protocol=4)
    with zipfile.ZipFile(model_path, "w") as zf:
        zf.writestr("archive/data.pkl", trojan_pickle)

    findings = analyzer.analyze(model_path)
    assert len(findings) >= 1
    assert any("REDUCE" in f.rule_id for f in findings)


def test_pytorch_analyzer_flags_zip_slip(tmp_path):
    analyzer = PyTorchAnalyzer()
    model_path = str(tmp_path / "zip_slip.pt")

    with zipfile.ZipFile(model_path, "w") as zf:
        # Malicious entry with directory traversal path
        zf.writestr("../../../etc/passwd", b"malicious content")
        zf.writestr("archive/data.pkl", pickle.dumps({"layer": 1}))

    findings = analyzer.analyze(model_path)
    slip_findings = [f for f in findings if f.rule_id == "PYTORCH-ZIP-SLIP-TRAVERSAL"]
    assert len(slip_findings) == 1
    assert slip_findings[0].severity == RiskLevel.CRITICAL


def test_pytorch_analyzer_flags_embedded_executable(tmp_path):
    analyzer = PyTorchAnalyzer()
    model_path = str(tmp_path / "embedded_exec.pt")

    with zipfile.ZipFile(model_path, "w") as zf:
        zf.writestr("archive/run_payload.sh", b"#!/bin/bash\necho trojan\n")
        zf.writestr("archive/data.pkl", pickle.dumps({"layer": 1}))

    findings = analyzer.analyze(model_path)
    exec_findings = [f for f in findings if f.rule_id == "PYTORCH-EMBEDDED-EXECUTABLE"]
    assert len(exec_findings) == 1
    assert exec_findings[0].severity == RiskLevel.HIGH
