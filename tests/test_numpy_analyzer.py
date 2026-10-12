"""
Unit tests for NumPyAnalyzer.
Validates detection of unsafe Object (|O) arrays and Zip Slip sequences in .npy / .npz archives.
"""

import struct
import zipfile
from scanner.analyzers.numpy_analyzer import NUMPY_MAGIC, NumPyAnalyzer
from scanner.rules.dangerous_symbols import RiskLevel


def _make_npy_bytes(descr: str, shape: tuple = (10,)) -> bytes:
    header_dict = f"{{'descr': '{descr}', 'fortran_order': False, 'shape': {shape}, }}\n"
    header_bytes = header_dict.encode("latin1")
    # Pad to 64-byte alignment
    pad_len = 64 - ((len(header_bytes) + 10) % 64)
    header_bytes += b" " * pad_len
    return NUMPY_MAGIC + b"\x01\x00" + struct.pack("<H", len(header_bytes)) + header_bytes


def test_numpy_clean_float_array(tmp_path):
    analyzer = NumPyAnalyzer()
    npy_file = tmp_path / "clean_weights.npy"
    npy_file.write_bytes(_make_npy_bytes("<f4", (64, 64)))

    findings = analyzer.analyze_file(str(npy_file))
    assert len(findings) == 0


def test_numpy_object_array_flagged(tmp_path):
    analyzer = NumPyAnalyzer()
    npy_file = tmp_path / "trojan_object.npy"
    npy_file.write_bytes(_make_npy_bytes("|O", (5,)))

    findings = analyzer.analyze_file(str(npy_file))
    assert len(findings) == 1
    assert findings[0].rule_id == "NUMPY-OBJECT-PICKLE-DESERIALIZATION"
    assert findings[0].severity == RiskLevel.CRITICAL


def test_numpy_npz_zip_slip_flagged(tmp_path):
    analyzer = NumPyAnalyzer()
    npz_file = tmp_path / "slip.npz"
    with zipfile.ZipFile(str(npz_file), "w") as zf:
        zf.writestr("../../etc/passwd", _make_npy_bytes("<f4"))

    findings = analyzer.analyze_file(str(npz_file))
    assert any(f.rule_id == "NUMPY-NPZ-ZIP-SLIP" for f in findings)
