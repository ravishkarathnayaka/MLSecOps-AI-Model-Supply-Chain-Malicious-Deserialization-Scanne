"""
Unit tests for KerasH5Analyzer.
Validates detection of unsafe Lambda layers and arbitrary bytecode deserialization vectors in Keras models.
"""

import base64
import json
import zipfile
from scanner.analyzers.keras_h5_analyzer import KerasH5Analyzer
from scanner.rules.dangerous_symbols import RiskLevel


def test_keras_safe_model_passes(tmp_path):
    analyzer = KerasH5Analyzer()
    safe_config = {
        "class_name": "Sequential",
        "config": {
            "layers": [
                {"class_name": "Dense", "config": {"units": 64, "activation": "relu"}},
                {"class_name": "Dense", "config": {"units": 10, "activation": "softmax"}},
            ]
        },
    }
    model_file = tmp_path / "safe_model.keras"
    with zipfile.ZipFile(str(model_file), "w") as zf:
        zf.writestr("config.json", json.dumps(safe_config))

    findings = analyzer.analyze_file(str(model_file))
    assert len(findings) == 0


def test_keras_lambda_layer_detected(tmp_path):
    analyzer = KerasH5Analyzer()
    lambda_config = {
        "class_name": "Sequential",
        "config": {
            "layers": [
                {
                    "class_name": "Lambda",
                    "config": {
                        "name": "malicious_lambda",
                        "function": [base64.b64encode(b"os.system('id')").decode()],
                    },
                }
            ]
        },
    }
    model_file = tmp_path / "lambda_model.keras"
    with zipfile.ZipFile(str(model_file), "w") as zf:
        zf.writestr("config.json", json.dumps(lambda_config))

    findings = analyzer.analyze_file(str(model_file))
    assert len(findings) >= 1
    assert any(f.rule_id == "KERAS-LAMBDA-LAYER-DETECTED" for f in findings)
    assert any(f.severity == RiskLevel.CRITICAL for f in findings)


def test_keras_raw_hdf5_detection(tmp_path):
    analyzer = KerasH5Analyzer()
    hdf5_file = tmp_path / "model.h5"
    # Construct mock HDF5 header + Lambda layer payload
    h5_content = b"\x89HDF\r\n\x1a\n" + b"padding" + b'{"class_name": "Lambda", "config": {}}'
    hdf5_file.write_bytes(h5_content)

    findings = analyzer.analyze_file(str(hdf5_file))
    assert len(findings) == 1
    assert findings[0].rule_id == "KERAS-HDF5-LAMBDA-LAYER"
