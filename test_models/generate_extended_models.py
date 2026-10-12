"""
Generates synthetic extended test models for NumPy, XGBoost, and TorchScript formats.
"""

import json
import os
import struct
import zipfile

import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner.analyzers.numpy_analyzer import NUMPY_MAGIC


def generate_extended_models(target_dir: str = "test_models") -> None:
    os.makedirs(target_dir, exist_ok=True)

    # 1. Safe NumPy array (<f4)
    header = b"{'descr': '<f4', 'fortran_order': False, 'shape': (10, 10), }\n"
    pad = 64 - ((len(header) + 10) % 64)
    header += b" " * pad
    safe_npy_bytes = NUMPY_MAGIC + b"\x01\x00" + struct.pack("<H", len(header)) + header + (b"\x00" * 400)
    with open(os.path.join(target_dir, "safe_array.npy"), "wb") as f:
        f.write(safe_npy_bytes)

    # 2. Trojan Object NumPy array (|O)
    header_trojan = b"{'descr': '|O', 'fortran_order': False, 'shape': (5,), }\n"
    pad = 64 - ((len(header_trojan) + 10) % 64)
    header_trojan += b" " * pad
    trojan_npy_bytes = NUMPY_MAGIC + b"\x01\x00" + struct.pack("<H", len(header_trojan)) + header_trojan
    with open(os.path.join(target_dir, "trojan_object.npy"), "wb") as f:
        f.write(trojan_npy_bytes)

    # 3. Safe XGBoost JSON
    safe_xgb = {"version": [1, 7, 0], "learner": {"objective": {"name": "reg:squarederror"}, "attributes": {}}}
    with open(os.path.join(target_dir, "safe_xgboost.json"), "w", encoding="utf-8") as f:
        json.dump(safe_xgb, f)

    # 4. Trojan XGBoost JSON
    trojan_xgb = {"version": [1, 7, 0], "learner": {"attributes": {"payload": "gAJjYnVpbHRpbnMKc..."}}}
    with open(os.path.join(target_dir, "trojan_xgboost.json"), "w", encoding="utf-8") as f:
        json.dump(trojan_xgb, f)

    # 5. Clean TorchScript
    with zipfile.ZipFile(os.path.join(target_dir, "clean_torchscript.pt"), "w") as zf:
        zf.writestr("code/__torch__/model.py", "def forward(x):\n    return x\n")

    # 6. Trojan TorchScript
    with zipfile.ZipFile(os.path.join(target_dir, "trojan_torchscript.pt"), "w") as zf:
        zf.writestr("code/__torch__/model.py", "def forward(x):\n    prim::PythonOp(x)\n    return x\n")

    print("[+] Generated extended synthetic test models successfully.")


if __name__ == "__main__":
    generate_extended_models()
