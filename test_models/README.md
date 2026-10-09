# Synthetic Test Models & Non-Destructive Benchmark Suite

This directory contains synthetically generated test models designed to validate static analysis rules, opcode disassembly engines, and format parsers **without executing untrusted model weights or harmful shell payloads**.

## Included Test Models

| File | Format | Classification | Security Vector Tested | Expected Result |
| :--- | :--- | :--- | :--- | :--- |
| `safe_model.safetensors` | Safetensors | Benign | Standard JSON header, valid buffer offsets | **PASS** |
| `malformed.safetensors` | Safetensors | Anomaly | Out-of-bounds tensor offset (`0 to 999999`) | **BLOCK** (`SAFETENSORS-BUFFER-OUT-OF-BOUNDS`) |
| `safe_model.pkl` | Pickle | Benign | Standard Python numeric and dict primitives | **PASS** |
| `trojan_print.pkl` | Pickle | Synthetic Trojan | Injected `builtins.print` via `REDUCE` opcode | **BLOCK** (`ARBITRARY-CODE-EXECUTION-REDUCE`) |
| `safe_model.pt` | PyTorch ZIP | Benign | Clean PyTorch ZIP archive with benign weights | **PASS** |
| `trojan_print.pt` | PyTorch ZIP | Synthetic Trojan | PyTorch ZIP containing `data.pkl` with `print` probe | **BLOCK** (`ARBITRARY-CODE-EXECUTION-REDUCE`) |
| `safe_model.onnx` | ONNX Protobuf | Benign | Standard `ai.onnx` domain and `Relu` operator | **PASS** |
| `custom_op.onnx` | ONNX Protobuf | Adversarial | Untrusted `custom.adversarial` domain and `ExecutePayload` op | **BLOCK** (`ONNX-UNTRUSTED-OPERATOR-DOMAIN`) |

## Safety Guarantee

None of the test models in this directory contain destructive system commands (e.g., `rm -rf`, reverse shells, socket exfiltration). The synthetic trojan models rely exclusively on benign `builtins.print` invocations via Python's `__reduce__` mechanism to trigger static disassembly rules cleanly and safely.

## Re-generating Test Models

To regenerate or refresh all synthetic test artifacts programmatically:

```bash
python test_models/generate_test_models.py
```
