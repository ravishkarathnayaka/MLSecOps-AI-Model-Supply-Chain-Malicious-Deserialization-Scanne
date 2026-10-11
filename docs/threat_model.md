# AI/ML Model Supply Chain Threat Model

This document outlines the security architecture, threat vectors, attack surfaces, and STRIDE mitigations for AI/ML model supply chain integrity.

```
       +-----------------------+
       | Hugging Face / Model  |
       | Hub (Untrusted Zone)  |
       +-----------+-----------+
                   |
                   v (Model Artifacts: .pkl, .pt, .onnx, .safetensors, .gguf)
        +---------------------+
        | MLSecOps Static AST |
        | Disassembly Engine  |
        +----------+----------+
                   |
                   v (Security Findings & Provenance Attestation)
        +---------------------+
        | Policy Gatekeeper   |
        | (FAIL on High/Crit) |
        +----------+----------+
                   |
         +---------+---------+
         |                   |
         v (Approved)        v (Rejected)
  +--------------+   +---------------+
  | KServe/vLLM  |   | Security Drop |
  | Inference Pod|   | & SARIF Alert |
  +--------------+   +---------------+
```

## 1. Threat Taxonomy

| Threat Vector | Affected Formats | Exploit Mechanism | Impact | MLSecOps Mitigation |
| :--- | :--- | :--- | :--- | :--- |
| **Pickle RCE** | `.pkl`, `.pt`, `.bin`, `.pth` | `GLOBAL` / `STACK_GLOBAL` + `REDUCE` executing `os.system` / `subprocess` | Full Remote Code Execution (RCE) on host or GPU worker | Safe static opcode disassembly via `pickletools.genops` without `pickle.load()` |
| **Zip Slip Traversal** | `.pt`, `.keras` | Archive entry paths with `../../` or absolute directories | Overwriting system binaries or SSH keys on unarchive | Archive entry manifest inspection for traversal tokens |
| **Untrusted ONNX Ops** | `.onnx` | Custom node operators (e.g. `PyOp`, `ExecutePayload`) with non-standard domains | Arbitrary dynamic library load during graph execution | Graph operator domain whitelist (`ai.onnx`, `ai.onnx.ml`) |
| **Safetensors Overflow** | `.safetensors` | Out-of-bounds `data_offsets` or header size exceeding file length | Buffer overflow / out-of-bounds memory read | Strict JSON schema and offset boundary mathematical validation |
| **Keras Lambda RCE** | `.h5`, `.keras` | Serialized Lambda layer base64 bytecode in `config.json` | Execution of custom code upon `load_model()` | AST configuration inspection flagging all Lambda layer nodes |
| **Steganographic Shellcode** | All formats | Encrypted payloads packed into float weight matrices | Evading signature detection for secondary loaders | Sliding window Shannon entropy analysis (>7.9 bits/byte) |

## 2. STRIDE Threat Analysis

- **Spoofing**: Tampering with author identity on public model hubs -> **Mitigation:** Cryptographic Sigstore Cosign verification and in-toto SLSA attestations.
- **Tampering**: Altering model weights in transit or storage -> **Mitigation:** Streaming SHA-256 digest comparison against Hugging Face Model Card manifests.
- **Repudiation**: Unlogged deployments of vulnerable models -> **Mitigation:** SARIF v2.1.0 audit trail committed to GitHub Security tab and SIEM.
- **Information Disclosure**: Exfiltrating environment secrets or API keys via network hooks -> **Mitigation:** Flagging network primitives (`socket`, `requests`, `urllib`).
- **Denial of Service**: Zip bombs or infinite header allocations -> **Mitigation:** Maximum header limits (100MB) and decompression ratio validation (>100x).
- **Elevation of Privilege**: Escaping inference container to host root -> **Mitigation:** Kubernetes validating webhook admission gate stopping pod initialization.
