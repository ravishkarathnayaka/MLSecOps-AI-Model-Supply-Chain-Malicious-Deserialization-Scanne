# MITRE ATLAS & OWASP Top 10 for LLM Threat Mapping Guide

## 1. Executive Summary

Enterprise artificial intelligence systems face specialized threat models distinct from traditional software architectures. To provide verifiable threat classification, MLSecOps maps every static finding, disassembly anomaly, and policy violation to two premier industry standards:

1. **MITRE ATLAS™ (Adversarial Threat Landscape for AI Systems)**
2. **OWASP Top 10 for Large Language Model (LLM) Applications**

---

## 2. Threat Matrix Correlation

| Threat Category | Scanner Detection Engine | MITRE ATLAS Technique | OWASP LLM ID | Risk Level |
| :--- | :--- | :--- | :--- | :--- |
| **Pickle Opcode Injection** | `PickleInspector` (AST opcode engine) | `AML.T0010.001`: Publish Poisoned Model | `LLM05`: Supply Chain Vulnerabilities | **CRITICAL** |
| **Prompt Injection Backdoors** | `scan_prompt_text` (regex / template) | `AML.T0043`: Craft Adversarial Data | `LLM01`: Prompt Injection | **HIGH** |
| **GPU Kernel Memory Tampering** | `lookup_gpu_memory_rule` (`ctypes`, `cudaMemcpy`) | `AML.T0010`: ML Supply Chain Compromise | `LLM05`: Supply Chain Vulnerabilities | **CRITICAL** |
| **Compute Hijacking / Cryptomining** | `scan_for_cryptomining` (Stratum / xmrig) | `AML.T0034`: Compute Resource Hijacking | `LLM04`: Model Denial of Service | **CRITICAL** |
| **Bias Tensor Steganography** | `scan_tensor_bytes_for_steganography` (ELF / ZIP) | `AML.T0018`: Backdoor ML Model | `LLM03`: Training Data Poisoning | **CRITICAL** |
| **Network Data Exfiltration** | `DangerousSymbols` (`socket`, `urllib`) | `AML.T0024`: Exfiltration via ML Artifacts | `LLM06`: Sensitive Information Disclosure | **CRITICAL** |
| **Unsigned Third-Party Artifacts** | `SigstoreVerifier` / `RekorProof` | `AML.T0010`: ML Supply Chain Compromise | `LLM05`: Supply Chain Vulnerabilities | **HIGH** |

---

## 3. SARIF & Automated SIEM Export

When exporting scan findings using the `--format sarif` CLI flag, all ATLAS and OWASP classifications are preserved within the SARIF v2.1.0 rule metadata tags:

```json
{
  "ruleId": "ARBITRARY-CODE-EXECUTION-REDUCE",
  "properties": {
    "tags": ["security", "mlsecops", "deserialization_injection"],
    "mitre_atlas": {
      "id": "AML.T0010",
      "name": "ML Supply Chain Compromise",
      "tactic": "Initial Access"
    },
    "owasp_llm": {
      "id": "LLM05",
      "title": "Supply Chain Vulnerabilities"
    }
  }
}
```

This guarantees seamless ingestion by enterprise SIEMs (Splunk, Microsoft Sentinel) and GitHub Advanced Security Code Scanning alerts.
