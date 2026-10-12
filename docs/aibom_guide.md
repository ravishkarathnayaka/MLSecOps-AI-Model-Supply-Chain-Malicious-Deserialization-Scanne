# AI Bill of Materials (AIBOM) & Model Provenance Guide

## 1. Overview & Regulatory Imperatives

Modern AI/ML systems ingest third-party foundation models and fine-tuned checkpoints from decentralized model hubs (e.g., Hugging Face, Civitai, PyTorch Hub). Without verifiable lineage and static transparency, models introduce critical supply chain risks:

- **Malicious Payload Deserialization:** Embedded Python code in serialized tensor weights (`pickle`, `PyTorch`).
- **Hidden Backdoors & Data Exfiltration:** Poisoned weights, custom graph operators, or dynamic callback hooks.
- **License Incompatibilities:** Unauthorized training data, restrictive commercial terms, or viral copyleft contamination.

To address these risks and fulfill international regulatory frameworks (such as the **EU AI Act Articles 11–13**, **NIST AI Risk Management Framework 1.0**, and **US Executive Order 14110**), MLSecOps generates standardized machine-readable **AI Software Bills of Materials (AIBOM)**.

---

## 2. Supported AIBOM Standards

### CycloneDX v1.5 (Machine Learning Profile)

CycloneDX v1.5 extends standard software bill of materials schemas with native `machine-learning-model` component types:

- **Component Identification:** Package URL (purl), model serial number, and semantic version.
- **Model Parameters & Architecture:** Hyperparameters, architecture family (`transformer`, `cnn`, `diffusion`), and input/output tensor shapes.
- **Data Governance:** Training datasets, evaluation metrics, and licensing terms.
- **Cryptographic Hashes:** Deterministic SHA-256 and SHA-512 digests of all weight shards.

#### Example CycloneDX JSON Excerpt:
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:3e29f0b8-4729-41d5-bc44-59e5ce675c91",
  "metadata": {
    "timestamp": "2026-10-12T17:40:00Z",
    "tools": [
      {
        "vendor": "MLSecOps",
        "name": "ai-supply-chain-scanner",
        "version": "1.0.0"
      }
    ],
    "component": {
      "type": "machine-learning-model",
      "name": "resnet50-production",
      "version": "1.0.0",
      "purl": "pkg:mlsec/model/resnet50-production@1.0.0",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "8f4e2b10a9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2"
        }
      ],
      "modelCard": {
        "modelParameters": {
          "task": "image-classification",
          "architecture": "ResNet-50",
          "framework": "PyTorch"
        }
      }
    }
  }
}
```

---

### SPDX v2.3 (AI Model Package Profile)

SPDX v2.3 provides legal, copyright, and licensing attestations for enterprise compliance teams:

- **Package Supplier & Origin:** Verifiable author and upstream repository.
- **Concluded & Declared Licenses:** SPDX License Identifiers (e.g., `Apache-2.0`, `MIT`, `OpenRAIL-M`).
- **External References:** Security advisory links and Sigstore transparency log entries.

---

## 3. Generating AIBOM via CLI

You can generate CycloneDX and SPDX AIBOM artifacts directly via the MLSecOps CLI:

```bash
# Generate CycloneDX v1.5 AIBOM
mlsec-scan --path ./models/resnet50.pt --aibom-cyclonedx ./bom/resnet50.cyclonedx.json

# Generate SPDX v2.3 SBOM
mlsec-scan --path ./models/resnet50.pt --aibom-spdx ./bom/resnet50.spdx.json
```

---

## 4. Cryptographic Provenance & Rekor Transparency Log

Every AIBOM record can be verified against keyless signatures generated via **Sigstore / Cosign**:

1. **SHA-256 Checksum Verification:** Ensures byte-for-byte fidelity with published model card checksums.
2. **Sigstore Rekor Log Proof:** Verifies that the artifact hash was logged in a tamper-evident public or private Rekor transparency log at signing time.
3. **In-Toto Attestation Validation:** Inspects cryptographic provenance envelopes (`bundle.sigstore.json`) to confirm build pipeline provenance without distributing long-lived private keys.

---

## 5. Kubernetes Admission Enforcement

Kubernetes admission controllers (`admission_gate/webhook_server.py`) and Kyverno policies query the generated AIBOM before allowing Pod execution:

- Models lacking a valid AIBOM are rejected with code `403 Forbidden`.
- Checksums that mismatch the AIBOM manifest trigger an immediate supply-chain quarantine event.
