# Triton Inference Server Model Repository Security Integration Guide

## 1. Overview

NVIDIA Triton Inference Server is widely deployed in production high-throughput inference environments. A Triton deployment organizes models within a hierarchical directory structure known as the **Model Repository**:

```text
model_repository/
├── bert_sequence_classifier/
│   ├── config.pbtxt
│   └── 1/
│       └── model.onnx
└── fraud_detection_torchscript/
    ├── config.pbtxt
    └── 1/
        └── model.pt
```

Because Triton can automatically reload models when filesystem changes occur (via `--model-control-mode=poll` or `--model-control-mode=explicit`), an attacker or malicious supply chain actor who compromises an object storage bucket (S3, GCS, MinIO) can deliver trojaned model weights directly into the running GPU memory space.

---

## 2. Threat Vectors in Triton Model Repositories

| Attack Vector | Triton Backend | Exploitation Mechanism | Mitigation |
| :--- | :--- | :--- | :--- |
| **Pickle Deserialization** | PyTorch / Python Backend | `__reduce__` shellcode payload inside `model.pt` | Static pickle AST opcode analysis |
| **Custom Node Operators** | ONNX Runtime Backend | Malicious external C++ operator referenced in graph | ONNX operator denylist checking |
| **Python Backend Injection** | Python Backend | Backdoored `model.py` script executing arbitrary system calls | Pre-flight AST parsing & import sandboxing |
| **Model Shard Tampering** | Safetensors / TensorRT | Corrupted weight offsets causing GPU buffer overflow | Header validation & SHA-256 hash verifier |

---

## 3. Pre-Flight Scanning in CI/CD & GitOps

Before promoting new model versions to the production model repository, execute the scanner in your CI/CD pipeline:

```bash
# Scan entire Triton model repository directory
mlsec-scan --path /path/to/triton/model_repository --fail-on high --format sarif --output triton-scan.sarif

# Verify exit code in deployment pipeline
if [ $? -ne 0 ]; then
    echo "[-] Model repository contains critical security vulnerabilities. Blocking deployment."
    exit 1
fi
```

---

## 4. Kubernetes Sidecar & Init Container Pattern

For deployments on Kubernetes, run MLSecOps as an **Init Container** that inspects shared volumes before Triton launches:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: triton-inference-server
  namespace: ml-serving
spec:
  replicas: 3
  template:
    spec:
      volumes:
        - name: model-repo-volume
          persistentVolumeClaim:
            claimName: s3-model-repo-pvc
      initContainers:
        - name: mlsecops-model-gatekeeper
          image: ghcr.io/mlsecops/scanner:latest
          command:
            - "mlsec-scan"
            - "--path"
            - "/models"
            - "--fail-on"
            - "high"
            - "--format"
            - "terminal"
          volumeMounts:
            - name: model-repo-volume
              mountPath: /models
              readOnly: true
      containers:
        - name: triton-server
          image: nvcr.io/nvidia/tritonserver:24.08-py3
          args:
            - "tritonserver"
            - "--model-repository=/models"
            - "--model-control-mode=none"
          volumeMounts:
            - name: model-repo-volume
              mountPath: /models
              readOnly: true
```

---

## 5. Triton Explicit Model Control Dynamic Webhook

When using `--model-control-mode=explicit`, Triton allows dynamic model loading via REST API:

```http
POST /v2/repository/models/{model_name}/load
```

To prevent unverified models from being loaded dynamically:

1. Configure an API Gateway (Envoy or Kong) in front of Triton's management port (8000/8001).
2. Direct all `/v2/repository/models/{model_name}/load` requests through the **MLSecOps Admission Controller** (`http://admission-gate.mlsecops:8080/v1/kserve/admit`).
3. If the scanner validates the model files in storage, the admission controller forwards the request to Triton.
4. If malicious opcodes or untrusted signatures are detected, the gateway immediately returns `403 Forbidden` with detailed SARIF diagnostic logs.
