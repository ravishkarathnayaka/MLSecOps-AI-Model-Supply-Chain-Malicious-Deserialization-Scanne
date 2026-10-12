# Azure Cloud AI & vLLM High-Throughput Serving Integration Guide

## 1. Overview

In large-scale enterprise LLM deployments, organizations frequently store terabyte-scale model checkpoints in **Microsoft Azure Blob Storage** (`az://`) and serve them using **vLLM** for maximum GPU throughput.

Without strict pre-flight admission gating, loading models from shared cloud buckets into GPU High-Bandwidth Memory (HBM) exposes the cluster to:
- Pickle deserialization shellcode executed during weight loading (`torch.load`).
- Sneaked unverified binary sharding (`.bin` files hidden inside Safetensors repos).
- Resource exhaustion from poisoned model configuration schemas.

This guide details how to integrate the **MLSecOps Azure Blob Scanner** and **vLLM Admission Guard** into your production MLOps pipeline.

---

## 2. Scanning Azure Blob Storage Repositories

The scanner streams remote weights directly from Azure Blob Storage without staging large files to worker disk:

```bash
# Scan models in an Azure Blob container
mlsec-scan --azure az://ml-models-prod/llama-3-70b/ --fail-on high --format sarif --output azure-scan.sarif
```

### Python SDK Usage:
```python
from scanner.integrations.azure_blob_scanner import AzureBlobScanner

scanner = AzureBlobScanner(connection_string="<AZURE_STORAGE_CONNECTION_STRING>")
results = scanner.scan_container_prefix(
    container="ml-models-prod",
    prefix="llama-3-70b/",
    fail_on_severity="HIGH",
)

for res in results:
    if not res.passed:
        print(f"[-] Quarantined compromised model: {res.summary}")
```

---

## 3. Integrating vLLM Pre-Flight Admission Guard

Use the `vLLMAdmissionGuard` to validate local or mounted model directories before passing weights to the vLLM engine:

```python
from vllm import LLM, SamplingParams
from admission_gate.vllm_guard import vLLMAdmissionGuard

MODEL_DIR = "/mnt/models/llama-3-8b-instruct"

# Step 1: Pre-flight admission evaluation
guard = vLLMAdmissionGuard(require_safetensors_only=True)
verdict = guard.evaluate_model_path(MODEL_DIR)

if not verdict.admitted:
    raise SecurityError(f"Deployment Blocked: {verdict.rejection_reason}")

# Step 2: Safe initialization into GPU memory
print("[+] Model passed MLSecOps pre-flight gate. Initializing vLLM engine...")
llm = LLM(model=MODEL_DIR)
```

---

## 4. Telemetry & Prometheus Monitoring

The MLSecOps admission controller exports standard Prometheus metrics for Grafana dashboards:

- `mlsecops_admission_requests_total{status="admitted|rejected"}`
- `mlsecops_threat_findings_total{severity="CRITICAL|HIGH", rule_id="..."}`
- `mlsecops_cache_hits_total`
- `mlsecops_scanned_bytes_total`

Configure your Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: "mlsecops-admission-gate"
    static_configs:
      - targets: ["admission-gate.mlsecops.svc.cluster.local:8080"]
    metrics_path: "/metrics"
```
