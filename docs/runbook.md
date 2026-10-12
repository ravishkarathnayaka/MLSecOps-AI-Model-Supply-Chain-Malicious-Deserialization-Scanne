# Enterprise Deployment & Security Incident Response Runbook

## 1. Production Architecture Overview

The MLSecOps Supply Chain Scanner operates across three tiers in enterprise environments:

1. **Pre-Commit / Pre-Merge (CI/CD):** Static bytecode inspection before model weights enter storage.
2. **Registry & Bucket Ingestion:** Asynchronous scheduled auditing of S3, GCS, MinIO, and MLflow registries.
3. **Runtime Admission Control:** Synchronous Kubernetes Validating Webhook intercepting KServe, vLLM, and Triton model load calls.

```text
                  +-----------------------------------+
                  |   Model Upload (Data Science)    |
                  +-----------------+-----------------+
                                    |
                                    v
                  +-----------------+-----------------+
                  |      Object Storage (S3/GCS)      |
                  +-----------------+-----------------+
                                    |
      +-----------------------------+-----------------------------+
      |                                                           |
      v                                                           v
+-----------------------+                               +-----------------------+
| MLSecOps Batch Audit  |                               | Kubernetes Admission  |
| - Daily/Hourly Scans  |                               | - KServe Webhook Gate |
| - SARIF Export        |                               | - Redis L2 Hash Cache |
| - Security Alerts     |                               | - mTLS Authentication |
+-----------------------+                               +-----------------------+
```

---

## 2. High-Availability Webhook Deployment

Deploy the admission controller with multi-replica high availability behind an internal Kubernetes Service:

```bash
# 1. Generate mTLS internal certificates
python -c "from admission_gate.tls_helper import generate_mtls_cert_bundle; generate_mtls_cert_bundle('./certs')"

# 2. Deploy via Helm
helm upgrade --install mlsecops-gatekeeper ./k8s/helm/mlsecops-admission \
  --namespace mlsecops-system \
  --create-namespace \
  --set replicaCount=3 \
  --set redis.enabled=true \
  --set redis.host="redis.mlsecops-system.svc.cluster.local"
```

---

## 3. Incident Response Playbook: Compromised Model Detected

When the MLSecOps scanner flags a model with `CRITICAL` or `HIGH` severity (e.g., `__reduce__` shellcode, custom node execution, or corrupted safetensors buffer):

### Step 1: Automated Quarantine & Blacklist
The Admission Controller immediately adds the SHA-256 hash to the distributed Redis cache with a `REJECTED` verdict:

```bash
# Verify quarantine status in Redis
redis-cli -h redis.mlsecops-system.svc.cluster.local GET "model_cache:<SHA256_HASH>"
```

### Step 2: Identify Active Workloads
Identify any running inference pods that may have loaded the compromised artifact prior to gate enforcement:

```bash
# Query pods running with model image or volume mount
kubectl get pods -A -l app.kubernetes.io/model-hash=<SHA256_HASH>
```

### Step 3: Immediate Cordon & Eviction
Isolate the worker node hosting the pod to prevent lateral movement across the cluster:

```bash
# Cordon and drain the node
kubectl cordon <node-name>
kubectl delete pod <compromised-pod-name> -n ml-serving --grace-period=0 --force
```

### Step 4: Digital Forensics & Payload Extraction
Extract the disassembly breakdown from the MLSecOps audit log:

```bash
mlsec-scan --path /path/to/compromised_model.pt --format json --output /tmp/forensics.json
jq '.findings[] | {rule_id, severity, message, description}' /tmp/forensics.json
```

### Step 5: Post-Incident Lineage Invalidation
Revoke the model's Sigstore attestation and notify the MLSecOps security operations center (SOC).

---

## 4. Disaster Recovery & Fail-Closed Policy

In the event of an outage in the admission controller or Redis cluster:

- **Strict Mode (Default):** The validating webhook enforces `failurePolicy: Fail`, preventing unverified models from starting.
- **Emergency Bypass (Break-Glass):** In certified disaster recovery scenarios where inference uptime is life-critical, operators can toggle the emergency bypass annotating the target namespace:

```bash
kubectl label namespace ml-serving mlsecops.io/break-glass=enabled --overwrite
```
*(Note: All break-glass events generate an immediate critical Slack/PagerDuty audit notification).*
