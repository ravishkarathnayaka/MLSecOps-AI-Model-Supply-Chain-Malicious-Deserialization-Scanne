# Deploying MLSecOps Admission Gate with KServe

This guide details how to intercept and validate models deployed to KServe before inference pods pull and load model weights into GPU memory.

## Prerequisites

- Kubernetes cluster (v1.26+)
- KServe installed (v0.11+)
- cert-manager installed

## Step 1: Deploy MLSecOps Admission Gate

```bash
kubectl apply -f admission_gate/k8s/deployment.yaml
```

Verify the pods are running:

```bash
kubectl get pods -n mlsecops-system
```

## Step 2: Register Validating Webhook

```bash
kubectl apply -f admission_gate/k8s/webhook-config.yaml
```

## Step 3: Test Admission Gate Blocking

Deploy an InferenceService targeting an unverified or trojaned model:

```yaml
apiVersion: "serving.kserve.io/v1beta1"
kind: "InferenceService"
metadata:
  name: "trojan-model-test"
  namespace: "default"
  labels:
    mlsecops.io/scan-enforced: "true"
spec:
  predictor:
    model:
      modelFormat:
        name: "pytorch"
      storageUri: "test_models/trojan_print.pt"
```

Apply the manifest:

```bash
kubectl apply -f test-service.yaml
```

Expected output:

```
Error from server (Forbidden): admission webhook "validate.model.mlsecops.io" denied the request:
Policy evaluation FAILED: Model rejected due to ARBITRARY-CODE-EXECUTION-REDUCE opcode injection.
```
