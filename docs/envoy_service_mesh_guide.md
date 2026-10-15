# Kubernetes Envoy External Authorization (ext_authz) & Zero-Trust Mesh Guide

## 1. Overview

In microservice inference meshes managed by **Istio**, **Linkerd**, or **Envoy Gateway**, inference servers such as **vLLM**, **Triton**, and **KServe** expose REST/gRPC endpoints for dynamic model loading (`POST /v1/models/load`).

An attacker or compromised service with cluster network access can submit unauthorized model loading requests containing malicious serialized weights.

By deploying the **MLSecOps Admission Controller** as an **Envoy External Authorization (ext_authz) service**, every model load request is statically inspected and authorized before touching host GPU memory.

---

## 2. Architecture Diagram

```text
 Client (K8s Pod)
       |
       |  POST /v1/models/load (Payload: {"model": "untrusted.pkl"})
       v
 [Envoy Ingress Sidecar]
       |
       |--- 1. CheckRequest (Headers, Body) ---> [MLSecOps ext_authz Gate]
       |                                                 |
       |                                          Static Disassembly
       |                                          & Opcode Inspection
       |                                                 |
       |<-- 2. CheckResponse (403 Forbidden) <------------+
       v
 403 Forbidden (Blocked before GPU allocation!)
```

---

## 3. Istio EnvoyFilter Configuration

Deploy the following `EnvoyFilter` to register the MLSecOps webhook as an ext_authz provider:

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: mlsecops-ext-authz
  namespace: ml-serving
spec:
  workloadSelector:
    labels:
      app: vllm-inference
  configPatches:
    - applyTo: HTTP_FILTER
      match:
        context: SIDECAR_INBOUND
        listener:
          filterChain:
            filter:
              name: "envoy.filters.network.http_connection_manager"
              subFilter:
                name: "envoy.filters.http.router"
      patch:
        operation: INSERT_BEFORE
        value:
          name: envoy.filters.http.ext_authz
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
            http_service:
              server_uri:
                uri: http://admission-gate.mlsecops.svc.cluster.local:8080/v1/envoy/check
                cluster: outbound|8080||admission-gate.mlsecops.svc.cluster.local
                timeout: 5s
              authorization_request:
                allowed_headers:
                  patterns:
                    - exact: "x-model-path"
                    - exact: "x-api-key"
              authorization_response:
                allowed_upstream_headers:
                  patterns:
                    - exact: "x-mlsecops-verdict"
```

---

## 4. Production Security Benefits

- **Zero-Latency In-Memory Verification:** Requests for previously verified models hit the Redis L2 hash cache (< 2ms response).
- **Zero Kernel Privileges:** The inference container never receives the byte stream of a quarantined model.
- **Fail-Closed Guarantee:** Network timeouts or policy rejections default to denying admission.
