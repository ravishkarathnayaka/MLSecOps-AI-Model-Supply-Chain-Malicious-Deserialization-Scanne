# Enterprise Edge & Mobile Model Security Deployment Guide

## 1. Overview

Edge AI and mobile deployments increasingly rely on platform-specific execution engines:
- **Apple CoreML:** iOS, iPadOS, and macOS endpoints executing via the Apple Neural Engine (ANE).
- **Intel OpenVINO:** Edge gateways, IoT devices, and industrial vision systems utilizing Intel CPUs/iGPUs.
- **NVIDIA TensorRT:** Autonomous vehicles, robotics, and low-latency edge servers with Jetson / RTX hardware.

Because edge applications run in client environments with broad operating system privileges, poisoned models deployed to mobile apps or IoT devices pose severe supply chain risks (credential exfiltration, device compromise, and firmware tampering).

---

## 2. Format Threat Highlights & Mitigations

### 1. Apple CoreML (`.mlpackage`, `.mlmodel`)
- **Threat Vector:** Dynamic custom model layers (`CustomModel`) executing unauthorized Objective-C or Swift code.
- **Scanner Rule:** `COREML-CUSTOM-OPERATOR-FLAGGED`
- **Mitigation:** Disallow custom operators in mobile release gates; enforce static ANE compilation.

### 2. Intel OpenVINO IR (`.xml`, `.bin`)
- **Threat Vector:** XML External Entity (XXE) injection inside topology XMLs, or out-of-bounds weight offsets.
- **Scanner Rules:** `OPENVINO-XXE-INJECTION-RISK`, `OPENVINO-WEIGHT-BUFFER-OVERFLOW`
- **Mitigation:** Strip XML DOCTYPE headers and statically verify weight buffer boundary offsets.

### 3. NVIDIA TensorRT (`.plan`, `.engine`)
- **Threat Vector:** External shared library dependencies (`libplugin.so`) loaded dynamically into the CUDA driver space.
- **Scanner Rule:** `TENSORRT-CUSTOM-PLUGIN-OR-LIB`
- **Mitigation:** Enforce static compilation and signature verification on all TensorRT plan engines before staging.

---

## 3. Automation in Edge Release Pipelines

```bash
# Scan mobile & edge model directory prior to packaging
mlsec-scan --path ./mobile_assets/ --fail-on high --format sarif --output edge-audit.sarif
```
