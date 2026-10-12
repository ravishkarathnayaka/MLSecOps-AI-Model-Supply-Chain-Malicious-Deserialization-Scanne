# CoreML and TensorFlow SavedModel Security Architecture Guide

## 1. Introduction

As machine learning systems are deployed across mobile devices (iOS / macOS), edge embedded hardware, and enterprise microservices, two prominent serialization architectures represent significant supply chain attack surfaces:

1. **Apple CoreML (`.mlpackage` / `.mlmodel`):** Deployed across Apple hardware platforms using Apple Neural Engine (ANE) and Metal accelerators.
2. **TensorFlow SavedModel (`saved_model.pb`, `variables/`, `assets/`):** Deployed in Google Cloud Vertex AI, TensorFlow Serving, and enterprise Java/C++ runtimes.

This guide details the threat mechanics inherent to these formats and explains how the MLSecOps static analyzer inspects them without executing dynamic code.

---

## 2. Threat Analysis: TensorFlow SavedModel

A TensorFlow SavedModel is an archive or directory containing a Protocol Buffer graph representation (`saved_model.pb`) alongside asset directories.

```text
saved_model/
├── saved_model.pb         <- GraphDef & MetaGraphDef Protocol Buffer
├── variables/
│   ├── variables.index
│   └── variables.data-00000-of-00001
└── assets/
    └── setup_script.sh    <- Potential supply chain persistence vector!
```

### Attack Vectors in SavedModel:

- **`PyFunc` / `PyFuncStateless` Arbitrary Execution:**
  TensorFlow includes legacy operators designed to execute arbitrary Python code directly from the computational graph runtime. If an untrusted SavedModel includes a `PyFunc` node, running inference evaluates arbitrary host Python functions.
- **Untrusted C++ Custom Kernels (`CustomOp`):**
  Models referencing non-standard C++ operator libraries can induce native memory corruption, buffer overflows, or execute malicious shared objects (`.so`).
- **Asset Directory Script Injection:**
  The `assets/` folder is frequently parsed by loading frameworks. Storing executable scripts (`.sh`, `.py`, `.bat`) can trigger secondary execution hooks in data pipelines.
- **Symlink Directory Traversal:**
  Malicious archives containing relative symlinks (`../../etc/shadow`) escaping the model root directory during extraction.

---

## 3. Threat Analysis: Apple CoreML

Modern CoreML models use the `.mlpackage` directory bundle or legacy `.mlmodel` Protobuf file.

### Attack Vectors in CoreML:

- **Untrusted `CustomModel` Layer Delegates:**
  CoreML supports custom neural network layers implemented via Swift, Objective-C, or Python callbacks. Malicious models declare custom classes designed to trigger arbitrary code execution upon model initialization.
- **Embedded Executable Assets:**
  Bundles containing `.dylib`, `.so`, or executable scripts disguised within package subdirectories.
- **`Manifest.json` Path Traversal:**
  CoreML packages utilize `Manifest.json` to map internal asset paths. Crafting path entries with directory traversal sequences (`../../`) targets system file overwrites during unarchiving.

---

## 4. Static Scanner Enforcement

The MLSecOps scanner validates both formats offline:

```bash
# Scan a TensorFlow SavedModel folder
mlsec-scan --path /models/saved_model_v1/ --fail-on high

# Scan an Apple CoreML bundle
mlsec-scan --path /models/classifier.mlpackage/ --fail-on high
```

All custom operators, path traversals, and dangerous assets are flagged as **CRITICAL** or **HIGH** severity violations before runtime admission.
