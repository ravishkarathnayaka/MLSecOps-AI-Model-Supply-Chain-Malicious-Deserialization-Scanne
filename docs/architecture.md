# MLSecOps Architecture Specification

The MLSecOps Model Supply Chain Scanner is designed for zero-trust model ingestion across development, CI/CD, and production Kubernetes clusters.

## Architectural Layers

1. **Static Analysis Layer (`scanner/analyzers/`)**:
   - `pickle_inspector.py`: Disassembles raw pickle opcodes without invoking `pickle.load()`. Tracks simulated stack state to catch `GLOBAL` and `REDUCE` execution calls.
   - `pytorch_analyzer.py`: Unpacks ZIP manifests, guards against Zip Slip path traversal, and evaluates inner `data.pkl` streams.
   - `safetensors_checker.py`: Parses 8-byte little-endian headers, validates JSON schemas, and enforces zero-executable memory bounds.
   - `onnx_analyzer.py`: Traverses ModelProto computation graph nodes and attributes to enforce domain allowlists (`ai.onnx`).
   - `gguf_checker.py`: Validates GGUF v2/v3 quantized LLM structures and metadata keys.
   - `keras_h5_analyzer.py`: Audits Keras Lambda layers for unmarshalled bytecode injection.
   - `entropy_analyzer.py`: Detects hidden steganographic blobs (>7.9 bits/byte).

2. **Policy & Rule Engine Layer (`scanner/rules/`)**:
   - `dangerous_symbols.py`: Comprehensive denylist of dangerous modules (`os`, `subprocess`, `ctypes`, `socket`, `multiprocessing`).
   - `policy_engine.py`: Configurable gate threshold (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) returning `AdmissionVerdict`.

3. **Cryptographic Provenance Layer (`scanner/provenance/`)**:
   - `hash_verifier.py`: Streaming SHA-256 and SHA-512 calculation.
   - `signature_checker.py`: Sigstore Cosign bundles, ECDSA/RSA detached signatures, and in-toto SLSA attestations.
   - `modelcard_auditor.py`: Hugging Face `README.md` YAML frontmatter auditing.

4. **Admission Controller Layer (`admission_gate/`)**:
   - `webhook_server.py`: FastAPI server intercepting Kubernetes KServe v1beta1 admission queries.
   - `cache.py`: High-throughput Redis caching for repeat pod autoscaling.
   - `metrics_exporter.py`: Prometheus text metrics exporter.

5. **Reporting & CLI Layer (`scanner/core/`, `cli/`)**:
   - `reporter.py`: SARIF v2.1.0, JSON, and terminal color reports.
   - `html_reporter.py`: Standalone HTML dashboards.
   - `csv_reporter.py`: Tabular compliance export.
   - `github_summary.py`: GitHub Actions `$GITHUB_STEP_SUMMARY` Markdown.
