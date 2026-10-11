# Contributing to MLSecOps Scanner

Thank you for your interest in contributing to the **MLSecOps: AI Model Supply Chain & Malicious Deserialization Scanner** project!

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/ravishkarathnayaka/MLSecOps-AI-Model-Supply-Chain-Malicious-Deserialization-Scanne.git
   cd MLSecOps-AI-Model-Supply-Chain-Malicious-Deserialization-Scanne
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install pytest pytest-cov ruff mypy
   ```

3. Run the test suite:
   ```bash
   python -m pytest tests/
   ```

## Development Guidelines

- **Zero Untrusted Execution:** Analyzers MUST never execute unvetted weights (no `pickle.load()`, `torch.load()`, or dynamic runtime calls).
- **Format Decoupling:** Format analyzers should run with minimal dependencies to ensure zero-cost operation in restricted air-gapped CI environments.
- **Test Coverage:** All new rules or format parsers must include unit tests under `tests/`.
- **Commit Messages:** Follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `test:`, `docs:`, `perf:`).
