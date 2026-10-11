.PHONY: help install test benchmark scan scan-sarif docker-build docker-up clean

help:
	@echo "MLSecOps Model Supply Chain Scanner - Makefile Commands"
	@echo "--------------------------------------------------------"
	@echo "make install       Install dependencies"
	@echo "make test          Run pytest suite with coverage"
	@echo "make benchmark     Run performance and latency benchmarks"
	@echo "make scan          Run CLI scanner against test_models/"
	@echo "make scan-sarif    Run CLI scanner outputting SARIF"
	@echo "make docker-build  Build admission gate Docker image"
	@echo "make docker-up     Start docker-compose local stack"
	@echo "make clean         Remove Python build/test caches"

install:
	pip install -r requirements.txt

test:
	python -m pytest tests/ -v

benchmark:
	python tests/benchmark_scanner.py

scan:
	python -m cli.main --path test_models/ --fail-on high

scan-sarif:
	python -m cli.main --path test_models/ --format sarif --output sarif-report.json

docker-build:
	docker build -f admission_gate/Dockerfile -t mlsecops-admission:latest .

docker-up:
	docker compose -f docker/docker-compose.yml up -d

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .coverage htmlcov
