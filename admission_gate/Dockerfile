# Production Dockerfile for MLSecOps Admission Controller Webhook
FROM python:3.12-slim

# Prevent Python from writing .pyc and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency definition
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY scanner /app/scanner
COPY admission_gate /app/admission_gate
COPY cli /app/cli

# Run as non-root user for container security hardening
RUN useradd -u 10001 -m mlsecops && chown -R mlsecops:mlsecops /app
USER mlsecops

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/healthz || exit 1

CMD ["uvicorn", "admission_gate.webhook_server:app", "--host", "0.0.0.0", "--port", "8000"]
