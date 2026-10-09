"""
FastAPI Admission Controller Webhook.
Intercepts model loading requests for inference runtimes (KServe, vLLM, Triton).
Blocks deployment if models contain injected deserialization opcodes or fail cryptographic provenance checks.
"""

import os
import shutil
import tempfile
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile, status
from pydantic import BaseModel, Field

from scanner.core.engine import ModelScanEngine
from scanner.core.reporter import Reporter
from scanner.rules.dangerous_symbols import RiskLevel

app = FastAPI(
    title="MLSecOps Admission Controller Webhook",
    description="Pre-deployment security gatekeeper for AI/ML inference clusters (KServe/vLLM/Triton)",
    version="1.0.0",
)

# In-memory metrics tracking
METRICS = {
    "total_scans": 0,
    "allowed_models": 0,
    "blocked_models": 0,
    "total_violations": 0,
}


class AdmissionReviewRequest(BaseModel):
    model_uri: str = Field(..., description="Local path or mounted URI of the model file or directory.")
    expected_sha256: Optional[str] = Field(None, description="Expected SHA256 digest from Model Card / catalog.")
    expected_sha512: Optional[str] = Field(None, description="Expected SHA512 digest.")
    signature_uri: Optional[str] = Field(None, description="Path to cryptographic signature file (.sig).")
    public_key_pem: Optional[str] = Field(None, description="Public key PEM text or file path for verification.")
    attestation_uri: Optional[str] = Field(None, description="Path to in-toto SLSA attestation JSON.")
    fail_on: str = Field("high", description="Severity threshold: critical, high, medium, low, info.")
    strict: bool = Field(False, description="Whether to reject un-allowlisted globals in strict mode.")
    include_sarif: bool = Field(False, description="Include full SARIF v2.1.0 output in response.")


class AdmissionReviewResponse(BaseModel):
    allowed: bool
    verdict: str
    fail_threshold: str
    violations_count: int
    findings_count: int
    risk_score: float
    summary: str
    model_uri: str
    scanned_files: List[str]
    findings: List[Dict[str, Any]]
    sarif: Optional[Dict[str, Any]] = None


@app.get("/healthz", tags=["System"])
def health_check() -> Dict[str, str]:
    return {"status": "healthy", "service": "mlsecops-admission-controller", "version": "1.0.0"}


@app.get("/metrics", tags=["System"])
def get_metrics() -> Dict[str, Any]:
    total = METRICS["total_scans"]
    pass_rate = round((METRICS["allowed_models"] / total * 100), 2) if total > 0 else 100.0
    return {
        **METRICS,
        "pass_rate_percent": pass_rate,
    }


@app.post("/v1/admission/review", response_model=AdmissionReviewResponse, tags=["Admission Gate"])
def review_model(request: AdmissionReviewRequest) -> AdmissionReviewResponse:
    """
    Admission controller hook. Evaluates model artifacts prior to inference loading.
    Returns HTTP 200 with allowed: false if blocked, or HTTP 403 when configured in strict enforcement.
    """
    METRICS["total_scans"] += 1

    sev_map = {
        "critical": RiskLevel.CRITICAL,
        "high": RiskLevel.HIGH,
        "medium": RiskLevel.MEDIUM,
        "low": RiskLevel.LOW,
        "info": RiskLevel.INFO,
    }
    threshold = sev_map.get(request.fail_on.lower(), RiskLevel.HIGH)

    engine = ModelScanEngine(
        fail_on_threshold=threshold,
        strict_mode=request.strict,
    )

    evaluation, scanned_files = engine.scan_path(
        path=request.model_uri,
        expected_sha256=request.expected_sha256,
        expected_sha512=request.expected_sha512,
        signature_path=request.signature_uri,
        public_key_pem=request.public_key_pem,
        attestation_path=request.attestation_uri,
    )

    if evaluation.passed:
        METRICS["allowed_models"] += 1
    else:
        METRICS["blocked_models"] += 1
        METRICS["total_violations"] += len(evaluation.violations)

    sarif_doc = None
    if request.include_sarif:
        sarif_doc = Reporter.to_sarif(evaluation, scanned_files)

    return AdmissionReviewResponse(
        allowed=evaluation.passed,
        verdict=evaluation.verdict.value,
        fail_threshold=threshold.value,
        violations_count=len(evaluation.violations),
        findings_count=len(evaluation.findings),
        risk_score=evaluation.risk_score,
        summary=evaluation.summary,
        model_uri=request.model_uri,
        scanned_files=scanned_files,
        findings=[f.to_dict() for f in evaluation.findings],
        sarif=sarif_doc,
    )


@app.post("/v1/scan/upload", tags=["Scan API"])
async def scan_uploaded_model(
    file: UploadFile = File(...),
    fail_on: str = "high",
    strict: bool = False,
) -> Dict[str, Any]:
    """
    Upload an artifact directly for static analysis and immediate security review.
    """
    METRICS["total_scans"] += 1
    sev_map = {
        "critical": RiskLevel.CRITICAL,
        "high": RiskLevel.HIGH,
        "medium": RiskLevel.MEDIUM,
        "low": RiskLevel.LOW,
        "info": RiskLevel.INFO,
    }
    threshold = sev_map.get(fail_on.lower(), RiskLevel.HIGH)

    # Save to secure temporary file
    suffix = os.path.splitext(file.filename or "model.bin")[1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp_path = tmp.name
        content = await file.read()
        tmp.write(content)

    try:
        engine = ModelScanEngine(fail_on_threshold=threshold, strict_mode=strict)
        evaluation, scanned = engine.scan_path(path=tmp_path)

        if evaluation.passed:
            METRICS["allowed_models"] += 1
        else:
            METRICS["blocked_models"] += 1
            METRICS["total_violations"] += len(evaluation.violations)

        sarif_doc = Reporter.to_sarif(evaluation, [file.filename or tmp_path])

        return {
            "filename": file.filename,
            "allowed": evaluation.passed,
            "verdict": evaluation.verdict.value,
            "risk_score": evaluation.risk_score,
            "summary": evaluation.summary,
            "violations_count": len(evaluation.violations),
            "findings": [f.to_dict() for f in evaluation.findings],
            "sarif": sarif_doc,
        }
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
