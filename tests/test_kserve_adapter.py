"""
Unit tests for KServeAdmissionAdapter.
Validates Kubernetes AdmissionReview request extraction and response formatting.
"""

from admission_gate.kserve_adapter import KServeAdmissionAdapter


def test_kserve_extract_standard_inferenceservice():
    review_req = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "12345-abcde",
            "object": {
                "spec": {
                    "predictor": {
                        "model": {
                            "modelFormat": {"name": "pytorch"},
                            "storageUri": "s3://prod-models/resnet50.pt",
                        }
                    }
                }
            },
        },
    }

    uri, fmt, uid = KServeAdmissionAdapter.extract_model_target(review_req)
    assert uri == "s3://prod-models/resnet50.pt"
    assert fmt == "pytorch"
    assert uid == "12345-abcde"


def test_kserve_build_response_allowed():
    res = KServeAdmissionAdapter.build_k8s_admission_response(
        uid="12345-abcde",
        allowed=True,
        message="Model safe for inference.",
    )
    assert res["apiVersion"] == "admission.k8s.io/v1"
    assert res["response"]["uid"] == "12345-abcde"
    assert res["response"]["allowed"] is True
    assert res["response"]["status"]["code"] == 200


def test_kserve_build_response_blocked():
    res = KServeAdmissionAdapter.build_k8s_admission_response(
        uid="12345-abcde",
        allowed=False,
        message="Blocked: Injected pickle REDUCE opcode detected.",
        status_code=403,
    )
    assert res["response"]["allowed"] is False
    assert res["response"]["status"]["code"] == 403
    assert "Injected pickle" in res["response"]["status"]["message"]
