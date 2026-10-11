"""
Kubernetes KServe InferenceService Admission Review Adapter.
Parses native Kubernetes AdmissionReview v1 payloads for KServe v1beta1 CRDs.
Translates storageUri and model specifications into MLSecOps scanner queries
and formats compliant AdmissionResponse objects.
"""

from typing import Any, Dict, Optional, Tuple


class KServeAdmissionAdapter:
    """
    Translates Kubernetes AdmissionReview objects to/from MLSecOps scanner format.
    """

    @classmethod
    def extract_model_target(cls, admission_review: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], str]:
        """
        Extracts (storageUri, modelFormat, uid) from Kubernetes AdmissionReview request.
        """
        request = admission_review.get("request", {})
        uid = request.get("uid", "00000000-0000-0000-0000-000000000000")
        obj = request.get("object", {})

        # Navigate spec -> predictor -> model -> storageUri
        spec = obj.get("spec", {})
        predictor = spec.get("predictor", {})
        model_spec = predictor.get("model", {})

        storage_uri = model_spec.get("storageUri")
        model_format = model_spec.get("modelFormat", {}).get("name")

        # Fallback check for vLLM or custom containers
        if not storage_uri:
            containers = predictor.get("containers", [])
            for c in containers:
                for env in c.get("env", []):
                    if env.get("name") in ("MODEL_URI", "MODEL_ID", "STORAGE_URI"):
                        storage_uri = env.get("value")
                        break

        return storage_uri, model_format, uid

    @classmethod
    def build_k8s_admission_response(
        cls,
        uid: str,
        allowed: bool,
        message: str,
        status_code: int = 200,
    ) -> Dict[str, Any]:
        """Formats a standard Kubernetes AdmissionReview v1 response object."""
        return {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": uid,
                "allowed": allowed,
                "status": {
                    "code": status_code if not allowed else 200,
                    "message": message,
                },
            },
        }
