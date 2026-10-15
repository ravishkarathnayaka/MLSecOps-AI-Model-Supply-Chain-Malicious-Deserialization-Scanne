"""
Authentication and HMAC Request Signature Verification for MLSecOps Admission Gate.
Protects admission controller endpoints with API keys and HMAC-SHA256 payload integrity proofs.
"""

import hashlib
import hmac
from typing import Optional, Set


class AdmissionAuthenticator:
    """Validates API keys and HMAC-SHA256 webhook request signatures."""

    def __init__(self, api_keys: Optional[Set[str]] = None, hmac_secret: Optional[str] = None):
        self.api_keys = api_keys or set()
        self.hmac_secret = hmac_secret.encode("utf-8") if hmac_secret else None

    def verify_api_key(self, provided_key: Optional[str]) -> bool:
        """Validates X-API-Key against configured keys."""
        if not self.api_keys:
            # Open mode if no keys configured
            return True
        if not provided_key:
            return False
        return any(hmac.compare_digest(provided_key, valid_key) for valid_key in self.api_keys)

    def verify_hmac_signature(self, payload_bytes: bytes, signature_header: Optional[str]) -> bool:
        """Validates X-Hub-Signature-256 header (sha256=<hex>)."""
        if not self.hmac_secret:
            return True
        if not signature_header or not signature_header.startswith("sha256="):
            return False

        received_sig = signature_header.split("sha256=", 1)[1]
        expected_sig = hmac.new(self.hmac_secret, payload_bytes, hashlib.sha256).hexdigest()
        return hmac.compare_digest(received_sig, expected_sig)
