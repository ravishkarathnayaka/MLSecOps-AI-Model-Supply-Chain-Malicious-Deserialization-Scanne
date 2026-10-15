"""
Unit tests validating admission webhook API key and HMAC-SHA256 signature authentication.
"""

import hashlib
import hmac
import unittest
from admission_gate.auth import AdmissionAuthenticator


class TestAdmissionAuth(unittest.TestCase):
    def test_api_key_valid(self):
        auth = AdmissionAuthenticator(api_keys={"secret-token-123", "admin-key-456"})
        self.assertTrue(auth.verify_api_key("secret-token-123"))
        self.assertFalse(auth.verify_api_key("wrong-token"))
        self.assertFalse(auth.verify_api_key(None))

    def test_hmac_signature_valid(self):
        secret = "super-secret-key"
        payload = b'{"model_path": "/models/resnet50.safetensors"}'
        expected_hex = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

        auth = AdmissionAuthenticator(hmac_secret=secret)
        self.assertTrue(auth.verify_hmac_signature(payload, f"sha256={expected_hex}"))
        self.assertFalse(auth.verify_hmac_signature(payload, "sha256=invalidhex123456"))
        self.assertFalse(auth.verify_hmac_signature(b'{"tampered": true}', f"sha256={expected_hex}"))
        self.assertFalse(auth.verify_hmac_signature(payload, None))


if __name__ == "__main__":
    unittest.main()
