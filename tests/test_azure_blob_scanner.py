"""
Unit tests validating Azure Blob Storage streaming model security scans.
"""

import pickle
import unittest
from unittest.mock import MagicMock

from scanner.integrations.azure_blob_scanner import AzureBlobScanner


class TestAzureBlobScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = AzureBlobScanner()

    def test_parse_azure_uri(self):
        container, blob = AzureBlobScanner.parse_azure_uri("az://models-prod/nlp/bert.safetensors")
        self.assertEqual(container, "models-prod")
        self.assertEqual(blob, "nlp/bert.safetensors")

    def test_scan_blob_trojan_pickle_blocked(self):
        # Generate malicious pickle byte sequence
        class Trojan:
            def __reduce__(self):
                import os
                return os.system, ("id",)

        payload = pickle.dumps(Trojan())
        result = self.scanner.scan_blob("models-prod", "trojan.pkl", payload, fail_on_severity="HIGH")
        self.assertFalse(result.passed)
        self.assertTrue(len(result.violations) > 0)

    def test_scan_container_with_mock_client(self):
        mock_client = MagicMock()
        mock_container = MagicMock()
        mock_client.get_container_client.return_value = mock_container

        mock_blob_meta = MagicMock()
        mock_blob_meta.name = "weights.pt"
        mock_container.list_blobs.return_value = [mock_blob_meta]

        mock_blob_client = MagicMock()
        mock_download = MagicMock()
        # safe zip/pt header
        mock_download.readall.return_value = b"PK\x03\x04"
        mock_blob_client.download_blob.return_value = mock_download
        mock_container.get_blob_client.return_value = mock_blob_client

        scanner = AzureBlobScanner(blob_service_client=mock_client)
        results = scanner.scan_container_prefix("models", prefix="nlp/")
        self.assertEqual(len(results), 1)


if __name__ == "__main__":
    unittest.main()
