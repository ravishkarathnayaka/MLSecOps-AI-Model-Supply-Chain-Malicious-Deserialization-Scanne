"""
Unit tests for HuggingFaceHubScanner.
Validates repository sibling inspection, pickle-only warning, and trust_remote_code auditing.
"""

from unittest.mock import MagicMock, patch
from scanner.integrations.huggingface import HuggingFaceHubScanner
from scanner.rules.dangerous_symbols import RiskLevel


def test_huggingface_pickle_only_repo_flagged():
    scanner = HuggingFaceHubScanner()
    mock_payload = {
        "siblings": [
            {"rfilename": "pytorch_model.bin"},
            {"rfilename": "config.json"},
        ],
        "cardData": {"license": "mit"},
    }

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = (
            '{"siblings": [{"rfilename": "pytorch_model.bin"}], "cardData": {"license": "mit"}}'.encode()
        )
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        findings, data = scanner.audit_repo_metadata("test-user/pickle-only-model")
        assert any(f.rule_id == "HF-LEGACY-PICKLE-ONLY-REPOSITORY" for f in findings)


def test_huggingface_trust_remote_code_flagged():
    scanner = HuggingFaceHubScanner()
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = (
            '{"siblings": [{"rfilename": "model.safetensors"}], "cardData": {"trust_remote_code": true}}'.encode()
        )
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        findings, data = scanner.audit_repo_metadata("test-user/custom-code-model")
        assert any(f.rule_id == "HF-TRUST-REMOTE-CODE-FLAGGED" for f in findings)
        assert any(f.severity == RiskLevel.HIGH for f in findings)
