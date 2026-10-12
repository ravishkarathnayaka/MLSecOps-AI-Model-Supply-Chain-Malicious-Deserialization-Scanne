"""
Unit tests for RekorVerifier.
Validates transparency log inclusion proof checks on Sigstore Cosign bundles.
"""

from scanner.provenance.rekor_verifier import RekorVerifier
from scanner.rules.dangerous_symbols import RiskLevel


def test_rekor_missing_tlog_entries(tmp_path):
    model_file = tmp_path / "model.bin"
    model_file.write_bytes(b"model data")
    empty_bundle = {"verificationMaterial": {"tlogEntries": []}}

    findings = RekorVerifier.verify_bundle_proof(str(model_file), empty_bundle)
    assert len(findings) == 1
    assert findings[0].rule_id == "REKOR-MISSING-TLOG-ENTRIES"


def test_rekor_incomplete_inclusion_proof(tmp_path):
    model_file = tmp_path / "model.bin"
    model_file.write_bytes(b"model data")
    incomplete_bundle = {
        "verificationMaterial": {
            "tlogEntries": [{"logIndex": 12345}]  # Missing signedEntryTimestamp
        }
    }

    findings = RekorVerifier.verify_bundle_proof(str(model_file), incomplete_bundle)
    assert len(findings) == 1
    assert findings[0].rule_id == "REKOR-INVALID-INCLUSION-PROOF"


def test_rekor_valid_proof(tmp_path):
    model_file = tmp_path / "model.bin"
    model_file.write_bytes(b"model data")
    valid_bundle = {
        "verificationMaterial": {
            "tlogEntries": [
                {
                    "logIndex": 54321,
                    "signedEntryTimestamp": "MEUCIQDx...",
                }
            ]
        }
    }

    findings = RekorVerifier.verify_bundle_proof(str(model_file), valid_bundle)
    assert len(findings) == 0
