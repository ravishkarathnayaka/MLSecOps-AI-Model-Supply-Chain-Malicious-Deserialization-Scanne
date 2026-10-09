"""
Unit tests validating cryptographic hash integrity, signature verification,
and SLSA/in-toto attestation validation.
"""

import json
import os
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from scanner.provenance.hash_verifier import HashVerifier
from scanner.provenance.signature_checker import SignatureChecker
from scanner.rules.dangerous_symbols import RiskLevel


@pytest.fixture
def sample_model_file(tmp_path):
    p = tmp_path / "model_weights.bin"
    p.write_bytes(b"dummy weights buffer for cryptographic signing 1234567890")
    return str(p)


def test_hash_verifier_matches(sample_model_file):
    digests = HashVerifier.compute_digests(sample_model_file)
    assert len(digests.sha256) == 64
    assert len(digests.sha512) == 128

    findings = HashVerifier.verify_against_expected(
        file_path=sample_model_file,
        expected_sha256=digests.sha256,
        expected_sha512=digests.sha512,
    )
    assert len(findings) == 0


def test_hash_verifier_mismatch(sample_model_file):
    findings = HashVerifier.verify_against_expected(
        file_path=sample_model_file,
        expected_sha256="0000000000000000000000000000000000000000000000000000000000000000",
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "PROVENANCE-SHA256-MISMATCH"
    assert findings[0].severity == RiskLevel.CRITICAL


def test_signature_checker_valid_rsa(sample_model_file, tmp_path):
    # Generate test RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(sample_model_file, "rb") as f:
        data = f.read()

    sig = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    sig_path = str(tmp_path / "model.sig")
    with open(sig_path, "wb") as f:
        f.write(sig)

    findings = SignatureChecker.verify_detached_signature(
        model_path=sample_model_file,
        signature_path=sig_path,
        public_key_pem=pub_pem,
    )
    assert len(findings) == 0


def test_signature_checker_invalid_signature(sample_model_file, tmp_path):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    bad_sig_path = str(tmp_path / "bad.sig")
    with open(bad_sig_path, "wb") as f:
        f.write(b"corrupted signature bytes 99999999999999999999999999999999")

    findings = SignatureChecker.verify_detached_signature(
        model_path=sample_model_file,
        signature_path=bad_sig_path,
        public_key_pem=pub_pem,
    )
    assert len(findings) >= 1
    assert any("SIG-" in f.rule_id for f in findings)


def test_intoto_attestation_verification(sample_model_file, tmp_path):
    digests = HashVerifier.compute_digests(sample_model_file)

    attestation = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://slsa.dev/provenance/v0.2",
        "subject": [
            {
                "name": os.path.basename(sample_model_file),
                "digest": {"sha256": digests.sha256},
            }
        ],
    }

    findings = SignatureChecker.verify_intoto_attestation(
        model_path=sample_model_file,
        attestation_file_or_data=attestation,
    )
    assert len(findings) == 0


def test_intoto_attestation_mismatch(sample_model_file):
    attestation = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [
            {
                "name": "other_model.bin",
                "digest": {"sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
            }
        ],
    }

    findings = SignatureChecker.verify_intoto_attestation(
        model_path=sample_model_file,
        attestation_file_or_data=attestation,
    )
    assert len(findings) >= 1
    assert any(f.rule_id == "ATTESTATION-DIGEST-MISMATCH" for f in findings)
