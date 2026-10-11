"""
Unit tests for AdmissionCache.
Validates cache miss, hit retrieval, and SHA-256 case normalization.
"""

from admission_gate.cache import AdmissionCache


def test_admission_cache_miss():
    cache = AdmissionCache()
    res = cache.get_cached_verdict("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
    assert res is None


def test_admission_cache_hit_and_normalization():
    cache = AdmissionCache()
    hash_val = "A1B2C3D4E5F67890A1B2C3D4E5F67890A1B2C3D4E5F67890A1B2C3D4E5F67890"
    verdict = {
        "allowed": True,
        "verdict": "PASSED",
        "risk_score": 0.0,
        "findings_count": 0,
    }

    assert cache.cache_verdict(hash_val, verdict) is True

    # Retrieve with lowercase hash
    retrieved = cache.get_cached_verdict(hash_val.lower())
    assert retrieved is not None
    assert retrieved["allowed"] is True
    assert retrieved["verdict"] == "PASSED"
