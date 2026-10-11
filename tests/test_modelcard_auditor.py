"""
Unit tests for ModelCardAuditor.
Validates YAML frontmatter parsing, trust_remote_code flagging, and hash matching against weights.
"""

import hashlib
from scanner.provenance.modelcard_auditor import ModelCardAuditor
from scanner.rules.dangerous_symbols import RiskLevel


def test_modelcard_missing_frontmatter():
    content = "# My Model\nThis is a standard markdown file without frontmatter."
    findings = ModelCardAuditor.audit_content(content)
    assert len(findings) == 1
    assert findings[0].rule_id == "MODELCARD-MISSING-YAML-METADATA"


def test_modelcard_trust_remote_code_flagged():
    content = """---
license: apache-2.0
trust_remote_code: true
tags:
- text-generation
---
# Model with custom code
"""
    findings = ModelCardAuditor.audit_content(content)
    assert any(f.rule_id == "MODELCARD-TRUST-REMOTE-CODE-ENABLED" for f in findings)
    assert any(f.severity == RiskLevel.HIGH for f in findings)


def test_modelcard_hash_verification(tmp_path):
    dummy_weight = tmp_path / "model.bin"
    payload = b"dummy tensor data"
    dummy_weight.write_bytes(payload)
    sha256 = hashlib.sha256(payload).hexdigest()

    card_content = f"""---
license: mit
sha256: {sha256}
---
# Model with matching digest
"""
    findings = ModelCardAuditor.audit_content(card_content, weights_path=str(dummy_weight))
    # No sha mismatch findings
    assert not any(f.rule_id == "PROVENANCE-SHA256-MISMATCH" for f in findings)


def test_modelcard_hash_mismatch(tmp_path):
    dummy_weight = tmp_path / "model.bin"
    dummy_weight.write_bytes(b"actual content")

    card_content = """---
license: mit
sha256: 0000000000000000000000000000000000000000000000000000000000000000
---
"""
    findings = ModelCardAuditor.audit_content(card_content, weights_path=str(dummy_weight))
    assert any(f.rule_id == "PROVENANCE-SHA256-MISMATCH" for f in findings)
