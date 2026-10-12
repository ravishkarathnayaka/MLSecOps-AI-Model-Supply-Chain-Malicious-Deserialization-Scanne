"""
Unit tests for AdmissionTLSHelper.
Validates generation of x509 CA, server certificates, and Subject Alternative Names (SANs).
"""

from cryptography import x509
from admission_gate.tls_helper import AdmissionTLSHelper


def test_tls_helper_cert_generation():
    certs = AdmissionTLSHelper.generate_webhook_certs(
        service_name="test-admission-svc",
        namespace="default",
    )

    assert "ca_cert" in certs
    assert "server_cert" in certs

    # Parse and inspect server cert
    server_x509 = x509.load_pem_x509_certificate(certs["server_cert"])
    san_ext = server_x509.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
    dns_values = [str(name.value) for name in san_ext.value]

    assert "test-admission-svc" in dns_values
    assert "test-admission-svc.default.svc.cluster.local" in dns_values


def test_tls_helper_ca_basic_constraints():
    certs = AdmissionTLSHelper.generate_webhook_certs()
    ca_x509 = x509.load_pem_x509_certificate(certs["ca_cert"])
    bc_ext = ca_x509.extensions.get_extension_for_oid(x509.OID_BASIC_CONSTRAINTS)

    assert bc_ext.value.ca is True
