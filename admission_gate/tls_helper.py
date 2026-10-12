"""
Admission Controller mTLS and Certificate Helper.
Generates self-signed CA and webhook serving certificates with SANs for Kubernetes API server validation,
and computes caBundle base64 strings.
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.oid import NameOID


class AdmissionTLSHelper:
    """Manages x509 certificates and caBundle generation for admission webhooks."""

    @classmethod
    def generate_webhook_certs(
        cls,
        service_name: str = "mlsecops-admission-service",
        namespace: str = "mlsecops-system",
        validity_days: int = 365,
    ) -> Dict[str, bytes]:
        """Generates CA certificate, server certificate, and private keys in PEM format."""
        # 1. CA key & cert
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mlsecops-webhook-ca")])
        now = datetime.now(timezone.utc)

        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )

        # 2. Server key & cert
        server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        dns_names = [
            x509.DNSName(service_name),
            x509.DNSName(f"{service_name}.{namespace}"),
            x509.DNSName(f"{service_name}.{namespace}.svc"),
            x509.DNSName(f"{service_name}.{namespace}.svc.cluster.local"),
        ]

        server_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, service_name)]))
            .issuer_name(ca_name)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(x509.SubjectAlternativeName(dns_names), critical=False)
            .sign(ca_key, hashes.SHA256())
        )

        return {
            "ca_cert": ca_cert.public_bytes(Encoding.PEM),
            "ca_key": ca_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
            "server_cert": server_cert.public_bytes(Encoding.PEM),
            "server_key": server_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
        }
