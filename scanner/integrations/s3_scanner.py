"""
AWS S3 and MinIO Object Storage Streaming Model Scanner.
Streams and validates model artifacts directly from S3-compatible cloud storage
without downloading full multi-gigabyte weight tensors to local disk.
"""

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from scanner.core.engine import ModelScanEngine
from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import EvaluationResult, Finding


class S3ModelScanner:
    """
    Streams and audits models hosted on AWS S3 or MinIO.
    """

    def __init__(self, engine: Optional[ModelScanEngine] = None, endpoint_url: Optional[str] = None):
        self.engine = engine or ModelScanEngine()
        self.endpoint_url = endpoint_url

    @staticmethod
    def parse_s3_uri(s3_uri: str) -> Tuple[str, str]:
        """Extracts (bucket, key) from s3://bucket/key/path."""
        parsed = urlparse(s3_uri)
        if parsed.scheme != "s3":
            raise ValueError(f"Invalid S3 URI scheme: {s3_uri}")
        bucket = parsed.netloc
        key = parsed.path.lstrip("/")
        return bucket, key

    def scan_s3_object_bytes(
        self,
        s3_uri: str,
        data_chunk: bytes,
        format_hint: Optional[str] = None,
    ) -> EvaluationResult:
        """Audits streamed S3 bytes directly in memory."""
        bucket, key = self.parse_s3_uri(s3_uri)
        fmt = format_hint or key.split(".")[-1]
        return self.engine.scan_bytes(data_chunk, format_hint=fmt, source_name=s3_uri)
