"""
Google Cloud Storage (GCS) Streaming Model Security Scanner.
Parses gs:// URIs and validates Vertex AI / GCP model buckets directly in-memory.
"""

from typing import Optional, Tuple
from urllib.parse import urlparse

from scanner.core.engine import ModelScanEngine
from scanner.rules.policy_engine import EvaluationResult


class GCSModelScanner:
    """
    Audits model artifacts hosted on Google Cloud Storage (gs://).
    """

    def __init__(self, engine: Optional[ModelScanEngine] = None):
        self.engine = engine or ModelScanEngine()

    @staticmethod
    def parse_gcs_uri(gcs_uri: str) -> Tuple[str, str]:
        """Extracts (bucket, object_path) from gs://bucket/path/to/model."""
        parsed = urlparse(gcs_uri)
        if parsed.scheme != "gs":
            raise ValueError(f"Invalid GCS URI scheme: {gcs_uri}")
        bucket = parsed.netloc
        path = parsed.path.lstrip("/")
        return bucket, path

    def scan_gcs_object_bytes(
        self,
        gcs_uri: str,
        data_chunk: bytes,
        format_hint: Optional[str] = None,
    ) -> EvaluationResult:
        """Audits streamed GCS bytes directly in memory."""
        bucket, path = self.parse_gcs_uri(gcs_uri)
        fmt = format_hint or path.split(".")[-1]
        return self.engine.scan_bytes(data_chunk, format_hint=fmt, source_name=gcs_uri)
