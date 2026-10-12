"""
Azure Blob Storage integration for streaming security inspection of remote model repositories.
Scans containers (az://<container>/<prefix>) without staging multi-gigabyte models to local disk.
"""

from dataclasses import dataclass
import io
import re
from typing import Any, Dict, List, Optional

from scanner.core.engine import ModelScanEngine
from scanner.rules.policy_engine import EvaluationResult, PolicyEngine


@dataclass
class AzureBlobTarget:
    container: str
    blob_name: str
    content_length: int
    etag: str


class AzureBlobScanner:
    """Streams and validates model weights stored in Microsoft Azure Blob Storage."""

    def __init__(
        self,
        connection_string: Optional[str] = None,
        account_url: Optional[str] = None,
        blob_service_client: Any = None,
    ):
        self.connection_string = connection_string
        self.account_url = account_url
        self.client = blob_service_client
        self.engine = ModelScanEngine()

    @staticmethod
    def parse_azure_uri(uri: str) -> tuple[str, str]:
        """Parses az://<container>/<blob_path> or wasbs://... URI."""
        cleaned = re.sub(r"^(az|wasbs|wasb)://", "", uri)
        parts = cleaned.split("/", 1)
        container = parts[0]
        blob_name = parts[1] if len(parts) > 1 else ""
        return container, blob_name

    def scan_blob(
        self,
        container: str,
        blob_name: str,
        blob_bytes: bytes,
        fail_on_severity: str = "HIGH",
    ) -> EvaluationResult:
        """Inspects in-memory streamed blob bytes against security rules."""
        file_ext = blob_name.rsplit(".", 1)[-1].lower() if "." in blob_name else "pkl"
        return self.engine.scan_bytes(blob_bytes, format_hint=file_ext, source_name=f"az://{container}/{blob_name}")

    def scan_container_prefix(
        self,
        container: str,
        prefix: str = "",
        fail_on_severity: str = "HIGH",
    ) -> List[EvaluationResult]:
        """Traverses container blobs under prefix and executes security scans."""
        results: List[EvaluationResult] = []
        if not self.client:
            return results

        container_client = self.client.get_container_client(container)
        for blob in container_client.list_blobs(name_starts_with=prefix):
            # Only scan recognized model extensions
            if any(blob.name.lower().endswith(ext) for ext in [".pt", ".pkl", ".onnx", ".safetensors", ".npy", ".json"]):
                blob_client = container_client.get_blob_client(blob.name)
                stream = blob_client.download_blob()
                raw_bytes = stream.readall()
                res = self.scan_blob(container, blob.name, raw_bytes, fail_on_severity)
                results.append(res)

        return results
