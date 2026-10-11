"""
Redis and In-Memory Admission Cache.
Stores model SHA-256 review verdicts to eliminate redundant scans during Kubernetes pod autoscaling.
"""

import json
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger("admission_cache")


class AdmissionCache:
    """
    Admission decision caching layer with Redis support and in-memory fallback.
    """

    def __init__(self, redis_url: Optional[str] = None, default_ttl_seconds: int = 86400):
        self.default_ttl = default_ttl_seconds
        self.redis_client = None
        self._in_memory_cache: Dict[str, str] = {}

        target_url = redis_url or os.getenv("REDIS_URL")
        if target_url:
            try:
                import redis

                self.redis_client = redis.Redis.from_url(target_url, decode_responses=True)
                self.redis_client.ping()
                logger.info("Connected to Redis cache at %s", target_url)
            except Exception as e:
                logger.warning("Redis connection failed (%s); using in-memory cache.", e)
                self.redis_client = None

    def get_cached_verdict(self, sha256_hash: str) -> Optional[Dict[str, Any]]:
        """Retrieves cached admission decision by model SHA-256."""
        key = f"mlsecops:admission:{sha256_hash.lower()}"
        if self.redis_client:
            try:
                val = self.redis_client.get(key)
                if val:
                    return json.loads(val)
            except Exception as e:
                logger.error("Redis get failed: %s", e)

        # In-memory fallback
        if key in self._in_memory_cache:
            try:
                return json.loads(self._in_memory_cache[key])
            except Exception:
                return None
        return None

    def cache_verdict(self, sha256_hash: str, verdict_data: Dict[str, Any], ttl: Optional[int] = None) -> bool:
        """Saves admission review verdict for model SHA-256."""
        key = f"mlsecops:admission:{sha256_hash.lower()}"
        payload = json.dumps(verdict_data)
        ttl_val = ttl or self.default_ttl

        if self.redis_client:
            try:
                self.redis_client.setex(key, ttl_val, payload)
                return True
            except Exception as e:
                logger.error("Redis setex failed: %s", e)

        self._in_memory_cache[key] = payload
        return True
