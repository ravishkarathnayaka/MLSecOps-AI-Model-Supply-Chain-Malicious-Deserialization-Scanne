"""
Unit tests validating Prometheus metrics exposition and thread safety in admission gate.
"""

import threading
import unittest

from admission_gate.metrics import AdmissionMetrics


class TestAdmissionMetrics(unittest.TestCase):
    def setUp(self):
        self.metrics = AdmissionMetrics()

    def test_record_admission_and_format(self):
        self.metrics.record_admission("admitted", "clean_model")
        self.metrics.record_admission("rejected", "reduce_payload")
        self.metrics.record_cache_hit()
        self.metrics.record_cache_miss()
        self.metrics.record_finding("CRITICAL", "ARBITRARY-CODE-EXECUTION-REDUCE")

        prom_text = self.metrics.generate_prometheus_text()
        self.assertIn('mlsecops_admission_requests_total{status="admitted",reason="clean_model"} 1', prom_text)
        self.assertIn('mlsecops_admission_requests_total{status="rejected",reason="reduce_payload"} 1', prom_text)
        self.assertIn("mlsecops_cache_hits_total 1", prom_text)
        self.assertIn("mlsecops_cache_misses_total 1", prom_text)
        self.assertIn('mlsecops_threat_findings_total{severity="CRITICAL",rule_id="ARBITRARY-CODE-EXECUTION-REDUCE"} 1', prom_text)

    def test_thread_safety_concurrent_increments(self):
        def worker():
            for _ in range(100):
                self.metrics.record_cache_hit()
                self.metrics.record_admission("admitted", "test")

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(self.metrics.cache_hits, 1000)
        self.assertEqual(self.metrics.admission_requests[("admitted", "test")], 1000)


if __name__ == "__main__":
    unittest.main()
