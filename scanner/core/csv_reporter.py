"""
CSV Report Generator for Enterprise Compliance and SIEM Ingestion.
Exports model security audit results into standardized CSV tables.
"""

import csv
import io
import json
from typing import List

from scanner.rules.policy_engine import EvaluationResult


class CSVReporter:
    """Exports findings into standard CSV format."""

    @classmethod
    def to_csv_string(cls, evaluation: EvaluationResult) -> str:
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

        # Header row
        writer.writerow([
            "rule_id",
            "severity",
            "title",
            "category",
            "location",
            "description",
            "details_json",
        ])

        for f in evaluation.findings:
            writer.writerow([
                f.rule_id,
                f.severity.value,
                f.title,
                f.category,
                f.location,
                f.description,
                json.dumps(f.details),
            ])

        return output.getvalue()
