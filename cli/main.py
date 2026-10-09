"""
MLSecOps CLI Scanner Tool.
Production CLI command: 'mlsec-scan --path ./models/ --fail-on high'
Provides text, JSON, and GitHub SARIF v2.1.0 scan reports for model supply chains.
"""

import argparse
import json
import os
import sys
from typing import List, Optional

from scanner.core.engine import ModelScanEngine
from scanner.core.reporter import Reporter
from scanner.rules.dangerous_symbols import RiskLevel


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="mlsec-scan",
        description="Static security scanner for AI/ML model artifacts (.pkl, .pt, .bin, .onnx, .safetensors).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--path",
        "-p",
        required=True,
        type=str,
        help="Path to a model file or directory containing model files to scan.",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["text", "json", "sarif"],
        default="text",
        help="Report output format: text (terminal), json, or sarif (GitHub Code Scanning). Default: text.",
    )
    parser.add_argument(
        "--fail-on",
        type=str,
        choices=["critical", "high", "medium", "low", "info"],
        default="high",
        help="Severity threshold that triggers a non-zero exit code (1). Default: high.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Optional file path to write scan output (especially for json or sarif formats).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        default=False,
        help="Enable strict mode (flags any unrecognized global reference, even if not explicitly denylisted).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable ANSI color output in terminal report.",
    )
    parser.add_argument(
        "--verify-sha256",
        type=str,
        default=None,
        help="Expected SHA-256 digest to verify model provenance against.",
    )
    parser.add_argument(
        "--verify-sha512",
        type=str,
        default=None,
        help="Expected SHA-512 digest to verify model provenance against.",
    )
    parser.add_argument(
        "--signature",
        type=str,
        default=None,
        help="Path to detached signature file (.sig) to verify.",
    )
    parser.add_argument(
        "--public-key",
        type=str,
        default=None,
        help="Path to public key PEM file for cryptographic signature verification.",
    )
    parser.add_argument(
        "--attestation",
        type=str,
        default=None,
        help="Path to in-toto / SLSA provenance attestation JSON file.",
    )

    return parser.parse_args(argv)


def run_cli(argv: Optional[List[str]] = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    try:
        args = parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 2

    # Map fail-on argument to RiskLevel enum
    sev_map = {
        "critical": RiskLevel.CRITICAL,
        "high": RiskLevel.HIGH,
        "medium": RiskLevel.MEDIUM,
        "low": RiskLevel.LOW,
        "info": RiskLevel.INFO,
    }
    threshold = sev_map[args.fail_on.lower()]

    engine = ModelScanEngine(
        fail_on_threshold=threshold,
        strict_mode=args.strict,
    )

    evaluation, scanned_files = engine.scan_path(
        path=args.path,
        expected_sha256=args.verify_sha256,
        expected_sha512=args.verify_sha512,
        signature_path=args.signature,
        public_key_pem=args.public_key,
        attestation_path=args.attestation,
    )

    # Format the output
    use_color = not args.no_color and sys.stdout.isatty() if hasattr(sys.stdout, "isatty") else False
    if args.no_color:
        use_color = False
    elif not sys.platform.startswith("win") or "ANSICON" in os.environ or "WT_SESSION" in os.environ:
        use_color = not args.no_color
    else:
        # Enable ANSI colors on Windows if possible
        use_color = not args.no_color

    if args.format == "sarif":
        report_data = Reporter.to_sarif(evaluation, scanned_files)
        content = json.dumps(report_data, indent=2)
    elif args.format == "json":
        report_data = Reporter.to_json(evaluation, scanned_files)
        content = json.dumps(report_data, indent=2)
    else:
        content = Reporter.to_terminal_text(evaluation, scanned_files, use_color=use_color)

    # Output to file or stdout
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"Report written successfully to: {args.output}")
        except Exception as e:
            print(f"Error writing output to {args.output}: {e}", file=sys.stderr)
            return 2
    else:
        print(content)

    # Return code: 0 if passed, 1 if policy violated
    return 0 if evaluation.passed else 1


def main() -> None:
    sys.exit(run_cli())


if __name__ == "__main__":
    main()
