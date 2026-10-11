#!/usr/bin/env bash
# MLSecOps Local Model Directory Scanner
set -euo pipefail

TARGET_PATH="${1:-test_models/}"
FAIL_ON="${2:-high}"
FORMAT="${3:-text}"

echo "=========================================================="
echo " Starting MLSecOps Static Model Security Audit"
echo " Target : ${TARGET_PATH}"
echo " Fail-on: ${FAIL_ON}"
echo " Format : ${FORMAT}"
echo "=========================================================="

python -m cli.main --path "${TARGET_PATH}" --fail-on "${FAIL_ON}" --format "${FORMAT}"
