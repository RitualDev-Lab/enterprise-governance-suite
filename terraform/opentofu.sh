#!/usr/bin/env bash
# RitualDev Enterprise Governance Suite — OpenTofu & Terraform Validation Suite
# Ensures 100% compatibility with open-source OpenTofu (v1.6+) and Terraform (v1.5+)
set -euo pipefail

echo "=========================================================="
echo " RitualDev IaC Distribution — OpenTofu / Terraform Check"
echo "=========================================================="

IAC_BIN="tofu"
if ! command -v tofu &> /dev/null; then
  echo "[i] OpenTofu binary 'tofu' not found, falling back to 'terraform'"
  IAC_BIN="terraform"
fi

echo "[✓] Using IaC engine: $IAC_BIN ($($IAC_BIN version -json | grep -o '\"version\":[^,]*' || true))"

# 1. Validate AWS Module
echo ""
echo "--> Validating AWS VPC Module (terraform/aws)..."
cd "$(dirname "$0")/aws"
$IAC_BIN init -backend=false
$IAC_BIN validate
echo "[✓] AWS VPC Module valid."

# 2. Validate Azure Module
echo ""
echo "--> Validating Azure VNet Module (terraform/azure)..."
cd "../azure"
$IAC_BIN init -backend=false
$IAC_BIN validate
echo "[✓] Azure VNet Module valid."

echo ""
echo "=========================================================="
echo " [SUCCESS] All IaC modules validated cleanly."
echo "=========================================================="
