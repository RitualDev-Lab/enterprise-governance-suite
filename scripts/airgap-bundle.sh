#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Ritual Enterprise Air-Gapped Offline Packaging Script
# Bundles all container images and Helm charts for 100% disconnected VPC deployment.
# ─────────────────────────────────────────────────────────────────────────────

OUTPUT_DIR="./airgap-bundle-$(date +%Y%m%d)"
mkdir -p "${OUTPUT_DIR}"

echo "📦 [1/3] Packaging Ritual Governance Umbrella Helm Chart..."
helm package ./helm/ritual-agent-governance -d "${OUTPUT_DIR}"

echo "🐳 [2/3] Pulling & Exporting Production Container Images..."
IMAGES=(
  "ghcr.io/ritualdev-lab/dbshield:0.2.0"
  "ghcr.io/ritualdev-lab/agentshield:0.1.4"
  "ghcr.io/ritualdev-lab/skillprism:0.2.0"
  "redis:7.2-alpine"
)

for img in "${IMAGES[@]}"; do
  echo "  --> Pulling ${img}..."
  docker pull "${img}"
done

echo "  --> Saving images to tar archive..."
docker save "${IMAGES[@]}" | gzip > "${OUTPUT_DIR}/ritual-governance-images.tar.gz"

echo "📄 [3/3] Generating Air-Gapped Checksum & Verification Manifest..."
cd "${OUTPUT_DIR}"
sha256sum * > SHA256SUMS
cd ..

echo "✅ Air-Gapped Governance Bundle ready at: ${OUTPUT_DIR}"
echo "Transfer this directory to your isolated, disconnected private VPC."
