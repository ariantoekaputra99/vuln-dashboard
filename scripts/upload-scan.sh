#!/usr/bin/env bash
# Upload hasil scan ke VulnDash dari pipeline CI/CD.
# Pemakaian: VULNDASH_URL=https://vuln.example.com VULNDASH_API_KEY=... ./upload-scan.sh TRIVY trivy.json [nama-aset] [CRITICALITY]
set -euo pipefail

TOOL="${1:?tool: TRIVY|ZAP|NUCLEI}"
FILE="${2:?path file hasil scan}"
ASSET="${3:-}"
CRIT="${4:-}"
: "${VULNDASH_URL:?set VULNDASH_URL}"
: "${VULNDASH_API_KEY:?set VULNDASH_API_KEY}"

args=(-fsS -X POST "$VULNDASH_URL/api/scans" -H "X-API-Key: $VULNDASH_API_KEY" -F "tool=$TOOL" -F "file=@$FILE")
[[ -n "$ASSET" ]] && args+=(-F "asset=$ASSET")
[[ -n "$CRIT" ]] && args+=(-F "criticality=$CRIT")

curl "${args[@]}"
echo
