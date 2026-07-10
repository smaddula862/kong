#!/usr/bin/env bash
# Lightweight sanity checks for the GitOps manifests in this directory.
# Validates YAML syntax and that every referenced per-DC/per-component value
# file exists. Does NOT contact any cluster.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail=0

echo "==> YAML syntax check"
# Prefer yamllint; fall back to python yaml.
if command -v yamllint >/dev/null 2>&1; then
  yamllint -d '{extends: relaxed, rules: {line-length: disable}}' \
    bootstrap openshift clusters || fail=1
elif command -v python3 >/dev/null 2>&1; then
  while IFS= read -r f; do
    python3 -c "import sys,yaml; list(yaml.safe_load_all(open(sys.argv[1])))" "$f" \
      || { echo "  invalid YAML: $f"; fail=1; }
  done < <(find bootstrap openshift clusters -name '*.yaml')
else
  echo "  (no yamllint/python3 available — skipping)"
fi

echo "==> Component value-file completeness"
components="apigee-operator apigee-datastore apigee-telemetry apigee-redis \
apigee-ingress-manager apigee-org apigee-env apigee-virtualhost"
for dc in common east west; do
  for c in $components; do
    f="clusters/$dc/$c/values.yaml"
    if [[ ! -f "$f" ]]; then
      echo "  MISSING: $f"; fail=1
    fi
  done
done

if [[ "$fail" -eq 0 ]]; then
  echo "==> OK: all checks passed"
else
  echo "==> FAILED"; exit 1
fi
