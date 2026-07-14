#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: ci/run-workflow-remediation-proof.sh --repo-root PATH --reachctl PATH --case CASE_ID

This mutates the target repo root by overwriting one vulnerable workflow file
with a defended fixture from the same repository, then rescans and validates
that the workflow-security findings for that path drop to zero.
Run it against a disposable copy of the testbed, not your main checkout.
EOF
}

repo_root=""
reachctl_bin="${REACHCTL_BIN:-reachctl}"
case_id=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo-root)
      repo_root="${2:-}"
      shift 2
      ;;
    --reachctl)
      reachctl_bin="${2:-}"
      shift 2
      ;;
    --case)
      case_id="${2:-}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [ -z "$repo_root" ] || [ -z "$case_id" ]; then
  usage
  exit 2
fi

repo_root="$(cd "$repo_root" && pwd)"
tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/workflow-remediation-proof.XXXXXX")"
before_dir="$tmp_root/before"
after_dir="$tmp_root/after"
mkdir -p "$before_dir" "$after_dir"

echo "== Pre-remediation scan =="
"$reachctl_bin" scan "$repo_root" --ci --dashboard --output "$before_dir" --metadata-out "$before_dir/metadata.json"

echo "== Apply deterministic remediation fixture =="
changed_rel="$(
  python3 "$repo_root/ci/apply-workflow-remediation-fixture.py" \
    --repo-root "$repo_root" \
    --case "$case_id"
)"
echo "changed workflow: $changed_rel"

if [[ "$changed_rel" == .github/workflows/* ]]; then
  if ! command -v actionlint >/dev/null 2>&1; then
    echo "actionlint is required for workflow remediation proof runs" >&2
    exit 2
  fi
  echo "== actionlint =="
  actionlint -shellcheck= "$repo_root/$changed_rel"
fi

echo "== Post-remediation scan =="
"$reachctl_bin" scan "$repo_root" --ci --dashboard --output "$after_dir" --metadata-out "$after_dir/metadata.json"

echo "== Validation =="
python3 "$repo_root/ci/validate-workflow-remediation.py" \
  --before "$before_dir/metadata.json" \
  --after "$after_dir/metadata.json" \
  --repo-root "$repo_root" \
  --case "$case_id"

echo "proof artifacts:"
echo "  before: $before_dir"
echo "  after:  $after_dir"
