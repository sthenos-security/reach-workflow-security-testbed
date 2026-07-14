#!/usr/bin/env python3
"""Validate a before/after workflow-remediation proof run for this testbed."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _json_dict(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _normalize_path(value: object, repo_root: Path | None) -> str:
    raw = str(value or "")
    if repo_root and raw.startswith(str(repo_root)):
        try:
            return str(Path(raw).relative_to(repo_root))
        except ValueError:
            return raw
    marker = "/.github/workflows/"
    if marker in raw:
        return ".github/workflows/" + raw.split(marker, 1)[1]
    return raw


def _load_findings(metadata_path: Path, repo_root: Path | None) -> list[dict[str, Any]]:
    metadata = _load_json(metadata_path)
    db_path = Path(str(metadata["db_path"]))
    scan_id = metadata.get("scan_id")
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    query = """
        select file_path, rule_id, raw_data
        from signals
        where scanner = ?
    """
    params: list[Any] = ["reachable-workflow-security"]
    if scan_id is not None:
        query += " and scan_id = ?"
        params.append(scan_id)
    rows = con.execute(query, params).fetchall()
    con.close()

    findings: list[dict[str, Any]] = []
    for row in rows:
        raw_data = _json_dict(row["raw_data"])
        findings.append(
            {
                "path": _normalize_path(row["file_path"], repo_root),
                "rule_id": str(row["rule_id"] or ""),
                "cicd_class": str(raw_data.get("cicd_class") or row["rule_id"] or ""),
            }
        )
    return findings


def _load_cases(cases_path: Path) -> dict[str, dict[str, Any]]:
    payload = _load_json(cases_path)
    cases = payload.get("cases")
    if not isinstance(cases, list):
        raise SystemExit(f"invalid remediation cases file: {cases_path}")
    loaded: dict[str, dict[str, Any]] = {}
    for case in cases:
        if isinstance(case, dict) and case.get("id"):
            loaded[str(case["id"])] = case
    return loaded


def _select_cases(
    all_cases: dict[str, dict[str, Any]],
    selected: list[str] | None,
) -> list[dict[str, Any]]:
    if not selected:
        return list(all_cases.values())
    missing = [case_id for case_id in selected if case_id not in all_cases]
    if missing:
        raise SystemExit(f"unknown remediation case ids: {', '.join(missing)}")
    return [all_cases[case_id] for case_id in selected]


def validate(args: argparse.Namespace) -> int:
    repo_root = args.repo_root.resolve() if args.repo_root else None
    before = _load_findings(args.before, repo_root)
    after = _load_findings(args.after, repo_root)
    cases_path = args.cases
    if repo_root and not cases_path.is_absolute():
        cases_path = repo_root / cases_path
    cases = _select_cases(_load_cases(cases_path), args.case)

    errors: list[str] = []
    lines: list[str] = []
    before_total = len(before)
    after_total = len(after)
    if after_total >= before_total:
        errors.append(
            f"total workflow findings did not decrease: before={before_total}, after={after_total}"
        )

    for case in cases:
        path = str(case["path"])
        expected_pre = set(str(value) for value in case.get("expected_pre_classes") or [])
        expected_post_findings = int(case.get("expected_post_findings", 0))
        before_matches = [finding for finding in before if finding["path"] == path]
        after_matches = [finding for finding in after if finding["path"] == path]
        before_classes = {finding["cicd_class"] for finding in before_matches}
        after_classes = {finding["cicd_class"] for finding in after_matches}

        if not before_matches:
            errors.append(f"{case['id']}: no pre-remediation workflow-security findings found for {path}")
            continue
        missing_pre = sorted(expected_pre - before_classes)
        if missing_pre:
            errors.append(
                f"{case['id']}: pre-remediation classes missing for {path}: {', '.join(missing_pre)}"
            )
        if len(after_matches) != expected_post_findings:
            errors.append(
                f"{case['id']}: expected {expected_post_findings} post-remediation findings for {path}, "
                f"got {len(after_matches)} ({', '.join(sorted(after_classes)) or 'none'})"
            )
        lines.append(
            f"{case['id']}: {path} before={len(before_matches)} after={len(after_matches)} "
            f"pre_classes={','.join(sorted(before_classes)) or 'none'} "
            f"post_classes={','.join(sorted(after_classes)) or 'none'}"
        )

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print("Workflow-remediation proof validation passed")
    print(f"  total workflow findings: before={before_total} after={after_total}")
    for line in lines:
        print(f"  {line}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True, help="Pre-remediation scan metadata JSON.")
    parser.add_argument("--after", type=Path, required=True, help="Post-remediation scan metadata JSON.")
    parser.add_argument("--repo-root", type=Path, help="Repo root for path normalization.")
    parser.add_argument(
        "--cases",
        type=Path,
        default=Path("expected/workflow-remediation.json"),
        help="Remediation-case manifest.",
    )
    parser.add_argument(
        "--case",
        action="append",
        help="Case id to validate. May be repeated. Defaults to all cases in the manifest.",
    )
    args = parser.parse_args()
    return validate(args)


if __name__ == "__main__":
    raise SystemExit(main())
