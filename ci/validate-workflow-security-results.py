#!/usr/bin/env python3
"""Validate REACHABLE workflow-security output for this testbed."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _workflow_step_path(session_dir: Path) -> Path:
    return session_dir / ".step-workflow_security.json"


def _load_native_findings_from_metadata(metadata_path: Path) -> dict[str, Any]:
    metadata = _load_json(metadata_path)
    db_path = Path(str(metadata["db_path"]))
    session_dir = Path(str(metadata["session_dir"]))
    scan_id = metadata.get("scan_id")
    step = _load_json(_workflow_step_path(session_dir))
    result = step.get("result") if isinstance(step.get("result"), dict) else {}
    coverage = result.get("coverage") if isinstance(result.get("coverage"), dict) else {}
    workflow_files = result.get("workflow_files") or coverage.get("workflow_files")

    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    query = """
        select
            file_path,
            rule_id,
            severity,
            prod_status,
            ai_review_prompt,
            scanner,
            raw_data
        from signals
        where scanner = ?
    """
    params: list[Any] = ["reachable-workflow-security"]
    if scan_id is not None:
        query += " and scan_id = ?"
        params.append(scan_id)
    rows = con.execute(query, params).fetchall()
    findings: list[dict[str, Any]] = []
    for row in rows:
        raw_data = row["raw_data"] or "{}"
        try:
            parsed = json.loads(raw_data)
        except json.JSONDecodeError:
            parsed = {}
        findings.append(
            {
                "file_path": row["file_path"],
                "rule_id": row["rule_id"],
                "severity": row["severity"],
                "prod_status": row["prod_status"],
                "ai_review_prompt": row["ai_review_prompt"],
                "scanner": row["scanner"],
                "cicd_class": parsed.get("cicd_class"),
            }
        )
    con.close()
    return {
        "findings": findings,
        "stats": {"workflow_files": workflow_files},
        "coverage": coverage,
    }


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


def _count(findings: list[dict[str, Any]], key: str, repo_root: Path | None = None) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for finding in findings:
        value = finding.get(key)
        if key == "file_path":
            value = _normalize_path(value, repo_root)
        counts[str(value or "UNKNOWN")] += 1
    return dict(sorted(counts.items()))


def _expect(label: str, actual: Any, expected: Any, errors: list[str]) -> None:
    if actual != expected:
        errors.append(f"{label}: expected {expected!r}, got {actual!r}")


def _matching(
    findings: list[dict[str, Any]],
    *,
    path: str,
    rule_id: str | None = None,
    cicd_class: str | None = None,
    scanner: str | None = None,
    repo_root: Path | None = None,
) -> list[dict[str, Any]]:
    matches = []
    for finding in findings:
        if _normalize_path(finding.get("file_path"), repo_root) != path:
            continue
        if rule_id and str(finding.get("rule_id") or "") != rule_id:
            continue
        if cicd_class and str(finding.get("cicd_class") or "") != cicd_class:
            continue
        if scanner and str(finding.get("scanner") or "") != scanner:
            continue
        matches.append(finding)
    return matches


def validate(args: argparse.Namespace) -> int:
    expected = _load_json(Path(args.expected))
    raw = (
        _load_json(Path(args.raw))
        if args.raw
        else _load_native_findings_from_metadata(Path(args.metadata))
    )
    repo_root = Path(args.repo_root).resolve() if args.repo_root else None
    findings = list(raw.get("findings") or [])
    errors: list[str] = []

    stats = raw.get("stats") if isinstance(raw.get("stats"), dict) else {}
    coverage = raw.get("coverage") if isinstance(raw.get("coverage"), dict) else {}
    native_expected = expected["native_expected"]
    native = [
        finding
        for finding in findings
        if str(finding.get("scanner") or "") == native_expected["scanner"]
    ]

    _expect("fixture_count", stats.get("workflow_files"), expected["fixture_count"], errors)
    _expect("coverage.status", coverage.get("status"), expected["minimum_contract"]["coverage_status"], errors)
    _expect("native.total_findings", len(native), native_expected["total_findings"], errors)
    _expect("native.by_class", _count(native, "cicd_class"), native_expected["by_class"], errors)
    _expect("native.by_rule_id", _count(native, "rule_id"), native_expected["by_rule_id"], errors)
    _expect("native.by_severity", _count(native, "severity"), native_expected["by_severity"], errors)
    _expect("native.by_path", _count(native, "file_path", repo_root), native_expected["by_path"], errors)

    for case in expected["required_detections"]:
        matches = _matching(
            native,
            path=case["path"],
            rule_id=case["rule_id"],
            cicd_class=case["class"],
            scanner=native_expected["scanner"],
            repo_root=repo_root,
        )
        if len(matches) < int(case["expected_min_findings"]):
            errors.append(
                f"{case['id']}: expected at least {case['expected_min_findings']} "
                f"{case['rule_id']} finding(s) in {case['path']}, got {len(matches)}"
            )
        for finding in matches:
            _expect(f"{case['id']}.risk", finding.get("severity"), case["risk"], errors)
            _expect(
                f"{case['id']}.prod_status",
                finding.get("prod_status"),
                expected["minimum_contract"]["workflow_security_prod_status"],
                errors,
            )
            _expect(
                f"{case['id']}.ai_review_prompt",
                finding.get("ai_review_prompt"),
                expected["minimum_contract"]["ai_review_prompt"],
                errors,
            )

    for control in expected["defended_controls"]:
        matches = _matching(
            native,
            path=control["path"],
            scanner=native_expected["scanner"],
            repo_root=repo_root,
        )
        _expect(
            f"defended.{control['path']}.native_findings",
            len(matches),
            int(control["native_findings_expected"]),
            errors,
        )

    for helper in expected.get("zero_native_helpers", []):
        matches = _matching(
            native,
            path=helper["path"],
            scanner=native_expected["scanner"],
            repo_root=repo_root,
        )
        _expect(
            f"zero_native.{helper['path']}.native_findings",
            len(matches),
            int(helper["native_findings_expected"]),
            errors,
        )

    serialized = json.dumps(findings)
    if "secret_value" in serialized.lower():
        errors.append("secret hygiene: finding payload contains secret_value")

    if errors:
        print("Workflow-security expected-results validation FAILED", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("Workflow-security expected-results validation passed")
    print(f"  workflow files: {stats.get('workflow_files')}")
    print(f"  native findings: {len(native)}")
    print(f"  native classes: {', '.join(sorted(native_expected['by_class']))}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--raw", help="Path to raw/workflow-security.json")
    source.add_argument(
        "--metadata",
        help="Path to reachctl scan metadata JSON written by --metadata-out",
    )
    parser.add_argument(
        "--expected",
        default=str(Path(__file__).resolve().parents[1] / "expected" / "workflow-security.json"),
        help="Path to expected workflow-security contract",
    )
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Repository root used to normalize absolute paths from optional tools",
    )
    return validate(parser.parse_args())


if __name__ == "__main__":
    sys.exit(main())
