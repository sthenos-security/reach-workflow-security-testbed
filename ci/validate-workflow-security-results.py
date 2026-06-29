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
            finding_id,
            file_path,
            rule_id,
            severity,
            app_reachability,
            prod_status,
            ai_review_prompt,
            requires_ai_review,
            ai_review_payload,
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
        payload = _json_dict(row["ai_review_payload"])
        findings.append(
            {
                "finding_id": row["finding_id"],
                "file_path": row["file_path"],
                "rule_id": row["rule_id"],
                "severity": row["severity"],
                "app_reachability": row["app_reachability"],
                "prod_status": row["prod_status"],
                "ai_review_prompt": row["ai_review_prompt"],
                "requires_ai_review": row["requires_ai_review"],
                "scanner": row["scanner"],
                "ai_review_payload": payload,
                "cicd_class": parsed.get("cicd_class") or _payload_cicd_class(row["rule_id"], payload),
                "evidence": _finding_evidence(parsed, payload),
            }
        )
    con.close()
    return {
        "findings": findings,
        "stats": {"workflow_files": workflow_files},
        "coverage": coverage,
    }


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


def _payload_cicd_class(rule_id: object, payload: dict[str, Any]) -> str | None:
    evidence = payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}
    sink = str(evidence.get("sink_operation") or evidence.get("workflow_call") or rule_id or "")
    if sink == "workflow_ui_log":
        return "cicd_step_summary_exfiltration"
    if sink == "debug_log":
        return "cicd_secret_exfiltration_path"
    if sink == "network_egress" and "*" in set(evidence.get("secret_names") or []):
        return "cicd_secret_exfiltration_path"
    if sink == "shell_execution":
        if _has_reusable_input_context(evidence):
            return "cicd_reusable_workflow_injection"
        return "cicd_command_injection"
    if sink == "evaluated_script_context":
        if _has_reusable_input_context(evidence):
            return "cicd_reusable_workflow_injection"
        return "cicd_code_injection"
    if sink == "checkout_ref":
        return "cicd_untrusted_checkout"
    if sink == "default_write_permissions":
        return "cicd_trigger_abuse"
    if sink == "pull_request_merge":
        return "cicd_auth_logic_error"
    if sink in {"package_publish", "container_publish", "release_publish", "deploy", "cloud_control", "network_egress"}:
        return "cicd_secret_authority_exposure"
    if "secrets" in sink:
        return "cicd_reusable_workflow_boundary"
    return None


def _has_reusable_input_context(evidence: dict[str, Any]) -> bool:
    return any(str(context).startswith("inputs.") for context in evidence.get("untrusted_contexts") or [])


def _finding_evidence(raw_data: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    raw_evidence = raw_data.get("evidence") if isinstance(raw_data.get("evidence"), dict) else {}
    if raw_evidence:
        return raw_evidence
    payload_evidence = payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}
    return payload_evidence


def _evidence_for(finding: dict[str, Any]) -> dict[str, Any]:
    evidence = finding.get("evidence")
    if isinstance(evidence, dict):
        return evidence
    raw_data = finding.get("raw_data")
    if isinstance(raw_data, dict) and isinstance(raw_data.get("evidence"), dict):
        return raw_data["evidence"]
    payload = finding.get("ai_review_payload")
    if isinstance(payload, dict) and isinstance(payload.get("evidence"), dict):
        return payload["evidence"]
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


def _is_workflow_path_finding(finding: dict[str, Any]) -> bool:
    return str(finding.get("id") or finding.get("finding_id") or "").startswith("workflow-path:")


def _expected_ai_review_prompt(finding: dict[str, Any], expected: dict[str, Any]) -> str | None:
    if _is_workflow_path_finding(finding):
        return expected["minimum_contract"]["path_ai_review_prompt"]
    return expected["minimum_contract"].get("candidate_ai_review_prompt")


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
    native_reachable_without_path = [
        finding
        for finding in native
        if str(finding.get("app_reachability") or "") == "REACHABLE"
        and not str(finding.get("id") or finding.get("finding_id") or "").startswith("workflow-path:")
    ]
    if native_reachable_without_path:
        examples = [
            f"{_normalize_path(finding.get('file_path'), repo_root)}:{finding.get('rule_id')}"
            for finding in native_reachable_without_path[:5]
        ]
        errors.append(
            "native.graph_contract: non-path native findings claimed REACHABLE: "
            + ", ".join(examples)
        )
    candidate_review_requests = [
        finding
        for finding in native
        if not _is_workflow_path_finding(finding)
        and (
            finding.get("ai_review_prompt")
            or int(finding.get("requires_ai_review") or 0) != 0
        )
    ]
    if candidate_review_requests:
        examples = [
            f"{_normalize_path(finding.get('file_path'), repo_root)}:{finding.get('rule_id')}"
            for finding in candidate_review_requests[:5]
        ]
        errors.append(
            "native.review_contract: non-path candidates requested workflow AI review: "
            + ", ".join(examples)
        )
    path_review_missing = [
        finding
        for finding in native
        if _is_workflow_path_finding(finding)
        and finding.get("ai_review_prompt") != expected["minimum_contract"]["path_ai_review_prompt"]
    ]
    if path_review_missing:
        examples = [
            f"{_normalize_path(finding.get('file_path'), repo_root)}:{finding.get('rule_id')}"
            for finding in path_review_missing[:5]
        ]
        errors.append(
            "path.review_contract: workflow-path findings missing workflow AI review: "
            + ", ".join(examples)
        )

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
                _expected_ai_review_prompt(finding, expected),
                errors,
            )

    for case in expected.get("required_evidence", []):
        matches = _matching(
            native,
            path=case["path"],
            rule_id=case["rule_id"],
            cicd_class=case["class"],
            scanner=native_expected["scanner"],
            repo_root=repo_root,
        )
        if not matches:
            errors.append(f"{case['id']}: no matching finding for evidence validation")
            continue
        evidence = _evidence_for(matches[0])
        component_names = {
            str(component.get("name"))
            for component in evidence.get("build_components") or []
            if isinstance(component, dict) and component.get("name")
        }
        expected_components = set(case.get("build_component_names") or [])
        if not expected_components <= component_names:
            errors.append(
                f"{case['id']}.build_component_names: expected {sorted(expected_components)!r} "
                f"to be contained in {sorted(component_names)!r}"
            )
        component_risks = {
            str(component.get("risk"))
            for component in evidence.get("build_components") or []
            if isinstance(component, dict) and component.get("risk")
        }
        expected_component_risks = set(case.get("build_component_risks") or [])
        if not expected_component_risks <= component_risks:
            errors.append(
                f"{case['id']}.build_component_risks: expected {sorted(expected_component_risks)!r} "
                f"to be contained in {sorted(component_risks)!r}"
            )
        if "download_execute_integrity_binding" in case:
            integrity_values = {
                bool(component.get("integrity_binding"))
                for component in evidence.get("build_components") or []
                if isinstance(component, dict)
                and component.get("component_type") == "remote_download"
                and "integrity_binding" in component
            }
            expected_integrity = bool(case["download_execute_integrity_binding"])
            if expected_integrity not in integrity_values:
                errors.append(
                    f"{case['id']}.download_execute_integrity_binding: expected "
                    f"{expected_integrity!r} in {sorted(integrity_values)!r}"
                )
        posture_context = {str(value) for value in evidence.get("posture_context") or []}
        expected_posture = set(case.get("posture_context") or [])
        if not expected_posture <= posture_context:
            errors.append(
                f"{case['id']}.posture_context: expected {sorted(expected_posture)!r} "
                f"to be contained in {sorted(posture_context)!r}"
            )
        permission_states = {str(value) for value in evidence.get("permission_states") or []}
        expected_permission_states = set(case.get("permission_states") or [])
        if not expected_permission_states <= permission_states:
            errors.append(
                f"{case['id']}.permission_states: expected {sorted(expected_permission_states)!r} "
                f"to be contained in {sorted(permission_states)!r}"
            )
        write_scopes = {str(value) for value in evidence.get("write_scopes") or []}
        expected_write_scopes = set(case.get("write_scopes") or [])
        if not expected_write_scopes <= write_scopes:
            errors.append(
                f"{case['id']}.write_scopes: expected {sorted(expected_write_scopes)!r} "
                f"to be contained in {sorted(write_scopes)!r}"
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
