#!/usr/bin/env python3
"""Apply a deterministic workflow-remediation fixture to this testbed."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _load_case(cases_path: Path, case_id: str) -> dict[str, Any]:
    payload = _load_json(cases_path)
    cases = payload.get("cases")
    if not isinstance(cases, list):
        raise SystemExit(f"invalid remediation cases file: {cases_path}")
    for case in cases:
        if isinstance(case, dict) and str(case.get("id") or "") == case_id:
            return case
    available = ", ".join(
        str(case.get("id") or "")
        for case in cases
        if isinstance(case, dict) and case.get("id")
    )
    raise SystemExit(f"unknown case {case_id!r}; available: {available}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True, help="Mutable testbed root to patch.")
    parser.add_argument(
        "--cases",
        type=Path,
        default=Path("expected/workflow-remediation.json"),
        help="Remediation-case manifest.",
    )
    parser.add_argument("--case", required=True, help="Case id from the remediation manifest.")
    args = parser.parse_args()

    repo_root = args.repo_root.resolve()
    case = _load_case((repo_root / args.cases).resolve() if not args.cases.is_absolute() else args.cases, args.case)
    target_rel = Path(str(case["path"]))
    replacement_rel = Path(str(case["replacement_source"]))
    target_path = repo_root / target_rel
    replacement_path = repo_root / replacement_rel

    if not replacement_path.is_file():
        raise SystemExit(f"replacement fixture not found: {replacement_path}")
    if not target_path.exists():
        raise SystemExit(f"target workflow not found: {target_path}")

    target_path.write_text(replacement_path.read_text(encoding="utf-8"), encoding="utf-8")
    print(str(target_rel))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
