from __future__ import annotations

import json
from pathlib import Path

from prooflint.models import Diagnostic, Finding, ManifestVerification, ValidationResult
from prooflint.reporters import (
    render_json,
    render_sarif,
    render_text,
    render_verification_json,
    render_verification_text,
)

GOLDEN = Path(__file__).parent / "golden"


def single_failure() -> ValidationResult:
    finding = Finding.from_mapping({"schema_version": "0.1"}, source_path=Path("finding.md"))
    diagnostic = Diagnostic(
        code="PL001",
        message="record both a target identifier and immutable fingerprint",
        field="target",
        path="finding.md",
        line=7,
    )
    return ValidationResult(finding=finding, diagnostics=(diagnostic,))


def test_text_report_matches_golden() -> None:
    assert render_text([single_failure()]) == (GOLDEN / "single-pl001.txt").read_text()


def test_json_report_matches_golden() -> None:
    assert render_json([single_failure()]) == (GOLDEN / "single-pl001.json").read_text()


def test_sarif_has_stable_21_contract() -> None:
    payload = json.loads(render_sarif([single_failure()]))
    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "Prooflint"
    assert run["tool"]["driver"]["rules"][0]["id"] == "PL001"
    result = run["results"][0]
    assert result["ruleId"] == "PL001"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 7


def test_empty_report_passes() -> None:
    assert json.loads(render_json([]))["passed"] is True
    assert render_text([]) == "Prooflint: 0 finding(s), 0 violation(s), 0 passed\n"


def test_manifest_verification_reporters() -> None:
    passing = ManifestVerification(ok=True, files_checked=2)
    assert render_verification_text(passing) == (
        "Prooflint manifest verification: PASS (2 file(s) checked)\n"
    )
    assert json.loads(render_verification_json(passing)) == {
        "errors": [],
        "files_checked": 2,
        "ok": True,
    }
    failing = ManifestVerification(ok=False, files_checked=1, errors=("SHA mismatch",))
    assert "FAIL" in render_verification_text(failing)
    assert "error: SHA mismatch" in render_verification_text(failing)
