from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from prooflint.models import Finding
from prooflint.rules import validate_finding
from tests.helpers import markdown_for, valid_mapping


def finding_from(mapping: dict[str, Any]) -> Finding:
    return Finding.from_mapping(
        mapping,
        source_path=Path("finding.md"),
        source_text=markdown_for(mapping),
    )


def codes_for(mapping: dict[str, Any], root: Path) -> list[str]:
    return [item.code for item in validate_finding(finding_from(mapping), root).diagnostics]


def test_valid_finding_passes(evidence_bundle: tuple[Path, str, str]) -> None:
    root, path, digest = evidence_bundle
    result = validate_finding(finding_from(valid_mapping(path, digest)), root)
    assert result.passed
    assert result.diagnostics == ()


@pytest.mark.parametrize(
    ("code", "mutate"),
    [
        ("PL001", lambda data: data.update(target={"system": "fixture"})),
        ("PL002", lambda data: data.update(scope={"authorized": False, "description": "x"})),
        ("PL003", lambda data: data.update(preconditions=[], affected_boundary="")),
        (
            "PL004",
            lambda data: data.update(
                reproduction={
                    "attempts": 3,
                    "successes": 0,
                    "environment": "Offline",
                    "steps": ["Compare"],
                }
            ),
        ),
        ("PL005", lambda data: data.update(observed=data["expected"])),
        ("PL006", lambda data: data.update(impact="")),
        (
            "PL007",
            lambda data: data.update(
                reproduction={
                    "attempts": 2,
                    "successes": 3,
                    "environment": "Offline",
                    "steps": ["Compare"],
                }
            ),
        ),
        (
            "PL008",
            lambda data: data["evidence"][0].update(sha256="0" * 64),
        ),
        ("PL009", lambda data: data.update(retest=[])),
        (
            "PL010",
            lambda data: data["evidence"][0].update(sensitive=True, redacted=False),
        ),
    ],
)
def test_each_rule_has_a_focused_failure(
    code: str,
    mutate: Any,
    evidence_bundle: tuple[Path, str, str],
) -> None:
    root, path, digest = evidence_bundle
    data = valid_mapping(path, digest)
    mutate(data)
    assert code in codes_for(data, root)


@pytest.mark.parametrize(
    "reproduction",
    [
        {"successes": 1, "environment": "Offline", "steps": ["x"]},
        {"attempts": 2, "environment": "Offline", "steps": ["x"]},
    ],
)
def test_pl007_rejects_one_sided_counters(
    reproduction: dict[str, Any],
    evidence_bundle: tuple[Path, str, str],
) -> None:
    root, path, digest = evidence_bundle
    data = valid_mapping(path, digest)
    data["status"] = "unverified"
    data["reproduction"] = reproduction
    assert "PL007" in codes_for(data, root)


def test_pl007_rejects_not_tested_with_verified_evidence(
    evidence_bundle: tuple[Path, str, str],
) -> None:
    root, path, digest = evidence_bundle
    data = valid_mapping(path, digest)
    data["status"] = "not_tested"
    data["reproduction"] = {
        "attempts": 0,
        "successes": 0,
        "environment": "",
        "steps": [],
    }
    assert "PL007" in codes_for(data, root)


@pytest.mark.parametrize(
    ("reproduction", "message"),
    [
        (
            {"attempts": -1, "successes": 0, "environment": "Offline", "steps": ["x"]},
            "attempts cannot be negative",
        ),
        (
            {"attempts": 1, "successes": -1, "environment": "Offline", "steps": ["x"]},
            "successes cannot be negative",
        ),
        (
            {"attempts": 1, "successes": 0, "environment": "Offline", "steps": []},
            "requires steps",
        ),
        (
            {"attempts": 1, "successes": 0, "environment": "", "steps": ["x"]},
            "requires an environment",
        ),
    ],
)
def test_pl007_explains_counter_and_context_contradictions(
    reproduction: dict[str, Any],
    message: str,
    evidence_bundle: tuple[Path, str, str],
) -> None:
    root, path, digest = evidence_bundle
    data = valid_mapping(path, digest)
    data["status"] = "unverified"
    data["reproduction"] = reproduction
    diagnostic = next(
        item
        for item in validate_finding(finding_from(data), root).diagnostics
        if item.code == "PL007"
    )
    assert message in diagnostic.message


def test_pl007_rejects_not_tested_with_nonzero_counters(
    evidence_bundle: tuple[Path, str, str],
) -> None:
    root, path, digest = evidence_bundle
    data = valid_mapping(path, digest)
    data["status"] = "not_tested"
    data["evidence"][0]["state"] = "unverified"
    data["reproduction"] = {
        "attempts": 1,
        "successes": 0,
        "environment": "Offline",
        "steps": ["x"],
    }
    diagnostic = next(
        item
        for item in validate_finding(finding_from(data), root).diagnostics
        if item.code == "PL007"
    )
    assert "not_tested status conflicts" in diagnostic.message


def test_pl008_reports_every_evidence_shape_problem(
    evidence_bundle: tuple[Path, str, str],
) -> None:
    root, path, digest = evidence_bundle
    data = valid_mapping(path, digest)
    data["status"] = "unverified"
    data["evidence"] = [
        {"path": "", "sha256": digest, "state": "unverified"},
        {"path": path, "state": "unverified"},
        {"path": path, "sha256": digest, "state": "unverified"},
        {"path": "missing.txt", "sha256": digest, "state": "unverified"},
    ]
    messages = [
        item.message
        for item in validate_finding(finding_from(data), root).diagnostics
        if item.code == "PL008"
    ]
    assert any("path is required" in message for message in messages)
    assert any("valid SHA-256" in message for message in messages)
    assert any("duplicate evidence path" in message for message in messages)
    assert any("does not exist" in message for message in messages)


def test_validation_defaults_to_source_parent(
    evidence_bundle: tuple[Path, str, str],
) -> None:
    root, path, digest = evidence_bundle
    finding = Finding.from_mapping(
        valid_mapping(path, digest),
        source_path=root / "finding.md",
    )
    assert validate_finding(finding).passed


def test_pl010_reports_each_unredacted_sensitive_item(
    evidence_bundle: tuple[Path, str, str],
) -> None:
    import hashlib

    root, path, digest = evidence_bundle
    second_path = "evidence/second.txt"
    second = root / second_path
    second.write_text("second")
    second_digest = hashlib.sha256(second.read_bytes()).hexdigest()
    data = valid_mapping(path, digest)
    first_item = data["evidence"][0]
    first_item.update(sensitive=True, redacted=False)
    second_item = dict(first_item)
    second_item.update(path=second_path, sha256=second_digest)
    data["evidence"].append(second_item)
    diagnostics = [
        item
        for item in validate_finding(finding_from(data), root).diagnostics
        if item.code == "PL010"
    ]
    assert [item.field for item in diagnostics] == ["evidence[0]", "evidence[1]"]


def test_in_memory_validation_defaults_to_working_directory(
    evidence_bundle: tuple[Path, str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    root, path, digest = evidence_bundle
    monkeypatch.chdir(root)
    assert validate_finding(Finding.from_mapping(valid_mapping(path, digest))).passed


def test_diagnostics_are_deterministic_and_rule_sorted(tmp_path: Path) -> None:
    data: dict[str, Any] = {
        "schema_version": "0.1",
        "status": "unverified",
        "target": {},
        "scope": {},
        "evidence": [],
        "reproduction": {},
    }
    first = validate_finding(finding_from(data), tmp_path).diagnostics
    second = validate_finding(finding_from(data), tmp_path).diagnostics
    assert first == second
    assert [item.code for item in first] == sorted(item.code for item in first)


def test_line_number_points_to_relevant_top_level_field(
    evidence_bundle: tuple[Path, str, str],
) -> None:
    root, path, digest = evidence_bundle
    data = valid_mapping(path, digest)
    data["target"] = {"system": "fixture"}
    finding = finding_from(data)
    diagnostic = next(
        item for item in validate_finding(finding, root).diagnostics if item.code == "PL001"
    )
    assert finding.source_text.splitlines()[diagnostic.line - 1] == "target:"
