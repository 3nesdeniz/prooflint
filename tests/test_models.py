from __future__ import annotations

from collections.abc import Mapping

import pytest

from prooflint.errors import ParseError
from prooflint.models import (
    Diagnostic,
    EvidenceItem,
    EvidenceState,
    Finding,
    FindingStatus,
    ManifestVerification,
    Reproduction,
    Scope,
    ValidationResult,
)


def test_nested_models_round_trip_to_mappings() -> None:
    evidence = EvidenceItem.from_mapping(
        {
            "kind": "trace",
            "path": "evidence/trace.txt",
            "sha256": "a" * 64,
            "state": "supported_inference",
            "redacted": True,
            "sensitive": True,
            "description": "Redacted trace",
            "observed_at": "2026-07-26T00:00:00Z",
        },
        0,
    )
    assert evidence.state is EvidenceState.SUPPORTED_INFERENCE
    assert evidence.to_mapping() == {
        "kind": "trace",
        "path": "evidence/trace.txt",
        "sha256": "a" * 64,
        "state": "supported_inference",
        "redacted": True,
        "sensitive": True,
        "description": "Redacted trace",
        "observed_at": "2026-07-26T00:00:00Z",
    }

    scope = Scope.from_mapping(
        {"authorized": True, "description": " Scope ", "boundaries": [" gate ", ""]}
    )
    assert scope.to_mapping() == {
        "authorized": True,
        "description": "Scope",
        "boundaries": ["gate"],
    }

    reproduction = Reproduction.from_mapping(
        {"attempts": 2, "successes": 1, "environment": " Offline ", "steps": [" Compare "]}
    )
    assert reproduction.to_mapping() == {
        "attempts": 2,
        "successes": 1,
        "environment": "Offline",
        "steps": ["Compare"],
    }


def test_nested_mapping_omits_absent_optional_values() -> None:
    assert EvidenceItem().to_mapping() == {
        "kind": "",
        "path": "",
        "state": "unverified",
        "redacted": False,
        "sensitive": False,
        "description": "",
    }
    assert Scope().to_mapping() == {"description": "", "boundaries": []}
    assert Reproduction().to_mapping() == {"environment": "", "steps": []}


def test_finding_defaults_are_typed() -> None:
    finding = Finding.from_mapping({"schema_version": "0.1"})
    assert finding.status is FindingStatus.UNVERIFIED
    assert finding.scope == Scope()
    assert finding.reproduction == Reproduction()


def test_invalid_evidence_state_is_a_parse_error() -> None:
    with pytest.raises(ParseError, match=r"evidence\[0\].state must be one of"):
        EvidenceItem.from_mapping({"state": "certain"}, 0)


def test_non_string_scalar_is_a_parse_error() -> None:
    with pytest.raises(ParseError, match="title must be a string"):
        Finding.from_mapping({"schema_version": "0.1", "title": 7})


def test_finding_mappings_are_deeply_immutable_and_copied() -> None:
    target = {"system": "fixture", "nested": {"revisions": ["v1", "v2"]}}
    finding = Finding.from_mapping(
        {
            "schema_version": "0.1",
            "target": target,
            "metadata": {"labels": ["synthetic"]},
        }
    )
    target["system"] = "mutated"
    assert finding.target["system"] == "fixture"
    nested = finding.target["nested"]
    assert isinstance(nested, Mapping)
    with pytest.raises(TypeError):
        finding.target["system"] = "mutated"  # type: ignore[index]
    with pytest.raises(TypeError):
        nested["revisions"] = ()  # type: ignore[index]
    assert finding.metadata["labels"] == ("synthetic",)


@pytest.mark.parametrize("value", [float("nan"), float("inf")])
def test_finding_mappings_reject_non_finite_numbers(value: float) -> None:
    with pytest.raises(ParseError, match="finite JSON values"):
        Finding.from_mapping({"schema_version": "0.1", "metadata": {"score": value}})


def test_finding_mappings_reject_non_json_values() -> None:
    with pytest.raises(ParseError, match="JSON-compatible"):
        Finding.from_mapping({"schema_version": "0.1", "metadata": {"labels": {"a"}}})


def test_direct_exported_model_constructors_deep_freeze_mutable_inputs() -> None:
    nested = ["v1"]
    target = {"system": "fixture", "nested": nested}
    boundaries = ["gateway"]
    preconditions = ["authorized fixture"]
    evidence_items = [EvidenceItem(path="evidence/trace.txt")]
    steps = ["send fixture"]
    finding = Finding(
        schema_version="0.1",
        target=target,
        scope=Scope(boundaries=boundaries),  # type: ignore[arg-type]
        preconditions=preconditions,  # type: ignore[arg-type]
        evidence=evidence_items,  # type: ignore[arg-type]
        reproduction=Reproduction(steps=steps),  # type: ignore[arg-type]
    )

    nested.append("v2")
    target["system"] = "mutated"
    boundaries.append("database")
    preconditions.append("mutated")
    evidence_items.clear()
    steps.append("mutated")

    assert finding.target == {"system": "fixture", "nested": ("v1",)}
    assert finding.scope.boundaries == ("gateway",)
    assert finding.preconditions == ("authorized fixture",)
    assert len(finding.evidence) == 1
    assert finding.reproduction.steps == ("send fixture",)
    with pytest.raises(TypeError):
        finding.target["system"] = "mutated"  # type: ignore[index]

    diagnostics = [Diagnostic("PL001", "message", "field", "path")]
    result = ValidationResult(finding, diagnostics)  # type: ignore[arg-type]
    diagnostics.clear()
    assert len(result.diagnostics) == 1

    errors = ["first"]
    verification = ManifestVerification(False, 0, errors)  # type: ignore[arg-type]
    errors.append("second")
    assert verification.errors == ("first",)


@pytest.mark.parametrize(
    ("factory", "message"),
    [
        (lambda: Finding(schema_version=" 0.1"), "schema_version"),
        (lambda: Finding(schema_version="0.1", status="verified "), "status"),
        (lambda: EvidenceItem(state=" verified"), "evidence.state"),
        (lambda: EvidenceItem(sha256=" " + "a" * 64), "evidence.sha256"),
        (lambda: EvidenceItem(sha256="A" * 64), "64 lowercase"),
    ],
)
def test_direct_contract_values_are_not_normalized(factory: object, message: str) -> None:
    with pytest.raises(ParseError, match=message):
        factory()  # type: ignore[operator]


@pytest.mark.parametrize(
    "factory",
    [
        lambda: Scope(boundaries=[1]),
        lambda: Reproduction(attempts=True),
        lambda: EvidenceItem(state="certain"),
        lambda: EvidenceItem(redacted="yes"),
        lambda: EvidenceItem(sensitive="yes"),
        lambda: Scope(authorized="yes"),
        lambda: Finding(schema_version="1.0"),
        lambda: Finding(schema_version="0.1", status="certain"),
        lambda: Finding(schema_version="0.1", scope={}),
        lambda: Finding(schema_version="0.1", reproduction={}),
        lambda: Finding(schema_version="0.1", evidence=[object()]),
        lambda: Finding(schema_version="0.1", severity=7),
        lambda: Finding(schema_version="0.1", body=None),
        lambda: Finding(schema_version="0.1", source_path="finding.json"),
        lambda: Finding(schema_version="0.1", source_text=None),
        lambda: Diagnostic([], "message", "field", "path"),
        lambda: Diagnostic("PL001", "message", "field", "path", line=True),
        lambda: ValidationResult(object(), ()),
        lambda: ValidationResult(Finding(schema_version="0.1"), [object()]),
        lambda: ManifestVerification("yes", 0),
        lambda: ManifestVerification(True, False),
    ],
)
def test_direct_exported_model_constructors_reject_invalid_runtime_types(factory: object) -> None:
    with pytest.raises(ParseError):
        factory()  # type: ignore[operator]
