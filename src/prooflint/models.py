"""Typed domain models for findings and diagnostics."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any

from prooflint.errors import ParseError


class EvidenceState(StrEnum):
    VERIFIED = "verified"
    SUPPORTED_INFERENCE = "supported_inference"
    UNVERIFIED = "unverified"
    NOT_TESTED = "not_tested"


class FindingStatus(StrEnum):
    VERIFIED = "verified"
    SUPPORTED_INFERENCE = "supported_inference"
    UNVERIFIED = "unverified"
    NOT_TESTED = "not_tested"


_MISSING = object()
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _mapping(value: object, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise ParseError(f"{field_name} must be an object")
    return dict(value)


def _text(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise ParseError(f"{field_name} must be a string")
    return value.strip()


def _contract_text(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise ParseError(f"{field_name} must be a string")
    if value != value.strip():
        raise ParseError(f"{field_name} may not have surrounding whitespace")
    return value


def _optional_text(value: object, field_name: str) -> str | None:
    if value is _MISSING:
        return None
    text = _text(value, field_name)
    return text or None


def _optional_sha256(value: object, field_name: str) -> str | None:
    if value is _MISSING:
        return None
    digest = _contract_text(value, field_name)
    if not _SHA256_RE.fullmatch(digest):
        raise ParseError(f"{field_name} must be 64 lowercase hexadecimal characters")
    return digest


def _string_tuple(value: object, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ParseError(f"{field_name} must be an array of strings")
    return tuple(item.strip() for item in value if item.strip())


def _immutable_string_tuple(value: object, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not all(isinstance(item, str) for item in value):
        raise ParseError(f"{field_name} must be an array of strings")
    return tuple(item.strip() for item in value if item.strip())


def _optional_int(value: object, field_name: str) -> int | None:
    if value is _MISSING:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ParseError(f"{field_name} must be an integer")
    return value


def _direct_optional_int(value: object, field_name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ParseError(f"{field_name} must be an integer")
    return value


def _optional_bool(value: object, field_name: str) -> bool | None:
    if value is _MISSING:
        return None
    if not isinstance(value, bool):
        raise ParseError(f"{field_name} must be a boolean")
    return value


def _freeze_json_value(value: object, field_name: str) -> object:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ParseError(f"{field_name} must contain only finite JSON values")
        return value
    if isinstance(value, (list, tuple)):
        return tuple(
            _freeze_json_value(item, f"{field_name}[{index}]") for index, item in enumerate(value)
        )
    if isinstance(value, Mapping) and all(isinstance(key, str) for key in value):
        return MappingProxyType(
            {key: _freeze_json_value(item, f"{field_name}.{key}") for key, item in value.items()}
        )
    raise ParseError(f"{field_name} must contain only JSON-compatible values")


def _frozen_mapping(value: object, field_name: str) -> Mapping[str, object]:
    data = _mapping(value, field_name)
    frozen = _freeze_json_value(data, field_name)
    if not isinstance(frozen, Mapping):
        raise AssertionError("frozen mapping invariant failed")  # pragma: no cover
    return frozen


def _empty_mapping() -> Mapping[str, object]:
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    kind: str = ""
    path: str = ""
    sha256: str | None = None
    state: EvidenceState = EvidenceState.UNVERIFIED
    redacted: bool = False
    sensitive: bool = False
    description: str = ""
    observed_at: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _text(self.kind, "evidence.kind"))
        object.__setattr__(self, "path", _text(self.path, "evidence.path"))
        object.__setattr__(
            self,
            "sha256",
            _optional_sha256(
                self.sha256 if self.sha256 is not None else _MISSING, "evidence.sha256"
            ),
        )
        raw_state = _contract_text(self.state, "evidence.state")
        try:
            object.__setattr__(self, "state", EvidenceState(raw_state))
        except ValueError as exc:
            allowed = ", ".join(item.value for item in EvidenceState)
            raise ParseError(f"evidence.state must be one of: {allowed}") from exc
        if not isinstance(self.redacted, bool):
            raise ParseError("evidence.redacted must be a boolean")
        if not isinstance(self.sensitive, bool):
            raise ParseError("evidence.sensitive must be a boolean")
        object.__setattr__(self, "description", _text(self.description, "evidence.description"))
        if self.observed_at is not None:
            object.__setattr__(
                self, "observed_at", _contract_text(self.observed_at, "evidence.observed_at")
            )

    @classmethod
    def from_mapping(cls, value: object, index: int) -> EvidenceItem:
        data = _mapping(value, f"evidence[{index}]")
        raw_state = _contract_text(
            data.get("state", EvidenceState.UNVERIFIED), f"evidence[{index}].state"
        )
        try:
            state = EvidenceState(raw_state)
        except ValueError as exc:
            allowed = ", ".join(item.value for item in EvidenceState)
            raise ParseError(f"evidence[{index}].state must be one of: {allowed}") from exc
        return cls(
            kind=_text(data.get("kind", ""), f"evidence[{index}].kind"),
            path=_text(data.get("path", ""), f"evidence[{index}].path"),
            sha256=_optional_sha256(data.get("sha256", _MISSING), f"evidence[{index}].sha256"),
            state=state,
            redacted=_optional_bool(data.get("redacted", _MISSING), f"evidence[{index}].redacted")
            or False,
            sensitive=_optional_bool(
                data.get("sensitive", _MISSING), f"evidence[{index}].sensitive"
            )
            or False,
            description=_text(data.get("description", ""), f"evidence[{index}].description"),
            observed_at=_optional_text(
                data.get("observed_at", _MISSING), f"evidence[{index}].observed_at"
            ),
        )

    def to_mapping(self) -> dict[str, object]:
        result: dict[str, object] = {
            "kind": self.kind,
            "path": self.path,
            "state": self.state.value,
            "redacted": self.redacted,
            "sensitive": self.sensitive,
            "description": self.description,
        }
        if self.sha256 is not None:
            result["sha256"] = self.sha256
        if self.observed_at is not None:
            result["observed_at"] = self.observed_at
        return result


@dataclass(frozen=True, slots=True)
class Scope:
    authorized: bool | None = None
    description: str = ""
    boundaries: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.authorized is not None and not isinstance(self.authorized, bool):
            raise ParseError("scope.authorized must be a boolean")
        object.__setattr__(self, "description", _text(self.description, "scope.description"))
        object.__setattr__(
            self, "boundaries", _immutable_string_tuple(self.boundaries, "scope.boundaries")
        )

    @classmethod
    def from_mapping(cls, value: object) -> Scope:
        data = _mapping(value, "scope")
        return cls(
            authorized=_optional_bool(data.get("authorized", _MISSING), "scope.authorized"),
            description=_text(data.get("description", ""), "scope.description"),
            boundaries=_string_tuple(data.get("boundaries", []), "scope.boundaries"),
        )

    def to_mapping(self) -> dict[str, object]:
        result: dict[str, object] = {
            "description": self.description,
            "boundaries": list(self.boundaries),
        }
        if self.authorized is not None:
            result["authorized"] = self.authorized
        return result


@dataclass(frozen=True, slots=True)
class Reproduction:
    attempts: int | None = None
    successes: int | None = None
    environment: str = ""
    steps: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "attempts", _direct_optional_int(self.attempts, "reproduction.attempts")
        )
        object.__setattr__(
            self, "successes", _direct_optional_int(self.successes, "reproduction.successes")
        )
        object.__setattr__(self, "environment", _text(self.environment, "reproduction.environment"))
        object.__setattr__(self, "steps", _immutable_string_tuple(self.steps, "reproduction.steps"))

    @classmethod
    def from_mapping(cls, value: object) -> Reproduction:
        data = _mapping(value, "reproduction")
        return cls(
            attempts=_optional_int(data.get("attempts", _MISSING), "reproduction.attempts"),
            successes=_optional_int(data.get("successes", _MISSING), "reproduction.successes"),
            environment=_text(data.get("environment", ""), "reproduction.environment"),
            steps=_string_tuple(data.get("steps", []), "reproduction.steps"),
        )

    def to_mapping(self) -> dict[str, object]:
        result: dict[str, object] = {
            "environment": self.environment,
            "steps": list(self.steps),
        }
        if self.attempts is not None:
            result["attempts"] = self.attempts
        if self.successes is not None:
            result["successes"] = self.successes
        return result


@dataclass(frozen=True, slots=True)
class Finding:
    schema_version: str
    id: str = ""
    title: str = ""
    profile: str = "ai-system"
    status: FindingStatus = FindingStatus.UNVERIFIED
    target: Mapping[str, object] = field(default_factory=_empty_mapping)
    scope: Scope = field(default_factory=Scope)
    preconditions: tuple[str, ...] = ()
    affected_boundary: str = ""
    expected: str = ""
    observed: str = ""
    impact: str = ""
    confidence: str = ""
    evidence: tuple[EvidenceItem, ...] = ()
    reproduction: Reproduction = field(default_factory=Reproduction)
    remediation: str = ""
    retest: tuple[str, ...] = ()
    severity: str | None = None
    metadata: Mapping[str, object] = field(default_factory=_empty_mapping)
    body: str = ""
    source_path: Path | None = None
    source_text: str = ""

    def __post_init__(self) -> None:
        schema_version = _contract_text(self.schema_version, "schema_version")
        if schema_version != "0.1":
            shown = schema_version or "<missing>"
            raise ParseError(f"unsupported schema_version {shown!r}; expected '0.1'")
        raw_status = _contract_text(self.status, "status")
        try:
            status = FindingStatus(raw_status)
        except ValueError as exc:
            allowed = ", ".join(item.value for item in FindingStatus)
            raise ParseError(f"status must be one of: {allowed}") from exc
        object.__setattr__(self, "status", status)
        for name in (
            "id",
            "title",
            "profile",
            "affected_boundary",
            "expected",
            "observed",
            "impact",
            "confidence",
            "remediation",
        ):
            object.__setattr__(self, name, _text(getattr(self, name), name))
        object.__setattr__(self, "target", _frozen_mapping(self.target, "target"))
        object.__setattr__(self, "metadata", _frozen_mapping(self.metadata, "metadata"))
        if not isinstance(self.scope, Scope):
            raise ParseError("scope must be a Scope")
        if not isinstance(self.reproduction, Reproduction):
            raise ParseError("reproduction must be a Reproduction")
        evidence = tuple(self.evidence)
        if not all(isinstance(item, EvidenceItem) for item in evidence):
            raise ParseError("evidence must contain only EvidenceItem values")
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(
            self, "preconditions", _immutable_string_tuple(self.preconditions, "preconditions")
        )
        object.__setattr__(self, "retest", _immutable_string_tuple(self.retest, "retest"))
        if self.severity is not None:
            object.__setattr__(self, "severity", _text(self.severity, "severity") or None)
        if not isinstance(self.body, str):
            raise ParseError("body must be a string")
        if self.source_path is not None and not isinstance(self.source_path, Path):
            raise ParseError("source_path must be a Path")
        if not isinstance(self.source_text, str):
            raise ParseError("source_text must be a string")

    @classmethod
    def from_mapping(
        cls,
        value: object,
        *,
        body: str = "",
        source_path: Path | None = None,
        source_text: str = "",
    ) -> Finding:
        data = _mapping(value, "finding")
        schema_version = _contract_text(data.get("schema_version", ""), "schema_version")
        if schema_version != "0.1":
            shown = schema_version or "<missing>"
            raise ParseError(f"unsupported schema_version {shown!r}; expected '0.1'")
        evidence_raw = data.get("evidence", [])
        if isinstance(evidence_raw, list):
            evidence = tuple(
                EvidenceItem.from_mapping(item, index) for index, item in enumerate(evidence_raw)
            )
        else:
            raise ParseError("evidence must be an array")
        raw_status = _contract_text(data.get("status", FindingStatus.UNVERIFIED), "status")
        try:
            status = FindingStatus(raw_status)
        except ValueError as exc:
            allowed = ", ".join(item.value for item in FindingStatus)
            raise ParseError(f"status must be one of: {allowed}") from exc
        mapped_body = _text(data.get("body", ""), "body")
        return cls(
            schema_version=schema_version,
            id=_text(data.get("id", ""), "id"),
            title=_text(data.get("title", ""), "title"),
            profile=_text(data.get("profile", "ai-system"), "profile"),
            status=status,
            target=_frozen_mapping(data.get("target", {}), "target"),
            scope=Scope.from_mapping(data.get("scope", {})),
            preconditions=_string_tuple(data.get("preconditions", []), "preconditions"),
            affected_boundary=_text(data.get("affected_boundary", ""), "affected_boundary"),
            expected=_text(data.get("expected", ""), "expected"),
            observed=_text(data.get("observed", ""), "observed"),
            impact=_text(data.get("impact", ""), "impact"),
            confidence=_text(data.get("confidence", ""), "confidence"),
            evidence=evidence,
            reproduction=Reproduction.from_mapping(data.get("reproduction", {})),
            remediation=_text(data.get("remediation", ""), "remediation"),
            retest=_string_tuple(data.get("retest", []), "retest"),
            severity=_optional_text(data.get("severity", _MISSING), "severity"),
            metadata=_frozen_mapping(data.get("metadata", {}), "metadata"),
            body=body or mapped_body,
            source_path=source_path,
            source_text=source_text,
        )

    def line_for(self, field_name: str) -> int:
        needle_yaml = f"{field_name}:"
        needle_json = f'"{field_name}"'
        for number, line in enumerate(self.source_text.splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith(needle_yaml) or stripped.startswith(needle_json):
                return number
        return 1


@dataclass(frozen=True, slots=True, order=True)
class Diagnostic:
    code: str
    message: str
    field: str
    path: str
    line: int = 1
    level: str = "error"

    def __post_init__(self) -> None:
        for name in ("code", "message", "field", "path", "level"):
            if not isinstance(getattr(self, name), str):
                raise ParseError(f"diagnostic.{name} must be a string")
        if isinstance(self.line, bool) or not isinstance(self.line, int):
            raise ParseError("diagnostic.line must be an integer")

    def to_mapping(self) -> dict[str, object]:
        return {
            "code": self.code,
            "level": self.level,
            "message": self.message,
            "field": self.field,
            "path": self.path,
            "line": self.line,
        }


@dataclass(frozen=True, slots=True)
class ValidationResult:
    finding: Finding
    diagnostics: tuple[Diagnostic, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.finding, Finding):
            raise ParseError("finding must be a Finding")
        diagnostics = tuple(self.diagnostics)
        if not all(isinstance(item, Diagnostic) for item in diagnostics):
            raise ParseError("diagnostics must contain only Diagnostic values")
        object.__setattr__(self, "diagnostics", diagnostics)

    @property
    def passed(self) -> bool:
        return not self.diagnostics


@dataclass(frozen=True, slots=True)
class ManifestVerification:
    ok: bool
    files_checked: int
    errors: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.ok, bool):
            raise ParseError("ok must be a boolean")
        if isinstance(self.files_checked, bool) or not isinstance(self.files_checked, int):
            raise ParseError("files_checked must be an integer")
        object.__setattr__(self, "errors", _immutable_string_tuple(self.errors, "errors"))

    def to_mapping(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "files_checked": self.files_checked,
            "errors": list(self.errors),
        }
