"""Version 0.1 deterministic finding rules."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from prooflint.errors import PathSafetyError
from prooflint.manifest import SHA256_RE
from prooflint.models import Diagnostic, EvidenceState, Finding, FindingStatus, ValidationResult
from prooflint.paths import hash_confined_file

Rule = Callable[[Finding, Path], list[tuple[str, str, str]]]

RULE_TITLES: dict[str, str] = {
    "PL001": "Target fingerprint required",
    "PL002": "Authorization and scope required",
    "PL003": "Preconditions and affected boundary required",
    "PL004": "Verified status requires reproducible evidence",
    "PL005": "Expected and observed behavior must differ",
    "PL006": "Impact must be evidence-linked",
    "PL007": "Reproduction counters must be consistent",
    "PL008": "Evidence paths and hashes must verify",
    "PL009": "Remediation and deterministic retest required",
    "PL010": "Sensitive evidence must be redacted",
}

IDENTITY_KEYS = {"repository", "model", "agent", "system", "endpoint", "asset"}
FINGERPRINT_KEYS = {"commit", "version", "revision", "digest", "model_revision"}


def _present(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _pl001(finding: Finding, _: Path) -> list[tuple[str, str, str]]:
    identity = any(_present(finding.target.get(key)) for key in IDENTITY_KEYS)
    fingerprint = any(_present(finding.target.get(key)) for key in FINGERPRINT_KEYS)
    if identity and fingerprint:
        return []
    return [("PL001", "target", "record both a target identifier and immutable fingerprint")]


def _pl002(finding: Finding, _: Path) -> list[tuple[str, str, str]]:
    if finding.scope.authorized is True and finding.scope.description:
        return []
    return [("PL002", "scope", "record explicit authorization and the tested scope")]


def _pl003(finding: Finding, _: Path) -> list[tuple[str, str, str]]:
    if finding.preconditions and finding.affected_boundary:
        return []
    return [("PL003", "preconditions", "record preconditions and the affected trust boundary")]


def _pl004(finding: Finding, _: Path) -> list[tuple[str, str, str]]:
    if finding.status is not FindingStatus.VERIFIED:
        return []
    reproduction = finding.reproduction
    has_verified_evidence = any(
        item.state is EvidenceState.VERIFIED and bool(item.path) for item in finding.evidence
    )
    if (
        reproduction.attempts is not None
        and reproduction.attempts > 0
        and reproduction.successes is not None
        and reproduction.successes > 0
        and has_verified_evidence
    ):
        return []
    return [
        (
            "PL004",
            "status",
            "verified status requires successful attempts and at least one verified evidence file",
        )
    ]


def _normalize_behavior(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().casefold()


def _pl005(finding: Finding, _: Path) -> list[tuple[str, str, str]]:
    if (
        finding.expected
        and finding.observed
        and _normalize_behavior(finding.expected) != _normalize_behavior(finding.observed)
    ):
        return []
    return [("PL005", "observed", "record distinct expected and observed behavior")]


def _pl006(finding: Finding, _: Path) -> list[tuple[str, str, str]]:
    if finding.impact and any(item.path for item in finding.evidence):
        return []
    return [("PL006", "impact", "state the impact and link it to an evidence file")]


def _pl007(finding: Finding, _: Path) -> list[tuple[str, str, str]]:
    reproduction = finding.reproduction
    attempts = reproduction.attempts
    successes = reproduction.successes
    problems: list[str] = []
    if attempts is not None and attempts < 0:
        problems.append("attempts cannot be negative")
    if successes is not None and successes < 0:
        problems.append("successes cannot be negative")
    if (attempts is None) != (successes is None):
        problems.append("attempts and successes must be recorded together")
    if attempts is not None and successes is not None and successes > attempts:
        problems.append("successes cannot exceed attempts")
    if attempts is not None and attempts > 0 and not reproduction.steps:
        problems.append("attempted reproduction requires steps")
    if attempts is not None and attempts > 0 and not reproduction.environment:
        problems.append("attempted reproduction requires an environment")
    if finding.status is FindingStatus.NOT_TESTED and any(
        count not in {None, 0} for count in (attempts, successes)
    ):
        problems.append("not_tested status conflicts with non-zero reproduction counters")
    if finding.status is FindingStatus.NOT_TESTED and any(
        item.state is EvidenceState.VERIFIED for item in finding.evidence
    ):
        problems.append("not_tested status conflicts with verified evidence")
    if not problems:
        return []
    return [("PL007", "reproduction", "; ".join(problems))]


def _pl008(finding: Finding, evidence_root: Path) -> list[tuple[str, str, str]]:
    problems: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for index, item in enumerate(finding.evidence):
        field = f"evidence[{index}]"
        if not item.path:
            problems.append(("PL008", field, "evidence path is required"))
            continue
        if item.path in seen:
            problems.append(("PL008", field, f"duplicate evidence path: {item.path}"))
            continue
        seen.add(item.path)
        if item.sha256 is None or not SHA256_RE.fullmatch(item.sha256):
            problems.append(("PL008", field, f"valid SHA-256 is required for {item.path}"))
            continue
        try:
            actual_digest, _, _ = hash_confined_file(evidence_root, item.path)
        except (PathSafetyError, FileNotFoundError) as exc:
            problems.append(("PL008", field, str(exc)))
            continue
        if actual_digest != item.sha256:
            problems.append(("PL008", field, f"SHA-256 mismatch for {item.path}"))
    return problems


def _pl009(finding: Finding, _: Path) -> list[tuple[str, str, str]]:
    if finding.remediation and finding.retest:
        return []
    return [("PL009", "retest", "record remediation and deterministic retest steps")]


def _pl010(finding: Finding, _: Path) -> list[tuple[str, str, str]]:
    problems: list[tuple[str, str, str]] = []
    for index, item in enumerate(finding.evidence):
        if item.sensitive and not item.redacted:
            problems.append(
                (
                    "PL010",
                    f"evidence[{index}]",
                    "sensitive evidence must be redacted before it is referenced",
                )
            )
    return problems


RULES: tuple[Rule, ...] = (
    _pl001,
    _pl002,
    _pl003,
    _pl004,
    _pl005,
    _pl006,
    _pl007,
    _pl008,
    _pl009,
    _pl010,
)


def validate_finding(
    finding: Finding,
    evidence_root: str | Path | None = None,
) -> ValidationResult:
    """Run all version 0.1 rules in stable rule order."""

    if evidence_root is None:
        root = finding.source_path.parent if finding.source_path is not None else Path.cwd()
    else:
        root = Path(evidence_root)
    display_path = str(finding.source_path) if finding.source_path is not None else "<memory>"
    diagnostics: list[Diagnostic] = []
    for rule in RULES:
        for code, field, message in rule(finding, root):
            source_field = field.split("[", maxsplit=1)[0]
            diagnostics.append(
                Diagnostic(
                    code=code,
                    message=message,
                    field=field,
                    path=display_path,
                    line=finding.line_for(source_field),
                )
            )
    return ValidationResult(finding=finding, diagnostics=tuple(sorted(diagnostics)))
