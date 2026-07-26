"""Stable text, JSON, and SARIF reporters."""

from __future__ import annotations

import json
from collections.abc import Iterable

from prooflint.models import Diagnostic, ManifestVerification, ValidationResult
from prooflint.rules import RULE_TITLES


def _diagnostics(results: Iterable[ValidationResult]) -> list[Diagnostic]:
    return sorted(diagnostic for result in results for diagnostic in result.diagnostics)


def render_text(results: Iterable[ValidationResult]) -> str:
    result_list = list(results)
    diagnostics = _diagnostics(result_list)
    lines = [
        f"{item.path}:{item.line}: {item.level} {item.code} {item.message} [{item.field}]"
        for item in diagnostics
    ]
    passed = sum(result.passed for result in result_list)
    lines.append(
        f"Prooflint: {len(result_list)} finding(s), {len(diagnostics)} violation(s), {passed} passed"
    )
    return "\n".join(lines) + "\n"


def render_json(results: Iterable[ValidationResult]) -> str:
    result_list = list(results)
    diagnostics = _diagnostics(result_list)
    payload = {
        "schema_version": "0.1",
        "passed": not diagnostics,
        "summary": {
            "findings": len(result_list),
            "violations": len(diagnostics),
            "passed": sum(result.passed for result in result_list),
        },
        "diagnostics": [item.to_mapping() for item in diagnostics],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_sarif(results: Iterable[ValidationResult]) -> str:
    diagnostics = _diagnostics(results)
    used_codes = sorted({item.code for item in diagnostics})
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Prooflint",
                        "informationUri": "https://github.com/3nesdeniz/prooflint",
                        "semanticVersion": "0.1.0",
                        "rules": [
                            {
                                "id": code,
                                "name": RULE_TITLES[code],
                                "shortDescription": {"text": RULE_TITLES[code]},
                            }
                            for code in used_codes
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": item.code,
                        "level": item.level,
                        "message": {"text": item.message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": item.path},
                                    "region": {"startLine": item.line},
                                }
                            }
                        ],
                        "properties": {"field": item.field},
                    }
                    for item in diagnostics
                ],
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_verification_text(result: ManifestVerification) -> str:
    status = "PASS" if result.ok else "FAIL"
    lines = [f"Prooflint manifest verification: {status} ({result.files_checked} file(s) checked)"]
    lines.extend(f"error: {message}" for message in result.errors)
    return "\n".join(lines) + "\n"


def render_verification_json(result: ManifestVerification) -> str:
    return json.dumps(result.to_mapping(), indent=2, sort_keys=True) + "\n"
