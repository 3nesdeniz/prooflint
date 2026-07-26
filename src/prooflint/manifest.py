"""Deterministic evidence manifest generation and verification."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from prooflint.errors import ManifestError, PathSafetyError
from prooflint.models import EvidenceState, Finding, ManifestVerification
from prooflint.paths import hash_confined_file, normalize_relative_path

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def build_manifest(finding: Finding, evidence_root: str | Path) -> dict[str, object]:
    """Build a stable manifest without timestamps or absolute paths."""

    files: list[dict[str, object]] = []
    seen: set[str] = set()
    for evidence in sorted(finding.evidence, key=lambda item: item.path):
        if not evidence.path:
            raise ManifestError("cannot manifest evidence with an empty path")
        try:
            canonical = normalize_relative_path(evidence.path)
        except (PathSafetyError, FileNotFoundError) as exc:
            raise ManifestError(str(exc)) from exc
        if canonical in seen:
            raise ManifestError(f"duplicate evidence path: {canonical}")
        seen.add(canonical)
        try:
            digest, size, _ = hash_confined_file(evidence_root, canonical)
        except (PathSafetyError, FileNotFoundError) as exc:
            raise ManifestError(str(exc)) from exc
        if evidence.sha256 is not None:
            declared = evidence.sha256
            if not SHA256_RE.fullmatch(declared):
                raise ManifestError(f"invalid declared SHA-256 for {canonical}")
            if declared != digest:
                raise ManifestError(f"declared SHA-256 does not match {canonical}")
        files.append(
            {
                "path": canonical,
                "sha256": digest,
                "size": size,
                "kind": evidence.kind,
                "state": evidence.state.value,
                "redacted": evidence.redacted,
                "sensitive": evidence.sensitive,
            }
        )
    return {
        "manifest_version": "0.1",
        "finding": {"id": finding.id, "schema_version": finding.schema_version},
        "files": files,
    }


def _manifest_files(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, dict):
        raise ManifestError("manifest must be a JSON object")
    expected_top_level = {"manifest_version", "finding", "files"}
    if set(value) != expected_top_level:
        raise ManifestError("manifest must contain exactly: manifest_version, finding, files")
    if value.get("manifest_version") != "0.1":
        raise ManifestError("unsupported manifest_version; expected '0.1'")
    finding = value.get("finding")
    if not isinstance(finding, dict) or set(finding) != {"id", "schema_version"}:
        raise ManifestError("manifest finding must contain exactly: id, schema_version")
    if not isinstance(finding.get("id"), str):
        raise ManifestError("manifest finding.id must be a string")
    if finding.get("schema_version") != "0.1":
        raise ManifestError("manifest finding.schema_version must be '0.1'")
    files = value.get("files")
    if not isinstance(files, list):
        raise ManifestError("manifest files must be an array")
    checked: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(files):
        if not isinstance(item, dict):
            raise ManifestError(f"manifest files[{index}] must be an object")
        expected_file_fields = {
            "path",
            "sha256",
            "size",
            "kind",
            "state",
            "redacted",
            "sensitive",
        }
        if set(item) != expected_file_fields:
            raise ManifestError(
                f"manifest files[{index}] must contain exactly: "
                "path, sha256, size, kind, state, redacted, sensitive"
            )
        path = item.get("path")
        digest = item.get("sha256")
        size = item.get("size")
        if not isinstance(path, str):
            raise ManifestError(f"manifest files[{index}].path must be a string")
        try:
            canonical = normalize_relative_path(path)
        except PathSafetyError as exc:
            raise ManifestError(str(exc)) from exc
        if canonical in seen:
            raise ManifestError(f"duplicate manifest path: {canonical}")
        seen.add(canonical)
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ManifestError(f"manifest files[{index}].sha256 is invalid")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ManifestError(f"manifest files[{index}].size must be a non-negative integer")
        if not isinstance(item.get("kind"), str):
            raise ManifestError(f"manifest files[{index}].kind must be a string")
        if item.get("state") not in {state.value for state in EvidenceState}:
            raise ManifestError(f"manifest files[{index}].state is invalid")
        if not isinstance(item.get("redacted"), bool):
            raise ManifestError(f"manifest files[{index}].redacted must be a boolean")
        if not isinstance(item.get("sensitive"), bool):
            raise ManifestError(f"manifest files[{index}].sensitive must be a boolean")
        checked.append(item)
    return checked


def verify_manifest(value: object, evidence_root: str | Path) -> ManifestVerification:
    """Verify every manifest entry without following symlinks."""

    files = _manifest_files(value)
    errors: list[str] = []
    checked = 0
    for item in files:
        path = str(item["path"])
        try:
            actual_digest, actual_size, _ = hash_confined_file(evidence_root, path)
        except (PathSafetyError, FileNotFoundError) as exc:
            errors.append(str(exc))
            continue
        checked += 1
        if actual_size != item["size"]:
            errors.append(
                f"size mismatch for {path}: expected {item['size']}, observed {actual_size}"
            )
        if actual_digest != item["sha256"]:
            errors.append(f"SHA-256 mismatch for {path}")
    return ManifestVerification(ok=not errors, files_checked=checked, errors=tuple(errors))
