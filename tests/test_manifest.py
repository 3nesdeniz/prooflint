from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from prooflint.errors import ManifestError, ParseError, PathSafetyError
from prooflint.manifest import build_manifest, verify_manifest
from prooflint.models import Finding
from prooflint.paths import (
    hash_confined_file,
    normalize_relative_path,
    read_bounded_regular_file,
    resolve_regular_file,
)
from tests.helpers import valid_mapping


def finding_for(path: str, digest: str | None) -> Finding:
    data = valid_mapping(path, digest or "0" * 64)
    if digest is None:
        data["evidence"][0].pop("sha256")
    return Finding.from_mapping(data)


def test_manifest_is_deterministic_and_contains_no_absolute_paths(
    evidence_bundle: tuple[Path, str, str],
) -> None:
    root, path, digest = evidence_bundle
    finding = finding_for(path, digest)
    first = build_manifest(finding, root)
    second = build_manifest(finding, root)
    assert first == second
    assert first["manifest_version"] == "0.1"
    files = first["files"]
    assert isinstance(files, list)
    assert files[0]["path"] == path
    assert files[0]["sha256"] == digest
    assert str(root) not in repr(first)
    assert verify_manifest(first, root).ok


def test_manifest_is_a_fresh_serializable_mapping_owned_by_the_caller(
    evidence_bundle: tuple[Path, str, str],
) -> None:
    root, path, digest = evidence_bundle
    finding = finding_for(path, digest)
    first = build_manifest(finding, root)
    first["manifest_version"] = "caller-mutated"
    first["files"].clear()

    second = build_manifest(finding, root)
    assert second["manifest_version"] == "0.1"
    assert len(second["files"]) == 1


def test_manifest_computes_missing_declared_hash(evidence_bundle: tuple[Path, str, str]) -> None:
    root, path, digest = evidence_bundle
    manifest = build_manifest(finding_for(path, None), root)
    assert manifest["files"][0]["sha256"] == digest


def test_verify_detects_tamper(evidence_bundle: tuple[Path, str, str]) -> None:
    root, path, digest = evidence_bundle
    manifest = build_manifest(finding_for(path, digest), root)
    (root / path).write_text("tampered and resized")
    result = verify_manifest(manifest, root)
    assert not result.ok
    assert result.files_checked == 1
    assert any("size mismatch" in error for error in result.errors)
    assert any("SHA-256 mismatch" in error for error in result.errors)


def test_verify_reports_missing_file(evidence_bundle: tuple[Path, str, str]) -> None:
    root, path, digest = evidence_bundle
    manifest = build_manifest(finding_for(path, digest), root)
    (root / path).unlink()
    result = verify_manifest(manifest, root)
    assert not result.ok
    assert result.files_checked == 0
    assert result.errors == (f"evidence file does not exist: {path}",)


@pytest.mark.parametrize(
    "unsafe",
    [
        "../secret.txt",
        "/tmp/secret.txt",
        "evidence\\trace.txt",
        "C:/secret.txt",
        "a//b",
        "./trace.txt",
        "",
    ],
)
def test_rejects_unsafe_paths(unsafe: str, tmp_path: Path) -> None:
    with pytest.raises(PathSafetyError):
        normalize_relative_path(unsafe)
    with pytest.raises(ManifestError):
        build_manifest(finding_for(unsafe, "0" * 64), tmp_path)


def test_rejects_duplicate_evidence_paths(evidence_bundle: tuple[Path, str, str]) -> None:
    root, path, digest = evidence_bundle
    data = valid_mapping(path, digest)
    data["evidence"].append(copy.deepcopy(data["evidence"][0]))
    with pytest.raises(ManifestError, match="duplicate evidence path"):
        build_manifest(Finding.from_mapping(data), root)


def test_rejects_declared_hash_mismatch(evidence_bundle: tuple[Path, str, str]) -> None:
    root, path, _ = evidence_bundle
    with pytest.raises(ManifestError, match="does not match"):
        build_manifest(finding_for(path, "0" * 64), root)


def test_rejects_invalid_declared_hash(evidence_bundle: tuple[Path, str, str]) -> None:
    _, path, digest = evidence_bundle
    data = valid_mapping(path, digest)
    data["evidence"][0]["sha256"] = "short"
    with pytest.raises(ParseError, match="64 lowercase"):
        Finding.from_mapping(data)


def test_rejects_symlinked_file_and_directory(evidence_bundle: tuple[Path, str, str]) -> None:
    root, _, digest = evidence_bundle
    outside = root.parent / "outside.txt"
    outside.write_text("outside")
    file_link = root / "evidence" / "linked.txt"
    file_link.symlink_to(outside)
    with pytest.raises(ManifestError, match="symlinks are not allowed"):
        build_manifest(finding_for("evidence/linked.txt", digest), root)

    real_dir = root / "real"
    real_dir.mkdir()
    (real_dir / "trace.txt").write_text("trace")
    dir_link = root / "linked-dir"
    dir_link.symlink_to(real_dir, target_is_directory=True)
    with pytest.raises(ManifestError, match="symlinks are not allowed"):
        build_manifest(finding_for("linked-dir/trace.txt", digest), root)


def test_rejects_symlinked_root(evidence_bundle: tuple[Path, str, str]) -> None:
    root, path, _ = evidence_bundle
    root_link = root.parent / "bundle-link"
    root_link.symlink_to(root, target_is_directory=True)
    with pytest.raises(PathSafetyError, match="root may not be a symlink"):
        resolve_regular_file(root_link, path)


def test_hashing_uses_the_descriptor_held_before_a_symlink_swap(
    evidence_bundle: tuple[Path, str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    root, relative, original_digest = evidence_bundle
    artifact = root / relative
    held_name = artifact.with_name("held-original.txt")
    outside = root.parent / "outside-race.txt"
    outside.write_text("outside replacement")
    original_read = os.read
    swapped = False

    def swap_then_read(descriptor: int, amount: int) -> bytes:
        nonlocal swapped
        if not swapped:
            swapped = True
            artifact.rename(held_name)
            artifact.symlink_to(outside)
        return original_read(descriptor, amount)

    monkeypatch.setattr("prooflint.paths.os.read", swap_then_read)
    observed_digest, observed_size, _ = hash_confined_file(root, relative)
    assert swapped
    assert observed_digest == original_digest
    assert observed_size == held_name.stat().st_size
    assert observed_digest != hashlib.sha256(outside.read_bytes()).hexdigest()


def test_descriptor_hashing_rejects_missing_and_non_directory_components(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="does not exist"):
        hash_confined_file(tmp_path, "missing/trace.txt")
    (tmp_path / "component").write_text("not a directory")
    with pytest.raises(PathSafetyError, match="non-directory component"):
        hash_confined_file(tmp_path, "component/trace.txt")
    (tmp_path / "directory").mkdir()
    with pytest.raises(PathSafetyError, match="not a regular file"):
        hash_confined_file(tmp_path, "directory")


def test_bounded_reader_detects_growth_after_initial_stat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "growing.txt"
    path.write_bytes(b"123456")
    real_fstat = os.fstat

    def report_small_size(descriptor: int) -> SimpleNamespace:
        metadata = real_fstat(descriptor)
        return SimpleNamespace(
            st_mode=metadata.st_mode,
            st_size=0,
            st_dev=metadata.st_dev,
            st_ino=metadata.st_ino,
        )

    monkeypatch.setattr("prooflint.paths.os.fstat", report_small_size)
    with pytest.raises(PathSafetyError, match="exceeds 4 bytes"):
        read_bounded_regular_file(path, 4)


def test_descriptor_read_errors_are_wrapped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "trace.txt"
    path.write_text("trace")

    def fail_read(_: int, __: int) -> bytes:
        raise OSError("synthetic read failure")

    monkeypatch.setattr("prooflint.paths.os.read", fail_read)
    with pytest.raises(PathSafetyError, match="cannot read regular file"):
        read_bounded_regular_file(path, 100)
    with pytest.raises(PathSafetyError, match="cannot read evidence path"):
        hash_confined_file(tmp_path, "trace.txt")


def test_root_change_during_descriptor_open_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "trace.txt"
    path.write_text("trace")
    real_fstat = os.fstat

    def changed_root(descriptor: int) -> SimpleNamespace:
        metadata = real_fstat(descriptor)
        return SimpleNamespace(
            st_dev=metadata.st_dev,
            st_ino=metadata.st_ino + 1,
            st_mode=metadata.st_mode,
        )

    monkeypatch.setattr("prooflint.paths.os.fstat", changed_root)
    with pytest.raises(PathSafetyError, match="root changed"):
        hash_confined_file(tmp_path, "trace.txt")


def test_evidence_root_swap_between_stat_and_open_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "bundle"
    root.mkdir()
    (root / "trace.txt").write_text("trusted")
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    (replacement / "trace.txt").write_text("attacker")
    held = tmp_path / "held"
    real_open = os.open
    swapped = False

    def swap_root_then_open(
        path: str | bytes,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if path == root.name and dir_fd is not None and not swapped:
            swapped = True
            root.rename(held)
            replacement.rename(root)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr("prooflint.paths.os.open", swap_root_then_open)
    with pytest.raises(PathSafetyError, match="root changed"):
        hash_confined_file(root, "trace.txt")
    assert swapped


def test_finding_leaf_swap_between_stat_and_open_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding = tmp_path / "finding.json"
    finding.write_text('{"schema_version":"0.1"}')
    replacement = tmp_path / "replacement.json"
    replacement.write_text('{"schema_version":"0.1","id":"attacker"}')
    held = tmp_path / "held.json"
    real_open = os.open
    swapped = False

    def swap_leaf_then_open(
        path: str | bytes,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if path == finding.name and dir_fd is not None and not swapped:
            swapped = True
            finding.rename(held)
            replacement.rename(finding)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr("prooflint.paths.os.open", swap_leaf_then_open)
    with pytest.raises(PathSafetyError, match="regular file changed"):
        read_bounded_regular_file(finding, 1000)
    assert swapped


def test_evidence_directory_and_leaf_swaps_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "bundle"
    trusted_dir = root / "evidence"
    trusted_dir.mkdir(parents=True)
    (trusted_dir / "trace.txt").write_text("trusted")
    attacker_dir = root / "attacker"
    attacker_dir.mkdir()
    (attacker_dir / "trace.txt").write_text("attacker")
    held_dir = root / "held"
    real_open = os.open
    swapped = False

    def swap_directory_then_open(
        path: str | bytes,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if path == "evidence" and dir_fd is not None and not swapped:
            swapped = True
            trusted_dir.rename(held_dir)
            attacker_dir.rename(trusted_dir)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr("prooflint.paths.os.open", swap_directory_then_open)
    with pytest.raises(PathSafetyError, match="evidence path changed"):
        hash_confined_file(root, "evidence/trace.txt")
    assert swapped

    monkeypatch.setattr("prooflint.paths.os.open", real_open)
    trusted_leaf = trusted_dir / "trace.txt"
    replacement_leaf = trusted_dir / "replacement.txt"
    replacement_leaf.write_text("new attacker")
    held_leaf = trusted_dir / "held.txt"
    swapped = False

    def swap_leaf_then_open(
        path: str | bytes,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if path == "trace.txt" and dir_fd is not None and not swapped:
            swapped = True
            trusted_leaf.rename(held_leaf)
            replacement_leaf.rename(trusted_leaf)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr("prooflint.paths.os.open", swap_leaf_then_open)
    with pytest.raises(PathSafetyError, match="evidence file changed"):
        hash_confined_file(root, "evidence/trace.txt")
    assert swapped


def test_bounded_reader_rejects_symlink_leaf_and_non_directory_ancestor(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("target")
    linked = tmp_path / "linked.txt"
    linked.symlink_to(target)
    with pytest.raises(PathSafetyError, match="symlinks are not allowed"):
        read_bounded_regular_file(linked, 100)

    component = tmp_path / "component"
    component.write_text("not a directory")
    with pytest.raises(PathSafetyError, match="not a directory"):
        read_bounded_regular_file(component / "child.txt", 100)


def test_rejects_missing_or_non_directory_root(tmp_path: Path) -> None:
    with pytest.raises(PathSafetyError, match="cannot resolve evidence root"):
        resolve_regular_file(tmp_path / "missing", "trace.txt")
    file_root = tmp_path / "file-root"
    file_root.write_text("not a directory")
    with pytest.raises(PathSafetyError, match="root is not a directory"):
        resolve_regular_file(file_root, "trace.txt")


def test_rejects_non_directory_component_and_directory_leaf(tmp_path: Path) -> None:
    (tmp_path / "component").write_text("file")
    with pytest.raises(PathSafetyError, match="non-directory component"):
        resolve_regular_file(tmp_path, "component/child.txt")
    (tmp_path / "directory").mkdir()
    with pytest.raises(PathSafetyError, match="not a regular file"):
        resolve_regular_file(tmp_path, "directory")


@pytest.mark.parametrize(
    "manifest",
    [
        None,
        {},
        {
            "manifest_version": "1",
            "finding": {"id": "X", "schema_version": "0.1"},
            "files": [],
        },
        {
            "manifest_version": "0.1",
            "finding": {},
            "files": [],
        },
        {
            "manifest_version": "0.1",
            "finding": {"id": "X", "schema_version": "0.1"},
            "files": {},
        },
        {
            "manifest_version": "0.1",
            "finding": {"id": "X", "schema_version": "0.1"},
            "files": ["bad"],
        },
        {
            "manifest_version": "0.1",
            "finding": {"id": "X", "schema_version": "0.1"},
            "files": [
                {
                    "path": "x",
                    "sha256": "0" * 64,
                    "size": 0,
                    "kind": "trace",
                    "state": "verified",
                    "redacted": True,
                }
            ],
        },
        {
            "manifest_version": "0.1",
            "finding": {"id": "X", "schema_version": "0.1"},
            "files": [
                {
                    "path": 1,
                    "sha256": "0" * 64,
                    "size": 0,
                    "kind": "trace",
                    "state": "verified",
                    "redacted": True,
                    "sensitive": False,
                }
            ],
        },
        {
            "manifest_version": "0.1",
            "finding": {"id": "X", "schema_version": "0.1"},
            "files": [
                {
                    "path": "../x",
                    "sha256": "0" * 64,
                    "size": 0,
                    "kind": "trace",
                    "state": "verified",
                    "redacted": True,
                    "sensitive": False,
                }
            ],
        },
        {
            "manifest_version": "0.1",
            "finding": {"id": "X", "schema_version": "0.1"},
            "files": [
                {
                    "path": "x",
                    "sha256": "bad",
                    "size": 0,
                    "kind": "trace",
                    "state": "verified",
                    "redacted": True,
                    "sensitive": False,
                }
            ],
        },
        {
            "manifest_version": "0.1",
            "finding": {"id": "X", "schema_version": "0.1"},
            "files": [
                {
                    "path": "x",
                    "sha256": "0" * 64,
                    "size": -1,
                    "kind": "trace",
                    "state": "verified",
                    "redacted": True,
                    "sensitive": False,
                }
            ],
        },
    ],
)
def test_verify_rejects_malformed_manifest(manifest: object, tmp_path: Path) -> None:
    with pytest.raises(ManifestError):
        verify_manifest(manifest, tmp_path)


def test_verify_rejects_duplicate_manifest_entries(evidence_bundle: tuple[Path, str, str]) -> None:
    root, path, digest = evidence_bundle
    manifest: dict[str, Any] = build_manifest(finding_for(path, digest), root)
    manifest["files"].append(copy.deepcopy(manifest["files"][0]))
    with pytest.raises(ManifestError, match="duplicate manifest path"):
        verify_manifest(manifest, root)


def test_verify_rejects_manifest_schema_drift(evidence_bundle: tuple[Path, str, str]) -> None:
    root, path, digest = evidence_bundle
    valid: dict[str, Any] = build_manifest(finding_for(path, digest), root)
    variants: list[dict[str, Any]] = []

    extra_top = copy.deepcopy(valid)
    extra_top["timestamp"] = "not deterministic"
    variants.append(extra_top)

    bad_finding = copy.deepcopy(valid)
    bad_finding["finding"] = {"id": 7, "schema_version": "0.1"}
    variants.append(bad_finding)

    bad_version = copy.deepcopy(valid)
    bad_version["finding"]["schema_version"] = "1.0"
    variants.append(bad_version)

    for field, value in [
        ("kind", 7),
        ("state", "certain"),
        ("redacted", "yes"),
        ("sensitive", None),
    ]:
        variant = copy.deepcopy(valid)
        variant["files"][0][field] = value
        variants.append(variant)

    for variant in variants:
        with pytest.raises(ManifestError):
            verify_manifest(variant, root)
