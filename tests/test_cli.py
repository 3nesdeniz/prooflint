from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import prooflint.cli as cli
from prooflint.errors import ProoflintError
from tests.helpers import markdown_for, valid_mapping, write_bundle


def run_cli(*args: object, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "prooflint", *(str(arg) for arg in args)],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )


def write_valid_finding(tmp_path: Path) -> tuple[Path, Path, Path]:
    root, relative, digest = write_bundle(tmp_path)
    finding = tmp_path / "finding.md"
    finding.write_text(markdown_for(valid_mapping(relative, digest)))
    return finding, root, root / relative


def test_version() -> None:
    result = run_cli("--version")
    assert result.returncode == 0
    assert result.stdout == "prooflint 0.1.0\n"
    assert result.stderr == ""


def test_init_refuses_overwrite_without_force(tmp_path: Path) -> None:
    output = tmp_path / "nested" / "finding.md"
    created = run_cli("init", output)
    assert created.returncode == 0
    assert output.read_text().startswith('---\nschema_version: "0.1"')

    refused = run_cli("init", output)
    assert refused.returncode == 2
    assert "use --force" in refused.stderr

    replaced = run_cli("init", output, "--force")
    assert replaced.returncode == 0


def test_init_rejects_symlink_output(tmp_path: Path) -> None:
    target = tmp_path / "target.md"
    target.write_text("do not replace")
    link = tmp_path / "link.md"
    link.symlink_to(target)
    result = run_cli("init", link, "--force")
    assert result.returncode == 2
    assert "symlinked output" in result.stderr
    assert target.read_text() == "do not replace"


def test_check_passes_valid_finding(tmp_path: Path) -> None:
    finding, root, _ = write_valid_finding(tmp_path)
    result = run_cli("check", finding, "--evidence-root", root)
    assert result.returncode == 0
    assert "0 violation(s), 1 passed" in result.stdout
    assert result.stderr == ""


@pytest.mark.parametrize("output_format", ["json", "sarif"])
def test_check_writes_machine_readable_output(tmp_path: Path, output_format: str) -> None:
    finding, root, _ = write_valid_finding(tmp_path)
    output = tmp_path / f"result.{output_format}"
    result = run_cli(
        "check",
        finding,
        "--evidence-root",
        root,
        "--format",
        output_format,
        "--out",
        output,
    )
    assert result.returncode == 0
    assert result.stdout == ""
    payload = json.loads(output.read_text())
    if output_format == "json":
        assert payload["passed"] is True
    else:
        assert payload["version"] == "2.1.0"


def test_check_returns_one_for_rule_violations(tmp_path: Path) -> None:
    root, relative, digest = write_bundle(tmp_path)
    data = valid_mapping(relative, digest)
    data["target"] = {"system": "missing-fingerprint"}
    finding = tmp_path / "invalid.json"
    finding.write_text(json.dumps(data))
    result = run_cli("check", finding, "--evidence-root", root, "--format", "json")
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["passed"] is False
    assert "PL001" in {item["code"] for item in payload["diagnostics"]}


def test_check_returns_two_for_parse_error(tmp_path: Path) -> None:
    finding = tmp_path / "bad.json"
    finding.write_text('{"schema_version":"0.1","status":"verifiedd"}')
    result = run_cli("check", finding)
    assert result.returncode == 2
    assert result.stdout == ""
    assert "status must be one of" in result.stderr


def test_check_discovers_supported_files_in_directory(tmp_path: Path) -> None:
    finding, root, _ = write_valid_finding(tmp_path)
    nested = tmp_path / "reports"
    nested.mkdir()
    finding.rename(nested / "finding.markdown")
    (nested / "ignored.txt").write_text("ignored")
    result = run_cli("check", nested, "--evidence-root", root)
    assert result.returncode == 0
    assert "1 finding(s)" in result.stdout


def test_check_returns_two_when_directory_has_no_findings(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("not a finding")
    result = run_cli("check", tmp_path)
    assert result.returncode == 2
    assert "no Markdown or JSON" in result.stderr


def test_check_returns_two_for_missing_input(tmp_path: Path) -> None:
    result = run_cli("check", tmp_path / "missing.md")
    assert result.returncode == 2
    assert "path does not exist" in result.stderr


def test_check_rejects_symlinked_finding(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    real.write_text('{"schema_version":"0.1"}')
    link = tmp_path / "link.json"
    link.symlink_to(real)
    result = run_cli("check", link)
    assert result.returncode == 2
    assert "symlinked finding" in result.stderr


def test_manifest_verify_and_tamper_exit_codes(tmp_path: Path) -> None:
    finding, root, artifact = write_valid_finding(tmp_path)
    manifest = tmp_path / "manifest.json"
    generated = run_cli(
        "manifest",
        finding,
        "--evidence-root",
        root,
        "--out",
        manifest,
    )
    assert generated.returncode == 0
    assert json.loads(manifest.read_text())["manifest_version"] == "0.1"

    verified = run_cli("verify", manifest, "--evidence-root", root, "--format", "json")
    assert verified.returncode == 0
    assert json.loads(verified.stdout)["ok"] is True

    artifact.write_text("tampered")
    tampered = run_cli("verify", manifest, "--evidence-root", root)
    assert tampered.returncode == 1
    assert "FAIL" in tampered.stdout
    assert "SHA-256 mismatch" in tampered.stdout


def test_verify_defaults_root_to_manifest_parent(tmp_path: Path) -> None:
    artifact = tmp_path / "trace.txt"
    artifact.write_text("trace")
    import hashlib

    content = artifact.read_bytes()
    manifest = {
        "manifest_version": "0.1",
        "finding": {"id": "X", "schema_version": "0.1"},
        "files": [
            {
                "path": "trace.txt",
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
                "kind": "trace",
                "state": "verified",
                "redacted": True,
                "sensitive": False,
            }
        ],
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    result = run_cli("verify", path)
    assert result.returncode == 0


@pytest.mark.parametrize(
    "content",
    [
        "{",
        "[]",
        '{"manifest_version":"9","finding":{},"files":[]}',
        '{"manifest_version":"0.1","manifest_version":"0.1","finding":{},"files":[]}',
        '{"manifest_version":"0.1","finding":{},"files":[],"score":NaN}',
    ],
)
def test_verify_returns_two_for_bad_manifest(tmp_path: Path, content: str) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(content)
    result = run_cli("verify", manifest)
    assert result.returncode == 2
    assert "prooflint: error:" in result.stderr


def test_verify_rejects_missing_and_symlinked_manifest(tmp_path: Path) -> None:
    missing = run_cli("verify", tmp_path / "missing.json")
    assert missing.returncode == 2
    assert "cannot read manifest" in missing.stderr

    target = tmp_path / "target.json"
    target.write_text(
        '{"manifest_version":"0.1","finding":{"id":"X","schema_version":"0.1"},"files":[]}'
    )
    link = tmp_path / "link.json"
    link.symlink_to(target)
    linked = run_cli("verify", link)
    assert linked.returncode == 2
    assert "symlinked manifest" in linked.stderr


def test_verify_rejects_manifest_beneath_symlinked_ancestor(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    manifest = real / "manifest.json"
    manifest.write_text(
        '{"manifest_version":"0.1","finding":{"id":"X","schema_version":"0.1"},"files":[]}'
    )
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)

    result = run_cli("verify", linked / "manifest.json")
    assert result.returncode == 2
    assert "symlink components are not allowed" in result.stderr


def test_init_rejects_existing_directory(tmp_path: Path) -> None:
    output = tmp_path / "finding.md"
    output.mkdir()
    result = run_cli("init", output, "--force")
    assert result.returncode == 2
    assert "not a regular file" in result.stderr


def test_output_writer_rejects_symlink(tmp_path: Path) -> None:
    finding, root, _ = write_valid_finding(tmp_path)
    target = tmp_path / "target.json"
    target.write_text("preserve")
    link = tmp_path / "output.json"
    link.symlink_to(target)
    result = run_cli(
        "check",
        finding,
        "--evidence-root",
        root,
        "--format",
        "json",
        "--out",
        link,
    )
    assert result.returncode == 2
    assert target.read_text() == "preserve"


def test_check_output_cannot_overwrite_its_finding(tmp_path: Path) -> None:
    finding, root, _ = write_valid_finding(tmp_path)
    original = finding.read_text()
    result = run_cli(
        "check",
        finding,
        "--evidence-root",
        root,
        "--out",
        finding,
    )
    assert result.returncode == 2
    assert "would overwrite an input file" in result.stderr
    assert finding.read_text() == original


def test_check_output_cannot_overwrite_referenced_evidence_or_hardlink(tmp_path: Path) -> None:
    finding, root, artifact = write_valid_finding(tmp_path)
    original = artifact.read_bytes()

    direct = run_cli("check", finding, "--evidence-root", root, "--out", artifact)
    assert direct.returncode == 2
    assert "would overwrite an input file" in direct.stderr
    assert artifact.read_bytes() == original

    alias = tmp_path / "artifact-alias.txt"
    alias.hardlink_to(artifact)
    linked = run_cli("check", finding, "--evidence-root", root, "--out", alias)
    assert linked.returncode == 2
    assert "would overwrite an input file" in linked.stderr
    assert artifact.read_bytes() == original


def test_check_output_cannot_create_a_missing_referenced_evidence_path(tmp_path: Path) -> None:
    root, relative, digest = write_bundle(tmp_path)
    data = valid_mapping(relative, digest)
    data["evidence"][0].update(path="evidence/missing.json", sha256="0" * 64)
    finding = tmp_path / "finding.json"
    finding.write_text(json.dumps(data))
    output = root / "evidence" / "missing.json"

    result = run_cli("check", finding, "--evidence-root", root, "--out", output)
    assert result.returncode == 2
    assert "would overwrite an input file" in result.stderr
    assert not output.exists()


def test_manifest_output_cannot_overwrite_evidence(tmp_path: Path) -> None:
    finding, root, artifact = write_valid_finding(tmp_path)
    original = artifact.read_text()
    result = run_cli(
        "manifest",
        finding,
        "--evidence-root",
        root,
        "--out",
        artifact,
    )
    assert result.returncode == 2
    assert "would overwrite an input file" in result.stderr
    assert artifact.read_text() == original


def test_directory_check_refuses_its_existing_json_output(tmp_path: Path) -> None:
    finding, root, _ = write_valid_finding(tmp_path)
    reports = tmp_path / "reports"
    reports.mkdir()
    finding.rename(reports / "finding.md")
    output = reports / "prooflint.json"
    command = (
        "check",
        reports,
        "--evidence-root",
        root,
        "--format",
        "json",
        "--out",
        output,
    )
    assert run_cli(*command).returncode == 0
    original = output.read_bytes()
    repeated = run_cli(*command)
    assert repeated.returncode == 2
    assert "would overwrite an input file" in repeated.stderr
    assert output.read_bytes() == original


def test_directory_check_never_excludes_report_shaped_json_input(tmp_path: Path) -> None:
    root, relative, digest = write_bundle(tmp_path)
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "finding.json").write_text(json.dumps(valid_mapping(relative, digest)))
    attacker = reports / "attacker.json"
    attacker_payload = {
        "schema_version": "0.1",
        "passed": True,
        "summary": {},
        "diagnostics": [],
    }
    original = json.dumps(attacker_payload, separators=(",", ":"))
    attacker.write_text(original)

    result = run_cli(
        "check",
        reports,
        "--evidence-root",
        root,
        "--format",
        "json",
        "--out",
        attacker,
    )
    assert result.returncode == 2
    assert "would overwrite an input file" in result.stderr
    assert attacker.read_text() == original


def test_directory_check_never_overwrites_a_discovered_finding(tmp_path: Path) -> None:
    root, relative, digest = write_bundle(tmp_path)
    reports = tmp_path / "reports"
    reports.mkdir()
    first = reports / "first.json"
    second = reports / "second.json"
    first.write_text(json.dumps(valid_mapping(relative, digest)))
    second.write_text(json.dumps(valid_mapping(relative, digest)))
    original = first.read_text()
    result = run_cli(
        "check",
        reports,
        "--evidence-root",
        root,
        "--format",
        "json",
        "--out",
        first,
    )
    assert result.returncode == 2
    assert "would overwrite an input file" in result.stderr
    assert first.read_text() == original


def test_output_parent_symlink_is_rejected_before_any_write(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    linked_parent = tmp_path / "reports"
    linked_parent.symlink_to(outside, target_is_directory=True)
    result = run_cli("init", linked_parent / "finding.md")
    assert result.returncode == 2
    assert "symlink components are not allowed" in result.stderr
    assert not (outside / "finding.md").exists()


def test_non_regular_manifest_and_output_are_rejected_without_blocking(tmp_path: Path) -> None:
    manifest_fifo = tmp_path / "manifest.json"
    output_fifo = tmp_path / "output.json"
    try:
        import os

        os.mkfifo(manifest_fifo)
        os.mkfifo(output_fifo)
    except (AttributeError, NotImplementedError):
        pytest.skip("FIFOs are not supported on this platform")

    verified = run_cli("verify", manifest_fifo)
    assert verified.returncode == 2
    assert "not a regular file" in verified.stderr

    finding, root, _ = write_valid_finding(tmp_path)
    checked = run_cli("check", finding, "--evidence-root", root, "--out", output_fifo)
    assert checked.returncode == 2
    assert "not a regular file" in checked.stderr


def test_oversized_and_huge_number_manifests_return_two(tmp_path: Path) -> None:
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (2 * 1024 * 1024 + 1))
    too_large = run_cli("verify", oversized)
    assert too_large.returncode == 2
    assert "exceeds 2097152 bytes" in too_large.stderr

    huge_number = tmp_path / "huge-number.json"
    huge_number.write_text("[" + "9" * 5000 + "]")
    numeric = run_cli("verify", huge_number)
    assert numeric.returncode == 2
    assert "invalid manifest JSON" in numeric.stderr


def test_non_utf8_manifest_returns_two(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(b"\xff\xfe")
    result = run_cli("verify", manifest)
    assert result.returncode == 2
    assert "manifest is not UTF-8" in result.stderr


def test_directory_with_only_its_generated_output_returns_two(tmp_path: Path) -> None:
    finding, root, _ = write_valid_finding(tmp_path)
    reports = tmp_path / "reports"
    reports.mkdir()
    moved = reports / "finding.md"
    finding.rename(moved)
    output = reports / "prooflint.json"
    first = run_cli("check", reports, "--evidence-root", root, "--format", "json", "--out", output)
    assert first.returncode == 0
    moved.unlink()
    second = run_cli("check", reports, "--evidence-root", root, "--format", "json", "--out", output)
    assert second.returncode == 2
    assert "would overwrite an input file" in second.stderr


def test_atomic_writer_cleans_temporary_file_after_write_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "result.txt"

    def fail_write(_: int, __: bytes) -> int:
        raise OSError("synthetic disk error")

    monkeypatch.setattr("prooflint.cli.os.write", fail_write)
    with pytest.raises(OSError, match="synthetic disk error"):
        cli._write_posix(output, "content")
    assert list(tmp_path.glob(".prooflint-*.tmp")) == []
    assert not output.exists()


def test_atomic_writer_rejects_non_regular_existing_leaf(tmp_path: Path) -> None:
    output = tmp_path / "result.txt"
    output.mkdir()
    with pytest.raises(ProoflintError, match="not a regular file"):
        cli._write_posix(output, "content")


def test_same_entry_fails_closed_on_samefile_inspection_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    left = tmp_path / "left"
    right = tmp_path / "right"
    left.write_text("left")
    right.write_text("right")

    def fail_samefile(_: object, __: object) -> bool:
        raise OSError("synthetic samefile error")

    monkeypatch.setattr("prooflint.cli.os.path.samefile", fail_samefile)
    assert cli._same_entry(left, right)


def test_check_wraps_malformed_explicit_yaml_timestamp_without_traceback(tmp_path: Path) -> None:
    finding = tmp_path / "timestamp.md"
    finding.write_text(
        "---\n"
        "schema_version: '0.1'\n"
        "evidence:\n"
        "  - observed_at: !!timestamp definitely-not-a-timestamp\n"
        "---\n"
    )
    result = run_cli("check", finding)
    assert result.returncode == 2
    assert "invalid YAML frontmatter" in result.stderr
    assert "Traceback" not in result.stderr
