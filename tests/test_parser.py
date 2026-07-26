from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from prooflint.errors import ParseError
from prooflint.models import FindingStatus
from prooflint.parser import load_finding
from tests.helpers import markdown_for, valid_mapping


def test_loads_markdown_frontmatter_and_body(
    tmp_path: Path, evidence_bundle: tuple[Path, str, str]
) -> None:
    _, relative, digest = evidence_bundle
    path = tmp_path / "finding.md"
    path.write_text(markdown_for(valid_mapping(relative, digest), "Human reviewer note."))
    finding = load_finding(path)
    assert finding.id == "TEST-001"
    assert finding.status is FindingStatus.VERIFIED
    assert finding.body == "Human reviewer note."
    assert finding.source_path == path


def test_loads_json_and_utf8_bom(tmp_path: Path, evidence_bundle: tuple[Path, str, str]) -> None:
    _, relative, digest = evidence_bundle
    data = valid_mapping(relative, digest)
    data["body"] = "JSON body"
    path = tmp_path / "finding.json"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps(data).encode())
    finding = load_finding(path)
    assert finding.body == "JSON body"


@pytest.mark.parametrize("status", ["verifiedd", "", "VERIFIED", "not-tested"])
def test_rejects_unknown_finding_status(tmp_path: Path, status: str) -> None:
    path = tmp_path / "finding.json"
    path.write_text(json.dumps({"schema_version": "0.1", "status": status}))
    with pytest.raises(ParseError, match="status must be one of"):
        load_finding(path)


@pytest.mark.parametrize(
    ("name", "content", "message"),
    [
        ("missing.md", "# no frontmatter\n", "requires YAML frontmatter"),
        ("unterminated.md", "---\nschema_version: '0.1'\n", "unterminated"),
        ("bad.md", "---\nscope: [\n---\n", "invalid YAML"),
        ("scalar.md", "---\nhello\n---\n", "must be an object"),
        ("bad.json", "{", "invalid JSON"),
        ("array.json", "[]", "must be an object"),
        ("plain.txt", "hello", "unsupported finding extension"),
    ],
)
def test_rejects_malformed_inputs(tmp_path: Path, name: str, content: str, message: str) -> None:
    path = tmp_path / name
    path.write_text(content)
    with pytest.raises(ParseError, match=message):
        load_finding(path)


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"schema_version": "1.0"},
        {"schema_version": "0.1", "target": []},
        {"schema_version": "0.1", "preconditions": "one"},
        {"schema_version": "0.1", "evidence": {}},
        {"schema_version": "0.1", "scope": {"authorized": "yes"}},
        {"schema_version": "0.1", "reproduction": {"attempts": True}},
        {"schema_version": "0.1", "body": ["not text"]},
    ],
)
def test_rejects_wrong_schema_or_types(tmp_path: Path, data: object) -> None:
    path = tmp_path / "finding.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ParseError):
        load_finding(path)


def test_rejects_non_utf8(tmp_path: Path) -> None:
    path = tmp_path / "finding.json"
    path.write_bytes(b"\xff\xfe")
    with pytest.raises(ParseError, match="UTF-8"):
        load_finding(path)


def test_rejects_oversized_input(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("prooflint.parser.MAX_FINDING_BYTES", 4)
    path = tmp_path / "finding.json"
    path.write_text("{}" * 3)
    with pytest.raises(ParseError, match="exceeds 4 bytes"):
        load_finding(path)


def test_rejects_source_symlink(tmp_path: Path) -> None:
    target = tmp_path / "real.json"
    target.write_text('{"schema_version": "0.1"}')
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(ParseError, match="symlinked finding"):
        load_finding(link)


def test_rejects_finding_beneath_symlinked_ancestor(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (real / "finding.json").write_text('{"schema_version": "0.1"}')
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(ParseError, match="symlink components are not allowed"):
        load_finding(linked / "finding.json")


def test_rejects_directory_with_supported_suffix(tmp_path: Path) -> None:
    directory = tmp_path / "directory.json"
    directory.mkdir()
    with pytest.raises(ParseError, match="not a regular file"):
        load_finding(directory)


def test_rejects_missing_source(tmp_path: Path) -> None:
    with pytest.raises(ParseError, match="cannot read finding"):
        load_finding(tmp_path / "missing.json")


def test_rejects_fifo_source_without_blocking(tmp_path: Path) -> None:
    path = tmp_path / "finding.json"
    try:
        os.mkfifo(path)
    except (AttributeError, NotImplementedError):
        pytest.skip("FIFOs are not supported on this platform")
    with pytest.raises(ParseError, match="not a regular file"):
        load_finding(path)


@pytest.mark.parametrize(
    ("name", "content", "message"),
    [
        (
            "duplicate.json",
            '{"schema_version":"0.1","status":"unverified","status":"verified"}',
            "duplicate JSON key",
        ),
        ("nan.json", '{"schema_version":"0.1","metadata":{"score":NaN}}', "non-standard"),
        (
            "duplicate.md",
            "---\nschema_version: '0.1'\nstatus: unverified\nstatus: verified\n---\n",
            "duplicate key",
        ),
    ],
)
def test_rejects_ambiguous_or_nonstandard_documents(
    tmp_path: Path, name: str, content: str, message: str
) -> None:
    path = tmp_path / name
    path.write_text(content)
    with pytest.raises(ParseError, match=message):
        load_finding(path)


def test_indented_yaml_dashes_are_not_a_frontmatter_delimiter(tmp_path: Path) -> None:
    path = tmp_path / "finding.md"
    path.write_text(
        "---\n"
        "schema_version: '0.1'\n"
        "scope:\n"
        "  description: |\n"
        "    ---\n"
        "    still frontmatter\n"
        "---\n"
        "body\n"
    )
    finding = load_finding(path)
    assert finding.scope.description == "---\nstill frontmatter"
    assert finding.body == "body"


def test_opening_frontmatter_delimiter_must_be_exact(tmp_path: Path) -> None:
    path = tmp_path / "finding.md"
    path.write_text("  ---\nschema_version: '0.1'\n---\n")
    with pytest.raises(ParseError, match="requires YAML frontmatter"):
        load_finding(path)


@pytest.mark.parametrize(
    "data",
    [
        {"schema_version": "0.1", "body": None},
        {"schema_version": "0.1", "target": None},
        {"schema_version": "0.1", "scope": None},
        {"schema_version": "0.1", "preconditions": None},
        {"schema_version": "0.1", "evidence": None},
        {"schema_version": "0.1", "reproduction": {"attempts": None}},
        {"schema_version": "0.1", "evidence": [{"redacted": None}]},
    ],
)
def test_explicit_null_does_not_bypass_schema_types(tmp_path: Path, data: object) -> None:
    path = tmp_path / "finding.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ParseError):
        load_finding(path)


@pytest.mark.parametrize("suffix", ["json", "md"])
def test_huge_integer_is_wrapped_as_parse_error(tmp_path: Path, suffix: str) -> None:
    digits = "9" * 5000
    path = tmp_path / f"finding.{suffix}"
    if suffix == "json":
        path.write_text(f'{{"schema_version":"0.1","metadata":{{"number":{digits}}}}}')
    else:
        path.write_text(f"---\nschema_version: '0.1'\nmetadata:\n  number: {digits}\n---\n")
    with pytest.raises(ParseError, match="invalid"):
        load_finding(path)
