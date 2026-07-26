from __future__ import annotations

import json
import re
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

import prooflint
from prooflint import build_manifest, load_finding, validate_finding, verify_manifest
from prooflint.errors import ParseError
from prooflint.models import Finding

ROOT = Path(__file__).parents[1]


def test_public_api_and_version() -> None:
    assert prooflint.__version__ == "0.1.0"
    assert callable(load_finding)
    assert callable(validate_finding)
    assert callable(build_manifest)
    assert callable(verify_manifest)


def test_bundled_schemas_are_valid_json_with_version_contracts() -> None:
    schema_root = ROOT / "src" / "prooflint" / "schema"
    finding_schema = json.loads((schema_root / "finding-0.1.schema.json").read_text())
    manifest_schema = json.loads((schema_root / "evidence-manifest-0.1.schema.json").read_text())
    assert finding_schema["properties"]["schema_version"]["const"] == "0.1"
    assert set(finding_schema["properties"]["status"]["enum"]) == {
        "verified",
        "supported_inference",
        "unverified",
        "not_tested",
    }
    assert manifest_schema["properties"]["manifest_version"]["const"] == "0.1"
    Draft202012Validator.check_schema(finding_schema)
    Draft202012Validator.check_schema(manifest_schema)
    assert not Draft202012Validator(finding_schema).is_valid(
        {"schema_version": "0.1", "body": None}
    )


def test_finding_schema_and_runtime_agree_on_contract_value_corpus() -> None:
    schema = json.loads(
        (ROOT / "src" / "prooflint" / "schema" / "finding-0.1.schema.json").read_text()
    )
    validator = Draft202012Validator(schema)
    corpus = [
        {
            "schema_version": "0.1",
            "status": "verified",
            "evidence": [{"state": "verified", "sha256": "a" * 64}],
        },
        {"schema_version": " 0.1"},
        {"schema_version": "0.1", "status": "verified "},
        {"schema_version": "0.1", "evidence": [{"state": " verified"}]},
        {"schema_version": "0.1", "evidence": [{"sha256": "a" * 64 + " "}]},
        {"schema_version": "0.1", "evidence": [{"sha256": "A" * 64}]},
        {"schema_version": "0.1", "evidence": [{"sha256": "short"}]},
        {"schema_version": "0.1", "evidence": [{"sha256": None}]},
    ]

    for document in corpus:
        schema_accepts = validator.is_valid(document)
        try:
            Finding.from_mapping(document)
        except ParseError:
            runtime_accepts = False
        else:
            runtime_accepts = True
        assert runtime_accepts is schema_accepts, document


def test_project_yaml_files_parse() -> None:
    assert yaml.safe_load((ROOT / "CITATION.cff").read_text())["version"] == "0.1.0"
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    assert "jobs" in workflow
    dependabot = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())
    assert dependabot["version"] == 2


def test_ci_actions_are_pinned_to_full_commit_shas() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    action_refs = re.findall(r"uses:\s+[^@\s]+@([^\s#]+)", workflow)
    assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", reference) for reference in action_refs)


def test_synthetic_example_passes_and_manifests() -> None:
    finding = load_finding(ROOT / "examples" / "findings" / "verified-synthetic.md")
    evidence_root = ROOT / "examples"
    result = validate_finding(finding, evidence_root)
    assert result.passed
    first = build_manifest(finding, evidence_root)
    second = build_manifest(finding, evidence_root)
    assert first == second
    committed = json.loads((ROOT / "examples" / "evidence-manifest.json").read_text())
    assert first == committed
    assert verify_manifest(first, evidence_root).ok

    finding_schema = json.loads(
        (ROOT / "src" / "prooflint" / "schema" / "finding-0.1.schema.json").read_text()
    )
    frontmatter = (ROOT / "examples" / "findings" / "verified-synthetic.md").read_text()
    raw_finding = yaml.safe_load(frontmatter.split("---", maxsplit=2)[1])
    Draft202012Validator(finding_schema).validate(raw_finding)

    manifest_schema = json.loads(
        (ROOT / "src" / "prooflint" / "schema" / "evidence-manifest-0.1.schema.json").read_text()
    )
    Draft202012Validator(manifest_schema).validate(committed)


def test_hypothesis_example_is_explicitly_not_tested() -> None:
    finding = load_finding(ROOT / "examples" / "findings" / "unverified-hypothesis.json")
    assert finding.status.value == "not_tested"
    assert not validate_finding(finding, ROOT / "examples").passed
    finding_schema = json.loads(
        (ROOT / "src" / "prooflint" / "schema" / "finding-0.1.schema.json").read_text()
    )
    raw = json.loads((ROOT / "examples" / "findings" / "unverified-hypothesis.json").read_text())
    Draft202012Validator(finding_schema).validate(raw)
