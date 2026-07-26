from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml


def digest_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def valid_mapping(path: str, digest: str) -> dict[str, Any]:
    return {
        "schema_version": "0.1",
        "id": "TEST-001",
        "title": "Synthetic finding",
        "profile": "ai-system",
        "status": "verified",
        "target": {"system": "synthetic-fixture", "version": "v1"},
        "scope": {
            "authorized": True,
            "description": "Local synthetic fixture",
            "boundaries": ["approval-gate"],
        },
        "preconditions": ["The fixed fixture reaches the gate"],
        "affected_boundary": "approval-gate",
        "expected": "The request is denied.",
        "observed": "The fixture records an accepted decision.",
        "impact": "The attached trace supports the bounded synthetic claim.",
        "confidence": "high",
        "evidence": [
            {
                "kind": "redacted_trace",
                "path": path,
                "sha256": digest,
                "state": "verified",
                "redacted": True,
                "sensitive": False,
                "description": "Synthetic trace",
            }
        ],
        "reproduction": {
            "attempts": 3,
            "successes": 3,
            "environment": "Offline fixture",
            "steps": ["Read and compare the fixed decisions"],
        },
        "remediation": "Bind the policy label to the request.",
        "retest": ["Require three denied decisions from the unchanged fixture"],
    }


def markdown_for(mapping: dict[str, Any], body: str = "Synthetic reviewer note.") -> str:
    frontmatter = yaml.safe_dump(mapping, sort_keys=False, allow_unicode=True)
    return f"---\n{frontmatter}---\n\n{body}\n"


def write_bundle(tmp_path: Path) -> tuple[Path, str, str]:
    root = tmp_path / "bundle"
    artifact = root / "evidence" / "trace.txt"
    artifact.parent.mkdir(parents=True)
    content = b"synthetic trace\nexpected=deny\nobserved=accept\n"
    artifact.write_bytes(content)
    return root, "evidence/trace.txt", digest_bytes(content)
