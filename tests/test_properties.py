from __future__ import annotations

import json
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from prooflint.errors import ParseError, PathSafetyError
from prooflint.models import Finding
from prooflint.parser import load_finding
from prooflint.paths import normalize_relative_path

SAFE_SEGMENT = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"),
        whitelist_characters="-_",
    ),
    min_size=1,
    max_size=16,
).filter(lambda value: value not in {".", ".."})


@given(st.lists(SAFE_SEGMENT, min_size=1, max_size=5))
def test_canonical_relative_paths_round_trip(segments: list[str]) -> None:
    path = "/".join(segments)
    assert normalize_relative_path(path) == path


@given(
    st.sampled_from(
        [
            "../x",
            "a/../x",
            "/absolute",
            "a\\b",
            "C:/x",
            "./x",
            "a//b",
            "a/./b",
            "\x00x",
        ]
    )
)
def test_unsafe_path_families_are_always_rejected(path: str) -> None:
    with pytest.raises(PathSafetyError):
        normalize_relative_path(path)


JSON_VALUES = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=20),
    lambda children: (
        st.lists(children, max_size=4)
        | st.dictionaries(st.text(min_size=1, max_size=8), children, max_size=4)
    ),
    max_leaves=12,
)


@given(st.dictionaries(st.text(min_size=1, max_size=12), JSON_VALUES, max_size=10))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_json_parser_returns_a_finding_or_a_documented_parse_error(
    tmp_path: Path, data: dict[str, object]
) -> None:
    path = tmp_path / "generated.json"
    path.write_text(json.dumps(data))
    try:
        finding = load_finding(path)
    except ParseError:
        return
    assert isinstance(finding, Finding)
    assert finding.schema_version == "0.1"
