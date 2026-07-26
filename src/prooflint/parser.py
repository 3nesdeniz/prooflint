"""Strict Markdown-frontmatter and JSON finding parsers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from prooflint.errors import ParseError, PathSafetyError
from prooflint.models import Finding
from prooflint.paths import read_bounded_regular_file

MAX_FINDING_BYTES = 2 * 1024 * 1024


class _DuplicateKeyError(ValueError):
    pass


class _UniqueSafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_yaml_mapping(
    loader: yaml.SafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    loader.flatten_mapping(node)
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_yaml_mapping,
)


def _construct_unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise _DuplicateKeyError(f"non-standard JSON constant: {value}")


def _read_text(path: Path) -> str:
    if path.is_symlink():
        raise ParseError(f"refusing symlinked finding: {path}")
    try:
        raw = read_bounded_regular_file(path, MAX_FINDING_BYTES)
    except PathSafetyError as exc:
        raise ParseError(f"cannot read finding {path}: {exc}") from exc
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ParseError(f"cannot read UTF-8 finding {path}: {exc}") from exc


def _parse_markdown(text: str, path: Path) -> tuple[dict[str, Any], str]:
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].rstrip("\r\n") != "---":
        raise ParseError(f"Markdown finding requires YAML frontmatter: {path}")
    closing = next(
        (index for index, line in enumerate(lines[1:], start=1) if line.rstrip("\r\n") == "---"),
        None,
    )
    if closing is None:
        raise ParseError(f"unterminated YAML frontmatter: {path}")
    frontmatter = "".join(lines[1:closing])
    body = "".join(lines[closing + 1 :]).strip()
    try:
        value = yaml.load(frontmatter, Loader=_UniqueSafeLoader)
    # PyYAML constructors may surface ordinary Python exceptions (for example,
    # AttributeError for a malformed explicit timestamp tag). All constructor
    # failures are untrusted-input errors, never CLI tracebacks.
    except Exception as exc:
        raise ParseError(f"invalid YAML frontmatter in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ParseError(f"YAML frontmatter must be an object: {path}")
    return value, body


def _parse_json(text: str, path: Path) -> tuple[dict[str, Any], str]:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_construct_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSON in {path}: {exc.msg} at line {exc.lineno}") from exc
    except _DuplicateKeyError as exc:
        raise ParseError(f"invalid JSON in {path}: {exc}") from exc
    except (ValueError, OverflowError, RecursionError) as exc:
        raise ParseError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ParseError(f"JSON finding must be an object: {path}")
    body = value.get("body", "")
    if not isinstance(body, str):
        raise ParseError("body must be a string")
    return value, body


def load_finding(path: str | Path) -> Finding:
    """Load a version 0.1 finding from Markdown frontmatter or JSON."""

    source = Path(path)
    text = _read_text(source)
    suffix = source.suffix.lower()
    if suffix in {".md", ".markdown"}:
        data, body = _parse_markdown(text, source)
    elif suffix == ".json":
        data, body = _parse_json(text, source)
    else:
        raise ParseError(f"unsupported finding extension {suffix!r}: {source}")
    return Finding.from_mapping(
        data,
        body=body,
        source_path=source,
        source_text=text,
    )
