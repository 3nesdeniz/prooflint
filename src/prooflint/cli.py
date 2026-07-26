"""Command-line interface for Prooflint."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from prooflint import __version__
from prooflint.errors import ManifestError, ParseError, PathSafetyError, ProoflintError
from prooflint.manifest import build_manifest, verify_manifest
from prooflint.parser import load_finding
from prooflint.paths import (
    ensure_no_symlink_components,
    normalize_relative_path,
    read_bounded_regular_file,
    resolve_regular_file,
)
from prooflint.reporters import (
    render_json,
    render_sarif,
    render_text,
    render_verification_json,
    render_verification_text,
)
from prooflint.rules import validate_finding
from prooflint.templates import FINDING_TEMPLATE

EXIT_OK = 0
EXIT_VIOLATIONS = 1
EXIT_TOOL_ERROR = 2
FINDING_SUFFIXES = {".json", ".markdown", ".md"}
MAX_MANIFEST_BYTES = 2 * 1024 * 1024


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prooflint",
        description="Local-first evidence hygiene checks for AI-security findings.",
    )
    parser.add_argument("--version", action="version", version=f"prooflint {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="create a synthetic finding template")
    init.add_argument("output", nargs="?", default="prooflint-finding.md", type=Path)
    init.add_argument("--profile", default="ai-system", choices=["ai-system"])
    init.add_argument("--force", action="store_true", help="replace an existing regular file")

    check = subparsers.add_parser("check", help="validate finding files")
    check.add_argument("paths", nargs="+", type=Path)
    check.add_argument("--evidence-root", type=Path)
    check.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    check.add_argument("--out", type=Path)

    manifest = subparsers.add_parser("manifest", help="generate an evidence manifest")
    manifest.add_argument("finding", type=Path)
    manifest.add_argument("--evidence-root", required=True, type=Path)
    manifest.add_argument("--out", required=True, type=Path)

    verify = subparsers.add_parser("verify", help="verify a generated evidence manifest")
    verify.add_argument("manifest", type=Path)
    verify.add_argument("--evidence-root", type=Path)
    verify.add_argument("--format", choices=["text", "json"], default="text")
    return parser


def _write(path: Path | None, content: str) -> None:
    if path is None:
        sys.stdout.write(content)
        return
    ensure_no_symlink_components(path.parent)
    if os.name == "posix":
        _write_posix(path, content)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        ensure_no_symlink_components(path)
        if path.exists() and not path.is_file():
            raise ProoflintError(f"output is not a regular file: {path}")
        _write_fallback(path, content)


def _open_output_directory(path: Path) -> int:
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    absolute = Path(os.path.abspath(path))
    current = os.open(absolute.anchor, directory_flags)
    succeeded = False
    try:
        for part in absolute.parts[1:]:
            try:
                os.mkdir(part, 0o755, dir_fd=current)
            except FileExistsError:
                pass
            metadata = os.stat(part, dir_fd=current, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise ProoflintError(f"symlink components are not allowed: {absolute}")
            if not stat.S_ISDIR(metadata.st_mode):
                raise ProoflintError(f"output path component is not a directory: {absolute}")
            next_descriptor = os.open(part, directory_flags, dir_fd=current)
            opened = os.fstat(next_descriptor)
            if (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino):
                os.close(next_descriptor)
                raise ProoflintError(f"output path component changed while opening: {absolute}")
            os.close(current)
            current = next_descriptor
        succeeded = True
        return current
    finally:
        if not succeeded:
            os.close(current)


def _write_posix(path: Path, content: str) -> None:
    directory = _open_output_directory(path.parent)
    temporary_name = f".prooflint-{secrets.token_hex(16)}.tmp"
    temporary_descriptor: int | None = None
    try:
        try:
            existing = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise ProoflintError(f"output is not a regular file: {path}")

        temporary_descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory,
        )
        payload = content.encode("utf-8")
        written = 0
        while written < len(payload):
            written += os.write(temporary_descriptor, payload[written:])
        os.fsync(temporary_descriptor)
        os.close(temporary_descriptor)
        temporary_descriptor = None
        os.replace(
            temporary_name,
            path.name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
        )
        os.fsync(directory)
    finally:
        if temporary_descriptor is not None:
            os.close(temporary_descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


def _write_fallback(path: Path, content: str) -> None:  # pragma: no cover - non-POSIX
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        ensure_no_symlink_components(path)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _same_entry(left: Path, right: Path) -> bool:
    same = os.path.realpath(left) == os.path.realpath(right)
    if left.exists() and right.exists():
        try:
            same = same or os.path.samefile(left, right)
        except OSError:
            return True
    return same


def _protect_inputs(output: Path | None, inputs: Sequence[Path]) -> None:
    if output is not None:
        for source in inputs:
            if _same_entry(output, source):
                raise ProoflintError(f"output would overwrite an input file: {source}")


def _discover(inputs: Sequence[Path]) -> list[Path]:
    candidates: set[Path] = set()
    for supplied in inputs:
        if supplied.is_symlink():
            candidates.add(supplied)
        elif supplied.is_dir():
            candidates.update(
                path
                for path in supplied.rglob("*")
                if path.suffix.lower() in FINDING_SUFFIXES and (path.is_file() or path.is_symlink())
            )
        elif supplied.is_file():
            candidates.add(supplied)
        else:
            raise ParseError(f"finding path does not exist: {supplied}")
    selected = sorted(candidates, key=lambda path: path.as_posix())
    if not selected:
        raise ParseError("no Markdown or JSON finding files found")
    return selected


def _init(args: argparse.Namespace) -> int:
    output: Path = args.output
    if output.is_symlink():
        raise ProoflintError(f"refusing symlinked output: {output}")
    if output.exists() and not args.force:
        raise ProoflintError(f"output already exists (use --force): {output}")
    if output.exists() and not output.is_file():
        raise ProoflintError(f"output is not a regular file: {output}")
    _write(output, FINDING_TEMPLATE)
    sys.stdout.write(f"Created {output}\n")
    return EXIT_OK


def _check(args: argparse.Namespace) -> int:
    results = []
    candidates = _discover(args.paths)
    _protect_inputs(args.out, candidates)
    evidence_inputs: list[Path] = []
    for candidate in candidates:
        finding = load_finding(candidate)
        root = args.evidence_root if args.evidence_root is not None else candidate.parent
        for item in finding.evidence:
            try:
                canonical = normalize_relative_path(item.path)
            except PathSafetyError:
                continue
            lexical = Path(os.path.abspath(root)).joinpath(*canonical.split("/"))
            try:
                evidence_inputs.append(resolve_regular_file(root, canonical))
            except (FileNotFoundError, PathSafetyError):
                evidence_inputs.append(lexical)
        results.append(validate_finding(finding, root))
    renderer = {"text": render_text, "json": render_json, "sarif": render_sarif}[args.format]
    _protect_inputs(args.out, [*candidates, *evidence_inputs])
    _write(args.out, renderer(results))
    return EXIT_OK if all(result.passed for result in results) else EXIT_VIOLATIONS


def _manifest(args: argparse.Namespace) -> int:
    finding = load_finding(args.finding)
    value = build_manifest(finding, args.evidence_root)
    evidence_files = [
        resolve_regular_file(args.evidence_root, item.path) for item in finding.evidence
    ]
    _protect_inputs(args.out, [args.finding, *evidence_files])
    _write(args.out, json.dumps(value, indent=2, sort_keys=True) + "\n")
    sys.stdout.write(f"Wrote manifest for {len(finding.evidence)} file(s) to {args.out}\n")
    return EXIT_OK


def _load_manifest(path: Path) -> object:
    if path.is_symlink():
        raise ManifestError(f"refusing symlinked manifest: {path}")
    try:
        raw = read_bounded_regular_file(path, MAX_MANIFEST_BYTES)
        text = raw.decode("utf-8-sig")
        return json.loads(
            text,
            object_pairs_hook=_unique_manifest_object,
            parse_constant=_reject_manifest_constant,
        )
    except PathSafetyError as exc:
        raise ManifestError(f"cannot read manifest {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ManifestError(f"manifest is not UTF-8: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ManifestError(f"invalid manifest JSON at line {exc.lineno}: {exc.msg}") from exc
    except (ValueError, OverflowError, RecursionError) as exc:
        raise ManifestError(f"invalid manifest JSON: {exc}") from exc


def _unique_manifest_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"duplicate manifest JSON key: {key!r}")
        result[key] = value
    return result


def _reject_manifest_constant(value: str) -> object:
    raise ManifestError(f"non-standard manifest JSON constant: {value}")


def _verify(args: argparse.Namespace) -> int:
    value = _load_manifest(args.manifest)
    root = args.evidence_root if args.evidence_root is not None else args.manifest.parent
    result = verify_manifest(value, root)
    output = (
        render_verification_json(result)
        if args.format == "json"
        else render_verification_text(result)
    )
    sys.stdout.write(output)
    return EXIT_OK if result.ok else EXIT_VIOLATIONS


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            return _init(args)
        if args.command == "check":
            return _check(args)
        if args.command == "manifest":
            return _manifest(args)
        if args.command == "verify":
            return _verify(args)
    except (ProoflintError, OSError) as exc:
        sys.stderr.write(f"prooflint: error: {exc}\n")
        return EXIT_TOOL_ERROR
    parser.error(f"unknown command: {args.command}")  # pragma: no cover - argparse invariant
    return EXIT_TOOL_ERROR  # pragma: no cover - parser.error raises
