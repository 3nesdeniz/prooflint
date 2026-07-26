"""Descriptor-pinned path confinement and hashing primitives."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path, PurePosixPath

from prooflint.errors import PathSafetyError

SHA256_CHUNK_SIZE = 1024 * 1024
_OPEN_BASE_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_DIRECTORY_FLAGS = _OPEN_BASE_FLAGS | _DIRECTORY | _NOFOLLOW


def normalize_relative_path(raw_path: str) -> str:
    """Return a canonical POSIX-relative path or reject it."""

    if not raw_path or "\x00" in raw_path or "\\" in raw_path or ":" in raw_path:
        raise PathSafetyError(f"unsafe evidence path: {raw_path!r}")
    pure = PurePosixPath(raw_path)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise PathSafetyError(f"unsafe evidence path: {raw_path!r}")
    canonical = pure.as_posix()
    if canonical != raw_path:
        raise PathSafetyError(f"evidence path is not canonical: {raw_path!r}")
    return canonical


def ensure_no_symlink_components(path: str | Path) -> None:
    """Reject every currently existing symlink component in a lexical path.

    This is a fast preflight for diagnostics. Security-sensitive callers also walk
    components through held directory descriptors before reading or writing.
    """

    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            break
        except OSError as exc:
            raise PathSafetyError(f"cannot inspect path component {current}: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise PathSafetyError(f"symlink components are not allowed: {current}")


def _same_identity(expected: os.stat_result, actual: os.stat_result) -> bool:
    return (expected.st_dev, expected.st_ino) == (actual.st_dev, actual.st_ino)


def _open_absolute_directory(path: str | Path, *, evidence_root: bool = False) -> tuple[int, Path]:
    """Open a directory after no-follow traversal of every lexical component."""

    absolute = Path(os.path.abspath(path))
    try:
        current = os.open(absolute.anchor, _DIRECTORY_FLAGS)
    except OSError as exc:  # pragma: no cover - a broken filesystem root is not testable
        raise PathSafetyError(f"cannot open filesystem root for {absolute}: {exc}") from exc
    succeeded = False
    try:
        component = Path(absolute.anchor)
        for part in absolute.parts[1:]:
            component /= part
            try:
                expected = os.stat(part, dir_fd=current, follow_symlinks=False)
            except FileNotFoundError:
                if evidence_root:
                    raise PathSafetyError(
                        f"cannot resolve evidence root {absolute}: not found"
                    ) from None
                raise PathSafetyError(f"path component does not exist: {component}") from None
            except OSError as exc:
                if evidence_root:
                    raise PathSafetyError(
                        f"cannot resolve evidence root {absolute}: {exc}"
                    ) from exc
                raise PathSafetyError(f"cannot inspect path component {component}: {exc}") from exc
            if stat.S_ISLNK(expected.st_mode):
                if evidence_root:
                    raise PathSafetyError(f"evidence root may not be a symlink: {component}")
                raise PathSafetyError(f"symlink components are not allowed: {component}")
            if not stat.S_ISDIR(expected.st_mode):
                if evidence_root:
                    raise PathSafetyError(f"evidence root is not a directory: {absolute}")
                raise PathSafetyError(f"path component is not a directory: {component}")
            try:
                next_descriptor = os.open(part, _DIRECTORY_FLAGS, dir_fd=current)
            except OSError as exc:
                if evidence_root:
                    raise PathSafetyError(
                        f"cannot safely open evidence root {absolute}: {exc}"
                    ) from exc
                raise PathSafetyError(
                    f"cannot safely open path component {component}: {exc}"
                ) from exc
            actual = os.fstat(next_descriptor)
            if not _same_identity(expected, actual):
                os.close(next_descriptor)
                if evidence_root:
                    raise PathSafetyError(f"evidence root changed while opening: {absolute}")
                raise PathSafetyError(f"path component changed while opening: {component}")
            os.close(current)
            current = next_descriptor
        succeeded = True
        return current, absolute
    finally:
        if not succeeded:
            os.close(current)


def _open_regular_path(path: str | Path) -> tuple[int, Path]:
    """Open a regular file without following its leaf or any ancestor symlink."""

    absolute = Path(os.path.abspath(path))
    parent_descriptor, _ = _open_absolute_directory(absolute.parent)
    descriptor: int | None = None
    succeeded = False
    try:
        try:
            expected = os.stat(absolute.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            raise PathSafetyError(
                f"cannot open regular file {absolute}: file does not exist"
            ) from None
        except OSError as exc:
            raise PathSafetyError(f"cannot inspect regular file {absolute}: {exc}") from exc
        if stat.S_ISLNK(expected.st_mode):
            raise PathSafetyError(f"symlinks are not allowed: {absolute}")
        if not stat.S_ISREG(expected.st_mode):
            raise PathSafetyError(f"path is not a regular file: {absolute}")
        try:
            descriptor = os.open(
                absolute.name,
                _OPEN_BASE_FLAGS | _NOFOLLOW | _NONBLOCK,
                dir_fd=parent_descriptor,
            )
        except OSError as exc:
            raise PathSafetyError(f"cannot open regular file {absolute}: {exc}") from exc
        actual = os.fstat(descriptor)
        if not stat.S_ISREG(actual.st_mode):
            raise PathSafetyError(f"path is not a regular file: {absolute}")
        if not _same_identity(expected, actual):
            raise PathSafetyError(f"regular file changed while opening: {absolute}")
        succeeded = True
        return descriptor, absolute
    finally:
        os.close(parent_descriptor)
        if descriptor is not None and not succeeded:
            os.close(descriptor)


def read_bounded_regular_file(path: str | Path, max_bytes: int) -> bytes:
    """Read at most ``max_bytes`` from a held, no-follow regular-file descriptor."""

    descriptor, source = _open_regular_path(path)
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_size > max_bytes:
            raise PathSafetyError(f"file exceeds {max_bytes} bytes: {source}")
        chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            chunk = os.read(descriptor, min(SHA256_CHUNK_SIZE, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > max_bytes:
            raise PathSafetyError(f"file exceeds {max_bytes} bytes: {source}")
        return b"".join(chunks)
    except OSError as exc:
        raise PathSafetyError(f"cannot read regular file {source}: {exc}") from exc
    finally:
        os.close(descriptor)


def _resolve_evidence_root(root: str | Path) -> tuple[int, Path]:
    """Return a descriptor-pinned, symlink-free evidence root and its display path."""

    return _open_absolute_directory(root, evidence_root=True)


def _open_confined_file(root: str | Path, canonical: str) -> tuple[int, Path]:
    """Open a regular evidence file beneath a descriptor-pinned root."""

    parts = PurePosixPath(canonical).parts
    root_descriptor, root_path = _resolve_evidence_root(root)
    current_descriptor = root_descriptor
    file_descriptor: int | None = None
    succeeded = False
    try:
        for part in parts[:-1]:
            try:
                expected = os.stat(part, dir_fd=current_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                raise FileNotFoundError(f"evidence file does not exist: {canonical}") from None
            except OSError as exc:
                raise PathSafetyError(f"cannot inspect evidence path {canonical!r}: {exc}") from exc
            if stat.S_ISLNK(expected.st_mode):
                raise PathSafetyError(f"symlinks are not allowed in evidence paths: {canonical!r}")
            if not stat.S_ISDIR(expected.st_mode):
                raise PathSafetyError(f"non-directory component in evidence path: {canonical!r}")
            try:
                next_descriptor = os.open(part, _DIRECTORY_FLAGS, dir_fd=current_descriptor)
            except OSError as exc:
                raise PathSafetyError(
                    f"cannot safely open evidence path {canonical!r}: {exc}"
                ) from exc
            actual = os.fstat(next_descriptor)
            if not _same_identity(expected, actual):
                os.close(next_descriptor)
                raise PathSafetyError(f"evidence path changed while opening: {canonical!r}")
            if current_descriptor != root_descriptor:
                os.close(current_descriptor)
            current_descriptor = next_descriptor

        leaf = parts[-1]
        try:
            expected_leaf = os.stat(leaf, dir_fd=current_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            raise FileNotFoundError(f"evidence file does not exist: {canonical}") from None
        except OSError as exc:
            raise PathSafetyError(f"cannot inspect evidence path {canonical!r}: {exc}") from exc
        if stat.S_ISLNK(expected_leaf.st_mode):
            raise PathSafetyError(f"symlinks are not allowed in evidence paths: {canonical!r}")
        if not stat.S_ISREG(expected_leaf.st_mode):
            raise PathSafetyError(f"evidence path is not a regular file: {canonical!r}")
        try:
            file_descriptor = os.open(
                leaf,
                _OPEN_BASE_FLAGS | _NOFOLLOW | _NONBLOCK,
                dir_fd=current_descriptor,
            )
        except OSError as exc:
            raise PathSafetyError(f"cannot safely open evidence path {canonical!r}: {exc}") from exc
        actual_leaf = os.fstat(file_descriptor)
        if not stat.S_ISREG(actual_leaf.st_mode):
            raise PathSafetyError(f"evidence path is not a regular file: {canonical!r}")
        if not _same_identity(expected_leaf, actual_leaf):
            raise PathSafetyError(f"evidence file changed while opening: {canonical!r}")
        succeeded = True
        return file_descriptor, root_path.joinpath(*parts)
    finally:
        if current_descriptor != root_descriptor:
            os.close(current_descriptor)
        os.close(root_descriptor)
        if file_descriptor is not None and not succeeded:
            os.close(file_descriptor)


def resolve_regular_file(root: str | Path, relative_path: str) -> Path:
    """Securely open and identify a regular file confined beneath ``root``."""

    canonical = normalize_relative_path(relative_path)
    descriptor, resolved = _open_confined_file(root, canonical)
    os.close(descriptor)
    return resolved


def hash_confined_file(root: str | Path, relative_path: str) -> tuple[str, int, Path]:
    """Hash a root-confined file through the same no-follow descriptor that was checked."""

    canonical = normalize_relative_path(relative_path)
    descriptor, resolved = _open_confined_file(root, canonical)
    digest = hashlib.sha256()
    size = 0
    try:
        while True:
            chunk = os.read(descriptor, SHA256_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    except OSError as exc:
        raise PathSafetyError(f"cannot read evidence path {canonical!r}: {exc}") from exc
    finally:
        os.close(descriptor)
    return digest.hexdigest(), size, resolved
