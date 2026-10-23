"""Authenticated remote UTF-8 file operations."""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class FileOperationResult:
    status: str
    message: str
    data: dict[str, Any] = field(default_factory=dict)


_locks_guard = threading.Lock()
_path_locks: dict[Path, threading.Lock] = {}


def _path_lock(path: Path) -> threading.Lock:
    with _locks_guard:
        return _path_locks.setdefault(path, threading.Lock())


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _candidate_path(workdir: Path, file_path: str) -> Path:
    if not file_path or "\x00" in file_path:
        raise ValueError("file_path must be a non-empty path without NUL bytes")
    path = Path(file_path)
    return path if path.is_absolute() else workdir / path


def _resolve_existing(
    workdir: Path,
    file_path: str,
) -> tuple[Path | None, FileOperationResult | None]:
    try:
        candidate = _candidate_path(workdir, file_path)
    except (TypeError, ValueError) as exc:
        return None, FileOperationResult("invalid_request", str(exc))
    if candidate.is_symlink() and not candidate.exists():
        return None, FileOperationResult("not_found", "file is a dangling symbolic link")
    try:
        path = candidate.resolve(strict=True)
    except FileNotFoundError:
        return None, FileOperationResult("not_found", "file does not exist")
    except OSError as exc:
        return None, FileOperationResult("io_error", str(exc))
    try:
        if not path.is_file():
            return None, FileOperationResult("not_file", "path is not a regular file")
    except OSError as exc:
        return None, FileOperationResult("io_error", str(exc))
    return path, None


def _resolve_write_path(
    workdir: Path,
    file_path: str,
) -> tuple[Path | None, FileOperationResult | None]:
    try:
        candidate = _candidate_path(workdir, file_path)
    except (TypeError, ValueError) as exc:
        return None, FileOperationResult("invalid_request", str(exc))
    if candidate.is_symlink() and not candidate.exists():
        return None, FileOperationResult("not_found", "file is a dangling symbolic link")
    try:
        if candidate.exists():
            path = candidate.resolve(strict=True)
            if not path.is_file():
                return None, FileOperationResult("not_file", "path is not a regular file")
            return path, None
        parent = candidate.parent.resolve(strict=True)
        if not parent.is_dir():
            return None, FileOperationResult("not_found", "parent directory does not exist")
        return parent / candidate.name, None
    except FileNotFoundError:
        return None, FileOperationResult("not_found", "parent directory does not exist")
    except OSError as exc:
        return None, FileOperationResult("io_error", str(exc))


def _read_text(
    path: Path,
    max_file_bytes: int,
) -> tuple[bytes | None, str | None, FileOperationResult | None]:
    try:
        if path.stat().st_size > max_file_bytes:
            return None, None, FileOperationResult(
                "file_too_large",
                f"file exceeds the {max_file_bytes}-byte limit",
            )
        raw = path.read_bytes()
    except FileNotFoundError:
        return None, None, FileOperationResult("not_found", "file does not exist")
    except OSError as exc:
        return None, None, FileOperationResult("io_error", str(exc))
    if len(raw) > max_file_bytes:
        return None, None, FileOperationResult(
            "file_too_large",
            f"file exceeds the {max_file_bytes}-byte limit",
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, None, FileOperationResult("not_utf8", "file is not valid UTF-8 text")
    return raw, text, None


def _atomic_write(path: Path, data: bytes, mode: int | None) -> None:
    parent = path.parent
    tmp_path: Path | None = None
    fd = -1
    for _ in range(100):
        candidate = parent / f".{path.name}.py2cc-{secrets.token_hex(8)}.tmp"
        try:
            fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
            tmp_path = candidate
            break
        except FileExistsError:
            continue
    if tmp_path is None or fd < 0:
        raise OSError("could not allocate a temporary file")
    try:
        if mode is not None:
            os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as file:
            fd = -1
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(tmp_path, path)
        tmp_path = None
        try:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            parent_fd = os.open(parent, flags)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        except OSError:
            pass
    finally:
        if fd >= 0:
            os.close(fd)
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)


def read_file(
    *,
    workdir: Path,
    file_path: str,
    offset: int,
    limit: int,
    max_file_bytes: int,
) -> FileOperationResult:
    path, error = _resolve_existing(workdir, file_path)
    if error is not None or path is None:
        return error or FileOperationResult("io_error", "could not resolve file")
    with _path_lock(path):
        raw, text, error = _read_text(path, max_file_bytes)
        if error is not None or raw is None or text is None:
            return error or FileOperationResult("io_error", "could not read file")
        lines = text.splitlines(keepends=True)
        total_lines = len(lines)
        if offset > max(1, total_lines):
            return FileOperationResult(
                "invalid_request",
                f"offset {offset} is past the final line {total_lines}",
            )
        selected = lines[offset - 1 : offset - 1 + limit]
        end_line = offset + len(selected) - 1 if selected else 0
        return FileOperationResult(
            "completed",
            "file read successfully",
            {
                "file_path": str(path),
                "content": "".join(selected),
                "sha256": _sha256(raw),
                "start_line": offset if selected else 0,
                "end_line": end_line,
                "total_lines": total_lines,
            },
        )


def edit_file(
    *,
    workdir: Path,
    file_path: str,
    old_string: str,
    new_string: str,
    expected_sha256: str,
    replace_all: bool,
    max_file_bytes: int,
) -> FileOperationResult:
    if not old_string:
        return FileOperationResult("invalid_request", "old_string must not be empty")
    if old_string == new_string:
        return FileOperationResult(
            "invalid_request",
            "old_string and new_string must be different",
        )
    path, error = _resolve_existing(workdir, file_path)
    if error is not None or path is None:
        return error or FileOperationResult("io_error", "could not resolve file")
    with _path_lock(path):
        raw, text, error = _read_text(path, max_file_bytes)
        if error is not None or raw is None or text is None:
            return error or FileOperationResult("io_error", "could not read file")
        if _sha256(raw) != expected_sha256:
            return FileOperationResult(
                "stale_file",
                "file changed since it was read; call remote_read again",
            )
        replacements = text.count(old_string)
        if replacements == 0:
            return FileOperationResult("no_match", "old_string was not found")
        if replacements > 1 and not replace_all:
            return FileOperationResult(
                "ambiguous_match",
                f"old_string matched {replacements} times; provide more context or set replace_all",
            )
        replacement_count = replacements if replace_all else 1
        updated = text.replace(old_string, new_string, -1 if replace_all else 1)
        try:
            updated_raw = updated.encode("utf-8")
        except UnicodeEncodeError:
            return FileOperationResult(
                "invalid_request",
                "new_string is not valid UTF-8 text",
            )
        if len(updated_raw) > max_file_bytes:
            return FileOperationResult(
                "file_too_large",
                f"edited file exceeds the {max_file_bytes}-byte limit",
            )
        try:
            latest = path.read_bytes()
            if _sha256(latest) != expected_sha256:
                return FileOperationResult(
                    "stale_file",
                    "file changed during the edit; call remote_read again",
                )
            mode = stat.S_IMODE(path.stat().st_mode)
            _atomic_write(path, updated_raw, mode)
        except FileNotFoundError:
            return FileOperationResult("not_found", "file disappeared during the edit")
        except OSError as exc:
            return FileOperationResult("io_error", str(exc))
        return FileOperationResult(
            "completed",
            "file edited successfully",
            {
                "file_path": str(path),
                "replacements": replacement_count,
                "sha256": _sha256(updated_raw),
            },
        )


def write_file(
    *,
    workdir: Path,
    file_path: str,
    content: str,
    max_file_bytes: int,
) -> FileOperationResult:
    try:
        data = content.encode("utf-8")
    except UnicodeEncodeError:
        return FileOperationResult(
            "invalid_request",
            "content is not valid UTF-8 text",
        )
    if len(data) > max_file_bytes:
        return FileOperationResult(
            "file_too_large",
            f"content exceeds the {max_file_bytes}-byte limit",
        )
    path, error = _resolve_write_path(workdir, file_path)
    if error is not None or path is None:
        return error or FileOperationResult("io_error", "could not resolve file")
    with _path_lock(path):
        try:
            created = not path.exists()
            previous = b""
            previous_size = 0
            mode: int | None = None
            if not created:
                if not path.is_file():
                    return FileOperationResult("not_file", "path is not a regular file")
                file_stat = path.stat()
                previous_size = file_stat.st_size
                mode = stat.S_IMODE(file_stat.st_mode)
                if file_stat.st_size == len(data):
                    previous = path.read_bytes()
            changed = created or previous_size != len(data) or previous != data
            if changed:
                _atomic_write(path, data, mode)
        except FileNotFoundError:
            return FileOperationResult("not_found", "parent directory does not exist")
        except OSError as exc:
            return FileOperationResult("io_error", str(exc))
        return FileOperationResult(
            "completed",
            "file written successfully",
            {
                "file_path": str(path),
                "created": created,
                "changed": changed,
                "bytes_written": len(data),
                "sha256": _sha256(data),
            },
        )
