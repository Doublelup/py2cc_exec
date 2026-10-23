from __future__ import annotations

import hashlib
import os
from pathlib import Path

from remote_exec.files import edit_file, read_file, write_file


MAX_FILE_BYTES = 1024 * 1024


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_read_file_returns_raw_line_window_and_whole_file_hash(tmp_path: Path) -> None:
    path = tmp_path / "sample.txt"
    raw = "alpha\nβeta\ngamma".encode()
    path.write_bytes(raw)

    result = read_file(
        workdir=tmp_path,
        file_path="sample.txt",
        offset=2,
        limit=1,
        max_file_bytes=MAX_FILE_BYTES,
    )

    assert result.status == "completed"
    assert result.data == {
        "file_path": str(path),
        "content": "βeta\n",
        "sha256": _hash(raw),
        "start_line": 2,
        "end_line": 2,
        "total_lines": 3,
    }


def test_read_file_rejects_invalid_utf8_range_and_large_file(tmp_path: Path) -> None:
    binary = tmp_path / "binary.dat"
    binary.write_bytes(b"\xff")
    assert read_file(
        workdir=tmp_path,
        file_path=str(binary),
        offset=1,
        limit=1,
        max_file_bytes=100,
    ).status == "not_utf8"

    text = tmp_path / "text.txt"
    text.write_text("one\ntwo\n")
    assert read_file(
        workdir=tmp_path,
        file_path="text.txt",
        offset=3,
        limit=1,
        max_file_bytes=100,
    ).status == "invalid_request"
    assert read_file(
        workdir=tmp_path,
        file_path="text.txt",
        offset=1,
        limit=1,
        max_file_bytes=3,
    ).status == "file_too_large"


def test_read_empty_file_returns_hash_and_only_accepts_first_offset(
    tmp_path: Path,
) -> None:
    path = tmp_path / "empty.txt"
    path.write_bytes(b"")

    result = read_file(
        workdir=tmp_path,
        file_path="empty.txt",
        offset=1,
        limit=10,
        max_file_bytes=100,
    )

    assert result.status == "completed"
    assert result.data["content"] == ""
    assert result.data["sha256"] == _hash(b"")
    assert result.data["total_lines"] == 0
    assert read_file(
        workdir=tmp_path,
        file_path="empty.txt",
        offset=2,
        limit=10,
        max_file_bytes=100,
    ).status == "invalid_request"


def test_edit_file_requires_current_hash_and_unique_match(tmp_path: Path) -> None:
    path = tmp_path / "module.py"
    original = b"value = 1\nvalue = 1\n"
    path.write_bytes(original)

    ambiguous = edit_file(
        workdir=tmp_path,
        file_path="module.py",
        old_string="value = 1",
        new_string="value = 2",
        expected_sha256=_hash(original),
        replace_all=False,
        max_file_bytes=MAX_FILE_BYTES,
    )
    assert ambiguous.status == "ambiguous_match"
    assert path.read_bytes() == original

    missing = edit_file(
        workdir=tmp_path,
        file_path="module.py",
        old_string="not present",
        new_string="replacement",
        expected_sha256=_hash(original),
        replace_all=False,
        max_file_bytes=MAX_FILE_BYTES,
    )
    assert missing.status == "no_match"
    assert path.read_bytes() == original

    unchanged = edit_file(
        workdir=tmp_path,
        file_path="module.py",
        old_string="value = 1",
        new_string="value = 1",
        expected_sha256=_hash(original),
        replace_all=True,
        max_file_bytes=MAX_FILE_BYTES,
    )
    assert unchanged.status == "invalid_request"
    assert path.read_bytes() == original

    stale = edit_file(
        workdir=tmp_path,
        file_path="module.py",
        old_string="value = 1",
        new_string="value = 2",
        expected_sha256="0" * 64,
        replace_all=True,
        max_file_bytes=MAX_FILE_BYTES,
    )
    assert stale.status == "stale_file"
    assert stale.data == {}
    assert path.read_bytes() == original

    completed = edit_file(
        workdir=tmp_path,
        file_path="module.py",
        old_string="value = 1",
        new_string="value = 2",
        expected_sha256=_hash(original),
        replace_all=True,
        max_file_bytes=MAX_FILE_BYTES,
    )
    updated = b"value = 2\nvalue = 2\n"
    assert completed.status == "completed"
    assert completed.data["replacements"] == 2
    assert completed.data["sha256"] == _hash(updated)
    assert path.read_bytes() == updated


def test_edit_file_can_delete_text_and_preserves_mode(tmp_path: Path) -> None:
    path = tmp_path / "script.sh"
    path.write_text("keep\nremove\n")
    path.chmod(0o750)
    original_hash = _hash(path.read_bytes())

    result = edit_file(
        workdir=tmp_path,
        file_path=str(path),
        old_string="remove\n",
        new_string="",
        expected_sha256=original_hash,
        replace_all=False,
        max_file_bytes=MAX_FILE_BYTES,
    )

    assert result.status == "completed"
    assert path.read_text() == "keep\n"
    assert path.stat().st_mode & 0o777 == 0o750


def test_write_file_creates_overwrites_and_reports_hash(tmp_path: Path) -> None:
    path = tmp_path / "new.txt"
    created = write_file(
        workdir=tmp_path,
        file_path="new.txt",
        content="hello\n",
        max_file_bytes=MAX_FILE_BYTES,
    )
    assert created.status == "completed"
    assert created.data["created"] is True
    assert created.data["changed"] is True
    assert created.data["sha256"] == _hash(b"hello\n")

    path.chmod(0o640)
    unchanged = write_file(
        workdir=tmp_path,
        file_path=str(path),
        content="hello\n",
        max_file_bytes=MAX_FILE_BYTES,
    )
    assert unchanged.data["created"] is False
    assert unchanged.data["changed"] is False

    overwritten = write_file(
        workdir=tmp_path,
        file_path="new.txt",
        content="updated\n",
        max_file_bytes=MAX_FILE_BYTES,
    )
    assert overwritten.data["changed"] is True
    assert path.read_text() == "updated\n"
    assert path.stat().st_mode & 0o777 == 0o640


def test_write_file_can_replace_a_larger_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "large.txt"
    path.write_bytes(b"x" * 100)

    result = write_file(
        workdir=tmp_path,
        file_path="large.txt",
        content="small",
        max_file_bytes=10,
    )

    assert result.status == "completed"
    assert result.data["changed"] is True
    assert path.read_bytes() == b"small"


def test_file_operations_follow_existing_symlink_and_reject_directory(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.txt"
    target.write_text("target")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    result = write_file(
        workdir=tmp_path,
        file_path="link.txt",
        content="changed",
        max_file_bytes=MAX_FILE_BYTES,
    )
    assert result.status == "completed"
    assert link.is_symlink()
    assert target.read_text() == "changed"

    directory_result = write_file(
        workdir=tmp_path,
        file_path=str(tmp_path),
        content="no",
        max_file_bytes=MAX_FILE_BYTES,
    )
    assert directory_result.status == "not_file"

    missing_parent = write_file(
        workdir=tmp_path,
        file_path="missing/file.txt",
        content="no",
        max_file_bytes=MAX_FILE_BYTES,
    )
    assert missing_parent.status == "not_found"


def test_new_file_respects_process_umask(tmp_path: Path) -> None:
    previous_umask = os.umask(0o027)
    try:
        result = write_file(
            workdir=tmp_path,
            file_path="mode.txt",
            content="mode",
            max_file_bytes=MAX_FILE_BYTES,
        )
    finally:
        os.umask(previous_umask)

    assert result.status == "completed"
    assert (tmp_path / "mode.txt").stat().st_mode & 0o777 == 0o640
