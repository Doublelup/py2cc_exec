"""Bounded, non-interactive Bash command execution."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


@dataclass(frozen=True)
class ExecutionResult:
    status: str
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool = False
    stderr_truncated: bool = False


def _drain_pipe(stream: BinaryIO, limit: int, output: dict[str, object], key: str) -> None:
    retained = bytearray()
    truncated = False
    while True:
        chunk = stream.read(64 * 1024)
        if not chunk:
            break
        remaining = max(0, limit - len(retained))
        if remaining:
            retained.extend(chunk[:remaining])
        if len(chunk) > remaining:
            truncated = True
    output[key] = bytes(retained)
    output[f"{key}_truncated"] = truncated


def _signal_process_group(proc: subprocess.Popen[bytes], sig: signal.Signals) -> None:
    try:
        os.killpg(proc.pid, sig)
    except ProcessLookupError:
        pass


def execute_bash(
    command: str,
    *,
    bash_path: str,
    workdir: Path,
    timeout_seconds: int,
    max_output_bytes: int,
) -> ExecutionResult:
    try:
        proc = subprocess.Popen(
            [bash_path, "--noprofile", "--norc", "-c", command],
            cwd=workdir,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        return ExecutionResult(
            status="internal_error",
            exit_code=None,
            stdout=b"",
            stderr=str(exc).encode("utf-8", errors="replace"),
        )

    assert proc.stdout is not None
    assert proc.stderr is not None
    captured: dict[str, object] = {}
    stdout_thread = threading.Thread(
        target=_drain_pipe,
        args=(proc.stdout, max_output_bytes, captured, "stdout"),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=_drain_pipe,
        args=(proc.stderr, max_output_bytes, captured, "stderr"),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _signal_process_group(proc, signal.SIGTERM)
        try:
            proc.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            _signal_process_group(proc, signal.SIGKILL)
            proc.wait()
    finally:
        # Do not leave background jobs holding the output pipes open.
        _signal_process_group(proc, signal.SIGTERM)

    deadline = time.monotonic() + 1.0
    for thread in (stdout_thread, stderr_thread):
        thread.join(max(0.0, deadline - time.monotonic()))
    if stdout_thread.is_alive() or stderr_thread.is_alive():
        _signal_process_group(proc, signal.SIGKILL)
        proc.stdout.close()
        proc.stderr.close()
        stdout_thread.join(timeout=0.5)
        stderr_thread.join(timeout=0.5)

    stdout = captured.get("stdout", b"")
    stderr = captured.get("stderr", b"")
    return ExecutionResult(
        status="timed_out" if timed_out else "completed",
        exit_code=None if timed_out else proc.returncode,
        stdout=stdout if isinstance(stdout, bytes) else b"",
        stderr=stderr if isinstance(stderr, bytes) else b"",
        stdout_truncated=bool(captured.get("stdout_truncated", False)),
        stderr_truncated=bool(captured.get("stderr_truncated", False)),
    )

