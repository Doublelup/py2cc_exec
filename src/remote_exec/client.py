"""B-side client for the authenticated remote execution protocol."""

from __future__ import annotations

import argparse
import getpass
import socket
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import load_private_key, sign_request
from .protocol import (
    NONCE_SIZE,
    PROTOCOL_VERSION,
    ProtocolError,
    decode_bytes,
    encode_bytes,
    recv_message,
    send_message,
)


class RemoteError(Exception):
    """Raised when the server rejects a request or sends an invalid response."""


@dataclass(frozen=True)
class CommandResult:
    request_id: str
    status: str
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool


def _load_private_key_with_prompt(path: Path) -> Ed25519PrivateKey:
    try:
        return load_private_key(path)
    except TypeError:
        password = getpass.getpass(f"Passphrase for {path}: ").encode("utf-8")
        return load_private_key(path, password)


def _require_message_type(message: dict[str, Any], expected: str) -> None:
    if message.get("type") == "error":
        raise RemoteError(f"{message.get('code', 'ERROR')}: {message.get('message', '')}")
    if message.get("type") != expected or message.get("version") != PROTOCOL_VERSION:
        raise ProtocolError(f"expected a {expected} message")


class RemoteExecClient:
    def __init__(
        self,
        host: str,
        port: int,
        private_key: Ed25519PrivateKey,
        *,
        connect_timeout: float = 10.0,
    ) -> None:
        self.host = host
        self.port = port
        self.private_key = private_key
        self.connect_timeout = connect_timeout
        self.sock: socket.socket | None = None
        self.sequence = 0
        self.nonce = b""

    def connect(self) -> None:
        if self.sock is not None:
            raise RuntimeError("client is already connected")
        sock = socket.create_connection((self.host, self.port), timeout=self.connect_timeout)
        try:
            challenge = recv_message(sock)
            _require_message_type(challenge, "challenge")
            if challenge.get("sequence") != 0:
                raise ProtocolError("initial challenge has an invalid sequence")
            nonce = decode_bytes(challenge.get("nonce"), expected_length=NONCE_SIZE)
        except Exception:
            sock.close()
            raise
        sock.settimeout(None)
        self.sock = sock
        self.sequence = 0
        self.nonce = nonce

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None
        self.nonce = b""

    def __enter__(self) -> "RemoteExecClient":
        self.connect()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def execute(self, command: str, *, timeout_seconds: int = 30) -> CommandResult:
        if self.sock is None or not self.nonce:
            raise RuntimeError("client is not connected")
        if timeout_seconds < 1:
            raise ValueError("timeout_seconds must be >= 1")

        request_id = str(uuid.uuid4())
        request: dict[str, Any] = {
            "type": "exec",
            "version": PROTOCOL_VERSION,
            "sequence": self.sequence,
            "request_id": request_id,
            "nonce": encode_bytes(self.nonce),
            "command": command,
            "timeout_seconds": timeout_seconds,
        }
        request["signature"] = encode_bytes(sign_request(self.private_key, request))
        send_message(self.sock, request)
        response = recv_message(self.sock)
        _require_message_type(response, "result")
        if response.get("sequence") != self.sequence:
            raise ProtocolError("result sequence does not match the request")
        if response.get("request_id") != request_id:
            raise ProtocolError("result request_id does not match the request")

        status = response.get("status")
        exit_code = response.get("exit_code")
        if status not in {"completed", "timed_out", "rejected", "internal_error"}:
            raise ProtocolError("invalid result status")
        if exit_code is not None and type(exit_code) is not int:
            raise ProtocolError("invalid exit code")
        if type(response.get("stdout_truncated")) is not bool:
            raise ProtocolError("invalid stdout_truncated flag")
        if type(response.get("stderr_truncated")) is not bool:
            raise ProtocolError("invalid stderr_truncated flag")

        stdout = decode_bytes(response.get("stdout"))
        stderr = decode_bytes(response.get("stderr"))
        next_nonce = decode_bytes(response.get("next_nonce"), expected_length=NONCE_SIZE)
        result = CommandResult(
            request_id=request_id,
            status=status,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            stdout_truncated=response["stdout_truncated"],
            stderr_truncated=response["stderr_truncated"],
        )
        self.nonce = next_nonce
        self.sequence += 1
        return result


def _display_result(result: CommandResult, *, show_status: bool) -> int:
    sys.stdout.buffer.write(result.stdout)
    sys.stdout.buffer.flush()
    sys.stderr.buffer.write(result.stderr)
    sys.stderr.buffer.flush()
    if result.stdout_truncated:
        print("\n[stdout truncated by server]", file=sys.stderr)
    if result.stderr_truncated:
        print("\n[stderr truncated by server]", file=sys.stderr)
    if show_status:
        print(f"[status={result.status} exit={result.exit_code}]", file=sys.stderr)
    if result.status == "timed_out":
        return 124
    if result.status != "completed" or result.exit_code is None:
        return 1
    return result.exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--command", help="execute one command and exit")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    private_key = _load_private_key_with_prompt(args.private_key)
    client = RemoteExecClient(args.host, args.port, private_key)
    try:
        client.connect()
        if args.command is not None:
            raise SystemExit(_display_result(client.execute(args.command, timeout_seconds=args.timeout), show_status=False))

        print("Connected. Enter Bash commands; use :quit or Ctrl-D to leave.")
        while True:
            try:
                command = input("rexec> ")
            except EOFError:
                print()
                break
            if command == ":quit":
                break
            if not command.strip():
                continue
            result = client.execute(command, timeout_seconds=args.timeout)
            _display_result(result, show_status=True)
    except (OSError, ProtocolError, RemoteError) as exc:
        raise SystemExit(f"connection failed: {exc}") from exc
    finally:
        client.close()


if __name__ == "__main__":
    main()

