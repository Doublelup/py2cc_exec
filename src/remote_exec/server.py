"""A-side remote command execution server."""

from __future__ import annotations

import argparse
import logging
import re
import secrets
import socket
import socketserver
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import load_public_key, verify_request
from .executor import ExecutionResult, execute_bash
from .files import FileOperationResult, edit_file, read_file, write_file
from .protocol import (
    FILE_REQUEST_TYPES,
    MAX_FRAME_SIZE,
    NONCE_SIZE,
    PROTOCOL_VERSION,
    SERVER_CAPABILITIES,
    SIGNATURE_SIZE,
    SIGNED_REQUEST_FIELDS,
    ProtocolError,
    decode_bytes,
    encode_bytes,
    recv_message,
    send_message,
)

LOG = logging.getLogger("py2cc_server")
MAX_READ_LINES = 2000
# JSON can expand one control byte to a six-byte ``\u00xx`` escape.
MAX_CONFIGURED_FILE_BYTES = (MAX_FRAME_SIZE - 64 * 1024) // 6
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class AuthenticationError(Exception):
    """Raised when a request cannot be authenticated."""


@dataclass(frozen=True)
class ServerConfig:
    public_key: Ed25519PublicKey
    workdir: Path
    bash_path: str = "/bin/bash"
    max_timeout: int = 300
    max_command_bytes: int = 64 * 1024
    max_output_bytes: int = 1024 * 1024
    max_file_bytes: int = 1024 * 1024
    idle_timeout: int = 600


def _require_int(message: dict[str, Any], field: str, *, minimum: int = 0) -> int:
    value = message.get(field)
    if type(value) is not int or value < minimum:
        raise ProtocolError(f"{field} must be an integer >= {minimum}")
    return value


def _validate_request_shape(message: dict[str, Any]) -> tuple[str, bytes, bytes]:
    request_type = message.get("type")
    if not isinstance(request_type, str) or request_type not in SIGNED_REQUEST_FIELDS:
        raise ProtocolError("unsupported request type")
    expected = {*SIGNED_REQUEST_FIELDS[request_type], "signature"}
    if set(message) != expected:
        raise ProtocolError("request has missing or unknown fields")
    if type(message["version"]) is not int or message["version"] != PROTOCOL_VERSION:
        raise ProtocolError("unsupported protocol version")
    _require_int(message, "sequence")
    try:
        parsed_id = uuid.UUID(message["request_id"])
    except (AttributeError, TypeError, ValueError) as exc:
        raise ProtocolError("request_id must be a UUID") from exc
    if str(parsed_id) != message["request_id"]:
        raise ProtocolError("request_id must use canonical UUID form")

    if request_type == "exec":
        _require_int(message, "timeout_seconds", minimum=1)
        if not isinstance(message["command"], str):
            raise ProtocolError("command must be a string")
    elif request_type == "read_file":
        if not isinstance(message["file_path"], str):
            raise ProtocolError("file_path must be a string")
        _require_int(message, "offset", minimum=1)
        limit = _require_int(message, "limit", minimum=1)
        if limit > MAX_READ_LINES:
            raise ProtocolError(f"limit must be <= {MAX_READ_LINES}")
    elif request_type == "edit_file":
        for field in ("file_path", "old_string", "new_string", "expected_sha256"):
            if not isinstance(message[field], str):
                raise ProtocolError(f"{field} must be a string")
        if type(message["replace_all"]) is not bool:
            raise ProtocolError("replace_all must be a boolean")
        if not SHA256_PATTERN.fullmatch(message["expected_sha256"]):
            raise ProtocolError("expected_sha256 must be 64 lowercase hexadecimal characters")
    elif request_type == "write_file":
        if not isinstance(message["file_path"], str):
            raise ProtocolError("file_path must be a string")
        if not isinstance(message["content"], str):
            raise ProtocolError("content must be a string")

    nonce = decode_bytes(message["nonce"], expected_length=NONCE_SIZE)
    signature = decode_bytes(message["signature"], expected_length=SIGNATURE_SIZE)
    return request_type, nonce, signature


def _send_error(sock: socket.socket, code: str, message: str) -> None:
    try:
        send_message(
            sock,
            {
                "type": "error",
                "version": PROTOCOL_VERSION,
                "code": code,
                "message": message,
            },
        )
    except (OSError, ProtocolError):
        pass


def _result_message(
    *,
    sequence: int,
    request_id: str,
    result: ExecutionResult,
    next_nonce: bytes,
) -> dict[str, Any]:
    return {
        "type": "result",
        "version": PROTOCOL_VERSION,
        "sequence": sequence,
        "request_id": request_id,
        "status": result.status,
        "exit_code": result.exit_code,
        "stdout": encode_bytes(result.stdout),
        "stderr": encode_bytes(result.stderr),
        "stdout_truncated": result.stdout_truncated,
        "stderr_truncated": result.stderr_truncated,
        "next_nonce": encode_bytes(next_nonce),
    }


def _file_result_message(
    *,
    sequence: int,
    request_id: str,
    operation: str,
    result: FileOperationResult,
    next_nonce: bytes,
) -> dict[str, Any]:
    return {
        "type": "file_result",
        "version": PROTOCOL_VERSION,
        "sequence": sequence,
        "request_id": request_id,
        "operation": operation,
        "status": result.status,
        "message": result.message,
        "data": result.data,
        "next_nonce": encode_bytes(next_nonce),
    }


def _execute_file_request(message: dict[str, Any], config: ServerConfig) -> FileOperationResult:
    request_type = message["type"]
    if request_type == "read_file":
        return read_file(
            workdir=config.workdir,
            file_path=message["file_path"],
            offset=message["offset"],
            limit=message["limit"],
            max_file_bytes=config.max_file_bytes,
        )
    if request_type == "edit_file":
        return edit_file(
            workdir=config.workdir,
            file_path=message["file_path"],
            old_string=message["old_string"],
            new_string=message["new_string"],
            expected_sha256=message["expected_sha256"],
            replace_all=message["replace_all"],
            max_file_bytes=config.max_file_bytes,
        )
    if request_type == "write_file":
        return write_file(
            workdir=config.workdir,
            file_path=message["file_path"],
            content=message["content"],
            max_file_bytes=config.max_file_bytes,
        )
    return FileOperationResult("unsupported", "file operation is not supported")


class RemoteExecHandler(socketserver.BaseRequestHandler):
    server: "RemoteExecTCPServer"

    def handle(self) -> None:
        sock: socket.socket = self.request
        config = self.server.config
        sock.settimeout(config.idle_timeout)
        nonce = secrets.token_bytes(NONCE_SIZE)
        sequence = 0
        send_message(
            sock,
            {
                "type": "challenge",
                "version": PROTOCOL_VERSION,
                "sequence": sequence,
                "nonce": encode_bytes(nonce),
                "capabilities": list(SERVER_CAPABILITIES),
            },
        )

        while True:
            try:
                message = recv_message(sock)
                request_type, received_nonce, signature = _validate_request_shape(message)
                if message["sequence"] != sequence:
                    raise AuthenticationError("sequence mismatch")
                if not secrets.compare_digest(received_nonce, nonce):
                    raise AuthenticationError("nonce mismatch")
                if not verify_request(config.public_key, message, signature):
                    raise AuthenticationError("invalid signature")
            except EOFError:
                return
            except socket.timeout:
                _send_error(sock, "IDLE_TIMEOUT", "connection was idle for too long")
                return
            except (AuthenticationError, ProtocolError) as exc:
                LOG.warning("rejected request from %s: %s", self.client_address[0], exc)
                _send_error(sock, "AUTH_FAILED", "request authentication failed")
                return
            except OSError:
                return

            # The authenticated nonce is consumed before operation validation or execution.
            nonce = b""
            next_nonce = secrets.token_bytes(NONCE_SIZE)
            if request_type == "exec":
                command = message["command"]
                timeout_seconds = message["timeout_seconds"]
                command_size = len(command.encode("utf-8"))

                if command_size > config.max_command_bytes:
                    result = ExecutionResult(
                        status="rejected",
                        exit_code=None,
                        stdout=b"",
                        stderr=b"command exceeds the server size limit",
                    )
                elif timeout_seconds > config.max_timeout:
                    result = ExecutionResult(
                        status="rejected",
                        exit_code=None,
                        stdout=b"",
                        stderr=b"requested timeout exceeds the server limit",
                    )
                else:
                    result = execute_bash(
                        command,
                        bash_path=config.bash_path,
                        workdir=config.workdir,
                        timeout_seconds=timeout_seconds,
                        max_output_bytes=config.max_output_bytes,
                    )
                response = _result_message(
                    sequence=sequence,
                    request_id=message["request_id"],
                    result=result,
                    next_nonce=next_nonce,
                )
            else:
                assert request_type in FILE_REQUEST_TYPES
                try:
                    file_result = _execute_file_request(message, config)
                except Exception:
                    LOG.exception("unexpected file operation failure")
                    file_result = FileOperationResult(
                        "io_error",
                        "internal file operation error",
                    )
                response = _file_result_message(
                    sequence=sequence,
                    request_id=message["request_id"],
                    operation=request_type,
                    result=file_result,
                    next_nonce=next_nonce,
                )

            try:
                send_message(sock, response)
            except (OSError, ProtocolError):
                return
            nonce = next_nonce
            sequence += 1


class RemoteExecTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address: tuple[str, int], config: ServerConfig):
        self.config = config
        super().__init__(server_address, RemoteExecHandler)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--workdir", type=Path, default=Path.cwd())
    parser.add_argument("--bash", default="/bin/bash", dest="bash_path")
    parser.add_argument("--max-timeout", type=int, default=300)
    parser.add_argument("--max-command-bytes", type=int, default=64 * 1024)
    parser.add_argument("--max-output-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--max-file-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--idle-timeout", type=int, default=600)
    parser.add_argument("--verbose", action="store_true")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    workdir = args.workdir.resolve(strict=True)
    if not workdir.is_dir():
        raise SystemExit(f"workdir is not a directory: {workdir}")
    if args.max_timeout < 1:
        raise SystemExit("max-timeout must be >= 1")
    if (
        args.max_command_bytes < 1
        or args.max_output_bytes < 1
        or args.max_file_bytes < 1
    ):
        raise SystemExit("command, output, and file limits must be >= 1")
    if args.max_file_bytes > MAX_CONFIGURED_FILE_BYTES:
        raise SystemExit(
            f"max-file-bytes must be <= {MAX_CONFIGURED_FILE_BYTES} to fit a protocol frame"
        )
    if args.idle_timeout < 1:
        raise SystemExit("idle-timeout must be >= 1")

    config = ServerConfig(
        public_key=load_public_key(args.public_key),
        workdir=workdir,
        bash_path=args.bash_path,
        max_timeout=args.max_timeout,
        max_command_bytes=args.max_command_bytes,
        max_output_bytes=args.max_output_bytes,
        max_file_bytes=args.max_file_bytes,
        idle_timeout=args.idle_timeout,
    )
    with RemoteExecTCPServer((args.host, args.port), config) as server:
        host, port = server.server_address
        print(f"listening on {host}:{port}; workdir={workdir}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nserver stopped", flush=True)


if __name__ == "__main__":
    main()

