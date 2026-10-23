"""A-side remote command execution server."""

from __future__ import annotations

import argparse
import logging
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
from .protocol import (
    NONCE_SIZE,
    PROTOCOL_VERSION,
    SIGNATURE_SIZE,
    ProtocolError,
    decode_bytes,
    encode_bytes,
    recv_message,
    send_message,
)

LOG = logging.getLogger("py2cc_server")


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
    idle_timeout: int = 600


def _require_int(message: dict[str, Any], field: str, *, minimum: int = 0) -> int:
    value = message.get(field)
    if type(value) is not int or value < minimum:
        raise ProtocolError(f"{field} must be an integer >= {minimum}")
    return value


def _validate_request_shape(message: dict[str, Any]) -> tuple[bytes, bytes]:
    expected = {
        "type",
        "version",
        "sequence",
        "request_id",
        "nonce",
        "command",
        "timeout_seconds",
        "signature",
    }
    if set(message) != expected:
        raise ProtocolError("request has missing or unknown fields")
    if message["type"] != "exec" or message["version"] != PROTOCOL_VERSION:
        raise ProtocolError("unsupported request type or protocol version")
    _require_int(message, "sequence")
    _require_int(message, "timeout_seconds", minimum=1)
    if not isinstance(message["command"], str):
        raise ProtocolError("command must be a string")
    try:
        parsed_id = uuid.UUID(message["request_id"])
    except (AttributeError, TypeError, ValueError) as exc:
        raise ProtocolError("request_id must be a UUID") from exc
    if str(parsed_id) != message["request_id"]:
        raise ProtocolError("request_id must use canonical UUID form")
    nonce = decode_bytes(message["nonce"], expected_length=NONCE_SIZE)
    signature = decode_bytes(message["signature"], expected_length=SIGNATURE_SIZE)
    return nonce, signature


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
            },
        )

        while True:
            try:
                message = recv_message(sock)
                received_nonce, signature = _validate_request_shape(message)
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

            # The authenticated nonce is consumed before command validation or execution.
            nonce = b""
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

            next_nonce = secrets.token_bytes(NONCE_SIZE)
            try:
                send_message(
                    sock,
                    _result_message(
                        sequence=sequence,
                        request_id=message["request_id"],
                        result=result,
                        next_nonce=next_nonce,
                    ),
                )
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
    if args.max_command_bytes < 1 or args.max_output_bytes < 1:
        raise SystemExit("command and output limits must be >= 1")
    if args.idle_timeout < 1:
        raise SystemExit("idle-timeout must be >= 1")

    config = ServerConfig(
        public_key=load_public_key(args.public_key),
        workdir=workdir,
        bash_path=args.bash_path,
        max_timeout=args.max_timeout,
        max_command_bytes=args.max_command_bytes,
        max_output_bytes=args.max_output_bytes,
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

