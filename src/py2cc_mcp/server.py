"""Local stdio MCP server backed by a persistent Py2CC client connection."""

from __future__ import annotations

import argparse
import logging
import math
import stat
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from remote_exec.client import CommandResult, RemoteError, RemoteExecClient
from remote_exec.crypto import InvalidKeyError, load_private_key
from remote_exec.protocol import ProtocolError

LOG = logging.getLogger("py2cc_mcp")

MCP_INSTRUCTIONS = """Use these tools only for user-authorized, non-interactive Bash work on the configured Py2CC host. Calls may modify the remote host and are not idempotent. Commands run in independent Bash processes without a PTY, so do not use vim, top, password prompts, or other interactive programs. Never retry a command when outcome_unknown is true."""

RUN_ANNOTATIONS = ToolAnnotations(
    title="Run remote Bash commands through Py2CC",
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=True,
)


@dataclass(frozen=True)
class MCPClientConfig:
    host: str
    port: int
    private_key: Ed25519PrivateKey
    connect_timeout: float = 10.0
    default_timeout: int = 30


ClientFactory = Callable[..., RemoteExecClient]


def _empty_result(status: str, error: str, *, outcome_unknown: bool) -> dict[str, Any]:
    return {
        "ok": False,
        "request_id": None,
        "status": status,
        "exit_code": None,
        "stdout": "",
        "stderr": error,
        "stdout_truncated": False,
        "stderr_truncated": False,
        "outcome_unknown": outcome_unknown,
    }


def _command_result(result: CommandResult) -> dict[str, Any]:
    return {
        "ok": result.status == "completed" and result.exit_code == 0,
        "request_id": result.request_id,
        "status": result.status,
        "exit_code": result.exit_code,
        "stdout": result.stdout.decode("utf-8", errors="replace"),
        "stderr": result.stderr.decode("utf-8", errors="replace"),
        "stdout_truncated": result.stdout_truncated,
        "stderr_truncated": result.stderr_truncated,
        "outcome_unknown": False,
    }


class Py2CCSession:
    """Own one serialized Py2CC connection for the lifetime of the MCP process."""

    def __init__(
        self,
        config: MCPClientConfig,
        *,
        client_factory: ClientFactory = RemoteExecClient,
    ) -> None:
        self.config = config
        self._client_factory = client_factory
        self._client: RemoteExecClient | None = None
        self._lock = threading.Lock()

    @property
    def connected(self) -> bool:
        return self._client is not None

    def _connect_locked(self) -> dict[str, Any] | None:
        if self._client is not None:
            return None
        client = self._client_factory(
            self.config.host,
            self.config.port,
            self.config.private_key,
            connect_timeout=self.config.connect_timeout,
        )
        try:
            client.connect()
        except (OSError, EOFError, ProtocolError, RemoteError) as exc:
            client.close()
            return _empty_result(
                "connection_error",
                f"{type(exc).__name__}: {exc}",
                outcome_unknown=False,
            )
        self._client = client
        return None

    def _drop_client_locked(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            finally:
                self._client = None

    def _effective_timeout(self, timeout_seconds: int | None) -> int | None:
        timeout = self.config.default_timeout if timeout_seconds is None else timeout_seconds
        if type(timeout) is not int or timeout < 1:
            return None
        return timeout

    def _execute_locked(self, command: str, timeout_seconds: int | None) -> dict[str, Any]:
        if not isinstance(command, str) or not command.strip():
            return _empty_result(
                "invalid_request",
                "command must be a non-empty string",
                outcome_unknown=False,
            )
        timeout = self._effective_timeout(timeout_seconds)
        if timeout is None:
            return _empty_result(
                "invalid_request",
                "timeout_seconds must be an integer >= 1",
                outcome_unknown=False,
            )

        connection_error = self._connect_locked()
        if connection_error is not None:
            return connection_error
        assert self._client is not None

        try:
            return _command_result(self._client.execute(command, timeout_seconds=timeout))
        except RemoteError as exc:
            self._drop_client_locked()
            return _empty_result(
                "remote_error",
                f"{type(exc).__name__}: {exc}",
                outcome_unknown=False,
            )
        except (OSError, EOFError, ProtocolError) as exc:
            # The remote command may have run if the connection failed after send.
            self._drop_client_locked()
            return _empty_result(
                "transport_error",
                f"{type(exc).__name__}: {exc}",
                outcome_unknown=True,
            )

    def run_command(self, command: str, timeout_seconds: int | None = None) -> dict[str, Any]:
        with self._lock:
            return self._execute_locked(command, timeout_seconds)

    def run_commands(
        self,
        commands: list[str],
        timeout_seconds: int | None = None,
        stop_on_error: bool = True,
    ) -> dict[str, Any]:
        if not isinstance(commands, list) or not commands:
            return {
                "ok": False,
                "status": "invalid_request",
                "results": [],
                "executed_count": 0,
                "requested_count": 0,
                "outcome_unknown": False,
                "error": "commands must be a non-empty list",
            }

        results: list[dict[str, Any]] = []
        with self._lock:
            for command in commands:
                result = self._execute_locked(command, timeout_seconds)
                results.append(result)
                connection_failed = result["status"] in {
                    "connection_error",
                    "transport_error",
                    "remote_error",
                }
                if connection_failed or (stop_on_error and not result["ok"]):
                    break

        all_attempted = len(results) == len(commands)
        all_ok = all(result["ok"] for result in results)
        if all_ok and all_attempted:
            status = "completed"
        elif all_attempted:
            status = "completed_with_errors"
        else:
            status = "stopped_on_error"
        return {
            "ok": all_ok and all_attempted,
            "status": status,
            "results": results,
            "executed_count": len(results),
            "requested_count": len(commands),
            "outcome_unknown": any(result["outcome_unknown"] for result in results),
            "error": None,
        }

    def close(self) -> None:
        with self._lock:
            self._drop_client_locked()


def create_mcp_server(session: Py2CCSession, *, log_level: str = "INFO") -> FastMCP:
    server = FastMCP(
        "py2cc",
        instructions=MCP_INSTRUCTIONS,
        log_level=log_level,
    )

    @server.tool(
        name="run_command",
        description="Run one non-interactive Bash command on the configured Py2CC host.",
        annotations=RUN_ANNOTATIONS,
        structured_output=True,
    )
    def run_command(command: str, timeout_seconds: int | None = None) -> dict[str, Any]:
        return session.run_command(command, timeout_seconds)

    @server.tool(
        name="run_commands",
        description="Run Bash commands sequentially over one authenticated Py2CC connection.",
        annotations=RUN_ANNOTATIONS,
        structured_output=True,
    )
    def run_commands(
        commands: list[str],
        timeout_seconds: int | None = None,
        stop_on_error: bool = True,
    ) -> dict[str, Any]:
        return session.run_commands(commands, timeout_seconds, stop_on_error)

    return server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--connect-timeout", type=float, default=10.0)
    parser.add_argument("--default-timeout", type=int, default=30)
    parser.add_argument("--verbose", action="store_true")
    return parser


def _load_mcp_config(args: argparse.Namespace) -> MCPClientConfig:
    if not args.host.strip():
        raise SystemExit("host must not be empty")
    if not 1 <= args.port <= 65535:
        raise SystemExit("port must be between 1 and 65535")
    if not math.isfinite(args.connect_timeout) or args.connect_timeout <= 0:
        raise SystemExit("connect-timeout must be greater than zero")
    if args.default_timeout < 1:
        raise SystemExit("default-timeout must be >= 1")

    try:
        private_key_path = args.private_key.expanduser().resolve(strict=True)
    except OSError as exc:
        raise SystemExit(f"cannot read private key: {exc}") from exc
    if not private_key_path.is_file():
        raise SystemExit(f"private key is not a file: {private_key_path}")
    mode = stat.S_IMODE(private_key_path.stat().st_mode)
    if mode & 0o077:
        raise SystemExit(
            f"private key permissions must be 600 or stricter; found {mode:03o}"
        )

    try:
        private_key = load_private_key(private_key_path)
    except TypeError as exc:
        raise SystemExit(
            "encrypted private keys are not supported by the stdio MCP server"
        ) from exc
    except (OSError, ValueError, InvalidKeyError) as exc:
        raise SystemExit(f"cannot load private key: {exc}") from exc

    return MCPClientConfig(
        host=args.host,
        port=args.port,
        private_key=private_key,
        connect_timeout=args.connect_timeout,
        default_timeout=args.default_timeout,
    )


def main() -> None:
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    session = Py2CCSession(_load_mcp_config(args))
    server = create_mcp_server(
        session,
        log_level="DEBUG" if args.verbose else "WARNING",
    )
    LOG.info("starting Py2CC MCP server for %s:%s", args.host, args.port)
    try:
        server.run(transport="stdio")
    finally:
        session.close()


if __name__ == "__main__":
    main()
