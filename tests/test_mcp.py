from __future__ import annotations

import argparse
import asyncio
import sys
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from py2cc_mcp import MCPClientConfig, Py2CCSession, create_mcp_server
from py2cc_mcp.server import _load_mcp_config
from py2cc_server import RemoteExecTCPServer, ServerConfig
from remote_exec.client import CommandResult
from remote_exec.crypto import generate_keypair


class FakeClient:
    def __init__(self, outcomes: list[CommandResult | BaseException]) -> None:
        self.outcomes = outcomes
        self.connect_calls = 0
        self.close_calls = 0
        self.executed: list[tuple[str, int]] = []

    def connect(self) -> None:
        self.connect_calls += 1

    def close(self) -> None:
        self.close_calls += 1

    def execute(self, command: str, *, timeout_seconds: int) -> CommandResult:
        self.executed.append((command, timeout_seconds))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def _result(request_id: str, *, exit_code: int = 0) -> CommandResult:
    return CommandResult(
        request_id=request_id,
        status="completed",
        exit_code=exit_code,
        stdout=f"out-{request_id}".encode(),
        stderr=b"",
        stdout_truncated=False,
        stderr_truncated=False,
    )


def _config() -> MCPClientConfig:
    return MCPClientConfig(
        host="127.0.0.1",
        port=9000,
        private_key=Ed25519PrivateKey.generate(),
    )


def test_run_command_reuses_one_connection() -> None:
    fake = FakeClient([_result("one"), _result("two")])
    session = Py2CCSession(_config(), client_factory=lambda *args, **kwargs: fake)

    first = session.run_command("printf one")
    second = session.run_command("printf two", timeout_seconds=7)

    assert first["stdout"] == "out-one"
    assert second["stdout"] == "out-two"
    assert fake.connect_calls == 1
    assert fake.executed == [("printf one", 30), ("printf two", 7)]


def test_run_commands_stops_on_nonzero_exit() -> None:
    fake = FakeClient([_result("one"), _result("two", exit_code=3), _result("three")])
    session = Py2CCSession(_config(), client_factory=lambda *args, **kwargs: fake)

    result = session.run_commands(["one", "two", "three"])

    assert result["status"] == "stopped_on_error"
    assert result["executed_count"] == 2
    assert [item["exit_code"] for item in result["results"]] == [0, 3]


def test_run_commands_can_continue_after_nonzero_exit() -> None:
    fake = FakeClient([_result("one"), _result("two", exit_code=3), _result("three")])
    session = Py2CCSession(_config(), client_factory=lambda *args, **kwargs: fake)

    result = session.run_commands(
        ["one", "two", "three"],
        stop_on_error=False,
    )

    assert result["status"] == "completed_with_errors"
    assert result["executed_count"] == 3


def test_transport_failure_is_not_retried_and_next_call_reconnects() -> None:
    clients = [FakeClient([EOFError("lost")]), FakeClient([_result("recovered")])]

    def factory(*args: object, **kwargs: object) -> FakeClient:
        return clients.pop(0)

    session = Py2CCSession(_config(), client_factory=factory)
    failed = session.run_command("touch marker")
    recovered = session.run_command("printf recovered")

    assert failed["status"] == "transport_error"
    assert failed["outcome_unknown"] is True
    assert recovered["ok"] is True


def test_connection_failure_has_known_outcome_and_is_not_retried() -> None:
    fake = FakeClient([])

    def fail_connect() -> None:
        fake.connect_calls += 1
        raise ConnectionRefusedError("refused")

    fake.connect = fail_connect  # type: ignore[method-assign]
    session = Py2CCSession(_config(), client_factory=lambda *args, **kwargs: fake)

    result = session.run_command("touch marker")

    assert result["status"] == "connection_error"
    assert result["outcome_unknown"] is False
    assert fake.connect_calls == 1
    assert fake.executed == []


def test_mcp_registers_both_destructive_tools() -> None:
    fake = FakeClient([_result("unused")])
    session = Py2CCSession(_config(), client_factory=lambda *args, **kwargs: fake)
    server = create_mcp_server(session)

    tools = asyncio.run(server.list_tools())

    assert {tool.name for tool in tools} == {"run_command", "run_commands"}
    assert all(tool.annotations is not None for tool in tools)
    assert all(tool.annotations.destructiveHint is True for tool in tools if tool.annotations)
    assert all(tool.annotations.idempotentHint is False for tool in tools if tool.annotations)


@pytest.fixture
def running_server(tmp_path: Path) -> Iterator[tuple[RemoteExecTCPServer, Ed25519PrivateKey]]:
    private_key = Ed25519PrivateKey.generate()
    server = RemoteExecTCPServer(
        ("127.0.0.1", 0),
        ServerConfig(
            public_key=private_key.public_key(),
            workdir=tmp_path,
            max_timeout=30,
            idle_timeout=5,
        ),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, private_key
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_session_runs_batch_against_real_server(
    running_server: tuple[RemoteExecTCPServer, Ed25519PrivateKey],
) -> None:
    server, private_key = running_server
    host, port = server.server_address
    session = Py2CCSession(MCPClientConfig(host, port, private_key))
    try:
        result = session.run_commands(
            ["printf first", "printf second >&2; exit 4"],
            stop_on_error=False,
        )
    finally:
        session.close()

    assert result["status"] == "completed_with_errors"
    assert result["results"][0]["stdout"] == "first"
    assert result["results"][1]["stderr"] == "second"
    assert result["results"][1]["exit_code"] == 4


def test_stdio_mcp_round_trip(
    running_server: tuple[RemoteExecTCPServer, Ed25519PrivateKey],
    tmp_path: Path,
) -> None:
    server, private_key = running_server
    host, port = server.server_address
    private_path = tmp_path / "client.key"
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)

    async def exercise() -> None:
        params = StdioServerParameters(
            command=sys.executable,
            args=[
                "-m",
                "py2cc_mcp",
                "--private-key",
                str(private_path),
                "--host",
                host,
                "--port",
                str(port),
            ],
        )
        async with stdio_client(params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as client:
                await client.initialize()
                tools = await client.list_tools()
                assert {tool.name for tool in tools.tools} == {
                    "run_command",
                    "run_commands",
                }
                response = await client.call_tool(
                    "run_commands",
                    {
                        "commands": ["printf alpha", "printf beta"],
                        "stop_on_error": True,
                    },
                )
                assert response.isError is False
                assert response.structuredContent is not None
                assert response.structuredContent["executed_count"] == 2
                assert [
                    item["stdout"] for item in response.structuredContent["results"]
                ] == ["alpha", "beta"]

    asyncio.run(exercise())


def test_mcp_config_rejects_encrypted_or_insecure_private_keys(tmp_path: Path) -> None:
    encrypted_private = tmp_path / "encrypted.key"
    encrypted_public = tmp_path / "encrypted.pub"
    generate_keypair(encrypted_private, encrypted_public, b"secret")

    args = argparse.Namespace(
        private_key=encrypted_private,
        host="127.0.0.1",
        port=9000,
        connect_timeout=10.0,
        default_timeout=30,
    )
    with pytest.raises(SystemExit, match="encrypted private keys"):
        _load_mcp_config(args)

    plain_private = tmp_path / "plain.key"
    plain_public = tmp_path / "plain.pub"
    generate_keypair(plain_private, plain_public, None)
    plain_private.chmod(0o644)
    args.private_key = plain_private
    with pytest.raises(SystemExit, match="permissions"):
        _load_mcp_config(args)

    args.private_key = encrypted_private
    args.host = " "
    with pytest.raises(SystemExit, match="host must not be empty"):
        _load_mcp_config(args)

    args.host = "127.0.0.1"
    args.connect_timeout = float("nan")
    with pytest.raises(SystemExit, match="connect-timeout"):
        _load_mcp_config(args)
