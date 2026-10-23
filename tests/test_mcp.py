from __future__ import annotations

import argparse
import asyncio
import hashlib
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
from remote_exec.client import CommandResult, FileResult
from remote_exec.crypto import generate_keypair


class FakeClient:
    def __init__(
        self,
        outcomes: list[CommandResult | BaseException],
        file_outcomes: list[FileResult | BaseException] | None = None,
    ) -> None:
        self.outcomes = outcomes
        self.file_outcomes = file_outcomes or []
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

    def _file_result(self) -> FileResult:
        outcome = self.file_outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def read_file(self, *args: object, **kwargs: object) -> FileResult:
        return self._file_result()

    def edit_file(self, *args: object, **kwargs: object) -> FileResult:
        return self._file_result()

    def write_file(self, *args: object, **kwargs: object) -> FileResult:
        return self._file_result()


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


def test_mcp_registers_tools_with_concrete_file_schemas() -> None:
    fake = FakeClient([_result("unused")])
    session = Py2CCSession(_config(), client_factory=lambda *args, **kwargs: fake)
    server = create_mcp_server(session)

    tools = asyncio.run(server.list_tools())

    assert {tool.name for tool in tools} == {
        "run_command",
        "run_commands",
        "remote_read",
        "remote_edit",
        "remote_write",
    }
    assert all(tool.annotations is not None for tool in tools)
    by_name = {tool.name: tool for tool in tools}
    assert by_name["run_command"].outputSchema is not None
    assert by_name["run_command"].outputSchema["additionalProperties"] is False
    assert "outcome_unknown" in by_name["run_command"].outputSchema["properties"]
    assert by_name["remote_read"].annotations is not None
    assert by_name["remote_read"].annotations.readOnlyHint is True
    assert by_name["remote_edit"].annotations is not None
    assert by_name["remote_edit"].annotations.destructiveHint is True
    edit_schema = by_name["remote_edit"].inputSchema
    assert set(edit_schema["required"]) == {
        "file_path",
        "old_string",
        "new_string",
        "expected_sha256",
    }
    assert edit_schema["properties"]["replace_all"]["default"] is False
    for name in ("remote_read", "remote_edit", "remote_write"):
        output_schema = by_name[name].outputSchema
        assert output_schema is not None
        assert "sha256" in output_schema["properties"]
        assert "sha256" in output_schema["required"]


def test_file_transport_failure_has_null_hash_and_unknown_outcome() -> None:
    fake = FakeClient([], [EOFError("lost")])
    session = Py2CCSession(_config(), client_factory=lambda *args, **kwargs: fake)

    result = session.remote_write("file.txt", "contents")

    assert result["status"] == "transport_error"
    assert result["sha256"] is None
    assert result["outcome_unknown"] is True


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
                    "remote_read",
                    "remote_edit",
                    "remote_write",
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

                written = await client.call_tool(
                    "remote_write",
                    {"file_path": "mcp.txt", "content": "one\ntwo\n"},
                )
                assert written.isError is False
                assert written.structuredContent is not None
                first_hash = written.structuredContent["sha256"]
                assert first_hash == hashlib.sha256(b"one\ntwo\n").hexdigest()

                read = await client.call_tool(
                    "remote_read",
                    {"file_path": "mcp.txt", "offset": 2, "limit": 1},
                )
                assert read.structuredContent is not None
                assert read.structuredContent["content"] == "two\n"
                assert read.structuredContent["sha256"] == first_hash

                edited = await client.call_tool(
                    "remote_edit",
                    {
                        "file_path": "mcp.txt",
                        "old_string": "two",
                        "new_string": "TWO",
                        "expected_sha256": first_hash,
                    },
                )
                assert edited.structuredContent is not None
                assert edited.structuredContent["replacements"] == 1
                assert edited.structuredContent["sha256"] == hashlib.sha256(
                    b"one\nTWO\n"
                ).hexdigest()

                stale = await client.call_tool(
                    "remote_edit",
                    {
                        "file_path": "mcp.txt",
                        "old_string": "one",
                        "new_string": "ONE",
                        "expected_sha256": first_hash,
                    },
                )
                assert stale.structuredContent is not None
                assert stale.structuredContent["status"] == "stale_file"
                assert stale.structuredContent["sha256"] is None

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
