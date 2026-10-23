from __future__ import annotations

import shlex
import socket
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from remote_exec.crypto import sign_request
from remote_exec.protocol import PROTOCOL_VERSION, encode_bytes, recv_message, send_message
from py2cc_client import RemoteExecClient
from py2cc_server import RemoteExecTCPServer, ServerConfig


@pytest.fixture
def running_server(tmp_path: Path) -> Iterator[tuple[RemoteExecTCPServer, Ed25519PrivateKey]]:
    private_key = Ed25519PrivateKey.generate()
    config = ServerConfig(
        public_key=private_key.public_key(),
        workdir=tmp_path,
        max_timeout=30,
        max_output_bytes=128,
        idle_timeout=5,
    )
    server = RemoteExecTCPServer(("127.0.0.1", 0), config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, private_key
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def _client(server: RemoteExecTCPServer, private_key: Ed25519PrivateKey) -> RemoteExecClient:
    host, port = server.server_address
    return RemoteExecClient(host, port, private_key)


def test_persistent_connection_and_bash_features(
    running_server: tuple[RemoteExecTCPServer, Ed25519PrivateKey],
) -> None:
    server, private_key = running_server
    with _client(server, private_key) as client:
        first_nonce = client.nonce
        first = client.execute("printf 'alpha\\n' | tr a-z A-Z")
        second_nonce = client.nonce
        second = client.execute("printf problem >&2; exit 7")

    assert first.stdout == b"ALPHA\n"
    assert first.exit_code == 0
    assert second.stderr == b"problem"
    assert second.exit_code == 7
    assert first_nonce != second_nonce
    assert client.sequence == 2


def test_timeout_and_output_limit_keep_connection_usable(
    running_server: tuple[RemoteExecTCPServer, Ed25519PrivateKey],
) -> None:
    server, private_key = running_server
    with _client(server, private_key) as client:
        timed_out = client.execute("sleep 2", timeout_seconds=1)
        truncated = client.execute("printf '%0200d' 0")
        final = client.execute("printf ok")

    assert timed_out.status == "timed_out"
    assert truncated.stdout_truncated
    assert len(truncated.stdout) == 128
    assert final.stdout == b"ok"


def test_replay_is_rejected_without_stopping_server(
    running_server: tuple[RemoteExecTCPServer, Ed25519PrivateKey],
    tmp_path: Path,
) -> None:
    server, private_key = running_server
    host, port = server.server_address
    marker = tmp_path / "marker"
    sock = socket.create_connection((host, port))
    challenge = recv_message(sock)
    request = {
        "type": "exec",
        "version": PROTOCOL_VERSION,
        "sequence": 0,
        "request_id": "4673d855-ec30-4afe-992e-f452530c7663",
        "nonce": challenge["nonce"],
        "command": f"printf x >> {shlex.quote(str(marker))}",
        "timeout_seconds": 2,
    }
    request["signature"] = encode_bytes(sign_request(private_key, request))
    send_message(sock, request)
    assert recv_message(sock)["type"] == "result"
    send_message(sock, request)
    assert recv_message(sock)["type"] == "error"
    sock.close()

    assert marker.read_text() == "x"
    with _client(server, private_key) as client:
        assert client.execute("printf alive").stdout == b"alive"


def test_wrong_private_key_is_rejected(
    running_server: tuple[RemoteExecTCPServer, Ed25519PrivateKey],
) -> None:
    server, good_key = running_server
    bad_key = Ed25519PrivateKey.generate()
    bad_client = _client(server, bad_key)
    bad_client.connect()
    with pytest.raises(Exception, match="AUTH_FAILED"):
        bad_client.execute("printf should-not-run")
    bad_client.close()

    with _client(server, good_key) as good_client:
        assert good_client.execute("printf accepted").stdout == b"accepted"

