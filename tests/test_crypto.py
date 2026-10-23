from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from remote_exec.crypto import (
    generate_keypair,
    load_private_key,
    load_public_key,
    sign_request,
    verify_request,
)
from remote_exec.protocol import encode_bytes


def _request() -> dict[str, object]:
    return {
        "type": "exec",
        "version": 1,
        "sequence": 0,
        "request_id": "d5683108-fd95-43c5-b722-a334de529643",
        "nonce": encode_bytes(b"n" * 32),
        "command": "printf hello",
        "timeout_seconds": 10,
    }


def test_generated_key_pair_signs_and_verifies(tmp_path: Path) -> None:
    private_path = tmp_path / "client.key"
    public_path = tmp_path / "client.pub"
    generate_keypair(private_path, public_path, None)

    private_key = load_private_key(private_path)
    public_key = load_public_key(public_path)
    request = _request()
    signature = sign_request(private_key, request)

    assert verify_request(public_key, request, signature)
    request["command"] = "printf altered"
    assert not verify_request(public_key, request, signature)
    assert private_path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    ("request_data", "changed_field", "changed_value"),
    [
        (
            {"type": "read_file", "file_path": "a.py", "offset": 1, "limit": 20},
            "limit",
            21,
        ),
        (
            {
                "type": "edit_file",
                "file_path": "a.py",
                "old_string": "old",
                "new_string": "new",
                "expected_sha256": "0" * 64,
                "replace_all": False,
            },
            "new_string",
            "altered",
        ),
        (
            {"type": "write_file", "file_path": "a.py", "content": "contents"},
            "content",
            "altered",
        ),
    ],
)
def test_file_request_signatures_cover_every_operation_field(
    request_data: dict[str, object],
    changed_field: str,
    changed_value: object,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    request_data.update(
        version=1,
        sequence=0,
        request_id="d5683108-fd95-43c5-b722-a334de529643",
        nonce=encode_bytes(b"n" * 32),
    )

    signature = sign_request(private_key, request_data)

    assert verify_request(public_key, request_data, signature)
    request_data[changed_field] = changed_value
    assert not verify_request(public_key, request_data, signature)

