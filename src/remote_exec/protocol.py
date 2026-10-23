"""Wire framing and canonical request encoding."""

from __future__ import annotations

import base64
import binascii
import json
import struct
from collections.abc import Mapping
from typing import Any

PROTOCOL_VERSION = 1
SIGNING_DOMAIN = b"REMOTE-EXEC-V1\x00"
NONCE_SIZE = 32
SIGNATURE_SIZE = 64
MAX_FRAME_SIZE = 8 * 1024 * 1024

SIGNED_REQUEST_FIELDS = (
    "type",
    "version",
    "sequence",
    "request_id",
    "nonce",
    "command",
    "timeout_seconds",
)


class ProtocolError(Exception):
    """Raised when a peer sends an invalid protocol message."""


def encode_bytes(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def decode_bytes(value: object, *, expected_length: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise ProtocolError("expected a Base64 string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ProtocolError("invalid Base64 data") from exc
    if expected_length is not None and len(decoded) != expected_length:
        raise ProtocolError(f"expected {expected_length} decoded bytes")
    return decoded


def canonical_json(message: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            message,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProtocolError("message is not valid JSON") from exc


def request_signing_bytes(request: Mapping[str, Any]) -> bytes:
    try:
        signed_request = {field: request[field] for field in SIGNED_REQUEST_FIELDS}
    except KeyError as exc:
        raise ProtocolError(f"missing signed field: {exc.args[0]}") from exc
    return SIGNING_DOMAIN + canonical_json(signed_request)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def decode_message(payload: bytes) -> dict[str, Any]:
    try:
        message = json.loads(payload.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except ProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid JSON message") from exc
    if not isinstance(message, dict):
        raise ProtocolError("top-level message must be an object")
    return message


def recv_exact(sock: Any, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise EOFError("peer closed the connection")
        chunks.extend(chunk)
    return bytes(chunks)


def recv_message(sock: Any, *, max_frame_size: int = MAX_FRAME_SIZE) -> dict[str, Any]:
    header = recv_exact(sock, 4)
    (size,) = struct.unpack(">I", header)
    if size == 0 or size > max_frame_size:
        raise ProtocolError(f"invalid frame size: {size}")
    return decode_message(recv_exact(sock, size))


def send_message(sock: Any, message: Mapping[str, Any], *, max_frame_size: int = MAX_FRAME_SIZE) -> None:
    payload = canonical_json(message)
    if not payload or len(payload) > max_frame_size:
        raise ProtocolError(f"invalid outgoing frame size: {len(payload)}")
    sock.sendall(struct.pack(">I", len(payload)) + payload)

