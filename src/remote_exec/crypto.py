"""Ed25519 key management and request signing."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .protocol import request_signing_bytes


class KeyErrorBase(Exception):
    """Base class for key loading and creation errors."""


class InvalidKeyError(KeyErrorBase):
    """Raised when a key file is not an Ed25519 key."""


def _write_new_file(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(data)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def generate_keypair(
    private_key_path: Path,
    public_key_path: Path,
    password: bytes | None,
) -> None:
    if private_key_path.exists() or public_key_path.exists():
        raise FileExistsError("refusing to overwrite an existing key file")

    private_key = Ed25519PrivateKey.generate()
    encryption: serialization.KeySerializationEncryption
    if password is None:
        encryption = serialization.NoEncryption()
    else:
        encryption = serialization.BestAvailableEncryption(password)

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    _write_new_file(private_key_path, private_bytes, 0o600)
    try:
        _write_new_file(public_key_path, public_bytes, 0o644)
    except Exception:
        private_key_path.unlink(missing_ok=True)
        raise


def load_private_key(path: Path, password: bytes | None = None) -> Ed25519PrivateKey:
    key: Any = serialization.load_pem_private_key(path.read_bytes(), password=password)
    if not isinstance(key, Ed25519PrivateKey):
        raise InvalidKeyError("private key is not an Ed25519 key")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    key: Any = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise InvalidKeyError("public key is not an Ed25519 key")
    return key


def sign_request(private_key: Ed25519PrivateKey, request: dict[str, Any]) -> bytes:
    return private_key.sign(request_signing_bytes(request))


def verify_request(
    public_key: Ed25519PublicKey,
    request: dict[str, Any],
    signature: bytes,
) -> bool:
    try:
        public_key.verify(signature, request_signing_bytes(request))
    except InvalidSignature:
        return False
    return True

