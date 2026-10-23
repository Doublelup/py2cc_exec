"""Generate the Ed25519 key pair used by the client and server."""

from __future__ import annotations

import argparse
import getpass
from pathlib import Path

from .crypto import generate_keypair


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-key", type=Path, default=Path("keys/client.key"))
    parser.add_argument("--public-key", type=Path, default=Path("keys/client.pub"))
    parser.add_argument(
        "--no-passphrase",
        action="store_true",
        help="store the private key without encryption (lab automation only)",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    password: bytes | None = None
    if not args.no_passphrase:
        first = getpass.getpass("Private-key passphrase: ")
        second = getpass.getpass("Repeat passphrase: ")
        if not first:
            raise SystemExit("passphrase cannot be empty; use --no-passphrase explicitly")
        if first != second:
            raise SystemExit("passphrases do not match")
        password = first.encode("utf-8")

    try:
        generate_keypair(args.private_key, args.public_key, password)
    except FileExistsError as exc:
        raise SystemExit(str(exc)) from exc
    print(f"private key: {args.private_key}")
    print(f"public key:  {args.public_key}")


if __name__ == "__main__":
    main()

