"""Command-line interface: genkey, encrypt, decrypt.

genkey and encrypt run on your own machine; decrypt is the trusted path that reads a
self-extractor's data members with the installed canopic instead of running its embedded
code. Everything is a stdin/stdout filter unless -i/-o/-k say otherwise.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys

from . import __version__, archive, core, crypto, formats


def _read_input(path: str | None) -> bytes:
    if path:
        with open(path, "rb") as handle:
            return handle.read()
    return sys.stdin.buffer.read()


def _write_bytes(path: str | None, data: bytes, *, executable: bool = False) -> None:
    if path:
        with open(path, "wb") as handle:
            handle.write(data)
        if executable:
            os.chmod(path, 0o700)
    else:
        sys.stdout.buffer.write(data)


def _write_text(path: str | None, text: str) -> None:
    if path:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)


def _prompt_new_passphrase() -> bytes:
    while True:
        first = getpass.getpass("Passphrase: ")
        if not first:
            print("canopic: passphrase must not be empty", file=sys.stderr)
            continue
        again = getpass.getpass("Confirm passphrase: ")
        if first != again:
            print("canopic: passphrases did not match; try again", file=sys.stderr)
            continue
        return first.encode()


def cmd_genkey(args: argparse.Namespace) -> None:
    password = _prompt_new_passphrase()
    salt = os.urandom(16)
    keyfile = formats.build_keyfile(password, salt)
    _write_text(args.output, json.dumps(keyfile, indent=2) + "\n")


def cmd_encrypt(args: argparse.Namespace) -> None:
    with open(args.key, encoding="utf-8") as handle:
        keyfile = json.load(handle)
    ciphertext = crypto.age_encrypt(_read_input(args.input), keyfile["recipient"])
    pyz = archive.build_pyz(formats.manifest_from_keyfile(keyfile), ciphertext)
    _write_bytes(args.output, pyz, executable=bool(args.output))


def cmd_decrypt(args: argparse.Namespace) -> None:
    _write_bytes(args.output, core.prompt_and_decrypt(args.archive))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="canopic",
        description="Password-derived asymmetric encryption to a self-extracting archive.",
    )
    parser.add_argument("--version", action="version", version=f"canopic {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    genkey = sub.add_parser("genkey", help="derive a public key from a passphrase")
    genkey.add_argument("-o", "--output", help="write key.json here (default: stdout)")
    genkey.set_defaults(func=cmd_genkey)

    encrypt = sub.add_parser("encrypt", help="encrypt to a public key into a self-extractor")
    encrypt.add_argument("-i", "--input", help="plaintext file (default: stdin)")
    encrypt.add_argument("-o", "--output", help="archive file (default: stdout)")
    encrypt.add_argument("-k", "--key", required=True, help="key.json from genkey")
    encrypt.set_defaults(func=cmd_encrypt)

    decrypt = sub.add_parser("decrypt", help="decrypt a .pyz archive (trusted path)")
    decrypt.add_argument("-o", "--output", help="write plaintext here (default: stdout)")
    decrypt.add_argument("archive", help="the .pyz archive to decrypt")
    decrypt.set_defaults(func=cmd_decrypt)
    return parser


def main(argv: list[str] | None = None) -> None:
    core.harden()
    args = _build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
