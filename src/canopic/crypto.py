"""Calls to the age binary for the encrypt and genkey sides.

Decryption and key derivation live in :mod:`canopic.core` (shared verbatim with the
self-extractor). This module holds only what the tool itself does: encrypting to a
recipient and computing a recipient from an identity.
"""

from __future__ import annotations

import subprocess

from . import core


def recipient_from_identity(identity: str) -> str:
    """Compute the age recipient (``age1...``) for an identity via ``age-keygen -y``."""
    out = core.run_with_secret_fd(
        lambda fd: ["age-keygen", "-y", f"/dev/fd/{fd}"], identity.encode()
    )
    return out.decode().strip()


def age_encrypt(plaintext: bytes, recipient: str) -> bytes:
    """Encrypt to a recipient. The recipient is public, so argv is fine here."""
    proc = subprocess.run(["age", "-r", recipient], input=plaintext, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode(errors="replace").strip() or "age failed")
    return proc.stdout
