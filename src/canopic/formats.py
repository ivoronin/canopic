"""JSON shapes for the public key file and the archive manifest.

key.json (public): recipient + salt + scrypt params. Carried to ``encrypt``.
manifest.json (inside the .pyz): salt + scrypt params only; the core re-derives
the identity from the passphrase, so no recipient is stored. Parsing the kdf block back
out lives in :mod:`canopic.core`, shared with the self-extractor.
"""

from __future__ import annotations

import base64

from . import core, crypto


def build_keyfile(
    password: bytes,
    salt: bytes,
    n: int = core.DEFAULT_N,
    r: int = core.DEFAULT_R,
    p: int = core.DEFAULT_P,
) -> dict:
    identity = core.derive_identity(password, salt, n, r, p)
    recipient = crypto.recipient_from_identity(identity)
    return {
        "v": 1,
        "scheme": "age",
        "kdf": {"alg": "scrypt", "n": n, "r": r, "p": p, "salt": base64.b64encode(salt).decode()},
        "recipient": recipient,
    }


def manifest_from_keyfile(keyfile: dict) -> dict:
    return {"v": 1, "scheme": "age", "kdf": dict(keyfile["kdf"])}
