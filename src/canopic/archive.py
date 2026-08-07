"""Build the self-extracting ``.pyz`` archive.

The archive is a zipapp (shebang + zip) with three members: ``__main__.py`` (the
``core`` module embedded verbatim), ``manifest.json`` (salt + scrypt params), and
``payload.age`` (the age ciphertext, stored uncompressed). zipfile tolerates the
shebang prefix, so the same bytes are both executable and readable. Reading members
back out lives in :mod:`canopic.core`, shared with the self-extractor.
"""

from __future__ import annotations

import importlib.resources as resources
import io
import json
import zipfile

SHEBANG = b"#!/usr/bin/env python3\n"


def _core_source() -> str:
    return resources.files("canopic").joinpath("core.py").read_text(encoding="utf-8")


def build_pyz(manifest: dict, ciphertext: bytes) -> bytes:
    """Return the self-extractor bytes: shebang + zipapp."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("__main__.py", _core_source())
        archive.writestr("manifest.json", json.dumps(manifest))
        # Ciphertext stored uncompressed: it is high-entropy and already compact.
        archive.writestr(
            zipfile.ZipInfo("payload.age"), ciphertext, compress_type=zipfile.ZIP_STORED
        )
    return SHEBANG + buffer.getvalue()
