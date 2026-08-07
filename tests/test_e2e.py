"""End-to-end round-trips through the real age binary and the actual self-extractor.

Small scrypt N for speed. getpass falls back to stdin when there is no tty, so the
subprocess tests feed the passphrase on stdin (the stub reads its ciphertext from its
own zip members, leaving stdin free).
"""

import os
import shutil
import subprocess
import sys

import pytest

from canopic import archive, core, crypto, formats

pytestmark = pytest.mark.skipif(
    shutil.which("age") is None or shutil.which("age-keygen") is None,
    reason="requires the age and age-keygen binaries",
)

SMALL_N = 1024
PASSWORD = b"correct horse battery staple"


def _make_archive(plaintext: bytes) -> bytes:
    keyfile = formats.build_keyfile(PASSWORD, os.urandom(16), n=SMALL_N)
    ciphertext = crypto.age_encrypt(plaintext, keyfile["recipient"])
    return archive.build_pyz(formats.manifest_from_keyfile(keyfile), ciphertext)


def test_trusted_path_roundtrip(tmp_path):
    plaintext = b"secret \x00\x01\x02 bytes"
    path = tmp_path / "secret.pyz"
    path.write_bytes(_make_archive(plaintext))
    assert core.decrypt_archive(str(path), PASSWORD) == plaintext


def test_trusted_path_wrong_password(tmp_path):
    path = tmp_path / "secret.pyz"
    path.write_bytes(_make_archive(b"data"))
    with pytest.raises(core.DecryptError, match="wrong passphrase or corrupt archive"):
        core.decrypt_archive(str(path), b"not the password")


def test_selfextractor_execution(tmp_path):
    plaintext = b"hello from the self extractor \xff\x00\xfe"
    path = tmp_path / "secret.pyz"
    path.write_bytes(_make_archive(plaintext))
    proc = subprocess.run(
        [sys.executable, str(path)],
        input=PASSWORD + b"\n",
        capture_output=True,
        start_new_session=True,
    )
    assert proc.returncode == 0, proc.stderr.decode(errors="replace")
    assert proc.stdout == plaintext


def test_selfextractor_shebang_execution(tmp_path):
    plaintext = b"executable archive"
    path = tmp_path / "secret.pyz"
    path.write_bytes(_make_archive(plaintext))
    path.chmod(0o755)
    proc = subprocess.run(
        [str(path)],
        input=PASSWORD + b"\n",
        capture_output=True,
        start_new_session=True,
    )
    assert proc.returncode == 0, proc.stderr.decode(errors="replace")
    assert proc.stdout == plaintext


def test_selfextractor_output_file(tmp_path):
    plaintext = b"written to a file"
    path = tmp_path / "secret.pyz"
    path.write_bytes(_make_archive(plaintext))
    out = tmp_path / "recovered.bin"
    proc = subprocess.run(
        [sys.executable, str(path), "-o", str(out)],
        input=PASSWORD + b"\n",
        capture_output=True,
        start_new_session=True,
    )
    assert proc.returncode == 0, proc.stderr.decode(errors="replace")
    assert out.read_bytes() == plaintext


def test_selfextractor_wrong_password(tmp_path):
    path = tmp_path / "secret.pyz"
    path.write_bytes(_make_archive(b"top secret"))
    proc = subprocess.run(
        [sys.executable, str(path)],
        input=b"wrong passphrase\n",
        capture_output=True,
        start_new_session=True,
    )
    assert proc.returncode != 0
    assert proc.stdout == b""
    assert b"wrong passphrase or corrupt archive" in proc.stderr
