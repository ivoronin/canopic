"""The shared, stdlib-only core, used by every canopic command and every archive.

This module is embedded verbatim as ``__main__.py`` inside every ``.pyz`` archive (the
self-extractor) and imported by the canopic package. Everything decrypt-time needs lives
here: bech32 encoding, scrypt key derivation, handing secrets to ``age`` over an inherited
fd, reading an archive's members, and the whole archive-to-plaintext flow. genkey and
encrypt reuse the same derivation and fd-passing, so the name is ``core``, not
``decryptor`` - decrypt is only one of its callers.

Because it is embedded verbatim, it imports nothing from canopic and uses only the
standard library plus the ``age`` binary; keep it that way. Splitting it by concern would
just move the aggregation into the archive builder (see docs/adr/0001). Both decrypt paths
call the same functions here, so they cannot drift.

Secrets reach ``age`` only over an inherited file descriptor, never on argv or disk;
the passphrase is read from the tty and never touches disk, argv, or the environment.
"""

import argparse
import base64
import getpass
import hashlib
import json
import os
import subprocess
import sys
import zipfile

# Hardened scrypt defaults. Memory is 128 * r * N bytes; N=2**20, r=8 -> ~1 GiB.
DEFAULT_N = 1 << 20
DEFAULT_R = 8
DEFAULT_P = 1

_IDENTITY_HRP = "age-secret-key-"
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


# --- Bech32 (BIP173), pinned by a known-answer test against real age keys ---


def _polymod(values):
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            chk ^= _GEN[i] if (top >> i) & 1 else 0
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _checksum(hrp, data):
    polymod = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _to_five_bit(data):
    acc = 0
    bits = 0
    out = []
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append((acc >> bits) & 31)
    if bits:
        out.append((acc << (5 - bits)) & 31)
    return out


def encode(hrp, data):
    """Bech32-encode ``data`` under human-readable prefix ``hrp``."""
    values = _to_five_bit(data)
    combined = values + _checksum(hrp, values)
    return hrp + "1" + "".join(_CHARSET[d] for d in combined)


# --- Key derivation ---


def scrypt_maxmem(n, r, p):
    """Upper bound on scrypt's memory use, with slack, for hashlib's maxmem guard."""
    return 128 * r * (n + p + 2)


def derive_identity(password, salt, n=DEFAULT_N, r=DEFAULT_R, p=DEFAULT_P):
    """Derive the age identity string (``AGE-SECRET-KEY-1...``) from a passphrase."""
    scalar = hashlib.scrypt(
        password, salt=salt, n=n, r=r, p=p, dklen=32, maxmem=scrypt_maxmem(n, r, p)
    )
    return encode(_IDENTITY_HRP, scalar).upper()


# --- Handing secrets to the age binary ---


def run_with_secret_fd(build_argv, secret, stdin=None):
    """Run a subprocess, exposing ``secret`` only via an inherited fd.

    ``build_argv(fd)`` returns the argv, referencing the secret as ``/dev/fd/<fd>``.
    The secret never appears on argv, in the environment, or on disk. Raises
    RuntimeError on a nonzero exit.
    """
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, secret)  # secret is tiny, well under the pipe buffer
    finally:
        os.close(write_fd)
    try:
        proc = subprocess.run(
            build_argv(read_fd), input=stdin, capture_output=True, pass_fds=(read_fd,)
        )
    finally:
        os.close(read_fd)
    if proc.returncode != 0:
        message = proc.stderr.decode(errors="replace").strip() or "subprocess failed"
        raise RuntimeError(message)
    return proc.stdout


def decrypt(ciphertext, password, salt, n, r, p):
    """Re-derive the identity from the passphrase and decrypt via ``age -d``.

    Raises RuntimeError on a wrong passphrase or corrupt ciphertext (age auth fail).
    """
    identity = derive_identity(password, salt, n, r, p).encode()
    return run_with_secret_fd(
        lambda fd: ["age", "--decrypt", "-i", f"/dev/fd/{fd}"], identity, stdin=ciphertext
    )


# --- Archive access (an archive is a zipapp: shebang + zip) ---


def read_members(source):
    """Read (manifest, ciphertext) from an archive path or file-like object."""
    with zipfile.ZipFile(source) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        ciphertext = archive.read("payload.age")
    return manifest, ciphertext


def parse_kdf(doc):
    """Return (salt, n, r, p) from a key.json or manifest.json kdf block."""
    kdf = doc["kdf"]
    if kdf.get("alg") != "scrypt":
        raise ValueError(f"unsupported kdf: {kdf.get('alg')!r}")
    return base64.b64decode(kdf["salt"]), int(kdf["n"]), int(kdf["r"]), int(kdf["p"])


class DecryptError(Exception):
    """A wrong passphrase or a corrupt archive: the one error mode of decrypt_archive.

    Both decrypt paths map it to the same user-facing message, so that message lives
    in exactly one place.
    """


def decrypt_archive(source, password):
    """Decrypt an archive (path or file-like) with the passphrase, returning plaintext.

    Reads the archive's members, re-derives the identity from the passphrase, and
    decrypts via ``age``. This is the whole trusted-path flow behind two arguments;
    the ``canopic decrypt`` command and the embedded self-extractor both call it, so
    the sequence cannot drift. Raises DecryptError on a wrong passphrase or a corrupt
    archive.
    """
    manifest, ciphertext = read_members(source)
    salt, n, r, p = parse_kdf(manifest)
    try:
        return decrypt(ciphertext, password, salt, n, r, p)
    except RuntimeError:
        raise DecryptError("wrong passphrase or corrupt archive") from None


def prompt_and_decrypt(source):
    """Prompt once for the passphrase and decrypt the archive at ``source``.

    The interactive half of the trusted-path flow, shared by ``canopic decrypt`` and the
    embedded self-extractor so the prompt, the error text, and the exit code cannot drift.
    Returns the plaintext; on a wrong passphrase or corrupt archive, writes the canonical
    message to stderr and exits 1.
    """
    password = getpass.getpass("Passphrase: ").encode()
    try:
        return decrypt_archive(source, password)
    except DecryptError as exc:
        sys.stderr.write(f"canopic: {exc}\n")
        raise SystemExit(1) from None


def harden():
    """Best-effort process hardening: no core dumps, private file mode."""
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass
    os.umask(0o077)


# --- Standalone self-extractor entry point (embedded as __main__.py) ---


def _archive_path():
    loader = globals().get("__loader__")
    archive = getattr(loader, "archive", None)
    if archive and zipfile.is_zipfile(archive):
        return archive
    candidate = os.path.abspath(sys.argv[0])
    if zipfile.is_zipfile(candidate):
        return candidate
    raise SystemExit("canopic: cannot locate the archive to decrypt")


def main():
    harden()
    parser = argparse.ArgumentParser(description="Decrypt this self-extracting archive.")
    parser.add_argument("-o", "--output", help="write plaintext here (default: stdout)")
    args = parser.parse_args()

    plaintext = prompt_and_decrypt(_archive_path())
    if args.output:
        with open(args.output, "wb") as handle:
            handle.write(plaintext)
    else:
        sys.stdout.buffer.write(plaintext)


if __name__ == "__main__":
    main()
