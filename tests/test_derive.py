"""Behavior tests for password → age identity derivation.

Small scrypt N here for speed; genkey uses the hardened default. These assert the
derivation is deterministic and sensitive to both inputs (the properties the whole
scheme relies on), not any particular byte value.
"""

from canopic import core

SALT_A = b"0123456789abcdef"
SALT_B = b"fedcba9876543210"


def test_identity_is_deterministic():
    i1 = core.derive_identity(b"hunter2", SALT_A, n=1024)
    i2 = core.derive_identity(b"hunter2", SALT_A, n=1024)
    assert i1 == i2
    assert i1.startswith("AGE-SECRET-KEY-1")


def test_identity_varies_with_salt():
    a = core.derive_identity(b"hunter2", SALT_A, n=1024)
    b = core.derive_identity(b"hunter2", SALT_B, n=1024)
    assert a != b


def test_identity_varies_with_password():
    a = core.derive_identity(b"hunter2", SALT_A, n=1024)
    b = core.derive_identity(b"hunter3", SALT_A, n=1024)
    assert a != b
