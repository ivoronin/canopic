"""Known-answer tests for the Bech32 encoder.

Ground truth is a real keypair emitted by `age-keygen`, decoded to its raw 32-byte
scalar/point. These vectors need no `age` binary at test time.
"""

from canopic.core import encode

# A real age keypair (from `age-keygen`), decoded to raw bytes.
KAT_SECRET = bytes.fromhex("8eb30d41a3a372ee93889431ca33457a9e97ddbb7bec9ce90382f08f5b7a5b8d")
KAT_IDENTITY = "AGE-SECRET-KEY-136ES6SDR5DEWAYUGJSCU5V69020F0HDM00KFE6GRSTCG7KM6TWXS3KX4KA"

KAT_PUBLIC = bytes.fromhex("618322669bedd1f1c50e1cdbccea1cbbe8ec49398660a3c79c73340865411d40")
KAT_RECIPIENT = "age1vxpjye5mahglr3gwrndue6suh05wcjfeses283uuwv6qse2pr4qq72wt6e"


def test_identity_encoding_matches_age():
    # age identities use HRP "age-secret-key-" (trailing hyphen), uppercased.
    assert encode("age-secret-key-", KAT_SECRET).upper() == KAT_IDENTITY


def test_recipient_encoding_matches_age():
    # age recipients use HRP "age", lowercase.
    assert encode("age", KAT_PUBLIC) == KAT_RECIPIENT
