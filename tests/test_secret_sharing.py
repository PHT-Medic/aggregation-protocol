import pytest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes

from protocol.secrets.secret_sharing import create_key_shares, combine_sharing_key_shares


def test_create_key_shares():
    sharing_key = ec.generate_private_key(ec.SECP384R1())

    sharing_key_hex = sharing_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).hex()

    shares = create_key_shares(sharing_key_hex, 10, 4)

    assert len(shares) == 10

    recovered_key = combine_sharing_key_shares(shares)
