import os

import pytest
from cryptography.hazmat.primitives import serialization

from protocol.models import HexString
from protocol.models.client_keys import ClientKeys
from protocol.secrets.secret_sharing import combine_key_shares, create_seed_shares, combine_seed_shares, \
    create_secret_shares
from protocol.secrets.masking import generate_random_seed

from Crypto.Protocol.SecretSharing import Shamir


def test_shamir_library():
    test_bytes = os.urandom(16)
    shares = Shamir.split(6, 10, test_bytes, ssss=False)
    assert len(shares) == 10

    recovered = Shamir.combine(shares[:6], ssss=False)
    assert recovered == test_bytes

    recovered = Shamir.combine(shares[:5], ssss=False)
    assert recovered != test_bytes


def test_create_key_shares():
    keys = ClientKeys()
    shares = keys.create_key_shares(10, 3)
    assert len(shares) == 10


def test_combine_key_shares():
    keys = ClientKeys()
    shares = keys.create_key_shares(10, 3)
    assert len(shares) == 10

    combined_key = combine_key_shares(shares)

    assert combined_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).hex() == keys.hex_sharing_key

    with pytest.raises(ValueError):
        combined_key = combine_key_shares(shares[:2])

    byte_shares = [s.get_bytes() for s in shares[0].segments]
    print(byte_shares)


def test_combine_key_shares_invalid_shares():
    keys = ClientKeys()
    shares = keys.create_key_shares(10, 6)
    assert len(shares) == 10

    combined_key = combine_key_shares(shares)
    assert combined_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).hex() == keys.hex_sharing_key

    # corrupt one of the given secrets
    shares[0].segments[5] = HexString(os.urandom(16).hex())
    with pytest.raises(ValueError):
        combined_key = combine_key_shares(shares[:6])

    # too few shares
    with pytest.raises(ValueError):
        combined_key = combine_key_shares(shares[:3])


def test_mask_seed_sharing():
    seed = os.urandom(4).hex()

    int_seed = int(seed, 16)

    shares = create_seed_shares(seed, 10, 3)
    assert len(shares) == 10

    combined_key = combine_seed_shares(shares)

    assert int(combined_key.hex(), 16) == int_seed


def test_create_secret_shares():
    seed = os.urandom(4).hex()
    keys = ClientKeys()
    shares = create_secret_shares(keys.hex_sharing_key, seed, 10, 3)

    assert shares.key_shares
    assert shares.seed_shares
