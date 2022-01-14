import pytest

from protocol.models.client_keys import ClientKeys
from protocol.secrets.secret_sharing import combine_key_shares


def test_create_key_shares():
    keys = ClientKeys()
    shares = keys.create_key_shares(10, 3)
    assert len(shares.shares) == 10


def test_combine_key_shares():
    keys = ClientKeys()
    shares = keys.create_key_shares(10, 3)
    assert len(shares.shares) == 10

    combined_key = combine_key_shares(shares.shares)

    assert combined_key.hex() == keys.hex_sharing_key
