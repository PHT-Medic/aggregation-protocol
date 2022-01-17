import os

from protocol.models.client_keys import ClientKeys
from protocol.secrets.key_agreement import derive_shared_key


def test_key_derivation():
    keys_1 = ClientKeys()
    keys_2 = ClientKeys()

    shared_key_1 = derive_shared_key(keys_1.cipher_key, keys_2.cipher_key_public)
    shared_key_2 = derive_shared_key(keys_2.cipher_key, keys_1.cipher_key_public)

    assert shared_key_1 == shared_key_2
    assert len(shared_key_1) == 32
