import os

import numpy as np
import pytest

from protocol import ClientProtocol, ServerProtocol
from protocol.models.server_messages import BroadCastClientKeys, ServerKeyBroadcast
from protocol.secrets.masking import (generate_user_masks, generate_random_seed, integer_seed_from_hex,
                                      _generate_private_mask, create_mask, expand_seed, generate_shared_mask)


@pytest.fixture
def key_broadcast():
    protocol = ClientProtocol()

    broadcasts = []
    keys = []
    for i in range(5):
        user_keys, msg = protocol.setup()
        client_broadcast = BroadCastClientKeys(
            user_id=f"user-{i}",
            broadcast=msg
        )
        broadcasts.append(client_broadcast)
        keys.append(user_keys)

    server_broadcast = ServerKeyBroadcast(participants=broadcasts)
    return server_broadcast, keys


@pytest.fixture
def cipher_broadcast(key_broadcast):
    protocol = ClientProtocol()
    broadcast, keys = key_broadcast
    seeds = []
    share_messages = []
    for i, key in enumerate(keys):
        seed, msg = protocol.process_key_broadcast(f"user-{i}", keys[0], broadcast=broadcast)
        seeds.append(seed)
        share_messages.append(msg)

    return broadcast, keys, seeds, share_messages


def test_generate_private_mask():
    seed = os.urandom(4).hex()
    mask_1 = _generate_private_mask(seed, 1000)
    mask_2 = _generate_private_mask(seed, 1000)

    # masks from the same seed should be mostly the same
    assert np.round(np.sum(mask_1 - mask_2), 10) == 0.0

    seed2 = os.urandom(4).hex()
    mask_3 = _generate_private_mask(seed2, 1000)

    # different seeds should differ significantly
    assert np.round(np.sum(mask_1 - mask_3), 10) != 0.0


def test_generate_seed():
    for i in range(1000):
        seed = generate_random_seed()
        assert integer_seed_from_hex(seed) <= 2 ** 32 - 1


def test_create_mask(cipher_broadcast):
    broadcast, keys, seeds, share_messages = cipher_broadcast
    seed = os.urandom(4).hex()
    mask = create_mask(user_id="user-0", participants=broadcast.participants, user_keys=keys[0], n_params=100,
                       seed=seed)
    assert len(mask) == 100


def test_private_mask_removal():
    seeds = [os.urandom(4).hex() for _ in range(100)]

    input = np.zeros(100)

    for seed in seeds:
        input += expand_seed(integer_seed_from_hex(seed), 100)

    for seed in seeds:
        input -= expand_seed(integer_seed_from_hex(seed), 100)

    assert np.round(np.sum(input), 10) == 0.0


def test_shared_mask_removal():
    protocol = ClientProtocol()

    seeds = [os.urandom(4).hex() for _ in range(10)]
    keys = [protocol.setup()[0] for _ in range(10)]

    mask = np.zeros(100)
    for i, user_key in enumerate(keys):

        for j, recipient in enumerate(keys):
            if i == j:
                pass
            if i > j:
                mask += generate_shared_mask(private_key=user_key.cipher_key, public_key=recipient.cipher_key_public,
                                             n_items=100)
            if i < j:
                mask -= generate_shared_mask(private_key=user_key.cipher_key, public_key=recipient.cipher_key_public,
                                             n_items=100)

    assert np.round(np.sum(mask), 10) == 0.0


def test_generate_user_mask_removal():
    protocol = ClientProtocol()
    server_protocol = ServerProtocol()

    keys_1, key_broadcast_1 = protocol.setup()
    keys_2, key_broadcast_2 = protocol.setup()
    keys_3, key_broadcast_3 = protocol.setup()

    seed_1, seed_2, seed_3 = os.urandom(4).hex(), os.urandom(4).hex(), os.urandom(4).hex()

    user_1 = "test-user-1"
    user_2 = "test-user-2"
    user_3 = "test-user-3"

    client_key_broadcasts = [BroadCastClientKeys(user_id=user_1, broadcast=key_broadcast_1),
                             BroadCastClientKeys(user_id=user_2, broadcast=key_broadcast_2),
                             BroadCastClientKeys(user_id=user_3, broadcast=key_broadcast_3)]

    server_key_broadcast = server_protocol.broadcast_keys(client_keys=client_key_broadcasts)

    private_mask_1 = _generate_private_mask(seed_1, 100)
    private_mask_2 = _generate_private_mask(seed_2, 100)
    private_mask_3 = _generate_private_mask(seed_3, 100)

    user_mask_1 = create_mask(user_id=user_1, user_keys=keys_1, participants=server_key_broadcast.participants,
                              seed=seed_1, n_params=100)

    user_mask_2 = create_mask(user_id=user_2, user_keys=keys_2, participants=server_key_broadcast.participants,
                              seed=seed_2, n_params=100)

    user_mask_3 = create_mask(user_id=user_3, user_keys=keys_3, participants=server_key_broadcast.participants,
                              seed=seed_3, n_params=100)

    mask = user_mask_1 + user_mask_2 + user_mask_3 - private_mask_1 - private_mask_2 - private_mask_3
    print(mask.sum())

    assert np.round(np.sum(mask), 10) == 0.0
