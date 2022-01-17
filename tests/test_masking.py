import pytest

from protocol import ClientProtocol
from protocol.models.server_messages import BroadCastClientKeys, ServerKeyBroadcast
from protocol.secrets.masking import generate_user_masks, generate_random_seed, integer_seed_from_hex


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


def test_generate_user_masks(cipher_broadcast):
    broadcast, keys, seeds, share_messages = cipher_broadcast

    masks = generate_user_masks(user_id="user-0", participants=broadcast.participants, user_keys=keys[0], n_params=100)
    assert len(masks) == len(keys) - 1

    masks = generate_user_masks(user_id="user-3", participants=broadcast.participants, user_keys=keys[3], n_params=100)
    assert len(masks) == len(keys) - 1


def test_generate_seed():
    for i in range(1000):
        seed = generate_random_seed()
        assert integer_seed_from_hex(seed) <= 2 ** 32 - 1
