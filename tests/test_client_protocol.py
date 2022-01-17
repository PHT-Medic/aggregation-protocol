import pytest
from protocol import ClientProtocol
from protocol.models.server_messages import ServerKeyBroadcast, BroadCastClientKeys
from protocol.models.client_keys import ClientKeys


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



def test_protocol_setup():
    protocol = ClientProtocol()
    keys, msg = protocol.setup()
    assert keys.hex_sharing_key
    assert keys.hex_cipher_key


def test_protocol_process_keys_from_server(key_broadcast):
    protocol = ClientProtocol()
    server_broadcast, keys = key_broadcast

    seed, response = protocol.process_key_broadcast("test", keys[0], server_broadcast)

    # error too few participants
    too_few = server_broadcast.copy()
    too_few.participants = server_broadcast.participants[:2]
    with pytest.raises(ValueError):
        protocol.process_key_broadcast("test", keys[0], too_few)

    # error when there are duplicate sharing keys
    duplicate_sharing_key_broadcast = server_broadcast.copy()
    duplicate_sharing_key_broadcast.participants[0].broadcast.sharing_public_key = "abab"
    duplicate_sharing_key_broadcast.participants[1].broadcast.sharing_public_key = "abab"

    with pytest.raises(ValueError):
        protocol.process_key_broadcast("test", keys[0], duplicate_sharing_key_broadcast)

    # error when there are duplicate cipher keys
    duplicate_cipher = server_broadcast.copy()
    duplicate_cipher.participants[0].broadcast.cipher_public_key = "abab"
    duplicate_cipher.participants[1].broadcast.cipher_public_key = "abab"

    with pytest.raises(ValueError):
        protocol.process_key_broadcast("test", keys[0], duplicate_cipher)


def test_share_keys(key_broadcast):
    protocol = ClientProtocol()
    server_broadcast, keys = key_broadcast

    seed, msg = protocol.process_key_broadcast("test", keys[0], server_broadcast)

    wrong_num_keys = server_broadcast.copy()
    wrong_num_keys.participants = server_broadcast.participants[:2]

    with pytest.raises(ValueError):
        seed, msg = protocol.process_key_broadcast("test", keys[0], wrong_num_keys)


def test_masking(cipher_broadcast):
    broadcast, keys, seeds, share_messages = cipher_broadcast

    print(broadcast.participants)
    user_key_0 = keys[0]
    user_key_1 = keys[1]





