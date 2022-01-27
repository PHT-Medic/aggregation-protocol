import numpy as np
import pytest
from protocol import ClientProtocol, ServerProtocol
from protocol.models.server_messages import ServerKeyBroadcast, BroadCastClientKeys, ServerCipherBroadcast, UserCipher, \
    ServerUnmaskBroadCast
from protocol.models.client_keys import ClientKeys
from protocol.secrets.ciphers import decrypt_cipher
from protocol.secrets.masking import _generate_private_mask
from protocol.secrets.util import load_public_key


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

    user_key_0 = keys[0]

    protocol = ClientProtocol()

    server_protocol = ServerProtocol()

    server_broadcast = server_protocol.broadcast_cyphers(share_messages, "user-0")

    mask = protocol.process_cipher_broadcast(user_id="user-0",
                                             keys=user_key_0,
                                             participants=broadcast.participants,
                                             input=np.zeros(100),
                                             cipher_broadcast=server_broadcast,
                                             seed=seeds[0]
                                             )

    assert len(mask.masked_input) == 100


def test_create_unmask_shares():
    client_protocol = ClientProtocol()

    # set up the protocol for three participants
    keys_1, broadcast_1 = client_protocol.setup()
    keys_2, broadcast_2 = client_protocol.setup()
    keys_3, broadcast_3 = client_protocol.setup()

    user_1 = "test-user-1"
    user_2 = "test-user-2"
    user_3 = "test-user-3"

    input_size = 1000

    # step through the server protocol and generate key broadcast
    server_protocol = ServerProtocol()

    client_key_broadcasts = [BroadCastClientKeys(user_id=user_1, broadcast=broadcast_1),
                             BroadCastClientKeys(user_id=user_2, broadcast=broadcast_2),
                             BroadCastClientKeys(user_id=user_3, broadcast=broadcast_3)]
    server_key_broadcast = server_protocol.broadcast_keys(client_key_broadcasts)

    assert len(server_key_broadcast.participants) == 3

    seed_1, share_msg_1 = client_protocol.process_key_broadcast(user_id=user_1, keys=keys_1,
                                                                broadcast=server_key_broadcast, k=2)
    seed_2, share_msg_2 = client_protocol.process_key_broadcast(user_id=user_2, keys=keys_2,
                                                                broadcast=server_key_broadcast, k=2)
    seed_3, share_msg_3 = client_protocol.process_key_broadcast(user_id=user_3, keys=keys_3,
                                                                broadcast=server_key_broadcast, k=2)

    # test cipher decryption based on client messages
    decrypted_cipher = decrypt_cipher(
        recipient=user_2,
        recipient_key=keys_2.cipher_key,
        sender_key=load_public_key(broadcast_1.cipher_public_key),
        sender=user_1,
        encrypted_cypher=share_msg_1.ciphers[0].cipher
    )

    assert decrypted_cipher

    share_messages = [share_msg_1, share_msg_2, share_msg_3]

    server_cipher_broadcast_1 = server_protocol.broadcast_cyphers(shared_ciphers=share_messages, user_id=user_1)
    server_cipher_broadcast_2 = server_protocol.broadcast_cyphers(shared_ciphers=share_messages, user_id=user_2)
    server_cipher_broadcast_3 = server_protocol.broadcast_cyphers(shared_ciphers=share_messages, user_id=user_3)

    mask_1 = client_protocol.process_cipher_broadcast(user_id=user_1, keys=keys_1,
                                                      participants=server_key_broadcast.participants,
                                                      input=np.zeros(input_size),
                                                      cipher_broadcast=server_cipher_broadcast_1,
                                                      seed=seed_1)

    mask_2 = client_protocol.process_cipher_broadcast(user_id=user_2, keys=keys_2,
                                                      participants=server_key_broadcast.participants,
                                                      input=np.zeros(input_size),
                                                      cipher_broadcast=server_cipher_broadcast_2,
                                                      seed=seed_2)

    mask_3 = client_protocol.process_cipher_broadcast(user_id=user_3, keys=keys_3,
                                                      participants=server_key_broadcast.participants,
                                                      input=np.zeros(input_size),
                                                      cipher_broadcast=server_cipher_broadcast_3,
                                                      seed=seed_3)

    masked_inputs = [mask_1, mask_2, mask_3]

    masked_input_sum = np.zeros(input_size)
    for mask in masked_inputs:
        masked_input_sum += mask.masked_input

    user_1_private_mask = _generate_private_mask(seed=seed_1, n_items=input_size)
    user_2_private_mask = _generate_private_mask(seed=seed_2, n_items=input_size)
    user_3_private_mask = _generate_private_mask(seed=seed_3, n_items=input_size)
    removed_mask = masked_input_sum - user_1_private_mask - user_2_private_mask - user_3_private_mask

    print(removed_mask.sum())

    unmask_broadcast = server_protocol.broadcast_unmask_participants(masked_inputs)

    # too few participants
    with pytest.raises(ValueError):
        too_few_unmask = unmask_broadcast.copy()
        too_few_unmask.participants = too_few_unmask.participants[:1]

        unmask_shares = client_protocol.process_unmask_broadcast(
            user_id=user_1,
            keys=keys_1,
            participants=server_key_broadcast.participants,
            unmask_broadcast=too_few_unmask,
            cipher_broadcast=server_cipher_broadcast_1
        )

    unmask_shares_1 = client_protocol.process_unmask_broadcast(
        user_id=user_1,
        keys=keys_1,
        participants=server_key_broadcast.participants,
        unmask_broadcast=unmask_broadcast,
        cipher_broadcast=server_cipher_broadcast_1
    )
    assert len(unmask_shares_1.seed_shares) == 2

    unmask_shares_2 = client_protocol.process_unmask_broadcast(
        user_id=user_2,
        keys=keys_2,
        participants=server_key_broadcast.participants,
        unmask_broadcast=unmask_broadcast,
        cipher_broadcast=server_cipher_broadcast_2
    )

    unmask_shares_3 = client_protocol.process_unmask_broadcast(
        user_id=user_3,
        keys=keys_3,
        participants=server_key_broadcast.participants,
        unmask_broadcast=unmask_broadcast,
        cipher_broadcast=server_cipher_broadcast_3
    )

    client_unmask_shares = [unmask_shares_1, unmask_shares_2, unmask_shares_3]



    response = server_protocol.aggregate_masked_inputs(client_key_broadcasts=client_key_broadcasts,
                                                       masked_inputs=masked_inputs,
                                                       unmask_shares=client_unmask_shares)

    assert np.round(np.sum(response.params), 10) == 0.0


