from protocol import ClientProtocol
from protocol.secrets.ciphers import decrypt_cipher
from protocol.models.client_keys import ClientKeys
from protocol.models.secrets import Cipher
from protocol.secrets.secret_sharing import create_secret_shares
from protocol.models.server_messages import ServerKeyBroadcast, BroadCastClientKeys
from protocol.models.client_messages import ShareKeysMessage
from protocol.secrets.util import load_public_key


def test_ciphers():
    protocol = ClientProtocol()
    keys_1, broadcast_1 = protocol.setup()
    keys_2, broadcast_2 = protocol.setup()

    sender = "test-sender"
    receiver = "test-receiver"

    server_broadcast = ServerKeyBroadcast(
        participants=[
            BroadCastClientKeys(
                user_id=sender,
                broadcast=broadcast_1
            ),
            BroadCastClientKeys(
                user_id=receiver,
                broadcast=broadcast_2
            ),

        ]
    )
    seed_1, share_msg_1 = protocol.process_key_broadcast(user_id=sender, keys=keys_1, broadcast=server_broadcast, k=2)
    seed_2, share_msg_2 = protocol.process_key_broadcast(user_id=receiver, keys=keys_2, broadcast=server_broadcast, k=2)

    cipher = share_msg_1.ciphers[0]

    assert cipher.recipient == receiver

    decrypted_cipher = decrypt_cipher(
        recipient=receiver,
        recipient_key=keys_2.cipher_key,
        sender_key=load_public_key(broadcast_1.cipher_public_key),
        sender=sender,
        encrypted_cypher=cipher.cipher
    )

    assert decrypted_cipher.sender == sender
    assert decrypted_cipher.recipient == receiver
    assert decrypted_cipher.key_share

    print(share_msg_1)
    print(share_msg_2)
