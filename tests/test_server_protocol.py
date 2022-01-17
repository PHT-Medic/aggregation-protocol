from protocol import ServerProtocol
from protocol.models.client_keys import ClientKeys
from protocol.models.server_messages import BroadCastClientKeys, ServerKeyBroadcast


def test_server_protocol_broadcast_keys():
    protocol = ServerProtocol()

    # generate key broadcasts
    broadcasts = []
    for i in range(5):
        keys = ClientKeys()
        broadcast_in = keys.key_broadcast()
        client_broadcast = BroadCastClientKeys(
            user_id=i,
            broadcast=broadcast_in
        )
        broadcasts.append(client_broadcast)

    broadcast = protocol.broadcast_keys(broadcasts)
    assert isinstance(broadcast, ServerKeyBroadcast)
