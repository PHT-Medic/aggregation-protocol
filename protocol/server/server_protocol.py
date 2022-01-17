from typing import List

from protocol.models.server_messages import ServerKeyBroadcast, BroadCastClientKeys


class ServerProtocol:

    def broadcast_keys(self, client_keys: List[BroadCastClientKeys]) -> ServerKeyBroadcast:
        return ServerKeyBroadcast(participants=client_keys)

    def broadcast_cyphers(self):
        pass
