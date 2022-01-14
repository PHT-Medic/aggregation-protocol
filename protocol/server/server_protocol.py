from typing import List

from protocol.models.server_messages import ServerKeyBroadcast, BroadCastClientKeys


class ServerAggregationProtocol:

    def broadcast_keys(self, client_keys: List[BroadCastClientKeys]):
        return ServerKeyBroadcast(participants=client_keys)
