from protocol.models.client_keys import ClientKeys
from protocol.models.server_messages import ServerKeyBroadcast


class ClientProtocol:

    def setup(self) -> ClientKeys:
        # todo get signing key and verification keys from server
        return ClientKeys()

    def process_key_broadcast(self, broadcast: ServerKeyBroadcast, k: int = 3):
        if len(broadcast.participants) < k:
            raise ValueError("Not enough participants")


    def share_keys(self):
        pass

    def create_secret_shares(self, client_keys: ClientKeys, server_keys: ServerKeyBroadcast):
        pass
