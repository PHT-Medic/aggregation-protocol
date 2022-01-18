from typing import List

from protocol.models.server_messages import (ServerKeyBroadcast, BroadCastClientKeys, ServerCipherBroadcast, UserCipher)
from protocol.models.client_messages import ShareKeysMessage, MaskedInput


class ServerProtocol:

    def broadcast_keys(self, client_keys: List[BroadCastClientKeys]) -> ServerKeyBroadcast:
        return ServerKeyBroadcast(participants=client_keys)

    def broadcast_cyphers(self, shared_ciphers: List[ShareKeysMessage], user_id: str) -> ServerCipherBroadcast:

        user_ciphers = []
        for message in shared_ciphers:
            if message.user_id == user_id:
                pass
            else:
                for cipher in message.ciphers:
                    if cipher.recipient == user_id:
                        user_cipher = UserCipher(
                            sender=message.user_id,
                            receiver=user_id,
                            cipher=cipher.cipher
                        )

                        user_ciphers.append(user_cipher)

        return ServerCipherBroadcast(ciphers=user_ciphers)

    def collect_masked_input(self, masked_input: MaskedInput):
        pass
