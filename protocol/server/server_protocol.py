from typing import List

from protocol.models.server_messages import (ServerKeyBroadcast, BroadCastClientKeys, ServerCipherBroadcast, UserCipher,
                                             Round4Participant, ServerUnmaskBroadCast)
from protocol.models.client_messages import ShareKeysMessage, MaskedInput


class ServerProtocol:

    def broadcast_keys(self, client_keys: List[BroadCastClientKeys]) -> ServerKeyBroadcast:
        return ServerKeyBroadcast(participants=client_keys)

    def broadcast_cyphers(self, shared_ciphers: List[ShareKeysMessage], user_id: str) -> ServerCipherBroadcast:

        user_ciphers = []
        # iterate over all ciphers received in the previous round
        for message in shared_ciphers:
            # don't add the user's own cipher
            if message.user_id == user_id:
                pass
            else:
                # from cipher submitted by other users get the cipher addressed to the user
                for cipher in message.ciphers:
                    if cipher.recipient == user_id:
                        user_cipher = UserCipher(
                            sender=message.user_id,
                            receiver=user_id,
                            cipher=cipher.cipher
                        )

                        user_ciphers.append(user_cipher)

        return ServerCipherBroadcast(ciphers=user_ciphers)

    def broadcast_unmask_participants(self, masked_inputs: List[MaskedInput]) -> ServerUnmaskBroadCast:
        # todo add signatures
        participants = [Round4Participant(user_id=mask_in.user_id) for mask_in in masked_inputs]
        return ServerUnmaskBroadCast(participants=participants)
