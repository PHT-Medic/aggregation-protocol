import os
from typing import Tuple, List

from protocol.models import HexString
from protocol.models.client_keys import ClientKeys
from protocol.models.secrets import SecretShares, EncryptedCipher
from protocol.models.server_messages import ServerKeyBroadcast, ServerCipherBroadcast, BroadCastClientKeys
from protocol.secrets.secret_sharing import create_secret_shares
from protocol.models.client_messages import ClientKeyBroadCast, ShareKeysMessage, MaskedInput
from protocol.secrets.ciphers import generate_encrypted_cipher
from protocol.secrets.util import load_public_key
from protocol.secrets.masking import generate_random_seed, create_mask


class ClientProtocol:

    def setup(self) -> Tuple[ClientKeys, ClientKeyBroadCast]:
        # todo get signing key and verification keys from server
        keys = ClientKeys()
        return keys, keys.key_broadcast()

    def process_key_broadcast(self, user_id: str, keys: ClientKeys, broadcast: ServerKeyBroadcast, k: int = 3):
        if len(broadcast.participants) < k:
            raise ValueError("Not enough participants")
        self._validate_broadcast(broadcast)

        # generate a new random seed
        seed = generate_random_seed()
        # generate the secret shares
        secret_shares = create_secret_shares(keys.hex_sharing_key, seed, n=len(broadcast.participants), k=k)
        # encrypt the secret shares with the cipher public keys and generate a message to the server with the
        # encrypted shares
        response = self.share_keys(user_id, keys, secret_shares, broadcast)

        return seed, response

    def process_cipher_broadcast(self,
                                 user_id: str,
                                 keys: ClientKeys,
                                 broadcast: ServerCipherBroadcast,
                                 participants: List[BroadCastClientKeys],
                                 mask_size: int,
                                 seed: str,
                                 ) -> MaskedInput:

        # filter round 2 participants
        round_2_ids = [cipher.sender for cipher in broadcast.ciphers]
        round_2_participants = [p for p in participants if p.user_id in round_2_ids]
        # generate the mask for the round 2 participants
        mask = create_mask(user_id=user_id,
                           user_keys=keys,
                           participants=round_2_participants,
                           n_params=mask_size,
                           seed=seed
                           )

        return MaskedInput(user_id=user_id, masked_input=list(mask))

    @staticmethod
    def share_keys(user_id: str,
                   client_keys: ClientKeys,
                   secret_shares: SecretShares,
                   broadcast: ServerKeyBroadcast,
                   ) -> ShareKeysMessage:

        if len(secret_shares.key_shares) != len(broadcast.participants):
            raise ValueError("Number of shares does not match number of participants")

        ciphers = []
        for key_share, seed_share, participant in zip(secret_shares.key_shares, secret_shares.seed_shares,
                                                      broadcast.participants):
            # Skip generating the cypher for yourself
            if participant.user_id == user_id:
                pass
            else:
                # generate the encrypted cipher
                cipher = generate_encrypted_cipher(
                    sender=user_id,
                    private_key=client_keys.cipher_key,
                    recipient=participant.user_id,
                    recipient_key=load_public_key(participant.broadcast.cipher_public_key),
                    seed_share=seed_share,
                    key_share=key_share
                )
                encrypted_cipher = EncryptedCipher(cipher=HexString(cipher), recipient=participant.user_id)
                ciphers.append(encrypted_cipher)

        return ShareKeysMessage(user_id=user_id, ciphers=ciphers)

    @staticmethod
    def _validate_broadcast(broadcast: ServerKeyBroadcast):
        def _all_unique(x):
            seen = list()
            return not any(i in seen or seen.append(i) for i in x)

        cipher_public_keys = [x.broadcast.cipher_public_key for x in broadcast.participants]
        sharing_public_keys = [x.broadcast.sharing_public_key for x in broadcast.participants]
        if not _all_unique(cipher_public_keys):
            raise ValueError("Duplicate signing keys.")
        if not _all_unique(sharing_public_keys):
            raise ValueError("Duplicate sharing keys.")
