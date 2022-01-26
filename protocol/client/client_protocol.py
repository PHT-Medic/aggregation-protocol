import os
from typing import Tuple, List

import numpy as np

from protocol.models import HexString
from protocol.models.client_keys import ClientKeys
from protocol.models.secrets import SecretShares, EncryptedCipher, Cipher
from protocol.models.server_messages import (ServerKeyBroadcast, ServerCipherBroadcast, BroadCastClientKeys,
                                             ServerUnmaskBroadCast, UserCipher)
from protocol.secrets.key_agreement import derive_shared_key
from protocol.secrets.secret_sharing import create_secret_shares
from protocol.models.client_messages import (ClientKeyBroadCast, ShareKeysMessage, MaskedInput, UnmaskShares,
                                             UnmaskSeedShare, UnmaskKeyShare)
from protocol.secrets.ciphers import generate_encrypted_cipher, decrypt_cipher
from protocol.secrets.util import load_public_key
from protocol.secrets.masking import generate_random_seed, create_mask


class ClientProtocol:

    def setup(self) -> Tuple[ClientKeys, ClientKeyBroadCast]:
        # todo get signing key and verification keys from server
        keys = ClientKeys()
        return keys, keys.key_broadcast()

    def process_key_broadcast(self,
                              user_id: str,
                              keys: ClientKeys,
                              broadcast: ServerKeyBroadcast,
                              k: int = 3):
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
                                 input: np.ndarray,
                                 seed: str,
                                 k: int = 3
                                 ) -> MaskedInput:

        # k - 1 since only ciphers not belonging to the user are needed
        if len(broadcast.ciphers) < k - 1:
            raise ValueError(f"Not enough ciphers collected - ({len(broadcast.ciphers)}/{k})")

        # filter round 2 participants
        round_2_ids = [cipher.sender for cipher in broadcast.ciphers]
        # round_2_participants = [p for p in participants if p.user_id in round_2_ids]
        # generate the mask for the round 2 participants
        mask = create_mask(user_id=user_id,
                           user_keys=keys,
                           participants=participants,
                           n_params=len(input),
                           seed=seed
                           )
        # add the mask to the input
        masked_input = mask + input

        return MaskedInput(user_id=user_id, masked_input=list(masked_input))

    def process_unmask_broadcast(self,
                                 user_id: str,
                                 keys: ClientKeys,
                                 cipher_broadcast: ServerCipherBroadcast,
                                 unmask_broadcast: ServerUnmaskBroadCast,
                                 participants: List[BroadCastClientKeys],
                                 k: int = 3
                                 ) -> UnmaskShares:

        if len(unmask_broadcast.participants) < k:
            raise ValueError(f"Not enough participants - ({len(unmask_broadcast.participants)}/{k})")

        shares = self._decrypt_ciphers(user_id=user_id, keys=keys, participants=participants,
                                       ciphers=cipher_broadcast.ciphers)

        round_1_participants = set([p.user_id for p in participants])
        round_2_participants = set([p.sender for p in cipher_broadcast.ciphers])

        unmask_shares = UnmaskShares.construct(user_id=user_id, seed_shares=[], key_shares=[])
        for share in shares:
            # add decrypted key share to unmask shares if users dropped out before round 2
            if share.sender in round_1_participants and share.sender not in round_2_participants:
                unmask_key_share = UnmaskKeyShare(user_id=share.sender, key_share=share.key_share)
                unmask_shares.key_shares.append(unmask_key_share)
            # otherwise, add the seed share
            if share.sender in round_2_participants:
                unmask_seed_share = UnmaskSeedShare(
                    user_id=share.sender,
                    seed_share=share.seed_share
                )
                unmask_shares.seed_shares.append(unmask_seed_share)
            else:
                raise ValueError(f"Unknown share sender {share.sender}")
        # return validated shares
        return UnmaskShares(**unmask_shares.dict())

    def _decrypt_ciphers(self, user_id: str, keys: ClientKeys, ciphers: List[UserCipher],
                         participants: List[BroadCastClientKeys]) -> List[Cipher]:

        if not len(ciphers) == len(participants) - 1:
            raise ValueError(f"Number of ciphers and participants must be equal. Cipher: {len(ciphers)}, "
                             f"Participants: {len(participants)}")

        decrypted_ciphers = []
        for i, cipher in enumerate(ciphers):
            if cipher.receiver != user_id:
                raise ValueError(
                    f"Cipher receiver must be the user id. Cipher receiver: {cipher.receiver}, user: {user_id}")
            sender_broadcast = [p for p in participants if p.user_id == cipher.sender][0]
            sender_public_key = load_public_key(sender_broadcast.broadcast.cipher_public_key)
            decrypted_cypher = decrypt_cipher(
                recipient=user_id,
                recipient_key=keys.cipher_key,
                sender_key=sender_public_key,
                encrypted_cypher=cipher.cipher,
                sender=cipher.sender
            )
            decrypted_ciphers.append(decrypted_cypher)

        return decrypted_ciphers

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
