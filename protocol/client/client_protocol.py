from typing import Tuple, List

import numpy as np

from protocol.models import HexString
from protocol.models.client_keys import ClientKeys
from protocol.models.secrets import SecretShares, EncryptedCipher, Cipher
from protocol.models.server_messages import (ServerKeyBroadcast, ServerCipherBroadcast, BroadCastClientKeys,
                                             ServerUnmaskBroadCast, UserCipher)
from protocol.secrets.secret_sharing import create_secret_shares
from protocol.models.client_messages import (ClientKeyBroadCast, ShareKeysMessage, MaskedInput, UnmaskShares,
                                             UnmaskSeedShare, UnmaskKeyShare)
from protocol.secrets.ciphers import generate_encrypted_cipher, decrypt_cipher
from protocol.secrets.util import load_public_key
from protocol.secrets.masking import generate_random_seed, create_mask


class ClientProtocol:

    @staticmethod
    def setup() -> Tuple[ClientKeys, ClientKeyBroadCast]:
        """
        Generate a new key pair and create a broadcast message to the server containing the corresponding public keys

        :return: Tuple of client keys containing a cipher and sharing key as well as the broadcast message to be
        sent to the server
        """

        # todo get signing key and verification keys from CA
        keys = ClientKeys()
        return keys, keys.key_broadcast()

    def process_key_broadcast(self,
                              user_id: str,
                              keys: ClientKeys,
                              broadcast: ServerKeyBroadcast,
                              k: int = 3) -> Tuple[str, ShareKeysMessage]:
        """
        Process a key broadcast message from the server. It contains the public keys of the participants for one
        iteration of the protocol.

        :param user_id: the user id of the client
        :param keys: the client keys (whose public keys have been broadcast to the server)
        :param broadcast: the server key broadcast containing a list of client public keys
        :param k: the minimum number of required participants
        :return: A Tuple containing the hex representation of the newly generated random seed and the share keys message
        containing encrypted ciphers for each other user
        """
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

    @staticmethod
    def process_cipher_broadcast(user_id: str,
                                 keys: ClientKeys,
                                 cipher_broadcast: ServerCipherBroadcast,
                                 participants: List[BroadCastClientKeys],
                                 input: np.ndarray,
                                 seed: str,
                                 k: int = 3
                                 ) -> MaskedInput:
        """
        Process the ciphers broadcast from the server in round 2 of the protocol, along with the clients input and
        generate  and apply the masks for the input based on the servers key broadcast as well as the previously 
        generated random seed.
        
        :param user_id: id of the client
        :param keys: key pair of the client matching the iteration of the protocol
        :param cipher_broadcast: server key broadcast containing the public keys of the other participants
        :param participants: list of  participants and their public keys received from the server
        :param input: the client's protocol input
        :param seed: the random seed generated in the previous round
        :param k: minimum number of participants

        :return: Pydantic model containing the masked input
        """

        # k - 1 since only ciphers not belonging to the user are needed
        if len(cipher_broadcast.ciphers) < k - 1:
            raise ValueError(f"Not enough ciphers collected - ({len(cipher_broadcast.ciphers)}/{k})")

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
        """
        Process the unmask broadcast from the server in round 3 of the protocol and generate the user unmask shares
        containing seed shares for all participants that participated in round 2. And the sharing key shares for all
        user that participated in round 1 but not round 2 of the protocol.

        :param user_id: the id of the client
        :param keys: the key pair of the client matching the iteration of the protocol
        :param cipher_broadcast: the encrypted ciphers received from the server in round 2
        :param unmask_broadcast: the unmask broadcast received from the server in round 3
        :param participants: the participants and their public keys received from the server
        :param k: the minimum number of participants
        :return: UnmaskShares to be sent to the server containing the seed shares and the sharing key shares
        according to the participants of the previous rounds.
        """

        if len(unmask_broadcast.participants) < k:
            raise ValueError(f"Not enough participants - ({len(unmask_broadcast.participants)}/{k})")

        # decrypt the encrypted ciphers received in round 2
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

    @staticmethod
    def _decrypt_ciphers(user_id: str, keys: ClientKeys, ciphers: List[UserCipher],
                         participants: List[BroadCastClientKeys]) -> List[Cipher]:
        """
        Decrypt the list of ciphers received from the server in round 2 using a symmetric key obtained via key
        derivation from the client's private key and each of the participants' public keys.

        :param user_id: the id of the client
        :param keys: the key pair of the client matching the iteration of the protocol
        :param ciphers: a list of encrypted ciphers received from the server in round 2
        :param participants: the participants and their public keys received from the server
        :return: a list of decrypted ciphers

        """

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
        """
        Generate a key share message to be sent to the server. Containing encrypted ciphers for each of the other
        participants. The ciphers contain Shamir shares of the private sharing key of the user as well as the user's
        private seed.

        :param user_id: the id of the client
        :param client_keys: the key pair of the client matching the iteration of the protocol
        :param secret_shares: secret shares of the private sharing key of the user and the user's private seed
        :param broadcast: key broadcast message received from the server
        :return: ShareKeysMessage containing the encrypted ciphers for each other participant
        """

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
        """
        Validate the broadcast received from the server. Check that all keys are unique.
        :param broadcast: key broadcast received from the server
        :return:
        """
        def _all_unique(x):
            seen = list()
            return not any(i in seen or seen.append(i) for i in x)

        cipher_public_keys = [x.broadcast.cipher_public_key for x in broadcast.participants]
        sharing_public_keys = [x.broadcast.sharing_public_key for x in broadcast.participants]
        if not _all_unique(cipher_public_keys):
            raise ValueError("Duplicate signing keys.")
        if not _all_unique(sharing_public_keys):
            raise ValueError("Duplicate sharing keys.")
