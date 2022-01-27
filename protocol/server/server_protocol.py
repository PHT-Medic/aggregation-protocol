from typing import List, Tuple, Union

import numpy as np

from protocol.secrets.masking import integer_seed_from_hex, expand_seed, generate_shared_mask
from protocol.secrets.secret_sharing import combine_key_shares, combine_seed_shares
from protocol.models.server_messages import (ServerKeyBroadcast, BroadCastClientKeys, ServerCipherBroadcast, UserCipher,
                                             Round4Participant, ServerUnmaskBroadCast, AggregatedParameters)
from protocol.models.client_messages import ShareKeysMessage, MaskedInput, UnmaskShares, UnmaskSeedShare, UnmaskKeyShare
from protocol.secrets.util import load_public_key


def _recover_shared_masks(user_key_shares: dict,
                          client_key_broadcasts: List[BroadCastClientKeys], mask_size: int = 100) -> np.ndarray:
    """
    Use a dictionary of key shares to recover the shared masks
    :param user_key_shares: dictionary containing a users key shares key: user_id, value: key shares for that user's
    sharing key
    :param client_key_broadcasts: List of public keys submitted by the clients
    :param mask_size: the size of the mask to generate
    :return: a numpy arra of size mask_size containing the recovered shared masks between users that dropped out before
    round 2.
    """
    reverse_shared_mask = np.zeros(mask_size)
    for broad_cast in client_key_broadcasts:
        sharing_key_shares = user_key_shares[broad_cast.user_id]
        recovered_sharing_key = combine_key_shares(sharing_key_shares, k=len(client_key_broadcasts) - 1)

        for receiver_broadcast in client_key_broadcasts:
            if receiver_broadcast.user_id != broad_cast.user_id:
                sharing_public_key = load_public_key(receiver_broadcast.broadcast.sharing_public_key)
                reverse_shared_mask += generate_shared_mask(private_key=recovered_sharing_key,
                                                            public_key=sharing_public_key, n_items=mask_size)

    return reverse_shared_mask


class ServerProtocol:

    @staticmethod
    def broadcast_keys(client_keys: List[BroadCastClientKeys]) -> ServerKeyBroadcast:
        """
        Broadcast a list of client key broadcast messages to all users
        :param client_keys: list of client key broadcasts submitted to the server
        :return: server broadcast containing the client keys
        """
        return ServerKeyBroadcast(participants=client_keys)

    @staticmethod
    def broadcast_cyphers(shared_ciphers: List[ShareKeysMessage], user_id: str) -> ServerCipherBroadcast:
        """
        Broadcast a list of ciphers addressed to a specific user
        :param shared_ciphers: list of ciphers received in round 2
        :param user_id: the user id to which the ciphers are addressed
        :return: ServerCipherBroadcast containing all ciphers addressed to the user in the current iteration
        """
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

    @staticmethod
    def broadcast_unmask_participants(masked_inputs: List[MaskedInput]) -> ServerUnmaskBroadCast:
        """
        Process a list of masked inputs received in round 3 and broadcast the participants of the unmasking round
        to all users
        :param masked_inputs: list of masked inputs received in round 3
        :return: Unmask broadcast containing the participants of the unmasking round
        """
        # todo add signatures
        participants = [Round4Participant(user_id=mask_in.user_id) for mask_in in masked_inputs]
        return ServerUnmaskBroadCast(participants=participants)

    def aggregate_masked_inputs(self, client_key_broadcasts: List[BroadCastClientKeys],
                                masked_inputs: List[MaskedInput],
                                unmask_shares: List[UnmaskShares]) -> AggregatedParameters:
        """
        Aggregate the masked inputs received in round 3 and unmask shares received in round 4. Use this to generate
        reverse masks to aggregate the masked inputs resulting in the unmasked sum of the masked inputs.

        :param client_key_broadcasts: keys submitted by the users in the current iteration
        :param masked_inputs: masked inputs submitted by the users in the current iteration
        :param unmask_shares: unmask shares submitted by the users in the current iteration
        :return: Aggregated parameters to be sent back to the users
        """

        # extract seed and key shares from the submitted unmask shares
        seed_shares = []
        key_shares = []
        for unmask_share in unmask_shares:
            seed_shares.extend(unmask_share.seed_shares)
            key_shares.extend(unmask_share.key_shares)

        input_size = len(masked_inputs[0].masked_input)
        # sum the masked inputs
        masked_sum = np.zeros(input_size)
        for masked_input in masked_inputs:
            masked_sum += masked_input.masked_input

        # generate the reverse masks
        reverse_mask, reverse_shared_mask = self._generate_reverse_mask(seed_shares, key_shares, client_key_broadcasts,
                                                                        mask_size=input_size)
        # subtract the seed based mask
        unmasked_sum = masked_sum - reverse_mask
        # for each dropped out user (if any) add the recovered shared mask
        if reverse_shared_mask:
            unmasked_sum += reverse_shared_mask

        return AggregatedParameters(params=list(unmasked_sum))

    @staticmethod
    def _generate_reverse_mask(seed_shares: List[UnmaskSeedShare],
                               key_shares: List[UnmaskKeyShare],
                               client_key_broadcasts: List[BroadCastClientKeys],
                               mask_size: int = 100
                               ) -> Tuple[np.ndarray, Union[np.ndarray, None]]:
        """
        Generate the reverse mask to unmask the sum of masked inputs
        :param seed_shares: shamir shares of the seed for all participants
        :param key_shares: shamir shares of the sharing key for all participants that dropped out in before round 2
        :param client_key_broadcasts: list of public keys broadcast by the clients in round 1
        :param mask_size: the size of the revers mask to generate
        :return:
        """
        user_seed_shares = {bc.user_id: [] for bc in client_key_broadcasts}
        user_key_shares = {bc.user_id: [] for bc in client_key_broadcasts}

        # aggregate the seed shares and key shares
        for share in seed_shares:
            user_seed_shares[share.user_id].append(share.seed_share)
        for share in key_shares:
            user_key_shares[share.user_id].append(share.key_share)

        # expand the combined random seed into the user masks
        seeds = [integer_seed_from_hex(combine_seed_shares(shares).hex()) for user_id, shares in
                 user_seed_shares.items()]
        # subtract the expanded user seeds
        reverse_mask = np.zeros(mask_size)
        for seed in seeds:
            reverse_mask += expand_seed(seed, mask_size)

        if len(key_shares) > 0:
            reverse_shared_mask = _recover_shared_masks(user_key_shares, client_key_broadcasts, mask_size)
            return reverse_mask, reverse_shared_mask
        else:
            return reverse_mask, None
