from typing import List, Tuple, Union

import numpy as np

from protocol.models.secrets import SeedShare
from protocol.secrets.masking import integer_seed_from_hex, expand_seed, generate_shared_mask
from protocol.secrets.secret_sharing import combine_key_shares, combine_seed_shares
from protocol.models.server_messages import (ServerKeyBroadcast, BroadCastClientKeys, ServerCipherBroadcast, UserCipher,
                                             Round4Participant, ServerUnmaskBroadCast, AggregatedParameters)
from protocol.models.client_messages import ShareKeysMessage, MaskedInput, UnmaskShares, UnmaskSeedShare, UnmaskKeyShare
from protocol.secrets.util import load_public_key


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

    def aggregate_masked_inputs(self, client_key_broadcasts: List[BroadCastClientKeys],
                                masked_inputs: List[MaskedInput],
                                unmask_shares: List[UnmaskShares]) -> AggregatedParameters:

        # todo recover mask seeds for users that submitted them

        seed_shares = []
        key_shares = []
        for unmask_share in unmask_shares:
            seed_shares.extend(unmask_share.seed_shares)
            key_shares.extend(unmask_share.key_shares)

        input_size = len(masked_inputs[0].masked_input)
        masked_sum = np.zeros(input_size)
        for masked_input in masked_inputs:
            masked_sum += masked_input.masked_input

        reverse_mask, reverse_shared_mask = self._generate_reverse_mask(seed_shares, key_shares, client_key_broadcasts,
                                                                        mask_size=input_size)
        unmasked_sum = masked_sum - reverse_mask
        if reverse_shared_mask:
            unmasked_sum += reverse_shared_mask

        return AggregatedParameters(params=list(unmasked_sum))

    def _generate_reverse_mask(self,
                               seed_shares: List[UnmaskSeedShare],
                               key_shares: List[UnmaskKeyShare],
                               client_key_broadcasts: List[BroadCastClientKeys],
                               mask_size: int = 100
                               ) -> Tuple[np.ndarray, Union[np.ndarray, None]]:
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
            reverse_shared_mask = self._recover_shared_masks(user_key_shares, client_key_broadcasts, mask_size)
            return reverse_mask, reverse_shared_mask
        else:
            return reverse_mask, None

        # add the shared masks to the reverse mask  (this is the final mask)

    def _recover_shared_masks(self, user_key_shares: dict,
                              client_key_broadcasts: List[BroadCastClientKeys], mask_size: int = 100) -> np.ndarray:

        reverse_shared_mask = np.zeros(mask_size)
        for broad_cast in client_key_broadcasts:
            sharing_key_shares = user_key_shares[broad_cast.user_id]
            recovered_sharing_key = combine_key_shares(sharing_key_shares, k=len(client_key_broadcasts) - 1)

            for receiver_broadcast in client_key_broadcasts:
                if receiver_broadcast.user_id != broad_cast.user_id:
                    sharing_public_key = load_public_key(receiver_broadcast.broadcast.sharing_public_key)
                    reverse_shared_mask += generate_shared_mask(private_key=recovered_sharing_key,
                                                                public_key=sharing_public_key, n_items=mask_size)

            print(f"{broad_cast.user_id} sharing key: {recovered_sharing_key}")

        return reverse_shared_mask
