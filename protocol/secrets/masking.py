import os
from typing import List

import numpy as np
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey

from protocol.models.client_keys import ClientKeys
from protocol.models.secrets import SharedMask
from protocol.models.server_messages import BroadCastClientKeys
from protocol.secrets.key_agreement import derive_shared_key
from protocol.secrets.util import load_public_key


def create_mask(user_id: str, user_keys: ClientKeys, participants: List[BroadCastClientKeys], seed: str,
                n_params: int) -> np.ndarray:
    private_mask = _generate_private_mask(seed, n_params)
    mask = generate_user_masks(private_mask, user_id, user_keys, participants, n_params)

    return mask


def _generate_private_mask(seed: str, n_items: int) -> np.ndarray:
    seed = integer_seed_from_hex(seed)
    return expand_seed(seed, n_items)


def generate_user_masks(private_mask: np.ndarray, user_id: str, user_keys: ClientKeys,
                        participants: List[BroadCastClientKeys],
                        n_params: int) -> np.ndarray:
    user_index = len(participants)
    for i, participant in enumerate(participants):
        # set the user index when the id matches the broadcast
        print(user_id, participant.user_id)
        if participant.user_id == user_id:
            user_index = i

        else:
            # load public key from broadcast
            public_key = load_public_key(participant.broadcast.sharing_public_key)
            # multiplier for mask based on index in list
            if i > user_index:
                private_mask -= generate_shared_mask(user_keys.sharing_key, public_key, n_params)
                print("subtracting mask")
            else:
                print("adding mask")
                private_mask += generate_shared_mask(user_keys.sharing_key, public_key, n_params)

    return private_mask


def generate_shared_mask(private_key: EllipticCurvePrivateKey, public_key: EllipticCurvePublicKey, n_items: int,
                         multiplier: int = None) -> np.ndarray:
    # derive the key and transform into random seed
    shared_key = derive_shared_key(private_key, public_key, length=4)
    seed = integer_seed_from_hex(shared_key.hex())

    # generate the random vector
    mask = expand_seed(seed, n_items=n_items)
    if multiplier:
        mask = mask * multiplier

    return mask


def expand_seed(seed: int, n_items: int) -> np.ndarray:
    np.random.seed(seed)

    mask = np.random.random(n_items)

    return mask


def generate_random_seed() -> str:
    return os.urandom(4).hex()


def integer_seed_from_hex(hex_seed: str) -> int:
    return int(hex_seed, 16)
